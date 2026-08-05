# frozen_string_literal: true

# ============================================================================
#  REGRESYON TESTLERI -- 2. TUR
# ----------------------------------------------------------------------------
#  1. tur duzeltmeleri sonrasi kalan ve YENI ORTAYA CIKAN kusurlar.
#
#  Bu turdaki bulgular iki gruba ayriliyor:
#    A) Duzeltmenin KENDISININ actigi acik  (webhook kimlik dogrulamasi)
#    B) 1. tur testinin ZAYIF olmasi yuzunden yesile donen ama gercekte
#       kapanmamis eksikler (GeoIP entegrasyonu, Telegram kacisi)
# ============================================================================

require 'minitest/autorun'
require 'json'
require 'yaml'
require 'tmpdir'
require 'fileutils'
require 'benchmark'
require 'rack/mock'

lib_path = File.expand_path('../lib', __dir__)
lib_path = File.expand_path('./lib') unless File.exist?(File.join(lib_path, 'log_sentry.rb'))
$LOAD_PATH.unshift(lib_path) unless $LOAD_PATH.include?(lib_path)

require 'log_sentry'
require 'log_sentry/web/app'
require 'log_sentry/engine'
require 'log_sentry/enrichers/geoip'
require 'log_sentry/notifiers/telegram'

class Regression2Test < Minitest::Test
  ROOT = if File.exist?(File.join(File.expand_path('..', __dir__), 'logsentry.gemspec'))
           File.expand_path('..', __dir__)
         else
           File.expand_path('.')
         end

  def setup
    @dir   = Dir.mktmpdir('logsentry-regression2')
    @store = LogSentry::Store.new(path: File.join(@dir, 'test.db'))

    @app = LogSentry::Web::App
    @app.set :store,              @store
    @app.set :archiver,           nil
    @app.set :alert_file,         nil
    @app.set :read_only,          true
    @app.set :auth_enabled,       false
    @app.set :auth_pass,          nil
    @app.set :rate_limit_enabled, false
    @request = Rack::MockRequest.new(@app)
    ENV.delete('LOGSENTRY_GITHUB_WEBHOOK_SECRET')
  end

  def teardown
    @store.close unless @store.closed?
    @app.set :store,        nil
    @app.set :auth_enabled, false
    @app.set :auth_pass,    nil
    LogSentry::Web::App::RATE_LIMIT_STORE.clear
    ENV.delete('LOGSENTRY_GITHUB_WEBHOOK_SECRET')
    FileUtils.remove_entry(@dir) if File.exist?(@dir)
  rescue Errno::EACCES
    nil
  end

  def post_webhook(body = JSON.generate(repository: { full_name: 'a/b' }), headers = {})
    @request.post('/webhooks/github',
                  { input: body, 'CONTENT_TYPE' => 'application/json' }.merge(headers))
  end

  # ==========================================================================
  #  A) DUZELTMENIN ACTIGI YENI ACIK
  # --------------------------------------------------------------------------
  #  /webhooks/github artik hem read_only'den hem Basic Auth'tan MUAF.
  #  HMAC kontrolu ise yalnizca `if secret && !secret.empty?` ile calisiyor.
  #  Sir ayarlanmamissa -- ki varsayilan bu -- geriye HICBIR kontrol kalmiyor:
  #  parola korumali bir panelde bile herkes veritabanina yazabiliyor.
  #
  #  Dogru davranis: ACIGA DEGIL, KAPALIYA dusmek. Sir yoksa istek reddedilmeli.
  # ==========================================================================
  def test_sir_ayarli_degilken_webhook_yaziya_izin_vermez
    res = post_webhook

    refute_equal 200, res.status,
                 'LOGSENTRY_GITHUB_WEBHOOK_SECRET ayarli degilken webhook kimlik dogrulamasiz ' \
                 'yaziya izin veriyor (fail-open). Sir yoksa istek reddedilmeli.'
  end

  def test_parola_korumali_panelde_webhook_yazamaz
    @app.set :auth_enabled, true
    @app.set :auth_user,    'admin'
    @app.set :auth_pass,    'cok-gizli'

    # Panel gercekten kilitli:
    assert_equal 401, @request.get('/').status

    50.times { |i| post_webhook(JSON.generate(repository: { full_name: "sahte/#{i}" })) }
    @store.flush

    assert_equal 0, @store.stats[:events],
                 'panel parola korumali oldugu halde webhook uzerinden ' \
                 "#{@store.stats[:events]} kayit yazildi -- kimlik dogrulamasiz yazma yolu"
  end

  def test_webhook_govde_boyutu_sinirli
    # Kimlik dogrulamasi olmayan bir uc noktada sinirsiz govde okumak
    # dogrudan hafiza tuketme saldirisidir.
    res = post_webhook(JSON.generate(repository: { full_name: 'a/b' }, pad: 'A' * 5_000_000))

    assert_equal 413, res.status,
                 'webhook 5 MB govdeyi kabul ediyor; govde boyutu sinirlanmali (413)'
  end

  # ==========================================================================
  #  B) ZAYIF TEST YUZUNDEN KAPANMAMIS EKSIKLER
  # ==========================================================================

  #  1. turdaki test yalnizca "GeoIP lib/ icinde geciyor mu" diye bakiyordu;
  #  bir `require_relative` + hicbir yerden cagrilmayan helper bunu tatmin
  #  etti. Gercek olcut: panelde GORUNUYOR mu?
  def test_geoip_panelde_gercekten_gosteriliyor
    views = Dir.glob(File.join(ROOT, 'lib', '**', '*.erb'))
    kullanan = views.select { |f| File.read(f).match?(/country_code/) }

    refute_empty kullanan,
                 'country_code helper tanimli ama hicbir .erb sablonu kullanmiyor -- ' \
                 'GeoIP hala olu kod'
  end

  #  Sahte tablo kaldirildi (dogru karar) ama yerine hicbir sey konmadi:
  #  artik her genel IP icin 'UNKNOWN' donuyor. Zenginlestirici hicbir sey
  #  zenginlestirmiyor.
  def test_geoip_en_az_bir_genel_ip_icin_veri_uretir
    sonuc = LogSentry::Enrichers::GeoIP.lookup('8.8.8.8')

    refute_equal 'UNKNOWN', sonuc,
                 'GeoIP her genel IP icin UNKNOWN donuyor -- veri kaynagi hic bagli degil, ' \
                 'zenginlestirici islevsiz'
  end

  #  1. turdaki test yalnizca `*` ve `_` sayisinin cift olmasina bakiyordu;
  #  karakterleri SILMEK de bunu saglar. Ama silmek KANITI TAHRIF eder:
  #  analist yanlis yolu inceler, SQLi yuku bozulur.
  def test_telegram_kaniti_tahrif_etmeden_kacislar
    ENV['LOGSENTRY_TELEGRAM_BOT_TOKEN'] = 'token'
    ENV['LOGSENTRY_TELEGRAM_CHAT_ID']   = 'chat'
    notifier = LogSentry::Notifiers::Telegram.new

    yol = "/wp-admin_backup/index.php?id=1'[OR]1=1"
    alert = LogSentry::Alert.new(
      rule: :sqli, severity: :critical, ip: '203.0.113.7',
      message: "SQL Injection (son istek: #{yol})",
      time: Time.now, count: 1, threshold: 0, window: 60, details: {}, evidence: []
    )

    text = notifier.send(:build_payload, alert)[:text]
    # Kacis isaretlerini kaldirinca ORIJINAL yol geri gelmeli.
    geri = text.gsub('\\', '')

    assert_includes geri, yol,
                    'Telegram govdesi karakterleri KACIRMAK yerine SILIYOR; ' \
                    "kanit tahrif oluyor (#{yol.inspect} -> mesajda yok)"
  ensure
    ENV.delete('LOGSENTRY_TELEGRAM_BOT_TOKEN')
    ENV.delete('LOGSENTRY_TELEGRAM_CHAT_ID')
  end

  #  Kural yuklendi ama config'teki `blacklist: []` kod icindeki
  #  DEFAULT_BLACKLIST'i eziyor -- kural etkin gorunup hicbir sey yakalamiyor.
  def test_threat_intel_varsayilan_kurulumda_gercekten_atesler
    cfg    = YAML.safe_load(File.read(File.join(ROOT, 'config', 'logsentry.yml')), aliases: true)
    engine = LogSentry::Engine.from_config(cfg)

    kotu = LogSentry::Rules::ThreatIntel::DEFAULT_BLACKLIST.first
    entry = LogSentry::Entry.new(
      ip: kotu, time: Time.now, http_method: 'GET', path: '/', protocol: 'HTTP/1.1',
      status: 200, bytes: 1, referer: '-', user_agent: 'x'
    )

    refute_empty engine.process(entry),
                 "threat_intel etkin ama config'teki 'blacklist: []' kod icindeki listeyi " \
                 'eziyor; kural hicbir zaman ateslemez (DEFAULT_BLACKLIST olu kod)'
  end

  # ==========================================================================
  #  C) HIZ SINIRI DUZELTMESININ MALIYETI
  # --------------------------------------------------------------------------
  #  Sizinti kapandi ama her istekte TUM hash taraniyor -- ustelik global
  #  mutex icinde. IP degistiren bir saldirgan karsisinda (kural motorunuzun
  #  credential_stuffing yorumunda anlattiginiz senaryo) hiz sinirlayici
  #  yavaslatan tarafa geciyor.
  # ==========================================================================
  def test_hiz_siniri_ip_sayisindan_bagimsiz_calisir
    olc = lambda do |ip_sayisi|
      LogSentry::Web::App::RATE_LIMIT_STORE.clear
      ip_sayisi.times { |i| LogSentry::Web::App.check_rate_limit("10.#{i / 65_536}.#{(i / 256) % 256}.#{i % 256}", 1_000_000, 60) }
      Benchmark.realtime { 500.times { LogSentry::Web::App.check_rate_limit('203.0.113.1', 1_000_000, 60) } }
    end

    kucuk = olc.call(200)
    buyuk = olc.call(10_000)
    oran  = buyuk / [kucuk, 0.0001].max

    assert_operator oran, :<, 5.0,
                    format('hiz sinirlayici IP sayisiyla dogrusal yavasliyor ' \
                           '(200 IP: %.1f ms, 10.000 IP: %.1f ms, %.1fx). ' \
                           'delete_if her istekte tum hash-i global mutex icinde tariyor.',
                           kucuk * 1000, buyuk * 1000, oran)
  ensure
    LogSentry::Web::App::RATE_LIMIT_STORE.clear
  end
end
