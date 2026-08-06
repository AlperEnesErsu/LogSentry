# frozen_string_literal: true

# ============================================================================
#  REGRESYON TESTLERI -- son 5 ozellikte bulunan eksikler
# ----------------------------------------------------------------------------
#  Bu dosyadaki testler DOGRU davranisi iddia eder. Su an bir kismi KIRMIZI;
#  her biri gercek bir kusuru sabitliyor. Kusur duzeltilince yesile doner.
#
#  Kapsam: GitHub webhook, /metrics, threat_intel yapilandirmasi, GeoIP,
#          Telegram bildirim govdesi, rate limit hafizasi, paketleme.
# ============================================================================

require 'minitest/autorun'
require 'json'
require 'tmpdir'
require 'fileutils'
require 'openssl'
require 'rack/mock'

lib_path = File.expand_path('../lib', __dir__)
lib_path = File.expand_path('./lib') unless File.exist?(File.join(lib_path, 'log_sentry.rb'))
$LOAD_PATH.unshift(lib_path) unless $LOAD_PATH.include?(lib_path)

require 'log_sentry'
require 'log_sentry/web/app'
require 'log_sentry/engine'
require 'log_sentry/enrichers/geoip'
require 'log_sentry/notifiers/telegram'

class RegressionTest < Minitest::Test
  # Depo koku. Yol icinde ASCII disi karakter varsa (orn. "Masaustu")
  # __dir__ Windows'ta bozulabiliyor; mevcut testlerdeki gibi cwd'ye dusuyoruz.
  ROOT = if File.exist?(File.join(File.expand_path('..', __dir__), 'logsentry.gemspec'))
           File.expand_path('..', __dir__)
         else
           File.expand_path('.')
         end

  def setup
    @dir   = Dir.mktmpdir('logsentry-regression')
    @store = LogSentry::Store.new(path: File.join(@dir, 'test.db'))

    @app = LogSentry::Web::App
    @app.set :store,               @store
    @app.set :archiver,            nil
    @app.set :alert_file,          nil
    @app.set :read_only,           true
    @app.set :auth_enabled,        false
    @app.set :auth_pass,           nil
    @app.set :rate_limit_enabled,  false
    @request = Rack::MockRequest.new(@app)
    ENV.delete('LOGSENTRY_GITHUB_WEBHOOK_SECRET')
  end

  def teardown
    @store.close unless @store.closed?
    @app.set :store, nil
    LogSentry::Web::App::RATE_LIMIT_STORE.clear
    ENV.delete('LOGSENTRY_GITHUB_WEBHOOK_SECRET')
    FileUtils.remove_entry(@dir) if File.exist?(@dir)
  rescue Errno::EACCES
    nil
  end

  def entry(ip: '203.0.113.9', path: '/x', ua: 'ua', status: 200, time: Time.now)
    LogSentry::Entry.new(
      ip: ip, time: time, http_method: 'GET', path: path, protocol: 'HTTP/1.1',
      status: status, bytes: 100, referer: '-', user_agent: ua
    )
  end

  # ==========================================================================
  #  1) GITHUB WEBHOOK -- store BAGLIYKEN cokuyor
  # --------------------------------------------------------------------------
  #  Mevcut testler store=nil iken kostugu icin `store&.append_event` satiri
  #  hic calismiyordu. Gercek kurulumda store HER ZAMAN bagli olur.
  # ==========================================================================
  def test_webhook_store_bagliyken_200_doner
    ENV['LOGSENTRY_GITHUB_WEBHOOK_SECRET'] = 'mysecret'
    payload = JSON.generate(
      zen: 'x',
      repository: { full_name: 'AlperEnesErsu/LogSentry' },
      sender: { login: 'AlperEnesErsu' }
    )
    sig = 'sha256=' + OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha256'), 'mysecret', payload)

    res = @request.post('/webhooks/github',
                        input: payload,
                        'CONTENT_TYPE' => 'application/json',
                        'HTTP_X_GITHUB_EVENT' => 'ping',
                        'HTTP_X_HUB_SIGNATURE_256' => sig)

    assert_equal 200, res.status,
                 'store bagliyken webhook 500 veriyor (Store#append_event yok, dogrusu record_event)'
  end

  def test_webhook_olayi_gercekten_veritabanina_yazar
    ENV['LOGSENTRY_GITHUB_WEBHOOK_SECRET'] = 'mysecret'
    payload = JSON.generate(repository: { full_name: 'a/b' }, sender: { login: 'c' })
    sig = 'sha256=' + OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha256'), 'mysecret', payload)

    @request.post('/webhooks/github',
                  input: payload,
                  'CONTENT_TYPE' => 'application/json',
                  'HTTP_X_GITHUB_EVENT' => 'push',
                  'HTTP_X_HUB_SIGNATURE_256' => sig)
    @store.flush

    paths = @store.events(limit: 10).map { |e| e[:path] }
    assert_includes paths, '/webhooks/github/push',
                    'webhook olayi veritabanina hic yazilmamis'
  end

  # ==========================================================================
  #  2) /metrics -- degerler dogru mu?
  # --------------------------------------------------------------------------
  #  Mevcut test yalnizca metrik ADLARININ gectigini kontrol ediyor, bu
  #  yuzden surekli 0 donen bir sayac fark edilmiyor.
  # ==========================================================================
  def test_metrics_events_total_gercek_sayiyi_verir
    5.times { |i| @store.record_event(entry(ip: "10.1.1.#{i}")) }
    @store.flush

    body = @request.get('/metrics').body
    line = body.lines.find { |l| l.start_with?('logsentry_events_total') }

    refute_nil line, 'logsentry_events_total satiri yok'
    assert_equal 5, line.split.last.to_i,
                 'events_total her zaman 0 (stats[:events_count] diye bir anahtar yok, dogrusu stats[:events])'
  end

  def test_metrics_alerts_total_1000_de_takilmaz
    1050.times do |i|
      @store.record_alert(
        LogSentry::Alert.new(
          rule: :sqli, severity: :critical, ip: "10.2.#{i / 256}.#{i % 256}",
          message: 'test', time: Time.now, count: 1, threshold: 0,
          window: 60, details: {}, evidence: []
        )
      )
    end
    @store.flush

    body = @request.get('/metrics').body
    line = body.lines.find { |l| l.start_with?('logsentry_alerts_total') }
    value = line.split.last.to_i

    assert_equal 1050, value,
                 'alerts_total limit:1000 ile sayiliyor, 1000 tavanina takiliyor (dogrusu count_alerts)'
  end

  # ==========================================================================
  #  3) THREAT INTEL -- yapilandirmadan ulasilabiliyor mu?
  # ==========================================================================
  def test_threat_intel_varsayilan_yapilandirmada_etkin
    config = YAML.load_file(File.join(ROOT, 'config', 'logsentry.yml'))

    assert config.dig('rules', 'threat_intel'),
           'threat_intel config/logsentry.yml icinde hic yok; kural gercek kurulumda ASLA calismaz'
  end

  def test_threat_intel_kara_listesi_yapilandirmadan_okunur
    config = {
      'cooldown' => 120,
      'rules' => {
        'threat_intel' => {
          'enabled' => true, 'window' => 60, 'threshold' => 0,
          'blacklist' => ['198.18.0.1']
        }
      }
    }

    engine = LogSentry::Engine.from_config(config)
    alerts = engine.process(entry(ip: '198.18.0.1'))

    refute_empty alerts,
                 'YAML icindeki blacklist yok sayiliyor (Engine.build_rule blacklist anahtarini gecirmiyor)'
  end

  def test_bilinmeyen_kural_secenegi_sessizce_yutulmaz
    config = {
      'cooldown' => 120,
      'rules' => { 'flood' => { 'enabled' => true, 'window' => 1, 'threshold' => 5, 'treshold' => 99 } }
    }

    # Bilinmeyen KURAL ADI patliyor ama bilinmeyen SECENEK ADI sessizce
    # yutuluyor -- yazim hatasi aylarca fark edilmez.
    assert_raises(ArgumentError, 'yazim hatali kural secenegi sessizce yok sayiliyor') do
      LogSentry::Engine.from_config(config)
    end
  end

  # ==========================================================================
  #  4) GEOIP -- uretimde kullanilabilir mi?
  # ==========================================================================
  def test_geoip_bir_yerden_cagriliyor
    hits = Dir.glob(File.join(ROOT, '{lib,bin}', '**', '*.{rb,erb}'))
              .reject { |f| f.end_with?('enrichers/geoip.rb') }
              .select { |f| File.read(f).match?(/GeoIP/) }

    refute_empty hits,
                 'GeoIP hicbir yerden cagrilmiyor -- olu kod (engine/store/panel entegrasyonu yok)'
  end

  def test_geoip_uydurma_veri_uretmez
    # 45.x -> 'RU' esleme tablosu tamamen uydurma. Gercek bir veritabani
    # yoksa 'UNKNOWN' donmeli; SIEM'de uydurma ulke kodu yanlis yonlendirir.
    assert_equal 'UNKNOWN', LogSentry::Enrichers::GeoIP.lookup('45.155.205.233'),
                 'GeoIP gercek veri olmadan ulke kodu uyduruyor (ilk oktete bakan sahte tablo)'
  end

  # ==========================================================================
  #  5) TELEGRAM -- saldirgan bildirim kanalini kirabiliyor mu?
  # --------------------------------------------------------------------------
  #  Panel icin h() ile XSS'e karsi ozenli davranilmis, ama ayni saldirgan
  #  verisi Telegram'a parse_mode: Markdown ile ham gonderiliyor.
  #  Dengesiz `*` / `_` / `[` karakterleri Telegram'da 400 "can't parse
  #  entities" hatasi verir -> alarm HIC GITMEZ. Saldirgan tek bir istekle
  #  kendisiyle ilgili bildirimi susturur.
  # ==========================================================================
  def test_telegram_govdesi_saldirgan_markdownunu_kacisla
    ENV['LOGSENTRY_TELEGRAM_BOT_TOKEN'] = 'token'
    ENV['LOGSENTRY_TELEGRAM_CHAT_ID']   = 'chat'
    notifier = LogSentry::Notifiers::Telegram.new

    alert = LogSentry::Alert.new(
      rule: :sqli, severity: :critical, ip: '203.0.113.7',
      # Gercek bir istek satirindan gelebilecek yol:
      message: "SQL Injection tespit edildi (son istek: /a?q=*bold_[x](y))",
      time: Time.now, count: 1, threshold: 0, window: 60, details: {}, evidence: []
    )

    payload = notifier.send(:build_payload, alert)
    text    = payload[:text]

    star_count       = text.count('*')
    underscore_count = text.count('_')

    assert_equal 0, star_count.odd? ? 1 : 0,
                 "Telegram Markdown govdesinde '*' dengesiz -> API 400 verir, alarm gitmez: #{text.inspect}"
    assert_equal 0, underscore_count.odd? ? 1 : 0,
                 "Telegram Markdown govdesinde '_' dengesiz -> API 400 verir, alarm gitmez"
  ensure
    ENV.delete('LOGSENTRY_TELEGRAM_BOT_TOKEN')
    ENV.delete('LOGSENTRY_TELEGRAM_CHAT_ID')
  end

  # ==========================================================================
  #  6) RATE LIMIT -- hafiza sizintisi
  # --------------------------------------------------------------------------
  #  Her IP icin bir dizi aciliyor; dizinin ICI temizleniyor ama BOS DIZI
  #  hash'te kaliyor. IP degistiren bir saldirgan hash'i sinirsiz buyutur.
  # ==========================================================================
  def test_rate_limit_suresi_gecmis_ipleri_unutur
    store = LogSentry::Web::App::RATE_LIMIT_STORE
    store.clear

    # 2000 farkli IP istek atsin (IP degistiren bir saldirgan / genis NAT).
    2000.times { |i| LogSentry::Web::App.check_rate_limit("198.51.#{i / 256}.#{i % 256}", 60, 60) }
    assert_equal 2000, store.size

    # Hepsinin penceresi coktan gecti; bir daha da hic gelmiyorlar.
    store.each_value { |times| times.map! { |t| t - 10_000 } }

    # Yeni bir istek gelsin -- bu noktada olu kayitlar dusmus olmali.
    LogSentry::Web::App.check_rate_limit('203.0.113.1', 60, 60)

    assert_operator store.size, :<=, 10,
                    "olu IP kayitlari hash'te kaliyor (#{store.size} kayit) -- " \
                    'RATE_LIMIT_STORE sinirsiz buyuyor, uzun calisan surecte hafiza sizintisi'
  ensure
    LogSentry::Web::App::RATE_LIMIT_STORE.clear
  end

  # ==========================================================================
  #  7) PAKETLEME -- README'de anlatilan arac gem ile kuruluyor mu?
  # ==========================================================================
  #  NOT: bu test once `spec.executables = ...` SATIRINI okuyordu. Liste
  #  cok satirli bir %w[] blogUNA donusunce assertion, kod dogru oldugu
  #  halde kirildi -- bicimlendirmeye bagimli bir testin klasik sonu.
  #  Artik blogun tamami okunuyor.
  #
  #  Daha genis kapsamli kardesi: regression3_test.rb ->
  #  test_bin_komutlari_gemspec_ile_ayni (bin/ ile listeyi birbirine kilitler)
  def test_doctor_araci_gemspec_icinde
    gemspec = File.read(File.join(ROOT, 'logsentry.gemspec'))
    executables = gemspec[/spec\.executables\s*=\s*(%w\[.*?\]|\[.*?\])/m, 1].to_s

    assert_includes executables, 'logsentry-doctor',
                    "bin/logsentry-doctor README'de anlatiliyor ama gemspec executables listesinde yok"
  end
end
