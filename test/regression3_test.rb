# frozen_string_literal: true

# ============================================================================
#  REGRESYON TESTLERI -- 3. TUR
# ----------------------------------------------------------------------------
#  1. ve 2. tur web/webhook/bildirim tarafina bakmisti. Bu tur, o ana kadar
#  HIC DOKUNULMAMIS alanlari hedefliyor:
#
#    - bin/logsentry --replay        (0 test ile yayinlanmis kullanici arayuzu)
#    - Fetchers::GitHub              (0 entegrasyon)
#    - Parser'in JSON yolu           (dokumante edilmemis, farkli katilikta)
#    - Store arama filtreleri        (LIKE joker sizintisi)
#    - Web::App varsayilanlari       (kutuphane olarak kullanildiginda)
# ============================================================================

require 'minitest/autorun'
require 'json'
require 'tmpdir'
require 'fileutils'
require 'open3'
require 'rack/mock'

lib_path = File.expand_path('../lib', __dir__)
lib_path = File.expand_path('./lib') unless File.exist?(File.join(lib_path, 'log_sentry.rb'))
$LOAD_PATH.unshift(lib_path) unless $LOAD_PATH.include?(lib_path)

require 'log_sentry'
require 'log_sentry/store'
require 'log_sentry/web/app'
require 'log_sentry/fetchers/github'

class Regression3Test < Minitest::Test
  ROOT = if File.exist?(File.join(File.expand_path('..', __dir__), 'logsentry.gemspec'))
           File.expand_path('..', __dir__)
         else
           File.expand_path('.')
         end

  def setup
    @dir = Dir.mktmpdir('logsentry-regression3')
  end

  def teardown
    FileUtils.remove_entry(@dir) if File.exist?(@dir)
  rescue Errno::EACCES
    nil
  end

  # ==========================================================================
  #  1) --replay: ayristirilamayan satirlar SESSIZCE atlaniyor
  # --------------------------------------------------------------------------
  #  Desteklenmeyen bir formatta (IIS/W3C) 31 satirlik, icinde GERCEK bir
  #  brute-force bulunan bir log verildiginde cikti sadece sunu diyor:
  #      "Simulasyon Tamamlandi: 0 alarm uretildi."
  #
  #  Kullanicinin cikaracagi sonuc: "saldiri yok / kurallarim yeterli".
  #  Gercek: tek satir bile okunamadi. Parser zaten failed_count tutuyor;
  #  replay onu hic raporlamiyor.
  # ==========================================================================
  def test_replay_ayristirilamayan_satirlari_raporlar
    log = File.join(@dir, 'iis.log')
    File.open(log, 'w') do |f|
      f.puts '#Fields: date time c-ip cs-method cs-uri-stem sc-status'
      31.times { |i| f.puts format('2026-07-01 10:00:%02d 66.66.66.66 POST /login 401', i % 60) }
    end

    out, = Open3.capture2e(RbConfig.ruby, File.join(ROOT, 'bin', 'logsentry'), '--replay', log,
                           chdir: ROOT)

    assert_match(/atlan|ayristirilamayan|okunamayan|basarisiz/i, out,
                 "replay tum satirlari atladi ama bunu hic soylemedi. Cikti:\n#{out}")
  end

  def test_replay_hicbir_satir_okunamazsa_sifir_koduyla_cikmaz
    log = File.join(@dir, 'bozuk.log')
    File.write(log, "bu bir log satiri degil\nbu da degil\n")

    _, status = Open3.capture2e(RbConfig.ruby, File.join(ROOT, 'bin', 'logsentry'), '--replay', log,
                                chdir: ROOT)

    refute_equal 0, status.exitstatus,
                 'hicbir satir ayristirilamadigi halde replay basarili (0) koduyla cikiyor -- ' \
                 'CI/script icinde bu sessiz bir yanlis-guvenlik sinyali'
  end

  # ==========================================================================
  #  2) Fetchers::GitHub -- ucuncu olu modul
  # --------------------------------------------------------------------------
  #  GeoIP ve country_code helper'i gibi, API Event fetcher da hicbir yerden
  #  cagrilmiyor: ne CLI secenegi, ne daemon entegrasyonu, ne yapilandirma.
  # ==========================================================================
  def test_github_fetcher_bir_yerden_cagriliyor
    kaynaklar = Dir.glob(File.join(ROOT, '{lib,bin}', '**', '*'))
                   .select { |f| File.file?(f) }
                   .reject { |f| f.end_with?('fetchers/github.rb') }

    kullanan = kaynaklar.select { |f| File.read(f).match?(/Fetchers::GitHub|fetch_events/) }

    refute_empty kullanan,
                 'Fetchers::GitHub hicbir yerden cagrilmiyor -- CLI secenegi de yok, ' \
                 'yapilandirma anahtari da yok. GitHub Integration ozelliginin ucte biri olu kod.'
  end

  # ==========================================================================
  #  2b) Web ayarlari YAPILANDIRMADAN okunuyor mu?
  # --------------------------------------------------------------------------
  #  Yasanan ariza: app.rb icinde eksiksiz bir hiz siniri (rate limiter)
  #  vardi, testleri de gecıyordu -- ama bin/logsentry-web onu YAML'dan hic
  #  okumuyordu. Sonuc: `rate_limit_enabled` uretimde HER ZAMAN false kaldi
  #  ve ozellik yalnizca test ortaminda calisti. Kimse fark etmedi cunku
  #  "kod var ve testi geciyor" ile "ozellik acik" ayni sey saniliyordu.
  #
  #  Bu test o sinif hatayi yakalar: bir ayarin hem app.rb'de tanimli hem
  #  bin/logsentry-web'de kablolanmis olmasini sart kosar.
  # ==========================================================================
  def test_web_ayarlari_yapilandirmadan_kablolaniyor
    launcher = File.read(File.join(ROOT, 'bin', 'logsentry-web'))

    %w[rate_limit_enabled rate_limit_max rate_limit_window trusted_proxies].each do |ayar|
      assert_match(/app\.set\s+:#{ayar}\b/, launcher,
                   "#{ayar} app.rb'de tanimli ama bin/logsentry-web onu " \
                   'yapilandirmadan okumuyor -- ozellik uretimde olu kalir.')
    end
  end

  def test_hiz_siniri_yapilandirmada_belgelenmis
    yml = File.read(File.join(ROOT, 'config', 'logsentry.yml'))

    assert_match(/^\s+rate_limit:/, yml,
                 'web.rate_limit blogu yapilandirmada yok -- operatorun ' \
                 'ozelligin varligindan haberi olmaz.')
  end

  # ==========================================================================
  #  2c) Saklama suresini UYGULAYAN bir zamanlayici var mi?
  # --------------------------------------------------------------------------
  #  Yasanan ariza: yapilandirmada iki saklama suresi tanimliydi
  #  (hot_retention_days: 90, retention_days: 730) ve bunlari uygulayan kod
  #  da vardi (Store#prune!, Archiver#prune!). Ama o kodu CAGIRAN hicbir sey
  #  yoktu -- ne cron, ne systemd timer, ne compose servisi. Yalnizca birinin
  #  elle `bin/logsentry-archive --prune` yazmasiyla calisiyordu.
  #
  #  Yani sicak katman sinirsiz buyuyor, arsiv hic temizlenmiyordu ve
  #  yapilandirmadaki sureler bir NIYET BEYANI olarak kaliyordu. KVKK
  #  tarafinda sorun ayarin yazili olmamasi degil, ISLEMEMESIDIR.
  # ==========================================================================
  def test_saklama_suresi_icin_zamanlayici_tanimli
    timer = File.join(ROOT, 'deploy', 'logsentry-archive.timer')
    unit  = File.join(ROOT, 'deploy', 'logsentry-archive.service')

    assert File.exist?(timer),
           'saklama suresini periyodik uygulayan bir systemd timer yok -- ' \
           'prune! kodu var ama onu cagiran hicbir sey yok.'
    assert File.exist?(unit), 'timer bir .service birimine dayanmali'

    assert_match(/OnCalendar=/, File.read(timer), 'timer bir takvim tanimlamali')
    assert_match(/--all\b/, File.read(unit),
                 'bakim birimi verify+roll+prune+prune_db calistirmali')
  end

  # Bakim betigi, sicak katmani yukleyemedigi durumda SESSIZCE basarili
  # gorunmemeli. Onceki halde LoadError yakalanip "sqlite3 gem yok" diye
  # TAHMIN edilen bir sebep yaziliyor ve sifir cikis koduyla devam
  # ediliyordu -- yani zamanlayici "basarili" goruyor, temizlik hic
  # calismiyordu. (Gercek sebep bambaskaydi: require_relative, yolunda
  # ASCII disi karakter olan kurulumlarda cozumu bozuyordu.)
  def test_bakim_betigi_sessizce_basarili_gorunmez
    src = File.read(File.join(ROOT, 'bin', 'logsentry-archive'))

    # Yalnizca KOD satirlari: aciklama satirlarinda bu kaliplardan
    # bahsetmek serbest (nitekim orada neden kullanilmadigi anlatiliyor).
    kod = src.lines.reject { |l| l.strip.start_with?('#') }.join

    refute_match(/rescue LoadError\s*\n\s*next puts/, kod,
                 'LoadError yutulup sifir cikis koduyla devam edilmemeli')
    refute_match(%r{require_relative ['"]\.\./lib}, kod,
                 'betik $LOAD_PATH uzerinden require kullanmali -- ' \
                 'require_relative ASCII disi yollarda bozuluyor')
    assert_match(/exit_code = 1/, kod,
                 'temizlik yapilamadiginda sifir olmayan cikis kodu gerekir')
  end

  def test_compose_bakim_servisi_tanimli
    compose = File.read(File.join(ROOT, 'docker-compose.yml'))

    assert_match(/logsentry-maintenance:/, compose,
                 'konteyner kurulumunda saklama suresini uygulayan servis yok')
    assert_match(/logsentry-archive/, compose,
                 'bakim servisi bin/logsentry-archive calistirmali')
  end

  # ==========================================================================
  #  3) Parser'in iki yolu farkli katiliktA
  # --------------------------------------------------------------------------
  #  combined: status alani yoksa satiri REDDEDIYOR (dogru -- durum kodu
  #            olmadan brute_force/flood kurallari calisamaz).
  #  json    : status alani yoksa 200 UYDURUYOR.
  #
  #  Sonuc: 401'leri kaydetmeyen bir JSON log formatinda her satir "basarili
  #  istek" gorunur ve brute_force kurali HICBIR ZAMAN atesleyemez.
  # ==========================================================================
  def test_json_yolunda_eksik_status_uydurulmaz
    parser = LogSentry::Parser.new(format: :combined)
    satir  = '{"ip":"1.2.3.4","time":"2026-07-01T10:00:00","method":"POST","path":"/login"}'

    entry = parser.parse(satir)

    assert_nil entry,
               'JSON satirinda status yokken 200 uyduruluyor; ayni eksiklik combined ' \
               "formatta satiri reddediyor. Uretilen status: #{entry&.status}"
  end

  def test_json_ve_combined_ayni_eksige_ayni_tepkiyi_verir
    parser = LogSentry::Parser.new(format: :combined)

    combined = parser.parse('1.2.3.4 - - [01/Jul/2026:10:00:00 +0300] "POST /login HTTP/1.1"  1')
    json     = parser.parse('{"ip":"1.2.3.4","time":"2026-07-01T10:00:00","method":"POST","path":"/login"}')

    assert_equal combined.nil?, json.nil?,
                 'ayni eksik alan (status) iki ayristirma yolunda farkli sonuclaniyor: ' \
                 "combined=#{combined.inspect[0, 20]}, json=status #{json&.status}"
  end

  def test_json_formati_dokumante_edilmis
    metinler = [File.read(File.join(ROOT, 'README.md')),
                File.read(File.join(ROOT, 'config', 'logsentry.yml'))].join("\n")
    geciyor  = metinler.match?(/format:\s*json|json.*log.*format|json_log/i)

    assert geciyor,
           "Parser, satir '{' ile basliyorsa yapilandirmadan BAGIMSIZ olarak JSON'a " \
           'geciyor (parser.rb:235), ama bu davranis ne READMEde ne configde geciyor'
  end

  # ==========================================================================
  #  4) Store arama filtresi -- LIKE joker sizintisi
  # --------------------------------------------------------------------------
  #  path_like degeri "%#{deger}%" icine gomuluyor; kullanicinin yazdigi
  #  '_' ve '%' karakterleri SQL joker karakteri olarak calisiyor.
  #  Analist '/a_b' arar, '/axb' de gelir -- adli incelemede yaniltici.
  # ==========================================================================
  def test_path_arama_joker_karakterlerini_kacislar
    store = LogSentry::Store.new(path: File.join(@dir, 'like.db'))
    ['/a_b', '/axb'].each do |yol|
      store.record_event(
        LogSentry::Entry.new(ip: '1.1.1.1', time: Time.now, http_method: 'GET', path: yol,
                             protocol: 'HTTP/1.1', status: 200, bytes: 1, referer: '-', user_agent: 'u')
      )
    end
    store.flush

    bulunan = store.events(path_like: '/a_b').map { |e| e[:path] }.sort

    assert_equal ['/a_b'], bulunan,
                 "LIKE joker karakteri kacisilmiyor: '/a_b' aramasi #{bulunan.inspect} dondurdu"
  ensure
    store&.close unless store.nil? || store.closed?
  end

  # ==========================================================================
  #  5) Web::App kutuphane olarak kullanildiginda
  # --------------------------------------------------------------------------
  #  page_size icin sinif duzeyinde varsayilan YOK. Diger tum ayarlarin
  #  (store, read_only, auth_*, rate_limit_*) varsayilani var. Yalnizca
  #  bin/logsentry-web doldurdugu icin uretimde fark edilmiyor; gem'i
  #  dogrudan mount eden biri /alerts sayfasinda 500 aliyor.
  # ==========================================================================
  def test_page_size_varsayilani_var
    assert_operator LogSentry::Web::App.settings.page_size.to_i, :>, 0,
                    'Web::App icin page_size varsayilani tanimli degil; ' \
                    'launcher disinda kullanildiginda /alerts 500 veriyor'
  end
end
