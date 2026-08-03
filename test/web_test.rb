# frozen_string_literal: true

# ============================================================================
#  Adim 7 testleri: web arayuzu
# ----------------------------------------------------------------------------
#  Calistirmak icin:   ruby test/web_test.rb
#
#  Gercek bir sunucu BASLATMIYORUZ. Rack::MockRequest ile uygulamaya
#  dogrudan istek gonderiyoruz -- port yok, ag yok, bekleme yok.
#  (rack-test gem'ine de ihtiyac yok; MockRequest rack'in kendi parcasi.)
#
#  Bu testlerin en onemlisi XSS testleri. Sebep: bu panelde gosterilen
#  verinin buyuk kismini SALDIRGAN yaziyor -- izlenen sunucuya istek atarak
#  log dosyasina istedigi metni sokabiliyor.
# ============================================================================

require 'minitest/autorun'
require 'tmpdir'

lib_path = File.expand_path('../lib', __dir__)
lib_path = File.expand_path('./lib') unless File.exist?(File.join(lib_path, 'log_sentry.rb'))
$LOAD_PATH.unshift(lib_path) unless $LOAD_PATH.include?(lib_path)

require 'log_sentry/web/app'
require 'log_sentry/store'
require 'json'
require 'rack/mock'
require 'log_sentry'
require 'log_sentry/archiver'

class WebTest < Minitest::Test
  T0 = Time.new(2026, 7, 29, 14, 0, 0, '+03:00')

  # Saldirganin log satirina sokabilecegi klasik XSS yuku
  XSS = '<script>alert(document.cookie)</script>'

  def setup
    @dir   = Dir.mktmpdir('logsentry-web')
    @store = LogSentry::Store.new(path: File.join(@dir, 'test.db'))
    @alert_file = File.join(@dir, 'alerts.jsonl')
    File.write(@alert_file, '')

    app = LogSentry::Web::App
    app.set :store,        @store
    app.set :archiver,     nil
    app.set :alert_file,   @alert_file
    app.set :read_only,    true
    app.set :page_size,    10
    app.set :auth_enabled,       false
    app.set :auth_pass,          nil
    app.set :rate_limit_enabled, false
    LogSentry::Web::App::RATE_LIMIT_STORE.clear

    @request = Rack::MockRequest.new(app)
  end

  def teardown
    @store&.close
    FileUtils.remove_entry(@dir) if @dir && File.exist?(@dir)
  rescue Errno::EACCES
    # Windows: acik dosya silinemez, sorun degil
    nil
  end

  def get(path)
    @request.get(path, lint: false)
  end

  def add_event(ip: '1.2.3.4', status: 200, path: '/', at: T0, agent: 'Chrome')
    @store.record_event(
      LogSentry::Entry.new(
        ip: ip, time: at, http_method: 'GET', path: path, protocol: 'HTTP/1.1',
        status: status, bytes: 100, referer: '-', user_agent: agent, raw: 'ham'
      )
    )
    @store.flush
  end

  def add_alert(rule: :brute_force, severity: :high, ip: '45.155.205.233',
                at: T0, message: 'test uyarisi', evidence: ['ham log 401'])
    @store.record_alert(
      LogSentry::Alert.new(
        rule: rule, severity: severity, ip: ip, message: message, time: at,
        count: 11, threshold: 10, window: 60,
        details: { automated: true }, evidence: evidence
      )
    )
  end

  # ==========================================================================
  #  TEMEL ROTALAR
  # ==========================================================================

  def test_dashboard_acilir
    add_event
    add_alert

    res = get('/')

    assert_equal 200, res.status
    assert_includes res.body, 'Dashboard'
    assert_includes res.body, '45.155.205.233'
  end

  def test_dashboard_bos_veritabaniyla_da_acilir
    # Yeni kurulumda hic veri yoktur. Panelin bos veriyle cokmemesi,
    # kullanicinin ilk izlenimidir.
    res = get('/')

    assert_equal 200, res.status
    assert_includes res.body, 'Dashboard'
  end

  def test_alarm_listesi
    3.times { |i| add_alert(at: T0 + i) }

    res = get('/alerts')

    assert_equal 200, res.status
    assert_includes res.body, 'Uyar'
    assert_equal 3, res.body.scan('kanıt →').size
  end

  def test_alarm_detayi
    add_alert
    add_event(ip: '45.155.205.233', status: 401, path: '/login')
    id = @store.alerts(limit: 1).first[:id]

    res = get("/alerts/#{id}")

    assert_equal 200, res.status
    assert_includes res.body, 'Neden alarm verildi'
    assert_includes res.body, 'ham log 401'     # kanit gorunuyor
    assert_includes res.body, '/login'          # baglam gorunuyor
  end

  def test_olmayan_alarm_404
    assert_equal 404, get('/alerts/999999').status
  end

  def test_harf_iceren_id_404
    # "abc".to_i => 0 -> bulunamaz. Cokmemeli.
    assert_equal 404, get('/alerts/abc').status
  end

  def test_olmayan_sayfa_404
    assert_equal 404, get('/olmayan/sayfa').status
  end

  def test_health_json_doner
    res = get('/health')

    assert_equal 200, res.status
    payload = JSON.parse(res.body)
    assert_equal true, payload['ok']
    assert_equal LogSentry::VERSION, payload['version']
  end

  def test_statik_dosyalar_sunulur
    css = get('/app.css')
    js  = get('/app.js')

    assert_equal 200, css.status
    assert_equal 200, js.status
    # Dis bagimlilik olmadigini dogrula: panel internetsiz sunucuda da calismali
    refute_includes css.body, 'http://'
    refute_includes css.body, 'cdn'
  end

  # ==========================================================================
  #  XSS -- BU DOSYANIN EN ONEMLI KISMI
  # --------------------------------------------------------------------------
  #  Saldirgan izlenen sunucuya sunu ister:
  #      GET /<script>alert(document.cookie)</script>
  #
  #  Nginx bunu access.log'a oldugu gibi yazar. Parser ayristirir, Store
  #  kaydeder, panel ekrana basar. Kacislamazsak tarayici o metni KOD olarak
  #  calistirir.
  #
  #  Yani saldirgan, PANELE HIC ERISMEDEN, sadece izlenen sunucuya bir istek
  #  atarak guvenlik panelinde kod calistirmis olur. Buna "depolanmis XSS"
  #  denir.
  # ==========================================================================

  def test_alarm_mesajindaki_xss_kacislanir
    add_alert(message: "60 saniyede 11 deneme (#{XSS})")

    res = get('/alerts')

    assert_equal 200, res.status
    refute_includes res.body, '<script>alert',
                    'XSS yuku ham haliyle sayfaya basildi -- panel ele gecirilebilir'
    assert_includes res.body, '&lt;script&gt;',
                    'yuk kacislanmis halde gorunmeli'
  end

  def test_kanitteki_xss_kacislanir
    # Kanit blogu HAM LOG SATIRI gosteriyor -- yani en dogrudan
    # saldirgan-kontrollu alan.
    add_alert(evidence: ["1.2.3.4 - - [...] \"GET /#{XSS} HTTP/1.1\" 404 0"])
    id = @store.alerts(limit: 1).first[:id]

    res = get("/alerts/#{id}")

    assert_equal 200, res.status
    refute_includes res.body, '<script>alert'
    assert_includes res.body, '&lt;script&gt;'
  end

  def test_yol_alanindaki_xss_kacislanir
    add_alert
    add_event(ip: '45.155.205.233', path: "/#{XSS}", status: 404)
    id = @store.alerts(limit: 1).first[:id]

    res = get("/alerts/#{id}")

    refute_includes res.body, '<script>alert'
  end

  def test_ip_alanindaki_xss_kacislanir
    # IP alani \S+ ile ayristiriliyor, yani gercek bir IP olmak zorunda degil.
    evil_ip = '"><script>alert(1)</script>'
    add_alert(ip: evil_ip)
    add_event(ip: evil_ip)

    res = get('/')

    refute_includes res.body, '<script>alert'
  end

  def test_user_agent_alanindaki_xss_kacislanir
    add_alert
    add_event(ip: '45.155.205.233', agent: XSS)
    id = @store.alerts(limit: 1).first[:id]

    res = get("/alerts/#{id}")

    refute_includes res.body, '<script>alert'
  end

  def test_filtre_degerindeki_xss_kacislanir
    # Kullanicidan gelen deger input value="..." icine basiliyor.
    # Kacislamazsak saldirgan " ile attribute'dan cikip kod ekleyebilir.
    res = get('/alerts?ip=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E')

    assert_equal 200, res.status
    refute_includes res.body, '<script>alert'
    assert_includes res.body, '&quot;'
  end

  # ==========================================================================
  #  SALT OKUNURLUK
  # ==========================================================================

  def test_post_reddedilir
    # Yazma yetkisi olmayan bir panel, ele gecirilse bile hasar veremez.
    res = @request.post('/alerts', lint: false)

    assert_equal 405, res.status
    assert_includes res.body, 'salt okunur'
  end

  def test_delete_ve_put_reddedilir
    assert_equal 405, @request.delete('/alerts/1', lint: false).status
    assert_equal 405, @request.put('/alerts/1', lint: false).status
  end

  def test_head_izinli
    # HEAD, GET'in govdesiz halidir -- izleme araclari bunu kullanir.
    assert_equal 200, @request.head('/health', lint: false).status
  end

  def test_yazma_acikken_post_405_donmez
    # Ayarin gercekten etkili oldugunu dogrula (aksi halde test bir sey
    # kanitlamaz). Yazma rotasi olmadigi icin 404 bekliyoruz -- ama 405 DEGIL.
    LogSentry::Web::App.set :read_only, false
    res = @request.post('/alerts', lint: false)

    refute_equal 405, res.status
  ensure
    LogSentry::Web::App.set :read_only, true
  end

  # ==========================================================================
  #  FILTRELER VE SAYFALAMA
  # ==========================================================================

  def test_kural_filtresi
    add_alert(rule: :brute_force)
    add_alert(rule: :flood)

    res = get('/alerts?rule=flood')

    assert_includes res.body, 'flood'
    assert_equal 1, res.body.scan('kanıt →').size
  end

  def test_bos_filtre_yok_sayilir
    # "?rule=" seklinde gelen bos filtre SQL'e "rule = ''" olarak gitmemeli.
    add_alert
    add_alert(rule: :flood)

    res = get('/alerts?rule=&severity=&ip=')

    assert_equal 2, res.body.scan('kanıt →').size
  end

  def test_sayfalama
    15.times { |i| add_alert(at: T0 + i) }   # page_size: 10

    page1 = get('/alerts?page=1')
    page2 = get('/alerts?page=2')

    assert_equal 10, page1.body.scan('kanıt →').size
    assert_equal 5,  page2.body.scan('kanıt →').size
    assert_includes page1.body, 'sayfa 1 / 2'
  end

  def test_gecersiz_sayfa_numarasi_cokmez
    add_alert

    assert_equal 200, get('/alerts?page=0').status
    assert_equal 200, get('/alerts?page=-5').status
    assert_equal 200, get('/alerts?page=abc').status
    assert_equal 200, get('/alerts?page=99999').status
  end

  def test_asiri_buyuk_hours_sinirlanir
    # Kullanicidan gelen her sayiya ust sinir koymak, kod kadar onemli
    # bir aliskanliktir: ?hours=999999999 ile sunucu yorulmasin.
    assert_equal 200, get('/?hours=999999999').status
    assert_equal 200, get('/?hours=abc').status
  end

  def test_sql_enjeksiyonu_web_katmaninda_da_etkisiz
    add_alert
    payloads = ["' OR 1=1 --", "'; DROP TABLE alerts; --"]

    payloads.each do |evil|
      res = get("/alerts?ip=#{Rack::Utils.escape(evil)}")
      assert_equal 200, res.status
      # Enjeksiyon calissaydi kayit donerdi
      assert_equal 0, res.body.scan('kanıt →').size, "enjeksiyon calisti: #{evil}"
    end

    # Tablo hala yerinde mi?
    assert_equal 1, @store.count_alerts
  end

  # ==========================================================================
  #  DEPOLAMA / ARSIV YOKSA
  # ==========================================================================

  def test_depolama_yoksa_503
    LogSentry::Web::App.set :store, nil

    res = get('/')
    assert_equal 503, res.status
    assert_includes res.body, 'Depolama'
  ensure
    LogSentry::Web::App.set :store, @store
  end

  def test_arsivci_yoksa_integrity_503
    res = get('/integrity')

    assert_equal 503, res.status
    assert_includes res.body, 'kapal'
  end

  def test_integrity_saglam_arsivde_200
    Dir.mktmpdir do |dir|
      archiver = LogSentry::Archiver.new(directory: File.join(dir, 'archive'))
      source = File.join(dir, 'access.log')
      File.write(source, "1.2.3.4 - - [...] \"GET / HTTP/1.1\" 200 5\n")
      archiver.archive_file(source)

      LogSentry::Web::App.set :archiver, archiver
      res = get('/integrity')

      assert_equal 200, res.status
      assert_includes res.body, 'Bütünlük sağlam'
    ensure
      LogSentry::Web::App.set :archiver, nil
    end
  end

  def test_integrity_bozuk_arsivde_500_doner
    # Butunluk bozulmussa HTTP durum kodu da bunu soylemeli: insan icin
    # sayfa, makine icin durum kodu. "curl -f" ile izlenebilir olmali.
    Dir.mktmpdir do |dir|
      archive_dir = File.join(dir, 'archive')
      archiver = LogSentry::Archiver.new(directory: archive_dir)
      source = File.join(dir, 'access.log')
      File.write(source, "1.2.3.4 - - [...] \"GET / HTTP/1.1\" 200 5\n")
      entry = archiver.archive_file(source)

      # Arsivi kurcala
      File.write(File.join(archive_dir, entry[:file]), 'artik gzip degil')

      LogSentry::Web::App.set :archiver, archiver
      res = get('/integrity')

      assert_equal 500, res.status
      assert_includes res.body, 'BOZULMUŞ'
    ensure
      LogSentry::Web::App.set :archiver, nil
    end
  end

  # ==========================================================================
  #  HATA YONETIMI
  # ==========================================================================

  def test_hata_sayfasi_yigin_izi_sizdirmaz
    # Yigin izi dosya yollarini, gem surumlerini ve kod yapisini aciga
    # cikarir -- saldirgan icin degerli bilgi.
    LogSentry::Web::App.get('/patlat-test') { raise 'kasitli hata' }

    res = nil
    _out, _err = capture_io { res = get('/patlat-test') }

    assert_equal 500, res.status
    refute_includes res.body, 'kasitli hata'
    refute_includes res.body, 'web_test.rb'
    refute_includes res.body, '/lib/log_sentry'
    assert_includes res.body, 'sunucu loguna'
  end

  # ==========================================================================
  #  SSE
  # ==========================================================================

  # DIKKAT: /stream rotasina MockRequest ile istek ATMIYORUZ.
  #
  # Sebep: o rota baglantiyi bilincli olarak ACIK TUTUYOR (stream :keep_open).
  # MockRequest yanit govdesinin bitmesini bekler, govde hic bitmez ve TEST
  # PAKETI SONSUZA KADAR TAKILIR. Bunu bizzat yasadik: paket 10 dakika
  # bekledikten sonra elle oldurulmek zorunda kaldi.
  #
  # Ders: "asla bitmeyen" bir uc noktayi, biten bir istek gibi test edemezsin.
  # Cozum, bicimlendirme mantigini disari alip onu test etmek; akisin kendisini
  # canli sunucuyla dogrulamak.
  def test_sse_cerceve_bicimi
    frame = LogSentry::Web::App.sse_frame({ 'rule' => 'brute_force', 'ip' => '1.2.3.4' })

    assert frame.start_with?('data: '), 'SSE mesaji "data: " ile baslamali'
    assert frame.end_with?("\n\n"),     'SSE mesaji iki satir sonu ile bitmeli'
    assert_equal 'brute_force', JSON.parse(frame.sub('data: ', '').strip)['rule']
  end

  def test_sse_cercevesi_satir_sonlarini_temizler
    # Alarm mesajinda satir sonu olursa SSE bicimi bozulur: bos satir
    # "mesaj bitti" anlamina gelir, yani mesaj ortadan ikiye ayrilir.
    # JSON.generate satir sonunu \n olarak kacislar.
    frame = LogSentry::Web::App.sse_frame({ 'message' => "iki\nsatir" })

    assert_equal 1, frame.scan("\n\n").size, 'govdede fazladan bos satir olmamali'
    assert_includes frame, '\\n'
  end

  def test_alert_file_yoksa_stream_503
    LogSentry::Web::App.set :alert_file, nil

    assert_equal 503, get('/stream').status
  ensure
    LogSentry::Web::App.set :alert_file, @alert_file
  end

  def test_basic_auth_yetkisiz_ve_yetkili_erisim
    LogSentry::Web::App.set :auth_enabled, true
    LogSentry::Web::App.set :auth_user, 'secretuser'
    LogSentry::Web::App.set :auth_pass, 'secretpass'

    # Yetkisiz istek 401 almali
    res = get('/')
    assert_equal 401, res.status

    # Dogru kimlik bilgileri ile 200 almali
    auth_header = 'Basic ' + ["secretuser:secretpass"].pack('m0')
    res_auth = @request.get('/', 'HTTP_AUTHORIZATION' => auth_header)
    assert_equal 200, res_auth.status
  ensure
    LogSentry::Web::App.set :auth_enabled, false
    LogSentry::Web::App.set :auth_pass, nil
  end

  def test_rate_limiter_esik_asilinca_429_doner
    LogSentry::Web::App.set :rate_limit_enabled, true
    LogSentry::Web::App.set :rate_limit_max, 2
    LogSentry::Web::App.set :rate_limit_window, 60
    LogSentry::Web::App::RATE_LIMIT_STORE.clear

    assert_equal 200, get('/').status
    assert_equal 200, get('/').status
    res = get('/')
    assert_equal 429, res.status
  ensure
    LogSentry::Web::App.set :rate_limit_enabled, false
    LogSentry::Web::App::RATE_LIMIT_STORE.clear
  end
end
