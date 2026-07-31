# frozen_string_literal: true

# ============================================================================
#  Allowlist testleri
# ----------------------------------------------------------------------------
#  Calistirmak icin:   ruby test/allowlist_test.rb
#
#  Allowlist iki yonlu bir risk tasir:
#    - Cok DAR olursa: gurultu devam eder, gercek alarm kaybolur
#    - Cok GENIS olursa: saldirgan onu kalkan olarak kullanir
#  Testler ikisini de kontrol ediyor.
# ============================================================================

require 'minitest/autorun'

lib_path = File.expand_path('../lib', __dir__)
lib_path = File.expand_path('./lib') unless File.exist?(File.join(lib_path, 'log_sentry.rb'))
$LOAD_PATH.unshift(lib_path) unless $LOAD_PATH.include?(lib_path)

require 'log_sentry/engine'

class AllowlistTest < Minitest::Test
  T0 = Time.new(2026, 7, 31, 10, 0, 0, '+03:00')

  def entry(ip: '1.2.3.4', path: '/', agent: 'Mozilla/5.0', status: 200)
    LogSentry::Entry.new(
      ip: ip, time: T0, http_method: 'GET', path: path, protocol: 'HTTP/1.1',
      status: status, bytes: 100, referer: '-', user_agent: agent, raw: 'ham'
    )
  end

  # --------------------------------------------------------------------------
  #  IP
  # --------------------------------------------------------------------------

  def test_tek_ip_muaf_tutulur
    list = LogSentry::Allowlist.new(ips: ['10.0.0.7'])

    assert list.allowed?(entry(ip: '10.0.0.7'))
    refute list.allowed?(entry(ip: '10.0.0.8'))
  end

  def test_cidr_araligi
    list = LogSentry::Allowlist.new(ips: ['10.20.30.0/24'])

    assert list.allowed?(entry(ip: '10.20.30.1'))
    assert list.allowed?(entry(ip: '10.20.30.254'))
    refute list.allowed?(entry(ip: '10.20.31.1'))
  end

  def test_ipv6
    list = LogSentry::Allowlist.new(ips: ['2001:db8::/32'])

    assert list.allowed?(entry(ip: '2001:db8::1'))
    refute list.allowed?(entry(ip: '2001:dbf::1'))
  end

  def test_gecersiz_ip_muaf_tutulmaz
    # Allowlist'in varsayilani "izin verme" olmali: supheye dusuldugunde
    # kaydi kurallara sok. Aksi halde bozuk bir IP alani, filtreyi atlamanin
    # yolu haline gelirdi.
    list = LogSentry::Allowlist.new(ips: ['10.0.0.7'])

    refute list.allowed?(entry(ip: 'bu-bir-ip-degil'))
    refute list.allowed?(entry(ip: ''))
  end

  def test_gecersiz_cidr_yapilandirmasi_yok_sayilir
    list = nil
    _out, err = capture_io do
      list = LogSentry::Allowlist.new(ips: ['10.0.0.7', 'cop-deger'])
    end

    assert_match(/gecersiz IP\/CIDR/, err)
    assert list.allowed?(entry(ip: '10.0.0.7')), 'gecerli girdi calismaya devam etmeli'
  end

  # --------------------------------------------------------------------------
  #  YOL
  # --------------------------------------------------------------------------

  def test_saglik_kontrolu_yolu_muaf
    # LB'nin saniyede birkac kez vurdugu /health, flood esigini rahatlikla
    # asar. Bu, tespit edilmesi gereken bir sey degil.
    list = LogSentry::Allowlist.new(paths: ['/health', '/metrics'])

    assert list.allowed?(entry(path: '/health'))
    assert list.allowed?(entry(path: '/health?verbose=1'))
    assert list.allowed?(entry(path: '/metrics'))
  end

  def test_yol_oneki_alt_yollari_kapsar_ama_benzerleri_kapsamaz
    # /health -> /health/db  EVET  (alt yol)
    # /health -> /healthcheck-admin  HAYIR
    #
    # Bu ayrim onemli: "start_with?" naif kullanilirsa /admin muafiyeti
    # /admin-panel-hack yolunu da muaf tutardi.
    list = LogSentry::Allowlist.new(paths: ['/health'])

    assert list.allowed?(entry(path: '/health'))
    assert list.allowed?(entry(path: '/health/db'))
    refute list.allowed?(entry(path: '/healthcheck-admin'))
    refute list.allowed?(entry(path: '/health-admin'))
  end

  def test_yol_buyuk_kucuk_harf_duyarsiz
    list = LogSentry::Allowlist.new(paths: ['/health'])

    assert list.allowed?(entry(path: '/HEALTH'))
  end

  # --------------------------------------------------------------------------
  #  USER-AGENT
  # --------------------------------------------------------------------------

  def test_izleme_araci_user_agenti
    list = LogSentry::Allowlist.new(user_agents: ['Zabbix', 'Prometheus'])

    assert list.allowed?(entry(agent: 'Zabbix/6.0'))
    assert list.allowed?(entry(agent: 'Prometheus/2.45 blackbox'))
    refute list.allowed?(entry(agent: 'Mozilla/5.0'))
  end

  def test_user_agent_yoksa_muaf_tutulmaz
    list = LogSentry::Allowlist.new(user_agents: ['Zabbix'])

    refute list.allowed?(entry(agent: nil))
    refute list.allowed?(entry(agent: '-'))
  end

  # --------------------------------------------------------------------------
  #  BOS LISTE VE ISTATISTIK
  # --------------------------------------------------------------------------

  def test_bos_allowlist_hicbir_seyi_muaf_tutmaz
    list = LogSentry::Allowlist.new

    assert list.empty?
    refute list.allowed?(entry)
    refute list.allowed?(entry(ip: '10.0.0.7', path: '/health', agent: 'Zabbix'))
  end

  def test_filtrelenen_kayitlar_sayilir
    # Bu sayaci IZLEMEK guvenlik acisindan onemli: aniden artiyorsa ya
    # allowlist fazla genis, ya da birileri onu kalkan olarak kullaniyor.
    list = LogSentry::Allowlist.new(ips: ['10.0.0.7'], paths: ['/health'])

    3.times { list.allowed?(entry(ip: '10.0.0.7')) }
    2.times { list.allowed?(entry(path: '/health')) }
    list.allowed?(entry(ip: '9.9.9.9', path: '/'))

    s = list.stats
    assert_equal 5, s[:skipped]
    assert_equal 3, s[:skipped_by][:ip]
    assert_equal 2, s[:skipped_by][:path]
  end

  # --------------------------------------------------------------------------
  #  MOTORLA BIRLIKTE
  # --------------------------------------------------------------------------

  def test_engine_allowlisteki_trafikte_alarm_uretmez
    # Saglik kontrolu senaryosu: saniyede 5 istek, flood esigi 3.
    engine = LogSentry::Engine.new(
      rules: [LogSentry::Rules::Flood.new(window: 60, threshold: 3)],
      allowlist: LogSentry::Allowlist.new(ips: ['10.0.0.7'])
    )

    20.times do |i|
      alerts = engine.process(entry(ip: '10.0.0.7', path: '/health'))
      assert_empty alerts, "#{i + 1}. istekte alarm uretilmemeliydi"
    end
  end

  def test_allowlist_diger_ipleri_etkilemez
    engine = LogSentry::Engine.new(
      rules: [LogSentry::Rules::Flood.new(window: 60, threshold: 3)],
      allowlist: LogSentry::Allowlist.new(ips: ['10.0.0.7'])
    )

    20.times { engine.process(entry(ip: '10.0.0.7')) }

    alerts = []
    10.times { alerts.concat(engine.process(entry(ip: '45.155.205.233'))) }

    refute_empty alerts, 'allowlist disindaki IP hala tespit edilmeli'
  end

  def test_allowlisteki_kayit_kayan_pencereyi_kirletmez
    # ONEMLI DETAY: filtreleme, kural CAGRILMADAN once yapiliyor.
    #
    # Saglik kontrolunu once pencereye alip sonra alarmi bastirsaydik,
    # o kayitlar MAX_EVENTS_PER_KEY sinirini doldurup gercek olaylari
    # pencereden disari itebilirdi.
    rule = LogSentry::Rules::Flood.new(window: 600, threshold: 5)
    engine = LogSentry::Engine.new(
      rules: [rule],
      allowlist: LogSentry::Allowlist.new(paths: ['/health'])
    )

    50.times { engine.process(entry(ip: '1.2.3.4', path: '/health')) }

    assert_equal 0, rule.stats[:tracked_keys],
                 'muaf kayitlar kayan pencereye hic girmemeli'
  end

  def test_engine_yapilandirmadan_allowlist_yukler
    config = {
      'rules' => { 'flood' => { 'enabled' => true, 'window' => 60, 'threshold' => 3 } },
      'allowlist' => {
        'ips'   => ['10.0.0.7'],
        'paths' => ['/health']
      }
    }

    engine = LogSentry::Engine.from_config(config)

    refute engine.allowlist.empty?
    20.times { engine.process(entry(ip: '10.0.0.7')) }
    assert_equal 0, engine.alert_count
  end

  def test_gercek_yapilandirmada_allowlist_bos
    # Varsayilan kurulum hicbir seyi muaf tutmamali: allowlist bilincli
    # bir karardir, sessiz bir varsayilan degil.
    path = File.expand_path('../config/logsentry.yml', __dir__)
    path = File.expand_path('config/logsentry.yml') unless File.exist?(path)
    engine = LogSentry::Engine.from_config(path)

    assert engine.allowlist.empty?,
           'varsayilan yapilandirmada allowlist bos olmali'
  end

  def test_engine_istatistiginde_allowlist_gorunur
    engine = LogSentry::Engine.new(
      rules: [LogSentry::Rules::Flood.new(window: 60, threshold: 3)],
      allowlist: LogSentry::Allowlist.new(ips: ['10.0.0.7'])
    )
    5.times { engine.process(entry(ip: '10.0.0.7')) }

    assert_equal 5, engine.stats[:allowlist][:skipped]
  end
end
