# frozen_string_literal: true

# ============================================================================
#  Kural motoru testleri
# ----------------------------------------------------------------------------
#  Calistirmak icin:   ruby test/engine_test.rb
#
#  Bu testler Parser testleri gibi "saf": zaman ve dosya sistemi yok.
#  Zamani biz uyduruyoruz (sabit bir Time nesnesi) -- bu, zamana bagli
#  mantigi test etmenin en guvenilir yolu. `sleep 61` yazip gercekten
#  beklemek yerine "olayin zamani 61 saniye sonra" diyoruz.
#
#  Kurallar Time.now yerine entry.time kullandigi icin bu mumkun.
#  Time.now kullanan bir kodu test etmek icin ya beklemek ya da zamani
#  taklit etmek (mock) gerekirdi; ikisi de daha kirilgan.
# ============================================================================

require 'minitest/autorun'

lib_path = File.expand_path('../lib', __dir__)
lib_path = File.expand_path('./lib') unless File.exist?(File.join(lib_path, 'log_sentry.rb'))
$LOAD_PATH.unshift(lib_path) unless $LOAD_PATH.include?(lib_path)

require 'log_sentry/engine'
require 'log_sentry/entry'

class EngineTest < Minitest::Test
  # Sabit bir baslangic zamani. Gercek "simdi"ye hic bagli degiliz.
  T0 = Time.new(2026, 7, 29, 14, 0, 0, '+03:00')

  # Test kaydi uretici.
  # NOT: `ip: ip` yazimini bilincli kullaniyoruz. Ruby 3.1+ kisayolu
  # (`ip:`) WSL'deki Ruby 3.0'da calismaz -- testler her iki ortamda da
  # calismali.
  def entry(ip: '1.2.3.4', status: 200, path: '/', at: T0,
            agent: 'Mozilla/5.0', method: 'GET')
    LogSentry::Entry.new(
      ip: ip, time: at, http_method: method, path: path, protocol: 'HTTP/1.1',
      status: status, bytes: 100, referer: '-', user_agent: agent,
      raw: "#{ip} - - [...] \"#{method} #{path}\" #{status}"
    )
  end

  # --------------------------------------------------------------------------
  #  BRUTE FORCE
  # --------------------------------------------------------------------------

  def test_brute_force_esik_asilinca_uyari_verir
    rule = LogSentry::Rules::BruteForce.new(window: 60, threshold: 10)

    # Ilk 10 basarisiz giris: esik ASILMADI (10 > 10 yanlis).
    10.times do |i|
      assert_nil rule.call(entry(status: 401, at: T0 + i)),
                 "#{i + 1}. denemede uyari uretilmemeliydi"
    end

    # 11. deneme: esik asildi.
    alert = rule.call(entry(status: 401, at: T0 + 10))

    refute_nil alert
    assert_equal :brute_force, alert.rule
    assert_equal :high,        alert.severity
    assert_equal '1.2.3.4',    alert.ip
    assert_equal 11,           alert.count
    assert_equal 10,           alert.threshold
  end

  def test_brute_force_403u_de_sayar
    # 403 = kimlik dogru ama izin yok / WAF engelledi. Bu da "girmeye
    # calisti, giremedi" anlamina gelir.
    rule = LogSentry::Rules::BruteForce.new(window: 60, threshold: 3)

    3.times { |i| rule.call(entry(status: 403, at: T0 + i)) }

    refute_nil rule.call(entry(status: 403, at: T0 + 3))
  end

  def test_brute_force_404u_saymaz
    # KRITIK AYRIM. 404 "olmayan sayfa" demektir, giris denemesi degil.
    # Sayarsak kirik link tiklayan normal kullanicilar alarm uretir ve
    # aracin yanlis pozitif orani kullanilamaz hale gelir.
    rule = LogSentry::Rules::BruteForce.new(window: 60, threshold: 3)

    20.times { |i| assert_nil rule.call(entry(status: 404, at: T0 + i)) }
    assert_equal 0, rule.alert_count
  end

  def test_brute_force_basarili_giristen_etkilenmez
    rule = LogSentry::Rules::BruteForce.new(window: 60, threshold: 3)

    20.times { |i| assert_nil rule.call(entry(status: 200, at: T0 + i)) }
  end

  # NOT: esik semantigi "ASARSA" oldugu icin (measured > threshold),
  # threshold: 2 ile alarm UCUNCU olayda duser. Asagidaki testlerde
  # 2 isinma + 1 tetikleyici deseni bu yuzden.
  def test_otomatik_arac_isaretlenir
    rule = LogSentry::Rules::BruteForce.new(window: 60, threshold: 2)
    2.times { |i| rule.call(entry(status: 401, at: T0 + i, agent: 'python-requests/2.31.0')) }
    alert = rule.call(entry(status: 401, at: T0 + 4, agent: 'python-requests/2.31.0'))

    assert_equal true, alert.details[:automated]
  end

  def test_tarayici_otomatik_isaretlenmez
    rule = LogSentry::Rules::BruteForce.new(window: 60, threshold: 2)
    2.times { |i| rule.call(entry(status: 401, at: T0 + i, agent: 'Mozilla/5.0 Chrome/126.0')) }
    alert = rule.call(entry(status: 401, at: T0 + 4, agent: 'Mozilla/5.0 Chrome/126.0'))

    assert_equal false, alert.details[:automated]
  end

  # --------------------------------------------------------------------------
  #  KAYAN PENCERE -- projenin en kritik yapisi
  # --------------------------------------------------------------------------

  def test_pencereden_cikan_olaylar_sayilmaz
    rule = LogSentry::Rules::BruteForce.new(window: 60, threshold: 5)

    # 10 basarisiz giris... ama hepsi COK ESKI.
    10.times { |i| rule.call(entry(status: 401, at: T0 + i)) }

    # 61 saniye sonra tek bir deneme. Onceki 10'u pencereden cikti.
    assert_nil rule.call(entry(status: 401, at: T0 + 200)),
               'pencereden cikmis olaylar hala sayiliyor'
  end

  def test_pencere_kayarak_ilerler
    rule = LogSentry::Rules::BruteForce.new(window: 10, threshold: 3)

    # Her 4 saniyede bir deneme: pencerede (10 sn) hicbir zaman 3'ten
    # fazla olmaz. Yavas bir saldirgan esigin ALTINDA kalir.
    #
    # Bu bir KUSUR degil, bilincli bir takas: esigi dusurup yavas
    # saldirilari da yakalayabilirsin, ama o zaman normal kullanicilar
    # da alarm uretmeye baslar. Guvenlikte her esik bir takastir.
    10.times { |i| assert_nil rule.call(entry(status: 401, at: T0 + (i * 4))) }
  end

  def test_farkli_ipler_ayri_takip_edilir
    rule = LogSentry::Rules::BruteForce.new(window: 60, threshold: 3)

    # Iki IP, her biri 3 deneme. Toplam 6 ama HICBIRI esigi asmadi.
    # Sayaci IP basina tutmasak, iki masum kullanici birlikte alarm
    # uretirdi.
    3.times do |i|
      assert_nil rule.call(entry(ip: '1.1.1.1', status: 401, at: T0 + i))
      assert_nil rule.call(entry(ip: '2.2.2.2', status: 401, at: T0 + i))
    end

    assert_equal 2, rule.tracked_keys
  end

  def test_entry_time_kullanilir_time_now_degil
    # Gecmis bir logu isliyor olabiliriz (start: :begin) ya da log
    # gecikmeli gelebilir. "Son 60 saniye" derken kastedilen OLAYLARIN
    # zamani, bizim saatimiz degil.
    #
    # Time.now kullanan bir kod bu testte hicbir alarm uretmezdi:
    # 2020'deki tum olaylari "cok eski" sayardi.
    past = Time.new(2020, 1, 1, 0, 0, 0, '+03:00')
    rule = LogSentry::Rules::BruteForce.new(window: 60, threshold: 3)

    3.times { |i| rule.call(entry(status: 401, at: past + i)) }
    alert = rule.call(entry(status: 401, at: past + 4))

    refute_nil alert, 'gecmis loglar islenemiyor -- Time.now kullaniliyor olabilir'
    assert_equal 2020, alert.time.year
  end

  # --------------------------------------------------------------------------
  #  SOGUTMA (COOLDOWN)
  # --------------------------------------------------------------------------

  def test_sogutma_tekrar_alarmi_susturur
    rule = LogSentry::Rules::BruteForce.new(window: 600, threshold: 2, cooldown: 120)

    2.times { |i| rule.call(entry(status: 401, at: T0 + i)) }
    refute_nil rule.call(entry(status: 401, at: T0 + 3)), 'ilk alarm uretilmeliydi'

    # Sogutma suresi icinde gelen her sey susturulur.
    10.times do |i|
      assert_nil rule.call(entry(status: 401, at: T0 + 10 + i)),
                 'sogutma sirasinda alarm uretilmemeliydi'
    end
  end

  def test_sogutma_bitince_tekrar_alarm_verir
    rule = LogSentry::Rules::BruteForce.new(window: 600, threshold: 2, cooldown: 120)

    2.times { |i| rule.call(entry(status: 401, at: T0 + i)) }
    refute_nil rule.call(entry(status: 401, at: T0 + 3))

    assert_nil   rule.call(entry(status: 401, at: T0 + 100))   # sogutma icinde
    refute_nil   rule.call(entry(status: 401, at: T0 + 200))   # sogutma bitti
  end

  def test_sogutma_sirasinda_saymaya_devam_eder
    # ONEMLI DETAY: sogutma sirasinda BILDIRMIYORUZ ama SAYIYORUZ.
    #
    # Saymayi birakirsak, sogutma bitince sayac sifirdan baslar ve devam
    # eden bir saldiri gorunmez hale gelir -- saldirgan sadece bekleyerek
    # tespit edilmekten kurtulur.
    rule = LogSentry::Rules::BruteForce.new(window: 600, threshold: 2, cooldown: 10)

    3.times { |i| rule.call(entry(status: 401, at: T0 + i)) }   # 3. alarmi uretir

    # Sogutma sirasinda 5 deneme daha (alarm yok, ama sayiliyor)
    5.times { |i| rule.call(entry(status: 401, at: T0 + 4 + i)) }

    alert = rule.call(entry(status: 401, at: T0 + 20))   # sogutma bitti

    refute_nil alert
    assert_equal 9, alert.count,
                 'sogutma sirasindaki olaylar sayilmamis -- saldirgan bekleyerek kacabilir'
  end

  # --------------------------------------------------------------------------
  #  FLOOD
  # --------------------------------------------------------------------------

  def test_flood_tum_istekleri_sayar
    rule = LogSentry::Rules::Flood.new(window: 1, threshold: 10)

    # Icerik onemli degil, HACIM onemli: basarili istekler de sayilir.
    10.times { |_i| rule.call(entry(status: 200, at: T0)) }
    alert = rule.call(entry(status: 200, at: T0))

    refute_nil alert
    assert_equal :flood, alert.rule
    assert_equal 11, alert.count
  end

  def test_flood_hiz_hesaplar
    rule = LogSentry::Rules::Flood.new(window: 2, threshold: 10)
    10.times { rule.call(entry(at: T0)) }
    alert = rule.call(entry(at: T0))

    assert_equal 11, alert.count
    assert_equal 5.5, alert.details[:rate_per_second]   # 11 istek / 2 saniye
  end

  # --------------------------------------------------------------------------
  #  PATH SCAN -- sayi degil CESITLILIK
  # --------------------------------------------------------------------------

  def test_path_scan_cesitlilik_olcer_hacim_olcmez
    # BU TEST KURALIN VARLIK SEBEBI.
    rule = LogSentry::Rules::PathScan.new(window: 300, threshold: 3)

    # 50 kez AYNI dizin -> cesitlilik 1 -> alarm YOK.
    # (Muhtemelen yer imi, bozuk bir bot, unutulmus bir istemci.)
    50.times do |i|
      assert_nil rule.call(entry(path: '/admin', at: T0 + i)),
                 'ayni dizine yapilan tekrarli istek tarama DEGILDIR'
    end

    # 4 FARKLI dizin -> cesitlilik 4 -> ALARM.
    # Toplam sadece 4 istek, ama niyet acik: kesfetme davranisi.
    rule2 = LogSentry::Rules::PathScan.new(window: 300, threshold: 3)
    %w[/admin /.env /wp-login.php].each_with_index do |path, i|
      assert_nil rule2.call(entry(path: path, at: T0 + i))
    end

    alert = rule2.call(entry(path: '/phpmyadmin', at: T0 + 4))

    refute_nil alert
    assert_equal 4, alert.count
    assert_equal :path_scan, alert.rule
    assert_equal :medium,    alert.severity
  end

  def test_path_scan_normal_sayfalari_yok_sayar
    rule = LogSentry::Rules::PathScan.new(window: 300, threshold: 2)

    %w[/ /about /products /api/v1/users /contact /blog].each_with_index do |path, i|
      assert_nil rule.call(entry(path: path, at: T0 + i))
    end
    assert_equal 0, rule.alert_count
  end

  def test_path_scan_sorgu_dizesini_yok_sayar
    # /admin?a=1 ile /admin?a=2 AYNI hedeftir.
    # Yok saymasak saldirgan sorgu dizesini degistirerek cesitliligi
    # yapay olarak sisirebilir (ya da biz yanlis alarm uretiriz).
    rule = LogSentry::Rules::PathScan.new(window: 300, threshold: 2)

    5.times { |i| assert_nil rule.call(entry(path: "/admin?deneme=#{i}", at: T0 + i)) }
  end

  def test_path_scan_buyuk_kucuk_harf_duyarsiz
    # /ADMIN, /Admin gibi oyunlar en eski filtre atlatma tekniklerinden biri.
    rule = LogSentry::Rules::PathScan.new(window: 300, threshold: 2)

    assert_nil rule.call(entry(path: '/ADMIN', at: T0))
    assert_nil rule.call(entry(path: '/.Env',  at: T0 + 1))
    refute_nil rule.call(entry(path: '/WP-Login.php', at: T0 + 2))
  end

  def test_path_scan_denenen_dizinleri_raporlar
    rule = LogSentry::Rules::PathScan.new(window: 300, threshold: 2)
    %w[/admin /.env].each_with_index { |p, i| rule.call(entry(path: p, at: T0 + i)) }
    alert = rule.call(entry(path: '/phpmyadmin', at: T0 + 2))

    assert_equal %w[/admin /.env /phpmyadmin].sort,
                 alert.details[:probed_paths].sort
  end

  # --------------------------------------------------------------------------
  #  KANIT ZINCIRI
  # --------------------------------------------------------------------------

  def test_kanit_ham_satirlari_tasir
    # Bir uyariyi "eyleme gecirilebilir" yapan sey kanittir.
    # Kanit gostermeyen alarm gurultudur.
    rule = LogSentry::Rules::BruteForce.new(window: 60, threshold: 2)
    2.times { |i| rule.call(entry(status: 401, at: T0 + i, path: '/login')) }
    alert = rule.call(entry(status: 401, at: T0 + 4, path: '/login'))

    refute_empty alert.evidence
    assert_includes alert.evidence.first, '/login'
    assert_includes alert.evidence.first, '401'
  end

  def test_kanit_sinirlanir
    # 150.000 satirlik bir DDoS alarminda hepsini tasimanin ne belleksel
    # ne insani bir faydasi var.
    # cooldown: 0 -> her olayda alarm uretsin, en sonuncusuna bakabilelim.
    # (Sogutma acik olsaydi ilk alarmdan sonrasi susturulur ve son cagri
    #  nil donerdi -- ki bu dogru davranis, ama burada olcmek istedigimiz
    #  sey o degil.)
    rule  = LogSentry::Rules::Flood.new(window: 600, threshold: 5, cooldown: 0)
    alert = nil
    50.times { |i| alert = rule.call(entry(at: T0 + i)) || alert }

    assert_equal 50, alert.count, 'tum olaylar sayilmis olmali'
    assert_equal LogSentry::MAX_EVIDENCE, alert.evidence.size,
                 'kanit sayisi sinirli kalmali'
  end

  def test_kanit_uretildigi_andaki_halini_korur
    # Alarm, canli degisen bir diziye REFERANS tutmamali.
    # Tutarsa, 10 dakika sonra baktiginda icinde bambaska satirlar bulursun.
    rule = LogSentry::Rules::BruteForce.new(window: 600, threshold: 2, cooldown: 0)
    2.times { |i| rule.call(entry(status: 401, at: T0 + i, path: '/login')) }
    alert = rule.call(entry(status: 401, at: T0 + 4, path: '/login'))

    snapshot = alert.evidence.dup

    # Alarm uretildikten SONRA yeni olaylar gelsin
    5.times { |i| rule.call(entry(status: 401, at: T0 + 10 + i, path: '/sonradan')) }

    assert_equal snapshot, alert.evidence, 'kanit sonradan degismis'
    refute(alert.evidence.any? { |raw| raw.include?('/sonradan') })
  end

  # --------------------------------------------------------------------------
  #  BELLEK SINIRLARI
  # --------------------------------------------------------------------------

  def test_bosalan_pencereler_temizlenir
    # Anahtar SAYISI da sinirli kalmali: her yeni IP yeni bir girdi acar
    # ve IP bir daha hic gorunmese bile orada durur.
    # Botnet saldirisinda yuz binlerce IP gorursun.
    rule = LogSentry::Rules::BruteForce.new(window: 10, threshold: 100)

    # 50 farkli IP'den birer istek
    50.times { |i| rule.call(entry(ip: "10.0.0.#{i}", status: 401, at: T0)) }
    assert_equal 50, rule.tracked_keys

    # Cok sonra tek bir istek -> temizlik calisir (30 sn araliginda)
    rule.call(entry(ip: '9.9.9.9', status: 401, at: T0 + 500))

    assert_operator rule.tracked_keys, :<, 50,
                    'bosalmis pencereler temizlenmemis'
  end

  def test_tek_anahtarda_olay_sayisi_sinirli
    rule = LogSentry::Rules::Flood.new(window: 100_000, threshold: 10_000_000)

    # Cok uzun pencereye cok fazla olay: sinir devreye girmeli.
    3_000.times { rule.call(entry(at: T0)) }

    assert_operator rule.stats[:largest_window], :<=,
                    LogSentry::Rules::Base::MAX_EVENTS_PER_KEY
  end

  # --------------------------------------------------------------------------
  #  ENGINE
  # --------------------------------------------------------------------------

  def test_engine_tum_kurallari_isletir
    engine = LogSentry::Engine.new(
      rules: [
        LogSentry::Rules::BruteForce.new(window: 60, threshold: 2),
        LogSentry::Rules::Flood.new(window: 60, threshold: 2)
      ]
    )

    # 401 istekleri IKI kurali da tetikler: hem basarisiz giris hem hacim.
    2.times { |i| engine.process(entry(status: 401, at: T0 + i)) }
    alerts = engine.process(entry(status: 401, at: T0 + 4))

    assert_equal 2, alerts.size, 'iki kural da tetiklenmeliydi'
    assert_equal %i[brute_force flood].sort, alerts.map(&:rule).sort
  end

  def test_engine_sessiz_kalabilir
    engine = LogSentry::Engine.new(
      rules: [LogSentry::Rules::BruteForce.new(window: 60, threshold: 10)]
    )

    assert_empty engine.process(entry(status: 200)),
                 'normal trafik uyari uretmemeli'
  end

  def test_engine_bos_kural_listesi_reddedilir
    assert_raises(ArgumentError) { LogSentry::Engine.new(rules: []) }
  end

  def test_engine_yapilandirmadan_kurulur
    config = {
      'cooldown' => 60,
      'rules' => {
        'brute_force' => { 'enabled' => true, 'window' => 30, 'threshold' => 5 },
        'flood'       => { 'enabled' => true, 'window' => 1,  'threshold' => 50 },
        'path_scan'   => { 'enabled' => false, 'window' => 300, 'threshold' => 3 }
      }
    }

    engine = LogSentry::Engine.from_config(config)

    assert_equal 2, engine.rules.size, 'kapali kural yuklenmemeli'
    brute = engine.rules.find { |r| r.name == :brute_force }
    assert_equal 30, brute.window
    assert_equal 5,  brute.threshold
    assert_equal 60, brute.cooldown, 'genel sogutma degeri uygulanmali'
  end

  def test_kural_bazinda_sogutma_gecersiz_kilinabilir
    config = {
      'cooldown' => 60,
      'rules' => {
        'flood' => { 'enabled' => true, 'window' => 1, 'threshold' => 50,
                     'cooldown' => 5 }
      }
    }

    engine = LogSentry::Engine.from_config(config)
    assert_equal 5, engine.rules.first.cooldown
  end

  def test_bilinmeyen_kural_baslangicta_patlar
    # En olasi senaryo: yapilandirmada yazim hatasi ("brute_fore").
    # Sessizce yok sayarsak servis sorunsuz baslar ama o kural HIC
    # calismaz -- ve bunu aylarca fark etmezsin.
    config = {
      'rules' => { 'brute_fore' => { 'enabled' => true, 'window' => 60, 'threshold' => 5 } }
    }

    error = assert_raises(ArgumentError) { LogSentry::Engine.from_config(config) }
    assert_match(/bilinmeyen kural/, error.message)
  end

  def test_gercek_yapilandirma_dosyasi_yuklenir
    # Projedeki asil config/logsentry.yml gecerli mi?
    # Bu test, yapilandirmayi elle bozdugumuzda haber verir.
    config_path = File.expand_path('../config/logsentry.yml', __dir__)
    config_path = File.expand_path('config/logsentry.yml') unless File.exist?(config_path)
    engine = LogSentry::Engine.from_config(config_path)

    assert_equal 6, engine.rules.size
    assert_equal %i[brute_force flood path_scan sqli xss scanner].sort, engine.rules.map(&:name).sort
  end

  def test_sqli_kurali_sql_enjeksiyonunu_yakalar
    rule = LogSentry::Rules::Sqli.new(window: 60, threshold: 0)
    sqli_entry = entry(path: '/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users')

    alert = rule.call(sqli_entry)
    refute_nil alert
    assert_equal :sqli, alert.rule
    assert_equal :critical, alert.severity
  end

  def test_xss_kurali_zararli_scriptleri_yakalar
    rule = LogSentry::Rules::Xss.new(window: 60, threshold: 0)
    xss_entry = entry(path: '/profile?name=<script>alert(document.cookie)</script>')

    alert = rule.call(xss_entry)
    refute_nil alert
    assert_equal :xss, alert.rule
    assert_equal :high, alert.severity
  end

  def test_scanner_kurali_otomatik_araclari_yakalar
    rule = LogSentry::Rules::Scanner.new(window: 60, threshold: 0)
    scanner_entry = entry(agent: 'sqlmap/1.5.2#stable (http://sqlmap.org)')

    alert = rule.call(scanner_entry)
    refute_nil alert
    assert_equal :scanner, alert.rule
    assert_equal :medium, alert.severity
  end

  # --------------------------------------------------------------------------
  #  SOZLESME
  # --------------------------------------------------------------------------

  def test_taban_sinif_eksik_metodda_patlar
    # Base soyut bir sinif: kendi basina kullanilamaz.
    # Yeni bir kural yazan kisi hangi metodlari doldurmasi gerektigini
    # ANLASILIR bir hatayla ogrenmeli.
    incomplete = Class.new(LogSentry::Rules::Base)

    assert_raises(NotImplementedError) do
      incomplete.new(window: 60, threshold: 1).call(entry)
    end
  end

  def test_kural_adi_sinif_adindan_uretilir
    assert_equal :brute_force, LogSentry::Rules::BruteForce.rule_name
    assert_equal :path_scan,   LogSentry::Rules::PathScan.rule_name
    assert_equal :flood,       LogSentry::Rules::Flood.rule_name
  end

  # --------------------------------------------------------------------------
  #  ALERT
  # --------------------------------------------------------------------------

  def test_alert_json_uretir
    rule = LogSentry::Rules::BruteForce.new(window: 60, threshold: 2)
    2.times { |i| rule.call(entry(status: 401, at: T0 + i)) }
    alert = rule.call(entry(status: 401, at: T0 + 4))

    record = JSON.parse(alert.to_json)

    assert_equal 'brute_force', record['rule']
    assert_equal '1.2.3.4',     record['ip']
    # ISO-8601: saat dilimini KAYBETMEYEN, siralanabilir tek standart bicim.
    assert_match(/\+03:00\z/, record['time'])
  end

  def test_alert_onem_siralamasi
    high = LogSentry::Alert.new(severity: :high)
    med  = LogSentry::Alert.new(severity: :medium)

    assert_operator high.severity_rank, :>, med.severity_rank
  end

  # --------------------------------------------------------------------------
  #  IMZA TABANLI KURALLAR -- kodlama tuzaklari
  # --------------------------------------------------------------------------

  def test_yuzde_kodlanmis_gecersiz_bayt_daemonu_oldurmez
    # GERCEK BIR ZAFIYETIN TESTI.
    #
    # Saldirgan  /search?q=%FF%FE  ister. Log satirinin KENDISI gecerli
    # UTF-8'dir -- yuzde kodlamasi yalnizca ASCII karakter kullanir -- yani
    # Parser'daki scrub devreye girmez ve kayit sorunsuz gecer.
    #
    # Ama Sqli/Xss kurallari kodu COZUNCE ortaya gecersiz baytlar cikar ve
    # o metinde regex calistirmak ArgumentError firlatir. Hata kuraldan
    # motora, motordan okuma dongusune yayilir:
    #     TEK BIR ISTEKLE TUM IZLEME DURUR.
    #
    # Adim 2'de Parser icin duzelttigimiz zafiyetin, kodlama cozuldukten
    # sonra geri gelmis hali.
    evil = entry(path: '/search?q=%FF%FE')

    %i[sqli xss].each do |name|
      rule = LogSentry::Engine::RULE_CLASSES[name.to_s].new(window: 60, threshold: 0)
      rule.call(evil)   # hata firlatirsa test coker ve bizi uyarir
    end

    # Uctan uca: motor bu satirda hayatta kalmali
    engine = LogSentry::Engine.new(
      rules: [
        LogSentry::Rules::Sqli.new(window: 60, threshold: 0),
        LogSentry::Rules::Xss.new(window: 60, threshold: 0)
      ]
    )
    engine.process(evil)

    pass
  end

  def test_yuzde_kodlanmis_saldiri_yuku_yakalanir
    # Kodlama temizligi, TESPITI bozmamali. Saldirganlar yuku zaten
    # kodlayarak gonderir; kod cozulmeden bakan bir kural kor kalir.
    rule = LogSentry::Rules::Xss.new(window: 60, threshold: 0)
    encoded = entry(path: '/profile?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E')

    refute_nil rule.call(encoded), 'kodlanmis XSS yuku yakalanmali'
  end

  def test_imza_kurallari_normal_trafikte_alarm_uretmez
    # Yanlis pozitif kontrolu: en sik goreceğimiz istekler sessiz kalmali.
    sqli = LogSentry::Rules::Sqli.new(window: 60, threshold: 0)
    xss  = LogSentry::Rules::Xss.new(window: 60, threshold: 0)

    %w[/ /about /products/42 /api/v1/users?page=2&sort=name
       /static/css/main.css /images/logo.png?v=3].each do |path|
      assert_nil sqli.call(entry(path: path)), "yanlis pozitif: #{path}"
      assert_nil xss.call(entry(path: path)),  "yanlis pozitif: #{path}"
    end
  end

  def test_scanner_bos_user_agenti_yok_sayar
    # "-" nginx'in "user-agent yok" yazma bicimi. Bunu bir arac adi
    # sanmamaliyiz.
    rule = LogSentry::Rules::Scanner.new(window: 60, threshold: 0)

    assert_nil rule.call(entry(agent: '-'))
    assert_nil rule.call(entry(agent: ''))
    refute_nil rule.call(entry(agent: 'Nikto/2.1.6'))
  end

  def test_imza_kurallari_ham_satir_yoksa_cokmez
    # keep_raw: false ile calisan bir Parser'da entry.raw nil olur.
    # Kural yol ve referer'e baktigi icin bundan etkilenmemeli.
    rule = LogSentry::Rules::Sqli.new(window: 60, threshold: 0)
    no_raw = LogSentry::Entry.new(
      ip: '1.2.3.4', time: T0, http_method: 'GET',
      path: '/x?q=union select 1', protocol: 'HTTP/1.1',
      status: 200, bytes: 1, referer: '-', user_agent: 'curl', raw: nil
    )

    refute_nil rule.call(no_raw)
  end

  # --------------------------------------------------------------------------
  #  KAPSAM AYRIMI: yuk nerede aranir?
  #     sqli / xss  ->  yol + referer
  #     scanner     ->  user-agent
  # --------------------------------------------------------------------------

  def test_referer_icindeki_yuk_yakalanir
    # Gercek saldirilarda yuk referer basliginda da tasinir.
    sqli = LogSentry::Rules::Sqli.new(window: 60, threshold: 0)
    e = LogSentry::Entry.new(
      ip: '1.2.3.4', time: T0, http_method: 'GET', path: '/', protocol: 'HTTP/1.1',
      status: 200, bytes: 1,
      referer: 'http://evil.example/?id=1 union select password from users',
      user_agent: 'Mozilla/5.0', raw: 'ham satir'
    )

    refute_nil sqli.call(e), 'referer icindeki SQLi yuku yakalanmali'
  end

  def test_user_agent_icindeki_yuk_sqli_alarmi_uretmez
    # BILINCLI KAPSAM KARARI.
    #
    # Onceki surumde kurallar ham log satirinin tamamini tariyordu; bu,
    # user-agent'inda "union select" yazan masum bir istegin CRITICAL
    # seviye alarm uretmesine yol aciyordu.
    #
    # Esigi 0 olan critical bir kuralda yanlis pozitif = gece 3'te bosuna
    # calan telefon = bir sure sonra gormezden gelinen alarmlar.
    # User-agent'i degerlendirmek scanner kuralinin isi.
    sqli = LogSentry::Rules::Sqli.new(window: 60, threshold: 0)
    xss  = LogSentry::Rules::Xss.new(window: 60, threshold: 0)

    e = LogSentry::Entry.new(
      ip: '1.2.3.4', time: T0, http_method: 'GET', path: '/', protocol: 'HTTP/1.1',
      status: 200, bytes: 1, referer: '-',
      user_agent: 'Mozilla union select <script>alert(1)</script>',
      raw: '1.2.3.4 - - [...] "GET / HTTP/1.1" 200 1 "-" ' \
           '"Mozilla union select <script>alert(1)</script>"'
    )

    assert_nil sqli.call(e), 'user-agent icerigi SQLi alarmi uretmemeli'
    assert_nil xss.call(e),  'user-agent icerigi XSS alarmi uretmemeli'
  end

  def test_user_agent_arac_imzasi_tasiyorsa_scanner_yakalar
    # Kapsam ayriminin diger yarisi: user-agent'a bakan kural scanner.
    scanner = LogSentry::Rules::Scanner.new(window: 60, threshold: 0)

    refute_nil scanner.call(entry(agent: 'sqlmap/1.8#stable'))
    assert_nil scanner.call(entry(agent: 'Mozilla/5.0 Chrome/126.0'))
  end
end
