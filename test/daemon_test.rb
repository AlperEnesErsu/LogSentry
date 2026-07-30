# frozen_string_literal: true

# ============================================================================
#  Adim 5 testleri: bildirim kanallari, sicak yenileme, PID dosyasi
# ----------------------------------------------------------------------------
#  Calistirmak icin:   ruby test/daemon_test.rb
#
#  Bu testlerde GERCEK HTTP istegi atmiyoruz ve GERCEK daemon baslatmiyoruz.
#  Sebep: bir testin gecmesi internete, harici bir servise ya da isletim
#  sistemi durumuna bagli olmamali. Oyle testler "kirilgan" (flaky) olur:
#  bazen gecer bazen gecmez, ve bir sure sonra kimse onlara guvenmez.
#
#  Onun yerine SINIRLARI test ediyoruz: govde dogru mu kuruldu, hata
#  yutuldu mu, sir sizdi mi. Gercek uctan uca dogrulamayi canli daemon
#  testiyle ayrica yaptik (raporda).
# ============================================================================

require 'minitest/autorun'
require 'tmpdir'
require 'fileutils'

lib_path = File.expand_path('../lib', __dir__)
lib_path = File.expand_path('./lib') unless File.exist?(File.join(lib_path, 'log_sentry.rb'))
$LOAD_PATH.unshift(lib_path) unless $LOAD_PATH.include?(lib_path)

require 'log_sentry'

class DaemonTest < Minitest::Test
  T0 = Time.new(2026, 7, 29, 14, 0, 0, '+03:00')

  def alert(severity: :high, rule: :brute_force)
    LogSentry::Alert.new(
      rule: rule, severity: severity, ip: '45.155.205.233',
      message: '60 saniyede 11 basarisiz giris', time: T0,
      count: 11, threshold: 10, window: 60,
      details: { automated: true }, evidence: ['ham log satiri 401']
    )
  end

  # ==========================================================================
  #  SOZLESME: "gonderemezsen TUM SISTEMI DURDURMAZSIN"
  # ==========================================================================

  def test_coken_notifier_hata_firlatmaz
    # BU TESTIN VARLIK SEBEBI:
    # Telegram 30 saniye cevap vermezse ya da DNS coktugu icin istek
    # basarisiz olursa, bu hata yukari yayilip daemon'u oldurmemeli.
    # "Bildirim gonderemedim" yuzunden "izlemeyi tamamen kaybettim" gibi
    # absurd bir sonuc olusmamali.
    broken = Class.new(LogSentry::Notifiers::Base) do
      private

      def deliver(_alert)
        raise Errno::ECONNREFUSED, 'baglanti reddedildi'
      end
    end.new

    result = nil
    # capture: warn ciktisini yakala, test ciktisini kirletmesin
    _out, _err = capture_io { result = broken.notify(alert) }

    assert_equal false, result, 'notify basarisizligi false ile bildirmeli'
    assert_equal 1, broken.failed_count
    assert_match(/ECONNREFUSED/, broken.last_error)
  end

  def test_basarili_notifier_sayilir
    ok = Class.new(LogSentry::Notifiers::Base) do
      private

      def deliver(_alert); end
    end.new

    assert_equal true, ok.notify(alert)
    assert_equal 1, ok.sent_count
    assert_equal 0, ok.failed_count
  end

  def test_taban_notifier_eksik_metodda_patlar
    # DIKKAT: bu hata YUTULMAZ, coker.
    #
    # Cunku NotImplementedError, StandardError'un altinda DEGILDIR
    # (ScriptError'un altindadir) ve notify sadece StandardError yakalar.
    #
    # Bu istedigimiz davranis: "internet yok" gecici bir CALISMA ZAMANI
    # durumudur, yutulur. "deliver metodunu yazmayi unutmusum" ise
    # PROGRAMCI HATASIDIR -- sessizce yutulmasi degil, gurultuyle
    # patlamasi gerekir.
    incomplete = Class.new(LogSentry::Notifiers::Base).new

    assert_raises(NotImplementedError) { incomplete.notify(alert) }
  end

  # ==========================================================================
  #  CONSOLE
  # ==========================================================================

  def test_console_alarmi_yazar
    io = StringIO.new
    LogSentry::Notifiers::Console.new(io: io).notify(alert)

    out = io.string
    assert_includes out, '45.155.205.233'
    assert_includes out, 'brute_force'
    assert_includes out, 'HIGH'
    assert_includes out, 'ham log satiri 401'   # kanit da basiliyor
  end

  def test_console_tty_olmayan_ciktida_renk_kullanmaz
    # StringIO bir terminal degil. Renk kodlari yazilirsa dosyaya
    # yonlendirilen loglar "\e[1;31mHIGH\e[0m" gibi cop iceren
    # okunamaz metinlere donusur. Daemon modunda cikti HER ZAMAN
    # dosyaya gittigi icin bu kontrol kritik.
    io = StringIO.new
    LogSentry::Notifiers::Console.new(io: io, color: true).notify(alert)

    refute_includes io.string, "\e[", 'tty olmayan ciktida ANSI kodu olmamali'
  end

  # ==========================================================================
  #  FILE (JSONL)
  # ==========================================================================

  def test_file_notifier_jsonl_yazar
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'alerts.jsonl')
      notifier = LogSentry::Notifiers::File.new(path: path)

      notifier.notify(alert)
      notifier.notify(alert(rule: :flood, severity: :medium))
      notifier.close

      lines = File.readlines(path)
      assert_equal 2, lines.size, 'her uyari TEK satir olmali'

      # Her satir tek basina gecerli bir JSON olmali -- JSONL'in tum anlami bu.
      first = JSON.parse(lines[0])
      assert_equal 'brute_force', first['rule']
      assert_equal '45.155.205.233', first['ip']
      assert_match(/\+03:00\z/, first['time'])   # ISO-8601, saat dilimiyle

      assert_equal 'flood', JSON.parse(lines[1])['rule']
    end
  end

  def test_file_notifier_uzerine_yazmaz_ekler
    # Bir kanit dosyasinin uzerine yazilmasi veri kaybidir.
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'alerts.jsonl')

      n1 = LogSentry::Notifiers::File.new(path: path)
      n1.notify(alert)
      n1.close

      # Servis yeniden baslatildi
      n2 = LogSentry::Notifiers::File.new(path: path)
      n2.notify(alert)
      n2.close

      assert_equal 2, File.readlines(path).size
    end
  end

  def test_file_notifier_dizini_olusturur
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'derin', 'klasor', 'alerts.jsonl')
      notifier = LogSentry::Notifiers::File.new(path: path)
      notifier.notify(alert)

      assert File.exist?(path)
      # Windows'ta acik dosya silinemez -> gecici dizin temizlenemez.
      notifier.close
    end
  end

  # ==========================================================================
  #  WEBHOOK -- sir yonetimi ve govde bicimleri
  # ==========================================================================

  def test_webhook_adres_yoksa_baslangicta_patlar
    error = assert_raises(ArgumentError) do
      LogSentry::Notifiers::Webhook.new(url_env: 'KESINLIKLE_OLMAYAN_DEGISKEN')
    end
    assert_match(/KESINLIKLE_OLMAYAN_DEGISKEN/, error.message)
  end

  def test_webhook_bilinmeyen_bicim_reddedilir
    assert_raises(ArgumentError) do
      LogSentry::Notifiers::Webhook.new(url: 'https://x.example/y', format: :whatsapp)
    end
  end

  def test_webhook_token_loglarda_gizlenir
    # Kendi log dosyana token yazmak, sirri dosyaya yazmakla ayni seydir --
    # ustelik log dosyalari genelde daha az korunur ve daha cok paylasilir.
    secret = 'https://api.telegram.org/bot123456:AAHgizliTokenBurada/sendMessage'
    hook = LogSentry::Notifiers::Webhook.new(
      url: secret, format: :generic
    )

    refute_includes hook.safe_url, 'AAHgizliTokenBurada'
    refute_includes hook.stats[:url], 'AAHgizliTokenBurada'
    assert_includes hook.safe_url, 'api.telegram.org'
  end

  def test_telegram_govdesi
    ENV['TEST_CHAT'] = '-100123'
    hook = LogSentry::Notifiers::Webhook.new(
      url: 'https://api.telegram.org/bot1:x/sendMessage',
      format: :telegram, chat_id_env: 'TEST_CHAT'
    )

    payload = hook.send(:build_payload, alert)

    assert_equal '-100123', payload[:chat_id]
    assert_includes payload[:text], '45.155.205.233'
    assert_includes payload[:text], 'brute_force'
    # high (rank 2) -> sessiz DEGIL, telefon calsin
    assert_equal false, payload[:disable_notification]
  ensure
    ENV.delete('TEST_CHAT')
  end

  def test_telegram_orta_seviyede_sessiz_bildirim
    # Gece 3'te telefonun her orta seviye uyaride calmasi, aracin
    # kapatilmasiyla sonuclanir.
    ENV['TEST_CHAT'] = '-100123'
    hook = LogSentry::Notifiers::Webhook.new(
      url: 'https://api.telegram.org/bot1:x/sendMessage',
      format: :telegram, chat_id_env: 'TEST_CHAT'
    )

    payload = hook.send(:build_payload, alert(severity: :medium))
    assert_equal true, payload[:disable_notification]
  ensure
    ENV.delete('TEST_CHAT')
  end

  def test_telegram_chat_id_yoksa_patlar
    ENV.delete('TEST_CHAT_YOK')
    assert_raises(ArgumentError) do
      LogSentry::Notifiers::Webhook.new(
        url: 'https://api.telegram.org/bot1:x/sendMessage',
        format: :telegram, chat_id_env: 'TEST_CHAT_YOK'
      )
    end
  end

  def test_slack_govdesi
    hook = LogSentry::Notifiers::Webhook.new(
      url: 'https://hooks.slack.com/services/T/B/xyz', format: :slack
    )
    payload = hook.send(:build_payload, alert)

    assert_includes payload[:text], 'brute_force'
    assert_equal 'header', payload[:blocks].first[:type]
  end

  def test_generic_govdesi_ham_kayittir
    hook = LogSentry::Notifiers::Webhook.new(url: 'https://x.example/hook')
    payload = hook.send(:build_payload, alert)

    assert_equal :brute_force, payload[:rule]
    assert_equal 11, payload[:count]
  end

  def test_webhook_hiz_siniri
    hook = LogSentry::Notifiers::Webhook.new(
      url: 'https://x.example/hook', rate_limit: 3
    )

    # rate_limited? sayaci artirir; 3'ten sonra true donmeli.
    capture_io do
      3.times { refute hook.send(:rate_limited?) }
      assert hook.send(:rate_limited?), 'dakika siniri uygulanmali'
    end

    assert_equal 1, hook.stats[:dropped]
  end

  # ==========================================================================
  #  SICAK YENILEME (SIGHUP) -- canli testte bulunan kusurun testi
  # ==========================================================================

  def test_ayni_ayarli_kural_yenilemede_korunur
    # GERCEK BIR KUSURUN TESTI.
    # Canli daemon testinde 120 saniyelik sogutmaya ragmen yenilemeden
    # 4 saniye sonra ayni alarmin ikinci kez dustugunu gorduk: motor
    # bastan kuruldugu icin kayan pencereler ve sogutma silinmisti.
    config = {
      'cooldown' => 120,
      'rules' => {
        'brute_force' => { 'enabled' => true, 'window' => 60, 'threshold' => 10 }
      }
    }

    old = LogSentry::Engine.from_config(config)
    new = LogSentry::Engine.from_config(config, reuse: old)

    assert_same old.rules.first, new.rules.first,
                'ayari degismeyen kural NESNE OLARAK korunmali (hafizasiyla)'
  end

  def test_ayari_degisen_kural_yeniden_kurulur
    config = {
      'rules' => { 'brute_force' => { 'enabled' => true, 'window' => 60, 'threshold' => 10 } }
    }
    changed = {
      'rules' => { 'brute_force' => { 'enabled' => true, 'window' => 60, 'threshold' => 25 } }
    }

    old = LogSentry::Engine.from_config(config)
    new = LogSentry::Engine.from_config(changed, reuse: old)

    refute_same old.rules.first, new.rules.first
    assert_equal 25, new.rules.first.threshold
  end

  def test_yenileme_sogutmayi_korur
    # Uctan uca: alarm uret, yenile, sogutma hala gecerli mi?
    config = {
      'cooldown' => 120,
      'rules' => {
        'brute_force' => { 'enabled' => true, 'window' => 600, 'threshold' => 2 }
      }
    }

    engine = LogSentry::Engine.from_config(config)
    e = lambda do |sec|
      LogSentry::Entry.new(ip: '1.2.3.4', time: T0 + sec, http_method: 'POST',
                           path: '/login', protocol: 'HTTP/1.1', status: 401,
                           bytes: 1, referer: '-', user_agent: 'curl', raw: 'ham')
    end

    2.times { |i| engine.process(e.call(i)) }
    refute_empty engine.process(e.call(3)), 'ilk alarm uretilmeliydi'

    # SIGHUP
    engine = LogSentry::Engine.from_config(config, reuse: engine)

    assert_empty engine.process(e.call(5)),
                 'yenilemeden sonra sogutma sifirlanmis -- ayni alarm tekrar dusuyor'
  end

  def test_kural_imzasi
    a = LogSentry::Rules::BruteForce.new(window: 60, threshold: 10)
    b = LogSentry::Rules::BruteForce.new(window: 60, threshold: 10)
    c = LogSentry::Rules::BruteForce.new(window: 60, threshold: 11)
    d = LogSentry::Rules::BruteForce.new(window: 60, threshold: 10, statuses: [401])

    assert_equal a.signature, b.signature
    refute_equal a.signature, c.signature
    refute_equal a.signature, d.signature, 'kurala ozel ayar da imzaya girmeli'
  end

  # ==========================================================================
  #  PID DOSYASI
  # ==========================================================================

  def test_pidfile_yazar_ve_siler
    Dir.mktmpdir do |dir|
      pf = LogSentry::Daemon::PidFile.new(File.join(dir, 'x.pid'))

      assert_equal Process.pid, pf.acquire!
      assert_equal Process.pid, pf.read
      assert pf.alive?, 'kendi process kimligimiz yasiyor olmali'

      pf.release
      refute File.exist?(pf.path)
    end
  end

  def test_pidfile_calisan_ornekte_hata_verir
    Dir.mktmpdir do |dir|
      pf = LogSentry::Daemon::PidFile.new(File.join(dir, 'x.pid'))
      pf.acquire!

      error = assert_raises(RuntimeError) { pf.acquire! }
      assert_match(/zaten calisiyor/, error.message)
      pf.release
    end
  end

  def test_bayat_pidfile_temizlenir
    # BILINMEDIGINDE SAATLER KAYBETTIREN TUZAK:
    # sunucu aniden kapanir (elektrik, OOM killer, kill -9), daemon PID
    # dosyasini silemez. Sunucu acilir, servis "zaten calisiyor" der --
    # ama calismiyor.
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'x.pid')
      # Neredeyse kesin olarak var olmayan bir PID yaz.
      File.write(path, '999999')

      pf = LogSentry::Daemon::PidFile.new(path)
      refute pf.alive?, 'olmayan PID yasiyor gorunmemeli'

      capture_io { pf.acquire! }   # bayat dosyayi temizleyip devralmali
      assert_equal Process.pid, pf.read
      pf.release
    end
  end

  def test_bozuk_pidfile_cokmez
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'x.pid')
      File.write(path, "cop veri\n")

      pf = LogSentry::Daemon::PidFile.new(path)
      assert_nil pf.read
      refute pf.alive?
    end
  end

  def test_pidfile_baskasinin_kaydini_silmez
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'x.pid')
      File.write(path, '999999')

      LogSentry::Daemon::PidFile.new(path).release

      assert File.exist?(path),
             'baska bir ornegin PID kaydi silinmemeli'
    end
  end

  # ==========================================================================
  #  SUPERVISOR -- boru hattinin birlestirilmesi
  # ==========================================================================

  def test_supervisor_uctan_uca_isler
    # Gercek bir log dosyasi yaz, --once modunda isle, alerts.jsonl'i dogrula.
    Dir.mktmpdir do |dir|
      access = File.join(dir, 'access.log')
      alerts = File.join(dir, 'alerts.jsonl')

      # 12 basarisiz giris -> brute_force esigini (10) asar
      File.open(access, 'w') do |f|
        12.times do |i|
          f.puts '45.155.205.233 - - [29/Jul/2026:14:00:' \
                 "#{format('%02d', i)} +0300] " \
                 '"POST /login HTTP/1.1" 401 178 "-" "python-requests/2.31.0"'
        end
      end

      config = {
        'log_file'   => access,
        'alert_file' => alerts,
        'cooldown'   => 120,
        'rules' => {
          'brute_force' => { 'enabled' => true, 'window' => 60, 'threshold' => 10 }
        },
        'notifiers' => { 'file' => { 'enabled' => true } }
      }

      supervisor = LogSentry::Supervisor.new(
        config: config, from_begin: true, once: true, quiet: true
      )

      # Supervisor kendi durumunu stdout'a logluyor; test ciktisini
      # kirletmesin diye yakaliyoruz.
      capture_io do
        thread = Thread.new { supervisor.run }
        sleep 1.5
        supervisor.stop
        thread.join(3)
      end

      assert File.exist?(alerts), 'alerts.jsonl olusmadi'
      records = File.readlines(alerts).map { |l| JSON.parse(l) }

      assert_equal 1, records.size, 'sogutma sayesinde tek uyari olmali'
      assert_equal 'brute_force', records.first['rule']
      assert_equal '45.155.205.233', records.first['ip']
      refute_empty records.first['evidence'], 'kanit tasinmali'
    end
  end

  def test_supervisor_bildirim_kanali_yoksa_reddeder
    config = {
      'log_file' => 'x.log',
      'rules' => { 'flood' => { 'enabled' => true, 'window' => 1, 'threshold' => 5 } },
      'notifiers' => {}
    }

    assert_raises(RuntimeError) { LogSentry::Supervisor.new(config: config) }
  end

  def test_webhook_eksik_sirla_servisi_durdurmaz
    # BILINCLI KARAR: "bildirim gonderemiyorum" ile "izleme yapamiyorum"
    # ayni siddette sorunlar degil. Sirri olmayan bir sunucuda bile izleme
    # calismali ve uyarilar dosyaya yazilmali.
    Dir.mktmpdir do |dir|
      config = {
        'log_file'   => File.join(dir, 'access.log'),
        'alert_file' => File.join(dir, 'alerts.jsonl'),
        'rules' => { 'flood' => { 'enabled' => true, 'window' => 1, 'threshold' => 5 } },
        'notifiers' => {
          'file'    => { 'enabled' => true },
          'webhook' => { 'enabled' => true, 'url_env' => 'OLMAYAN_SIR_DEGISKENI' }
        }
      }

      supervisor = nil
      _out, err = capture_io do
        supervisor = LogSentry::Supervisor.new(config: config, quiet: true)
      end

      assert_match(/webhook devre disi/, err)
      assert_equal %w[file], supervisor.notifiers.map(&:name)

      # Windows'ta acik bir dosya silinemez; gecici dizin temizlenebilsin
      # diye kanallari kapatiyoruz. (Ayni sebeple gercek daemon da
      # kapanirken notifier'lari close ediyor.)
      supervisor.notifiers.each(&:close)
    end
  end
end
