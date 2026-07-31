# frozen_string_literal: true

# ============================================================================
#  ADIM 5f -- Supervisor: butun boru hattini birlestiren orkestratör
# ----------------------------------------------------------------------------
#  Bu dosya yeni bir yetenek eklemiyor. Yaptigi tek sey, dort adimda
#  yazdigimiz bagimsiz parcalari birbirine baglamak:
#
#      TAILER  ->  PARSER  ->  ENGINE  ->  NOTIFIERS
#      (adim 3)   (adim 2)    (adim 4)     (adim 5)
#
#  Parcalarin hicbiri digerini TANIMIYOR. Tailer, Parser'in var oldugunu
#  bilmez; Engine, alarmin nereye gittigini bilmez. Onlari tanistiran tek
#  yer burasi.
#
#  Bu desene "bagimlilik enjeksiyonu" (dependency injection) denir ve
#  faydasi test edilebilirlikte gorulur: her parcayi tek basina, digerleri
#  olmadan test edebildik -- 72 testin hicbiri disk, ag ya da zaman
#  beklemesine ihtiyac duymadi.
# ============================================================================

require 'yaml'
require 'json'
require_relative 'log_sentry/tailer'
require_relative 'log_sentry/parser'
require_relative 'log_sentry/engine'
require_relative 'log_sentry/daemon'
require_relative 'log_sentry/notifiers/console'
require_relative 'log_sentry/notifiers/file'
require_relative 'log_sentry/notifiers/webhook'

module LogSentry
  VERSION = '0.6.0'

  class Supervisor
    attr_reader :config, :engine, :notifiers, :tailer, :parser, :started_at, :store

    # ------------------------------------------------------------------------
    #  Yapilandirmadan kurulum
    #  overrides: komut satirindan gelen, dosyayi ezen ayarlar
    # ------------------------------------------------------------------------
    def self.from_config(config_path, **overrides)
      config = YAML.load_file(config_path)
      new(config: config, config_path: config_path, **overrides)
    end

    def initialize(config:, config_path: nil, log_file: nil, from_begin: false,
                   quiet: false, once: false)
      @config      = config
      @config_path = config_path
      @quiet       = quiet
      @once        = once

      # log_files (kalip) verilmisse log_file zorunlu degil.
      configured_path = log_file || config['log_file']
      if configured_path.nil? && config['log_files'].nil?
        raise KeyError, 'yapilandirmada log_file ya da log_files bulunmali'
      end

      @log_path = configured_path && File.expand_path(configured_path)

      # Parser artik yapilandirmadan kuruluyor: LB arkasindaki kurulumlarda
      # hem log formati hem de gercek istemci adresinin nasil bulunacagi
      # degisiyor (bkz. config/logsentry.yml -> log_format / trusted_proxies).
      @parser = Parser.new(
        format:          (config['log_format'] || 'combined').to_sym,
        trusted_proxies: config['trusted_proxies'] || []
      )
      @engine = Engine.from_config(config)

      # Depolama istege bagli: yapilandirmada storage yoksa Store hic
      # kurulmaz ve sqlite3 gem'i bile yuklenmez. Adim 1-5 boyunca
      # kurdugumuz "sifir bagimlilik" ozelligini korumak icin require
      # dosyanin basinda degil, BURADA (ihtiyac aninda) yapiliyor.
      @store = build_store(config)

      @notifiers = build_notifiers(config)
      @last_flush = Time.now

      # ----------------------------------------------------------------------
      #  TEK DOSYA MI, KALIP MI?
      # ----------------------------------------------------------------------
      #  log_file  : tek bir yol      -> Tailer
      #  log_files : glob kalibi      -> MultiTailer
      #
      #  Kalip, iki gercek ihtiyaci karsiliyor: tarihli rotasyon (her gun
      #  yeni dosya adi) ve cok sunuculu kurulum (birden fazla dosya).
      # ----------------------------------------------------------------------
      @log_pattern = config['log_files']

      @tailer =
        if @log_pattern
          require_relative 'log_sentry/multi_tailer'
          MultiTailer.new(
            @log_pattern,
            start: from_begin ? :begin : :end,
            state_dir: config.dig('daemon', 'state_dir') || 'logs/.state'
          )
        else
          Tailer.new(
            @log_path,
            start: from_begin ? :begin : :end,
            state_file: config.dig('daemon', 'state_file')
          )
        end

      @running          = false
      @reload_requested = false
      @stats_requested  = false
      @alert_total      = 0
      @started_at       = nil
      @last_line_at     = nil
    end

    # ------------------------------------------------------------------------
    #  --once modu: dosya sonuna gelince cik
    # ------------------------------------------------------------------------
    #  Bu ne kadar sure yeni satir gelmezse "dosya bitti" sayacagimizi
    #  belirliyor.
    #
    #  Neden boyle bir esik gerekiyor? Cunku Tailer BILINCLI olarak dosya
    #  sonunda durmuyor -- Adim 3'un tum amaci buydu: "dosya bitti" diye bir
    #  sey yok, sadece "su an yeni satir yok" var.
    #
    #  Ilk yazdigimda --once, okuma thread'inin olmesini bekliyordu; thread
    #  hic olmedigi icin komut sonsuza kadar bekledi. Kusuru canli deneme
    #  yakaladi. Ders: "bitti" tanimi olmayan bir akista "bitti"yi kendin
    #  tanimlamak zorundasin.
    ONCE_IDLE_TIMEOUT = 1.5

    # ========================================================================
    #  ANA CALISMA DONGUSU
    # ------------------------------------------------------------------------
    #  NEDEN IKI THREAD?
    #
    #  Tailer#each_line bloke eden bir sonsuz dongu. Icinde otururken
    #  sinyalleri (SIGHUP ile yapilandirma yenileme gibi) isleyecek bir
    #  yer yok: dosyaya yeni satir yazilmazsa dongu hicbir sey yapmaz ve
    #  sinyal bayragimizi kimse kontrol etmez.
    #
    #  Cozum: okuma islemini ayri bir thread'e al, ANA THREAD'i sinyalleri
    #  islemek icin serbest birak.
    #
    #  Bu tesadufi bir tercih degil: Ruby'de sinyal isleyicileri ANA
    #  THREAD'de calisir. Yani ana thread'i bos tutmak, sinyal isleme icin
    #  zaten dogru tasarimdir. Gercek servislerin cogu bu sekilde kurulur:
    #  bir "kabul/okuma" thread'i, bir "denetim" thread'i.
    # ========================================================================
    def run
      @running      = true
      @started_at   = Time.now
      @last_line_at = Time.now

      install_signal_handlers
      log "LogSentry v#{VERSION} basladi (PID #{Process.pid})"
      log(@log_pattern ? "izlenen kalip : #{@log_pattern}" : "izlenen dosya : #{@log_path}")
      log "kurallar      : #{@engine.rules.map(&:name).join(', ')}"
      log "bildirim      : #{@notifiers.map(&:name).join(', ')}"

      reader = Thread.new do
        # Thread icindeki bir hata sessizce yutulur ve thread olur --
        # program calismaya devam eder ama artik HICBIR SEY OKUMAZ.
        # Bir izleme aracinda bundan daha sinsi bir arizanin olmasi zor.
        # Bu yuzden thread govdesini acikca sariyoruz.
        begin
          # MultiTailer bloga iki deger verir (satir, kaynak); Tailer bir
          # tane. Ruby'de blok parametreleri esnektir: |line, source| yazip
          # tek deger gelirse source nil olur -- yani ayni blok ikisiyle de
          # calisir, ek bir kosula gerek kalmaz.
          @tailer.each_line { |line, source| handle_line(line, source) }
        rescue StandardError => e
          log "OKUMA THREAD'I COKTU: #{e.class}: #{e.message}"
          e.backtrace&.first(5)&.each { |l| log "  #{l}" }
          @running = false
        end
      end

      # --- Denetim dongusu (ana thread) ---
      while @running
        handle_reload  if @reload_requested
        dump_stats     if @stats_requested
        periodic_flush

        # Tek seferlik mod: bir sure yeni satir gelmediyse "dosya bitti" say.
        # (Tailer bilincli olarak dosya sonunda durmuyor -- Adim 3'un amaci
        #  buydu. O yuzden "bitti"yi burada tanimliyoruz.)
        if @once && (!reader.alive? || (Time.now - @last_line_at) > ONCE_IDLE_TIMEOUT)
          log "--once: #{ONCE_IDLE_TIMEOUT} saniyedir yeni satir yok, cikiliyor"
          break
        end

        sleep 0.2
      end

      @tailer.stop
      reader.join(3)   # en fazla 3 saniye bekle, sonra devam et
      shutdown
    end

    def stop
      @running = false
      @tailer.stop
    end

    def stats
      {
        version:    VERSION,
        pid:        Process.pid,
        uptime:     @started_at ? (Time.now - @started_at).round : 0,
        log_file:   @log_path,
        tailer:     @tailer.stats,
        parser:     @parser.stats,
        engine:     @engine.stats,
        alerts:     @alert_total,
        notifiers:  @notifiers.map(&:stats),
        store:      @store&.stats
      }
    end

    private

    # ------------------------------------------------------------------------
    #  PERIYODIK TAMPON BOSALTMA
    # ------------------------------------------------------------------------
    #  Store, olaylari 500'luk partiler halinde yaziyor (performans icin).
    #  Ama sakin bir gecede saatte 50 istek gelirse tampon dolmaz ve o
    #  kayitlar saatlerce diske yazilmaz -- web arayuzunde "hic veri yok"
    #  gorunur.
    #
    #  Cozum: parti dolmasa da belirli aralikla bosalt. Bu, toplu yazmanin
    #  performans kazanci ile verinin gorunur olmasi arasindaki dengeyi kurar.
    #  Ayni desen Filebeat/Fluentd'de "flush_interval" olarak gecer.
    # ------------------------------------------------------------------------
    FLUSH_INTERVAL = 5

    def periodic_flush
      return if @store.nil?
      return if (Time.now - @last_flush) < FLUSH_INTERVAL

      @last_flush = Time.now
      @store.flush
    rescue StandardError => e
      # Veritabani yazamiyorsa (disk dolu, dosya kilitli) IZLEME DURMAZ.
      # Alarmlar hala ekrana, JSONL'e ve webhook'a gidiyor.
      log "DEPOLAMA HATASI (yoksayildi): #{e.class}: #{e.message}"
    end

    # ------------------------------------------------------------------------
    #  BORU HATTININ TAMAMI -- dort satir
    # ------------------------------------------------------------------------
    def handle_line(line, source = nil)
      @last_line_at = Time.now         # --once modunun bosta kalma olcumu

      entry = @parser.parse(line)      # 1) metin -> veri
      return if entry.nil?             #    anlasilmayan satiri gec

      entry.source = source            #    hangi dosyadan/sunucudan geldi

      @store&.record_event(entry)      # 2) kaydet (tamponlanir)

      @engine.process(entry).each do |alert|   # 3) kurallari isle
        @alert_total += 1
        dispatch(alert)                        # 4) bildir
      end
    end

    # Bir alarmi TUM kanallara gonder.
    #
    # Dikkat: notifier.notify kendi icinde hata yakaliyor (Notifiers::Base).
    # Yani bir kanalin cokmesi digerlerini engellemez. Telegram erisilemez
    # olsa bile alarm hala dosyaya yazilir ve ekrana basilir.
    def dispatch(alert)
      @notifiers.each { |notifier| notifier.notify(alert) }
    end

    # ------------------------------------------------------------------------
    #  SINYALLER -- arka plandaki process ile konusmanin tek yolu
    # ------------------------------------------------------------------------
    #  SIGTERM : "nazikce kapan"  -> kill <pid>, systemd stop, docker stop
    #  SIGINT  : Ctrl-C
    #  SIGHUP  : "yapilandirmayi yeniden oku" (gelenek)
    #  SIGUSR1 : "durumunu raporla" (uygulamaya ozel)
    #
    #  SIGKILL (kill -9) TRAP EDILEMEZ. Cekirdek process'i sormadan
    #  oldurur. Bu yuzden nazik kapanmaya guvenen hicbir sey (tampon
    #  bosaltma, PID dosyasi silme) -9 sonrasi garanti degildir.
    #
    #  SINYAL ISLEYICI ICINDE NE YAPILABILIR?
    #  Neredeyse hicbir sey. Isleyici, programin herhangi bir noktasinda,
    #  bir I/O isleminin TAM ORTASINDA calisabilir. Icinde puts yazmak,
    #  kilit almak ya da bellek ayirmak kilitlenmeye (deadlock) yol acabilir.
    #
    #  Dogru desen: SADECE bir bayrak indir, isi ana donguye birak.
    #  Asagidaki isleyicilerin hepsi tek satir; gercek is yukaridaki
    #  denetim dongusunde yapiliyor.
    # ------------------------------------------------------------------------
    def install_signal_handlers
      Signal.trap('TERM') { @running = false; @tailer.stop }
      Signal.trap('INT')  { @running = false; @tailer.stop }

      # HUP ve USR1 Windows'ta yok. Signal.list ile varligini kontrol
      # etmeden trap etmek ArgumentError firlatir.
      Signal.trap('HUP')  { @reload_requested = true } if Signal.list.key?('HUP')
      Signal.trap('USR1') { @stats_requested  = true } if Signal.list.key?('USR1')
    end

    # ------------------------------------------------------------------------
    #  SICAK YENILEME (hot reload)
    # ------------------------------------------------------------------------
    #  Esik degistirmek icin servisi yeniden baslatmak zorunda kalmak,
    #  kayan pencerelerin sifirlanmasi demek: yeniden baslatmanin oldugu
    #  anda devam eden bir saldiri gorunmez hale gelir.
    #
    #  SIGHUP ile motoru yeniden kuruyoruz. DIKKAT: Tailer'a DOKUNMUYORUZ --
    #  dosya konumunu koruyor, tek satir kaybetmiyoruz.
    #
    #  Yapilandirma bozuksa ESKIYE DONUYORUZ. Yanlis bir YAML yuzunden
    #  calisan bir izleme sistemini kaybetmek kabul edilemez.
    # ------------------------------------------------------------------------
    def handle_reload
      @reload_requested = false
      return log('yenileme atlandi: yapilandirma dosyasi yok') if @config_path.nil?

      log 'SIGHUP alindi -- yapilandirma yeniden okunuyor'

      new_config = YAML.load_file(@config_path)

      # reuse: @engine -> ayari DEGISMEMIS kurallarin hafizasi korunur.
      # (Bu olmadan devam eden bir saldirida sayaclar ve sogutma sifirlanir;
      #  canli testte ayni alarmin 4 saniye icinde iki kez dustugunu gorduk.)
      new_engine    = Engine.from_config(new_config, reuse: @engine)
      new_notifiers = build_notifiers(new_config)

      kept    = new_engine.rules.count { |r| @engine.rules.include?(r) }
      rebuilt = new_engine.rules.size - kept

      old_notifiers = @notifiers
      @config    = new_config
      @engine    = new_engine
      @notifiers = new_notifiers
      old_notifiers.each(&:close)

      log "yenilendi: #{@engine.rules.map { |r| "#{r.name}(#{r.threshold}/#{r.window}s)" }.join(' ')}"
      log "  #{kept} kural hafizasiyla korundu, #{rebuilt} kural yeniden kuruldu"
    rescue StandardError => e
      log "YENILEME BASARISIZ (#{e.class}: #{e.message}) -- eski yapilandirma korunuyor"
    end

    def dump_stats
      @stats_requested = false
      log "DURUM: #{JSON.generate(stats)}"
    end

    def shutdown
      log 'kapaniyor...'
      # Tamponlari bosalt, dosyalari kapat. Nazik kapanmanin anlami budur:
      # elindeki isi kaybetmeden birak.
      @notifiers.each(&:close)

      # Store'u EN SONDA kapatiyoruz: close icinde flush var, yani tamponda
      # bekleyen olaylar diske yaziliyor. Sirayi ters yapsak StoreNotifier
      # kapali bir veritabanina yazmaya calisirdi.
      if @store
        pending = @store.flush
        log "depolama: #{pending} bekleyen olay yazildi" if pending.positive?
        @store.close
      end

      log "toplam #{@alert_total} uyari uretildi, " \
          "#{@tailer.lines_read} satir okundu"
      log 'kapandi'
    end

    # ------------------------------------------------------------------------
    #  BILDIRIM KANALLARINI KUR
    # ------------------------------------------------------------------------
    def build_store(config)
      settings = config['storage']
      return nil unless settings && settings['database']

      require_relative 'log_sentry/store'
      require_relative 'log_sentry/notifiers/store'

      Store.new(
        path:             settings['database'],
        store_all_events: settings.fetch('store_all_events', true),
        batch_size:       settings.fetch('batch_size', Store::DEFAULT_BATCH_SIZE)
      )
    rescue LoadError => e
      # sqlite3 gem'i kurulu degilse SERVISI DURDURMUYORUZ.
      # Depolama bir iyilestirmedir; izleme cekirdek islevdir.
      warn "[uyari] depolama devre disi (#{e.message}). " \
           'Kurmak icin: gem install sqlite3'
      nil
    end

    def build_notifiers(config)
      settings = config['notifiers'] || {}
      list     = []

      if settings.dig('console', 'enabled') && !@quiet
        list << Notifiers::Console.new(color: settings.dig('console', 'color') != false)
      end

      if settings.dig('file', 'enabled')
        list << Notifiers::File.new(path: config.fetch('alert_file', 'logs/alerts.jsonl'))
      end

      # Store varsa alarmlar veritabanina da yazilir -- boylece web arayuzu
      # filtreleyebilir, sayfalayabilir, tek alarmin detayina inebilir.
      list << Notifiers::Store.new(store: @store) if @store

      if settings.dig('webhook', 'enabled')
        webhook = settings['webhook']
        begin
          list << Notifiers::Webhook.new(
            url_env: webhook['url_env'],
            format:  (webhook['format'] || 'generic').to_sym,
            timeout: webhook['timeout'] || 5,
            rate_limit: webhook['rate_limit'] || Notifiers::Webhook::DEFAULT_RATE_LIMIT
          )
        rescue ArgumentError => e
          # Webhook yapilandirmasi eksikse (token yok) SERVISI DURDURMUYORUZ.
          #
          # Bu bilincli bir karar: "bildirim gonderemiyorum" ile "izleme
          # yapamiyorum" ayni siddette sorunlar degil. Sirri olmayan bir
          # sunucuda bile izleme calismali, uyarilar dosyaya yazilmali.
          # Ama sessiz de kalmiyoruz -- eksigi acikca soyluyoruz.
          warn "[uyari] webhook devre disi: #{e.message}"
        end
      end

      raise 'hicbir bildirim kanali etkin degil' if list.empty?

      list
    end

    def log(message)
      # Daemon modunda stdout log dosyasina yonlendirilmis durumda,
      # yani bu satirlar oraya duser.
      puts "[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] #{message}"
      $stdout.flush
    end
  end
end
