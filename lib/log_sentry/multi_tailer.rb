# frozen_string_literal: true

# ============================================================================
#  MultiTailer -- birden fazla dosyayi ayni anda izleme
# ----------------------------------------------------------------------------
#  Tailer TEK bir dosya yolunu izler. Bu iki gercek senaryoda yetmiyor:
#
#  1) TARIHLI ROTASYON
#     Bazi kurulumlar her gun YENI BIR DOSYA ADI uretir:
#         access-2026-07-31.log
#         access-2026-08-01.log      <- ertesi gun
#     Tek bir yolu izleyen yapilandirma, gece yarisindan sonra SESSIZCE
#     kor kalir. Dosya hala var, Tailer hala calisiyor, hata yok -- ama
#     yeni satirlar baska bir dosyaya yaziliyor.
#
#     (Numarali rotasyonda -- access.log.1 -- bu sorun YOKTUR, cunku
#      sunucu ayni ada yazmaya devam eder; Tailer'in inode takibi yeter.)
#
#  2) BIRDEN FAZLA SUNUCU / SITE
#     Kurumsal ortamda tek bir makinede birden cok vhost, ya da merkezi
#     bir dizine toplanmis birden cok sunucunun loglari olur:
#         /var/log/nginx/*/access.log
#
#  Cozum: sabit bir YOL yerine bir KALIP (glob) izlemek, ve kalibla
#  eslesen her dosya icin ayri bir Tailer calistirmak.
#
#  TASARIM: MultiTailer, Tailer'i YENIDEN YAZMAZ -- birden fazlasini
#  yonetir. Rotasyon, kismi satir, checkpoint gibi zor isler zaten
#  Tailer'da cozulmus durumda; burada yalnizca "hangi dosyalar" sorusu
#  var. Bilesenleri birlestirerek yeni yetenek elde etmek, onlari
#  degistirerek elde etmekten her zaman daha ucuzdur.
# ============================================================================

require 'digest'
require 'fileutils'
require_relative 'tailer'

module LogSentry
  class MultiTailer
    # Yeni dosya var mi diye kac saniyede bir bakalim?
    # Tarihli rotasyonda gunde bir kez degisir; 10 saniye fazlasiyla sik.
    DISCOVERY_INTERVAL = 10

    # Ayni anda en fazla kac dosya izlensin?
    #
    # Her dosya bir thread ve bir acik dosya tanimlayicisi demek. Kalip
    # yanlislikla genis yazilirsa (orn. /var/log/*) yuzlerce dosya bulunur
    # ve process kaynaklari tukenir. (Sinirsiz buyuyen hicbir yapiya yer
    # yok -- projedeki tekrar eden ders, burada dosya sayisi kiliginda.)
    MAX_CONCURRENT = 50

    # Bu kadar suredir yeni satir gelmeyen VE en yeni dosya olmayan
    # dosyalarin izlemesi birakilir.
    #
    # Neden gerekli? Tarihli rotasyonda her gun yeni bir dosya eklenir.
    # Eskileri birakmazsak 30 gun sonra 30 thread, 90 gun sonra 90 thread
    # calisiyor olur -- hicbiri is yapmadan.
    IDLE_TIMEOUT = 600

    # Tuketici yavassa kuyruk sinirsiz buyumesin: SizedQueue dolunca
    # URETICIYI BEKLETIR (backpressure). Bellegi patlatmak yerine okumayi
    # yavaslatmak dogru davranistir.
    QUEUE_SIZE = 10_000

    attr_reader :pattern, :lines_read, :files_seen

    # pattern   : Dir.glob kalibi  ("logs/access*.log", "/var/log/nginx/*/access.log")
    # start     : :end (tail -f gibi) veya :begin
    # state_dir : her dosyanin konum kaydinin tutulacagi dizin (nil ise tutulmaz)
    def initialize(pattern, start: :end, state_dir: nil,
                   poll_interval: Tailer::DEFAULT_POLL_INTERVAL,
                   discovery_interval: DISCOVERY_INTERVAL)
      @pattern            = pattern
      @start              = start
      @state_dir          = state_dir
      @poll_interval      = poll_interval
      # Testlerde kisaltilabilsin diye disaridan verilebiliyor. Sabiti
      # degistirmek yerine parametre yapmak, testin 51 saniye yerine
      # saniyeler icinde kosmasini sagliyor -- yavas test, kosulmayan
      # testtir.
      @discovery_interval = discovery_interval

      @tailers    = {}          # yol => Tailer
      @threads    = {}          # yol => Thread
      @last_line  = {}          # yol => son satirin geldigi zaman
      @queue      = SizedQueue.new(QUEUE_SIZE)
      @running    = false
      @lines_read = 0
      @files_seen = 0
      @dropped    = 0
      @mutex      = Mutex.new

      FileUtils.mkdir_p(@state_dir) if @state_dir
    end

    # ------------------------------------------------------------------------
    #  ANA DONGU
    # ------------------------------------------------------------------------
    #  Uretici tarafi: her dosya icin bir thread, satirlari kuyruga koyar.
    #  Tuketici tarafi: bu dongu, kuyruktan alip bloga verir.
    #
    #  Blok iki deger alir: satir ve KAYNAK (dosya yolu). Cok sunuculu bir
    #  kurulumda "hangi sunucudan geldi" bilgisi olmadan alarm eksik kalir.
    # ------------------------------------------------------------------------
    def each_line
      @running = true
      last_discovery = Time.now - @discovery_interval   # ilk turda hemen tara

      while @running
        if Time.now - last_discovery >= @discovery_interval
          discover
          reap_idle
          last_discovery = Time.now
        end

        # Kuyrukta bekleyen her seyi bosalt.
        drained = 0
        while @running && drained < 1_000
          item = begin
            @queue.pop(true)
          rescue ThreadError
            nil
          end
          break if item.nil?

          line, source = item
          @lines_read += 1
          drained += 1
          yield(line, source)
        end

        # Hicbir sey yoksa kisa bir uyku: CPU'yu bosa doldurmayalim.
        sleep @poll_interval if drained.zero? && @running
      end

      stop_all
      self
    end

    def stop
      @running = false
      @mutex.synchronize { @tailers.each_value(&:stop) }
    end

    def running?
      @running
    end

    def stats
      @mutex.synchronize do
        {
          pattern:      @pattern,
          watched:      @tailers.size,
          files_seen:   @files_seen,
          lines_read:   @lines_read,
          dropped_files: @dropped,
          queue_depth:  @queue.size,
          files:        @tailers.map do |path, tailer|
            { path: path, lines: tailer.lines_read, rotations: tailer.rotations }
          end
        }
      end
    end

    private

    # ------------------------------------------------------------------------
    #  KESIF -- kalibla eslesen yeni dosyalari bul
    # ------------------------------------------------------------------------
    def discover
      matches = Dir.glob(@pattern).select { |p| File.file?(p) }.sort

      if matches.size > MAX_CONCURRENT
        # En yeni dosyalari tut; eskiler zaten buyumuyordur.
        matches = matches.sort_by { |p| -File.mtime(p).to_i }.first(MAX_CONCURRENT)
        warn "[multi_tailer] kalip #{@pattern} icin #{MAX_CONCURRENT} dosya siniri " \
             'asildi; yalnizca en yeniler izleniyor'
      end

      matches.each do |path|
        next if @mutex.synchronize { @tailers.key?(path) }

        start_tailing(path)
      end
    end

    def start_tailing(path)
      # ------------------------------------------------------------------
      #  BASLANGIC KONUMU -- ince ama kritik ayrim.
      #
      #  Ilk acilista bulunan dosyalar icin kullanicinin istedigi mod
      #  gecerli (:end -> yalnizca bundan sonrasi).
      #
      #  Ama CALISIRKEN ortaya cikan bir dosya (tarihli rotasyonda gece
      #  yarisi olusan yeni gunun dosyasi) icin :end YANLIS olur: dosyanin
      #  basindan bizim onu fark ettigimiz ana kadar yazilan satirlari
      #  kaybederiz. Sonradan gorulen dosyalar HER ZAMAN bastan okunur.
      # ------------------------------------------------------------------
      first_scan = @files_seen.zero? || @tailers.empty? && @lines_read.zero?
      mode = first_scan ? @start : :begin

      tailer = Tailer.new(path, start: mode, poll_interval: @poll_interval,
                                state_file: state_file_for(path))

      thread = Thread.new do
        tailer.each_line do |line|
          @last_line[path] = Time.now
          @queue << [line, path]   # kuyruk doluysa burada bekler (backpressure)
        end
      rescue StandardError => e
        # Bir dosyanin okumasi cokerse DIGERLERI devam etmeli.
        warn "[multi_tailer] #{path} okunamadi: #{e.class}: #{e.message}"
      end

      @mutex.synchronize do
        @tailers[path] = tailer
        @threads[path] = thread
        @last_line[path] = Time.now
        @files_seen += 1
      end
    end

    # ------------------------------------------------------------------------
    #  TEMIZLIK -- artik yazilmayan dosyalarin izlemesini birak
    # ------------------------------------------------------------------------
    def reap_idle
      newest = @mutex.synchronize { @tailers.keys.max_by { |p| File.exist?(p) ? File.mtime(p).to_i : 0 } }
      now = Time.now

      idle = @mutex.synchronize do
        @tailers.keys.select do |path|
          next false if path == newest         # en yeni dosyayi asla birakma
          next true  unless File.exist?(path)  # silinmis
          (now - (@last_line[path] || now)) > IDLE_TIMEOUT
        end
      end

      idle.each { |path| stop_tailing(path) }
    end

    def stop_tailing(path)
      tailer = nil
      thread = nil
      @mutex.synchronize do
        tailer = @tailers.delete(path)
        thread = @threads.delete(path)
        @last_line.delete(path)
        @dropped += 1
      end
      tailer&.stop
      thread&.join(2)
      thread&.kill if thread&.alive?
    end

    def stop_all
      paths = @mutex.synchronize { @tailers.keys }
      paths.each { |path| stop_tailing(path) }
    end

    # Her dosyanin kendi konum kaydi olmali; yoksa yeniden baslatmada
    # hepsi ayni dosyayi paylasip birbirinin konumunu ezer.
    #
    # Dosya adini dogrudan kullanamayiz (icinde / ve : olabilir), o yuzden
    # yolun ozetini kullaniyoruz. Okunabilir kalsin diye basina dosya adini
    # da ekliyoruz.
    #
    # Basta NOKTA YOK: bunlar kendi dizinlerinde duruyor, gizlemenin faydasi
    # yok. Aksine, sorun ararken `ls` ile gorunmeyen dosyalar isi zorlastirir.
    def state_file_for(path)
      return nil if @state_dir.nil?

      digest = Digest::SHA256.hexdigest(File.expand_path(path))[0, 12]
      safe   = File.basename(path).gsub(/[^\w.-]/, '_')
      File.join(@state_dir, "#{safe}.#{digest}.state")
    end
  end
end
