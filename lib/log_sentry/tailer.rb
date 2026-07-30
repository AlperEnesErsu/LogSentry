# frozen_string_literal: true

# ============================================================================
#  ADIM 3 -- Tailer: dosyayi canli izleme
# ----------------------------------------------------------------------------
#  Linux'taki `tail -f` komutunun Ruby'deki karsiligi.
#
#  KAVRAMSAL SICRAMA:
#  Adim 1'de yazdigimiz kod dosyayi okur, biter ve cikardi. Bu bir SCRIPT'ti.
#  Bu dosyadaki kod hic bitmeyecek. Bu bir SERVIS.
#
#     Log analizi                    Izleme (monitoring)
#     -----------                    -------------------
#     dun olan, sabit veri           su an olan, akan veri
#     program baslar, biter          program hic bitmez
#     "ne oldu?"                     "su an ne oluyor?"
#     adli inceleme                  MUDAHALE SANSI
#
#  Filebeat, Promtail, Fluentd, Datadog Agent -- hepsinin kaputunun altinda
#  bu dosyadaki dongu var. Basit gorunur; zorluk asagidaki KENAR DURUMLARDA.
# ============================================================================

require 'json'
require 'time'      # Time#iso8601 icin
require 'fileutils'

module LogSentry
  class Tailer
    # Yeni veri yoksa ne kadar bekleyelim?
    # Bu deger bir TAKAS (trade-off):
    #   kucuk (0.05) -> alarmi daha hizli uretirsin, CPU'yu daha cok mesgul edersin
    #   buyuk (2.0)  -> CPU bosta durur, saldiriyi 2 saniye gec gorursun
    # 0.2 saniye pratikte iyi bir orta nokta.
    DEFAULT_POLL_INTERVAL = 0.2

    # Rotasyon kontrolu pahalidir (her seferinde diske stat cagrisi).
    # Her dongude degil, saniyede bir yapiyoruz.
    ROTATION_CHECK_INTERVAL = 1.0

    # Konumu kac saniyede bir diske kaydedelim (yeniden baslatma guvenligi)
    CHECKPOINT_INTERVAL = 5.0

    # Tek bir satir 1 MB'i gecerse bir sey yanlis demektir.
    # Bu sinir olmadan, satir sonu karakteri hic gelmeyen bozuk bir yazici
    # tum RAM'i yiyebilir. (Adim 1 ve 2'deki dersin ucuncu tekrari:
    # BIR DAEMON ICINDE SINIRSIZ BUYUYEN HICBIR YAPIYA YER YOKTUR.)
    MAX_PARTIAL_BYTES = 1_048_576

    attr_reader :path, :lines_read, :bytes_read,
                :rotations, :truncations, :reopens, :partial_flushes

    # path       : izlenecek dosya
    # start      : :end   -> tail -f gibi, sadece BUNDAN SONRA yazilanlari oku
    #              :begin -> dosyanin basindan basla (once gecmisi isle)
    # state_file : konumu kaydedecegimiz dosya (nil ise kaydetme)
    def initialize(path,
                   start: :end,
                   poll_interval: DEFAULT_POLL_INTERVAL,
                   state_file: nil)
      @path          = path
      @start         = start
      @poll_interval = poll_interval
      @state_file    = state_file

      @file    = nil
      @running = false

      # Yarim kalmis satir tamponu. Neden gerekli oldugu asagida (bolum: gets).
      # +'' yazimi: frozen_string_literal: true oldugu icin degistirilebilir
      # bos bir String uretmenin yolu. (Sabit metinler donmus/immutable olur.)
      @partial = +''

      @lines_read      = 0
      @bytes_read      = 0
      @rotations       = 0
      @truncations     = 0
      @reopens         = 0
      @partial_flushes = 0

      @last_rotation_check = Time.now
      @last_checkpoint     = Time.now
    end

    # ------------------------------------------------------------------------
    #  ANA DONGU
    # ------------------------------------------------------------------------
    #  Sonsuz dongu. Her turda:
    #    1) okunacak yeni satir var mi? varsa hepsini oku ve bloga ver
    #    2) dosya dondurulmus/kesilmis mi? kontrol et
    #    3) konumu kaydet (gerekiyorsa)
    #    4) biraz uyu -- CPU'yu bosa harcamamak icin
    #
    #  4. ADIM OLMADAN NE OLUR?
    #  `while true; file.gets; end` yazarsan program bir CPU cekirdegini
    #  %100 doldurur ve hicbir sey yapmaz. Buna "busy wait" (mesgul bekleme)
    #  denir ve bir sunucuda yapilabilecek en saygisiz seydir. sleep, isletim
    #  sistemine "beni 200 ms uyut, bu sure boyunca islemciyi baskasina ver"
    #  demektir.
    # ------------------------------------------------------------------------
    def each_line
      return enum_for(:each_line) unless block_given?

      @running = true
      open_file

      while @running
        # Kesilme kontrolu OKUMADAN ONCE ve HER TURDA yapilir.
        # Neden her turda: bu kontrol ucuzdur (acik tutucuya fstat, disk
        # uzerinde isim aramasi yok). Rotasyon kontrolu ise pahalidir
        # (yol uzerinden stat) -- o yuzden saniyede bir.
        # Neden okumadan once: aciklama check_truncation'in basinda.
        check_truncation

        # Onemli: read_available BLOKLAMAZ. Okunacak sey varsa okur,
        # yoksa hemen doner. Bekleme isini sondaki sleep yapar.
        read_available { |line| yield line }

        break unless @running

        check_rotation { |line| yield line }
        checkpoint_if_due

        sleep @poll_interval
      end
    ensure
      # ensure blogu, metod NASIL biterse bitsin calisir:
      # normal cikis, exception, hatta Ctrl-C (Interrupt).
      # Konumu kaydetmek icin tek guvenli yer burasi -- aksi halde
      # beklenmedik bir cikista nerede kaldigimizi kaybederiz.
      save_checkpoint
      close_file
    end

    # Donguyu durdurur. Baska bir thread'den veya sinyal isleyicisinden
    # cagrilabilir olmasi ONEMLI: Adim 5'te SIGTERM aldigimizda tam olarak
    # bunu cagiracagiz ("nazik kapanma" / graceful shutdown).
    def stop
      @running = false
    end

    def running?
      @running
    end

    def stats
      {
        lines_read:      @lines_read,
        bytes_read:      @bytes_read,
        rotations:       @rotations,
        truncations:     @truncations,
        reopens:         @reopens,
        partial_flushes: @partial_flushes,
        position:        @file&.pos
      }
    end

    private

    # ========================================================================
    #  DOSYA ACMA + KONUMLANDIRMA
    # ========================================================================

    # NEDEN 'rb' (BINARY) MODU?
    #
    # Windows'ta metin modunda dosya acarsan Ruby \r\n dizisini otomatik
    # olarak \n'e cevirir. Bu okuma icin kolaylik, ama BIZIM ICIN FELAKET:
    # cunku okudugumuz karakter sayisi ile dosyadaki BAYT sayisi birbirinden
    # ayrilir. Konumu (pos/seek) bayt cinsinden takip eden bir tailer'da bu,
    # yeniden baslatmada yanlis yere atlamak demektir.
    #
    # Binary modda okuyup satirlari kendimiz temizliyoruz. chomp hem \n hem
    # \r\n'i dogru sekilde atar, yani bize ek bir maliyeti yok.
    #
    # Cikan satirlari force_encoding ile UTF-8 olarak isaretliyoruz --
    # gecersiz baytlar olabilir, onlari Parser scrub ile temizliyor (Adim 2).
    def open_file
      wait_for_file

      @file = File.open(@path, 'rb')

      resumed = resume_from_checkpoint
      unless resumed
        case @start
        when :end
          # IO::SEEK_END = "dosyanin sonuna gore konumlan", 0 = tam sonu.
          # tail -f'in varsayilan davranisi: gecmisi okuma, bundan sonrasini izle.
          @file.seek(0, IO::SEEK_END)
        when :begin
          @file.seek(0, IO::SEEK_SET)
        else
          raise ArgumentError, "start :end veya :begin olmali (verilen: #{@start.inspect})"
        end
      end

      @identity = current_identity
    end

    def close_file
      @file&.close
    rescue IOError
      # Zaten kapali. Kapatma sirasindaki hata onemli degil.
    ensure
      @file = nil
    end

    # Dosya henuz yoksa bekle.
    # Gercek hayatta cok olur: servis, nginx'ten ONCE baslatilmis olabilir;
    # ya da logrotate dosyayi tasidi ve yenisi henuz olusmadi.
    # "Dosya yok" bir HATA degil, GECICI BIR DURUMDUR -- cokmek yerine bekle.
    def wait_for_file
      logged = false

      until File.exist?(@path)
        unless logged
          warn "[tailer] dosya bekleniyor: #{@path}"
          logged = true
        end
        return unless @running

        sleep 1
      end
    end

    # ========================================================================
    #  OKUMA -- ve YARIM SATIR problemi
    # ========================================================================
    #
    #  Naif yaklasim:
    #      while (line = @file.gets) ; yield line ; end
    #
    #  Bunun gizli bir hatasi var. Sunucu su anda satiri YAZIYOR olabilir.
    #  Diske dusen sey:
    #
    #      45.155.205.233 - - [29/Jul/2026:14:39:25 +0300] "POST /log
    #                                                              ^ hepsi bu
    #
    #  gets, satir sonu karakteri gormese bile eldeki veriyi DONDURUR.
    #  Bu yarim satiri Parser'a verirsen:
    #    - kalip uymaz, "basarisiz" sayilir
    #    - ve satirin geri kalani bir sonraki turda AYRI bir satir gibi gelir
    #  Sonuc: bir gercek olay, iki bozuk kayda donusur ve ikisi de atilir.
    #  Yani ISTEK KAYBEDERSIN -- hem de tam olarak trafigin en yogun oldugu
    #  anlarda, yani saldiri anlarinda.
    #
    #  COZUM: satir sonu karakteri YOKSA veriyi tamponda beklet, bir sonraki
    #  turda basina ekle.
    # ========================================================================
    def read_available
      return unless @file

      loop do
        chunk = @file.gets   # nil -> okunacak yeni veri yok (simdilik)
        break if chunk.nil?

        @bytes_read += chunk.bytesize

        if chunk.end_with?("\n")
          # Tam satir. Varsa onceki yarim parcayi basina ekle.
          line = @partial.empty? ? chunk : (@partial + chunk)
          @partial = +''
          @lines_read += 1
          yield line.force_encoding(Encoding::UTF_8).chomp
        else
          # Yarim satir: tampona koy ve bekle.
          @partial << chunk

          # Sinir kontrolu: satir sonu hic gelmiyorsa (bozuk yazici, ikili
          # veri) tamponu bosalt. Kaydi Parser reddedecek -- ama en azindan
          # bellek sinirsiz buyumeyecek.
          if @partial.bytesize > MAX_PARTIAL_BYTES
            @partial_flushes += 1
            warn "[tailer] #{MAX_PARTIAL_BYTES} bayttir satir sonu gelmedi, tampon bosaltiliyor"
            line = @partial.force_encoding(Encoding::UTF_8)
            @partial = +''
            @lines_read += 1
            yield line
          end

          break   # daha fazla okumaya calisma, sonraki turda devam
        end
      end
    end

    # ========================================================================
    #  ROTASYON VE KESILME (TRUNCATION)
    # ========================================================================
    #
    #  Log dosyalari sonsuza kadar buyumez -- `logrotate` her gun devreye
    #  girer. Iki farkli yontem kullanir ve IKISI DE bizim acik dosya
    #  tutucumuzu bozar:
    #
    #  A) TASI-VE-YENISINI-OLUSTUR (create mode, varsayilan)
    #        access.log  ->  access.log.1  (yeniden adlandirilir)
    #        access.log  <-  yeni bos dosya olusturulur
    #
    #     Bizim acik tutucumuz TASINAN dosyayi isaret etmeye devam eder!
    #     Cunku Unix'te dosya tutucusu isme degil, INODE'a baglidir.
    #     Sonuc: yeni dosyaya yazilan hicbir sey gorulmez. Servis calisiyor
    #     gorunur, log akiyor gorunur -- ama ARTIK HICBIR SEY GORMEZ.
    #     Bu, izleme sistemlerinin en klasik ve en sinsi arizasidir.
    #
    #     TESPIT: yoldaki dosyanin inode'u, bizim acik tuttugumuzunkinden
    #     farkli mi? -> farkliysa rotasyon olmus.
    #
    #  B) KOPYALA-VE-SIFIRLA (copytruncate mode)
    #        access.log kopyalanir, sonra ICERIGI SIFIRLANIR (dosya ayni kalir)
    #
    #     Inode degismez, yani A'nin tespiti burada calismaz. Ama dosya
    #     boyutu bizim konumumuzun ALTINA duser.
    #
    #     TESPIT: dosya boyutu < bizim konum -> kesilme olmus, basa don.
    #
    #  Ikisini de kontrol etmek zorundayiz, cunku hangi modun kullanildigini
    #  bilemeyiz -- ve bu, kodumuzun degil sistem yoneticisinin karari.
    # ========================================================================
    # ------------------------------------------------------------------------
    #  B) KESILME KONTROLU  (yukaridaki aciklamanin "copytruncate" kismi)
    # ------------------------------------------------------------------------
    #  Dosya boyutu bizim okuma konumumuzun ALTINA dustuyse icerik sifirlanmis
    #  demektir. Basa donmemiz gerekir.
    #
    #  --- BU KONTROLUN NEDEN OKUMADAN ONCE VE HER TURDA OLDUGU ---
    #
    #  Ilk yazdigimizda bu kontrol rotasyon kontrolunun icindeydi, yani
    #  SANIYEDE BIR kez calisiyordu. Testimiz gercek bir veri kaybi buldu:
    #
    #     t=0.00  konum=5, boyut=5          (normal)
    #     t=0.01  logrotate dosyayi sifirla  -> boyut=0, konum=5  (KESILME)
    #     t=0.02  sunucu yeni satir yazdi    -> boyut=6, konum=5
    #     t=0.03  okuma yapiyoruz: 5. bayttan itibaren oku
    #             -> yeni satirin ORTASINDAN baslayan cop veri okundu
    #     t=1.00  kesilme kontrolu: boyut(6) < konum(6)? HAYIR.
    #             -> kesilme ARTIK ANLASILAMAZ, satir kaybedildi
    #
    #  Kontrolu her tura almak bu pencereyi 1 saniyeden 0.02 saniyeye
    #  indiriyor. Maliyeti ihmal edilebilir, kazanci buyuk.
    #
    #  DURUSTCE SOYLEMEK GEREKIR: bu pencere SIFIRLANAMAZ. "Sifirla" ile
    #  "yeni veri yaz" arasinda ne kadar kisa olursa olsun bir aralik vardir
    #  ve o aralikta veri kaybi mumkundur. Bu, kodumuzun degil COPYTRUNCATE
    #  YONTEMININ yapisal kusurudur -- logrotate'in kendi dokumantasyonu da
    #  bu modun veri kaybedebilecegini soyler.
    #
    #  Pratik sonuc: logrotate yapilandirirken copytruncate yerine varsayilan
    #  "create" modunu tercih et. Bir DevOps muhendisi olarak bu tercihi
    #  bilincli yapman, kodda ne kadar ugrasirsan ugras elde edemeyecegin
    #  bir garantiyi bedavaya verir.
    # ------------------------------------------------------------------------
    def check_truncation
      return unless @file
      return unless @file.size < @file.pos

      @truncations += 1
      warn '[tailer] dosya kesilmis (copytruncate): basa donuluyor'
      @file.seek(0, IO::SEEK_SET)
      @partial = +''   # yarim satir artik gecersiz
    rescue IOError, SystemCallError
      # Dosya silinmis olabilir; rotasyon kontrolu bunu ele alacak.
      nil
    end

    def check_rotation
      now = Time.now
      return if now - @last_rotation_check < ROTATION_CHECK_INTERVAL

      @last_rotation_check = now
      return unless @file

      # --- A) Rotasyon kontrolu ---
      begin
        current = current_identity
      rescue Errno::ENOENT
        # Yoldaki dosya su an yok (tasindi, yenisi henuz olusmadi).
        # Acik tutucumuzu KORUYORUZ -- eski dosyada okunmamis satir olabilir.
        # Bir sonraki turda yeniden bakariz.
        return
      end

      return if current == @identity

      # Rotasyon var. Ama ONCE eski dosyada kalan satirlari BOSALTIYORUZ.
      # Bu adimi atlarsan, rotasyon anindaki son satirlari kaybedersin --
      # ve o satirlar tam da "gunun son olaylari"dir.
      read_available { |line| yield line }

      @rotations += 1
      @reopens   += 1
      warn "[tailer] rotasyon algilandi, dosya yeniden aciliyor: #{@path}"

      close_file
      @partial = +''
      @file    = File.open(@path, 'rb')
      # Yeni dosya bastan okunur: icindeki her satir yeni, hicbirini gormedik.
      @file.seek(0, IO::SEEK_SET)
      @identity = current_identity
    end

    # ========================================================================
    #  Bir dosyanin "kimligi". Ayni dosya mi, yeni dosya mi?
    # ------------------------------------------------------------------------
    #  ino = inode numarasi: dosyanin dosya sistemindeki kimlik numarasi.
    #  Isim degisir, inode degismez. Isim ayni kalir ama inode degisirse
    #  o dosya YENIDIR. Rotasyon tespitinin dayanagi budur.
    #
    #  --- GERCEK BIR TASINABILIRLIK TUZAGI (bu projede yasadik) ---
    #
    #  Ilk yazdigimizda kimligi [dev, ino] ikilisi olarak tanimladik.
    #  dev = aygit numarasi (hangi disk/bolum). Mantikli: iki farkli diskteki
    #  iki dosyanin inode'u ayni olabilir, dev bu belirsizligi cozer.
    #
    #  Windows'ta olculen sonuc:
    #      File.stat(yol).dev  ->  2      (yoldan bakinca)
    #      acik_dosya.stat.dev ->  0      (tutucudan bakinca)
    #      ino                 ->  ikisinde de AYNI
    #
    #  Yani Ruby, ayni dosya icin nereden sordugunuza gore farkli dev
    #  dondurdu. Sonuc: her kontrolde "dosya degismis" sanip surekli
    #  yeniden aciyor ve bastan okuyor -- her satiri TEKRAR isliyorduk.
    #  Belirti tuhaftir: alarmlar cift cift geliyor ama kodda dongu yok.
    #
    #  Cozum iki katmanli:
    #    1) Kimligi her zaman AYNI KAYNAKTAN al (yoldan bakarak).
    #    2) ino guvenilirse dev'e hic bakma -- tek bir yolu izliyoruz,
    #       o yolun iki farkli diskte olmasi diye bir durum yok.
    #
    #  FAT32/exFAT ve bazi ag surucularinde ino 0 gelir. O zaman
    #  boyut+degisim zamanina dusuyoruz: ideal degil ama hicbir sey
    #  yapmamaktan iyi -- ve en onemlisi, SESSIZCE YANLIS calismaktan iyi.
    # ========================================================================
    def file_identity(stat)
      return [stat.ino] unless stat.ino.zero?

      [stat.dev, stat.size, stat.mtime.to_i]
    end

    # Kimligi her zaman yoldan bakarak uret -- yukaridaki tuzagin 1. maddesi.
    def current_identity
      file_identity(File.stat(@path))
    end

    # ========================================================================
    #  KONUM KAYDI (CHECKPOINT) -- yeniden baslatma guvenligi
    # ========================================================================
    #
    #  Senaryo: servisi guncellemek icin yeniden baslattin. 4 saniye surdu.
    #  O 4 saniyede gelen satirlara ne oldu?
    #
    #    Kayit YOKSA + start: :end  -> o satirlar SONSUZA KADAR KAYBOLDU.
    #                                  Tam o anda saldiri varsa hic gormedin.
    #    Kayit YOKSA + start: :begin -> tum dosya bastan islenir, ayni
    #                                  alarmlar tekrar uretilir (gurultu).
    #    Kayit VARSA                 -> tam biraktigin yerden devam.
    #
    #  Filebeat'in "registry" dosyasi, Promtail'in "positions.yaml" dosyasi
    #  tam olarak bunu yapar.
    #
    #  ONEMLI TASARIM TERCIHI: konumu isledikten SONRA kaydediyoruz.
    #  Cokme aninda birkac satir TEKRAR islenebilir (at-least-once / en az
    #  bir kez). Alternatifi, kaydedip sonra islemek olurdu: o zaman cokmede
    #  satir KAYBEDILIR (at-most-once / en fazla bir kez).
    #  Guvenlik izlemesinde tekrar eden alarm can sikicidir; KACIRILAN alarm
    #  ise aracin varlik sebebini ortadan kaldirir. Bu yuzden tekrari seciyoruz.
    # ========================================================================
    def checkpoint_if_due
      return unless @state_file
      return if Time.now - @last_checkpoint < CHECKPOINT_INTERVAL

      save_checkpoint
    end

    def save_checkpoint
      return unless @state_file && @file

      # ino'yu acik tutucudan aliyoruz: hem her zaman erisilebilir (dosya
      # yoldan silinmis olsa bile), hem de ino degeri iki kaynakta da ayni
      # (dev'in tersine -- yukaridaki tasinabilirlik notuna bak).
      state = {
        path: File.expand_path(@path),
        ino:  @file.stat.ino,
        pos:  @file.pos,
        at:   Time.now.iso8601
      }

      # ATOMIK YAZMA: once gecici dosyaya yaz, sonra yerine tasi.
      # Dogrudan uzerine yazarken elektrik kesilirse yari yazilmis, bozuk bir
      # JSON kalir ve bir sonraki baslangicta konumu okuyamazsin.
      # rename islemi ayni dosya sisteminde atomiktir: ya eski hali ya yeni
      # hali gorulur, arada bir sey yok. (Veritabanlarinin da kullandigi
      # temel hile budur.)
      tmp = "#{@state_file}.tmp"
      FileUtils.mkdir_p(File.dirname(@state_file))
      File.write(tmp, JSON.generate(state))
      File.rename(tmp, @state_file)
      @last_checkpoint = Time.now
    rescue SystemCallError => e
      # Konum kaydedilemedi. Bu, izlemeyi durdurmak icin bir sebep DEGILDIR.
      warn "[tailer] konum kaydedilemedi: #{e.message}"
    end

    # Kaydedilmis konumdan devam etmeye calisir. Basarili ise true doner.
    def resume_from_checkpoint
      return false unless @state_file && File.exist?(@state_file)

      state = JSON.parse(File.read(@state_file))
      stat  = @file.stat

      # Kayit BU dosyaya mi ait? Rotasyon olmussa eski konum anlamsizdir.
      unless stat.ino.zero? || state['ino'] == stat.ino
        warn '[tailer] kayitli konum baska bir dosyaya ait (rotasyon), yok sayiliyor'
        return false
      end

      pos = state['pos'].to_i

      # Kayitli konum dosya boyutundan buyukse dosya kesilmis demektir.
      if pos > stat.size
        warn '[tailer] kayitli konum dosya boyutundan buyuk (kesilme), basa donuluyor'
        return false
      end

      @file.seek(pos, IO::SEEK_SET)
      warn "[tailer] kayitli konumdan devam: #{pos} / #{stat.size} bayt"
      true
    rescue JSON::ParserError, SystemCallError => e
      warn "[tailer] konum dosyasi okunamadi (#{e.message}), yok sayiliyor"
      false
    end
  end
end
