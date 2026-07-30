# frozen_string_literal: true

# ============================================================================
#  ADIM 4b -- Rules::Base: tum kurallarin ortak atasi
# ----------------------------------------------------------------------------
#  SOZLESME (mimari dokumani, bolum 5):
#    Sana bir Entry veririm; bana ya bir Alert ya da nil dondurursun.
#    Kendi hafizani (kimin kac kez ne yaptigini) kendin tutarsin.
#
#  Bu dosya projenin en yogun muhendislik kismi. Uc kuralimizin UCU DE
#  buradaki mekanizmayi paylasiyor, cunku "brute force", "DDoS" ve "dizin
#  taramasi" aslinda ayni sorunun farkli esiklerle sorulmus halleri:
#
#      "Ayni kaynaktan, belirli bir SURE icinde, belirli bir SAYIDAN
#       fazla su olay oldu mu?"
#
#  Kural            Neyi sayar                    Pencere   Esik
#  ---------------  ----------------------------  --------  ----
#  BruteForce       401/403 yanitlari                 60 sn    10
#  Flood            tum istekler                       1 sn   100
#  PathScan         FARKLI hassas dizinler           300 sn     3
# ============================================================================

require 'cgi'
require_relative '../alert'

module LogSentry
  module Rules
    class Base
      # Tek bir anahtar (genelde bir IP) icin en fazla kac olay tutalim?
      #
      # Neden gerekli? Pencere zaten sureyle sinirli, ama SURE sinirli olmasi
      # SAYI'nin sinirli olmasini garanti etmez. Saniyede 500.000 istek
      # gonderen bir saldirgan, 1 saniyelik pencereye 500.000 kayit sokar.
      # Pencere "dogru" calisir ve bellek biter.
      MAX_EVENTS_PER_KEY = 2_000

      # Kac farkli anahtar (IP) takip edelim?
      #
      # BU EN KRITIK SINIR. Yukaridaki sinir "bir IP cok istek atarsa"yi
      # cozuyor; bu sinir "cok fazla FARKLI IP gelirse"yi cozuyor.
      # Dagitik bir saldiride (botnet) yuz binlerce farkli IP gorursun ve
      # her biri icin bir pencere acarsan hafiza patlar.
      #
      # Ironi sudur: DDoS'u tespit etmek icin yazdigin kod, DDoS'un kendisi
      # tarafindan RAM tuketilerek oldurulebilir. Sinir koymak, aracin
      # saldiri aninda AYAKTA KALMASI icin gerekli.
      MAX_KEYS = 50_000

      # Temizlik (housekeeping) kac saniyede bir yapilsin?
      HOUSEKEEPING_INTERVAL = 30

      attr_reader :name, :window, :threshold, :cooldown, :severity,
                  :evaluated_count, :alert_count

      def initialize(window:, threshold:, cooldown: 120, severity: :medium, **_extra)
        @window    = window      # saniye
        @threshold = threshold   # bu sayiyi ASARSA alarm
        @cooldown  = cooldown    # ayni anahtar icin susma suresi
        @severity  = severity
        @name      = self.class.rule_name

        # Kayan pencereler: { "ip" => [[zaman, deger], ...] }
        @events = {}

        # Kanit tamponu: { "ip" => [ham satir, ...] }  (sinirli)
        @evidence = {}

        # Sogutma: { "ip" => bu zamana kadar susacagiz }
        @silenced_until = {}

        @evaluated_count = 0
        @alert_count     = 0
        @last_housekeeping = nil
        @dropped_keys      = 0
      end

      # Alt siniflar kendi adini soyler. `self.class.rule_name` ile
      # cagirdigimiz icin SINIF metodu olmasi gerekiyor.
      def self.rule_name
        # Isimsiz sinif (Class.new(Base)) icin `name` nil doner.
        # Testlerde ve dinamik kural uretiminde bu olur; NoMethodError
        # yerine anlamli bir deger dondurmek daha dogru.
        return :anonymous if name.nil?

        # LogSentry::Rules::BruteForce -> :brute_force
        name.split('::').last
            .gsub(/([a-z])([A-Z])/, '\1_\2')
            .downcase
            .to_sym
      end

      # ======================================================================
      #  ANA METOD -- "SABLON METOD" (template method) desenidir
      # ----------------------------------------------------------------------
      #  Bu metod ISIN SIRASINI tanimlar; her adimin ICERIGINI alt siniflar
      #  doldurur. Boylece "kural nasil calisir" mantigi TEK bir yerde
      #  yaziliyor ve alt siniflar sadece kendine ozgu karari veriyor.
      #
      #  Yeni bir kural yazmak istediginde uc kucuk metod yazman yeterli:
      #     interested? / message_for / (gerekirse) measure
      #  Pencere yonetimi, sogutma, bellek sinirlari, kanit toplama -- hepsi
      #  bedavaya gelir. Iyi bir taban sinifin degeri budur.
      # ======================================================================
      def call(entry)
        @evaluated_count += 1

        # 1) Bu kayit beni ilgilendiriyor mu? (alt sinif karar verir)
        return nil unless interested?(entry)

        # 2) DIKKAT: entry.time kullaniyoruz, Time.now DEGIL.
        #
        #    Neden onemli? Sistem yavassa, log gecikmeli geliyorsa ya da
        #    gecmis bir dosyayi isliyorsak (start: :begin) bu ikisi
        #    birbirinden saatler farkli olabilir. "Son 60 saniye" derken
        #    kastettigimiz sey OLAYLARIN zamani, bizim saatimiz degil.
        #
        #    Bu hatayi yapan bir sistem, gecmis logu isledigi anda TUM
        #    olaylari "cok eski" sayip hicbir alarm uretmez -- ve bunu
        #    sessizce yapar.
        now = entry.time
        key = key_for(entry)

        # 3) Olayi pencereye ekle, eskiyeni at
        track(key, now, value_for(entry), entry.raw)

        # 4) Periyodik temizlik (bellek sinirlarini korumak icin)
        housekeeping(now)

        # 5) Esik asildi mi?
        measured = measure(key)
        return nil unless measured > @threshold

        # 6) Bu anahtar icin susuyor muyuz?
        #    ONEMLI: bu kontrol 3. adimdan SONRA. Sogutma sirasinda da
        #    saymaya devam ediyoruz -- sadece BILDIRMIYORUZ. Saymayi
        #    birakirsak, sogutma bitince sayac sifirdan baslar ve devam
        #    eden bir saldiri gorunmez hale gelir.
        return nil if silenced?(key, now)

        silence!(key, now)
        @alert_count += 1

        build_alert(entry, measured)
      end

      # Su anda kac anahtar takip ediliyor? (gozlemlenebilirlik)
      def tracked_keys
        @events.size
      end

      # ======================================================================
      #  YAPILANDIRMA IMZASI -- sicak yenilemenin (SIGHUP) can alici noktasi
      # ----------------------------------------------------------------------
      #  SORUN: SIGHUP geldiginde motoru bastan kurarsak yeni kural nesneleri
      #  olusur -- ve onlarin kayan pencereleri BOSTUR, sogutma kayitlari
      #  YOKTUR. Sonuc: devam eden bir saldirida
      #    - sayaclar sifirlanir (saldirgan gorunmez hale gelir), ya da
      #    - sogutma sifirlanir (ayni alarm tekrar tekrar duser).
      #
      #  Bunu canli testte bizzat gorduk: 120 saniyelik sogutmaya ragmen
      #  yenilemeden 4 saniye sonra ayni alarm ikinci kez uretildi.
      #
      #  COZUM: yenilemede SADECE AYARI DEGISEN kurallari yeniden kur.
      #  Ayari aynen duran kuralin nesnesini -- dolayisiyla hafizasini --
      #  oldugu gibi koru.
      #
      #  Bu imza o karsilastirmayi mumkun kilar. Alt siniflar kendine ozgu
      #  ayarlari varsa extra_signature'i ezer.
      # ======================================================================
      def signature
        [@name, @window, @threshold, @cooldown, @severity, extra_signature]
      end

      # Kurala ozel ayarlar. Varsayilan: yok.
      def extra_signature
        nil
      end

      def stats
        {
          rule:          @name,
          evaluated:     @evaluated_count,
          alerts:        @alert_count,
          tracked_keys:  @events.size,
          dropped_keys:  @dropped_keys,
          largest_window: @events.values.map(&:size).max || 0
        }
      end

      # ======================================================================
      #  ALT SINIFLARIN DOLDURACAGI KISIMLAR
      # ======================================================================

      # Bu kayit bu kurali ilgilendiriyor mu?
      # Ornek: BruteForce sadece 401/403 ile ilgilenir.
      def interested?(_entry)
        raise NotImplementedError, "#{self.class} interested? metodunu tanimlamali"
      end

      # Insan icin alarm mesaji.
      def message_for(_entry, _measured)
        raise NotImplementedError, "#{self.class} message_for metodunu tanimlamali"
      end

      # Pencerede neyi sayiyoruz?
      #  - Varsayilan: OLAY SAYISI (count)
      #  - PathScan bunu ezip FARKLI DEGER SAYISI (distinct) kullanir
      def measure(key)
        (@events[key] || []).size
      end

      # Olaylari hangi anahtar altinda gruplayacagiz? Varsayilan: IP.
      # (Ileride "kullanici adi basina" bir kural yazmak isterseniz burasi
      #  degisir, geri kalan hicbir sey degismez.)
      def key_for(entry)
        entry.ip
      end

      # Pencereye hangi degeri yazacagiz? Varsayilan: hicbir sey (sadece
      # sayiyoruz). PathScan burada YOL'u dondurur, cunku FARKLI yollari
      # saymasi gerekiyor.
      def value_for(_entry)
        nil
      end

      # Alarma eklenecek kurala ozel bilgiler.
      def details_for(_entry, _measured)
        {}
      end

      # ======================================================================
      #  IMZA TABANLI KURALLAR ICIN ORTAK YARDIMCI
      # ----------------------------------------------------------------------
      #  Sqli ve Xss gibi kurallar istegin ICERIGINDE kalip arar. Bu, iki
      #  tuzak barindirir ve ikisi de canli testte ortaya cikti:
      #
      #  1) KODLAMA COKMESI  (gercek bir zafiyetti)
      #     Saldirgan /?x=%FF%FE ister. Log satirinin kendisi gecerli UTF-8'dir
      #     (yuzde kodlamasi sadece ASCII karakter kullanir), yani Parser'daki
      #     scrub devreye girmez. Ama CGI.unescape bunu cozunce ortaya GECERSIZ
      #     baytlar cikar -- ve o metinde regex calistirmak
      #     "ArgumentError: invalid byte sequence in UTF-8" firlatir.
      #
      #     Sonuc: TEK BIR ISTEKLE tum izleme durur. Adim 2'de Parser icin
      #     duzelttigimiz zafiyetin, kodlama cozuldukten sonra geri gelmis hali.
      #     Cozum ayni: cozdukten SONRA da temizle.
      #
      #  2) GEREKSIZ IS
      #     Normal trafigin neredeyse tamaminda yuzde kodlamasi yoktur.
      #     Metinde '%' yoksa cozmeye hic gerek yok -- bu, her satirda iki kat
      #     regex taramasindan kurtariyor.
      # ======================================================================

      # ----------------------------------------------------------------------
      #  Kalip aranacak metin: YOL + REFERER
      # ----------------------------------------------------------------------
      #  Neden ham satirin tamami degil?
      #
      #  Ilk surumde entry.raw taraniyordu -- yani IP, zaman damgasi, durum
      #  kodu ve USER-AGENT dahil her sey. Bunun olcumlenmis bir yan etkisi
      #  vardi: user-agent'inda "union select" yazan masum bir istek,
      #  CRITICAL seviye SQLi alarmi uretiyordu.
      #
      #  Esigi 0 olan critical bir kuralda yanlis pozitif, gece 3'te bosuna
      #  telefon calmasi demektir -- ve Adim 4'te ogrendigimiz gibi SIEM
      #  projelerini bitiren sey yanlis tespit degil, BILDIRIM YORGUNLUGUDUR.
      #
      #  Bu yuzden sorumluluklari ayirdik:
      #     sqli / xss  ->  YOL ve REFERER  (saldiri yukunun tasindigi yerler)
      #     scanner     ->  USER-AGENT      (aracin kendini ele verdigi yer)
      #
      #  Referer'i tutuyoruz cunku gercek saldirilarda yuk orada da tasinir
      #  ve referer, user-agent'in aksine "arac imzasi" niyetine kullanilmaz.
      #
      #  Bedeli durustce: yalnizca user-agent icinde SQL yuku tasiyan bir
      #  istek artik bu kurallara gorunmez. O senaryo, tanidik bir arac
      #  imzasi tasiyorsa scanner kuralina takilir; tasimiyorsa kacar.
      #  Her esik ve her kapsam bir takastir.
      # ----------------------------------------------------------------------
      def payload_text(entry)
        text = "#{entry.path} #{entry.referer}"
        text.valid_encoding? ? text : text.scrub('?')
      end

      # Yuzde kodlamasi cozulmus hali (gerekmiyorsa nil).
      def decoded_payload(text)
        return nil unless text.include?('%')

        decoded = CGI.unescape(text)
        decoded.valid_encoding? ? decoded : decoded.scrub('?')
      rescue StandardError
        # Bozuk kodlama cozulemedi -- kural bu satiri gormemis olsun,
        # ama PROGRAM DURMASIN.
        nil
      end

      # Kalip, istegin ham halinde ya da kodu cozulmus halinde geciyor mu?
      def payload_matches?(entry, pattern)
        text = payload_text(entry)
        return true if pattern.match?(text)

        decoded = decoded_payload(text)
        !decoded.nil? && pattern.match?(decoded)
      end

      private

      # ======================================================================
      #  KAYAN PENCERE (SLIDING WINDOW) -- projenin en kritik yapisi
      # ----------------------------------------------------------------------
      #  Naif cozum: her IP'nin TUM olaylarini bir listede tut.
      #  Sorun: servis haftalarca calisacak, liste sonsuza kadar buyur, RAM
      #  biter. (Adim 1'de File.read icin soyledigimiz seyin ta kendisi.)
      #
      #  Kayan pencere: her anahtar icin sadece SON <window> saniyeyi tut,
      #  eskiyeni bastan at.
      #
      #    Simdi: 14:39:25   pencere: [14:38:25 ... 14:39:25]
      #
      #    [14:38:10] [14:38:50] [14:39:01] [14:39:05] [14:39:22] [14:39:25]
      #     ^ 60 sn'den eski
      #     +-- ATILIR         +--------- bunlar sayilir: 5 tane ---------+
      #
      #  Boylece bellek kullanimi SABIT kalir: bir anahtar en fazla
      #  <window> saniyelik veri tutar.
      # ======================================================================
      def track(key, now, value, raw)
        list = (@events[key] ||= [])
        list << [now, value]

        # Pencereden cikanlari at.
        #
        # Neden shift ile basindan atiyoruz? Cunku liste zaman sirali:
        # en eski en basta. Bastan atmak, tum listeyi taramaktan cok daha
        # ucuz (O(atilan sayisi), O(toplam) degil).
        #
        # NOT: Array#shift Ruby'de basit bir isaretci kaydirmasidir, tum
        # diziyi kopyalamaz -- bu yuzden burada guvenle kullanilabilir.
        cutoff = now - @window
        list.shift while list.any? && list.first[0] < cutoff

        # Tek anahtar icin olay sayisi sinirini koru.
        # Pencere suresi dolmadan da cok fazla olay birikebilir.
        list.shift while list.size > MAX_EVENTS_PER_KEY

        # Kanit: en son N ham satiri tut.
        ev = (@evidence[key] ||= [])
        ev << raw if raw
        ev.shift while ev.size > MAX_EVIDENCE
      end

      # ======================================================================
      #  TEMIZLIK (HOUSEKEEPING) -- anahtar uzayini sinirlamak
      # ----------------------------------------------------------------------
      #  track metodu her anahtarin ICINI sinirliyor. Ama anahtar SAYISI
      #  hala sinirsiz: her yeni IP yeni bir Hash girdisi acar ve o girdi,
      #  IP bir daha hic gorunmese bile orada durur.
      #
      #  Normal bir sitede gunde binlerce farkli IP gorursun -- sorun degil.
      #  Bir botnet saldirisinda yuz binlerce gorursun -- sorun.
      #
      #  Iki asamali cozum:
      #    1) Bosalmis pencereleri sil (ucuz, her zaman yapilir)
      #    2) Hala cok fazlaysa, EN ESKI goruleni at (zorunlu tahliye)
      # ======================================================================
      def housekeeping(now)
        return if @last_housekeeping && (now - @last_housekeeping) < HOUSEKEEPING_INTERVAL

        @last_housekeeping = now
        cutoff = now - @window

        # 1) Penceresi tamamen bosalmis anahtarlari kaldir.
        @events.delete_if do |key, list|
          list.shift while list.any? && list.first[0] < cutoff
          if list.empty?
            @evidence.delete(key)
            true
          else
            false
          end
        end

        # Suresi gecmis sogutma kayitlarini da temizle.
        @silenced_until.delete_if { |_key, until_time| until_time < now }

        # 2) Zorunlu tahliye: hala sinirin uzerindeysek en eski gorulenleri at.
        #
        # Bu bir KAYIP demektir: attigimiz anahtarin gecmisini unutuyoruz.
        # Ama alternatifi process'in olmesi, yani TUM izlemenin durmasi.
        # Muhendislik boyledir: kotu iki secenek arasindan daha az kotusunu
        # bilerek secmek. Onemli olan, bunu SESSIZCE yapmamak -- o yuzden
        # sayiyor ve uyariyoruz.
        return if @events.size <= MAX_KEYS

        excess = @events.size - MAX_KEYS
        oldest = @events.sort_by { |_key, list| list.last[0] }.first(excess)
        oldest.each do |key, _list|
          @events.delete(key)
          @evidence.delete(key)
          @dropped_keys += 1
        end

        warn "[#{@name}] anahtar siniri asildi, #{excess} en eski kayit dusuruldu " \
             "(toplam dusen: #{@dropped_keys})"
      end

      # ======================================================================
      #  SOGUTMA (COOLDOWN) -- bildirim yorgunlugunu onlemek
      # ----------------------------------------------------------------------
      #  Bu olmadan arac KULLANILAMAZ. Bir brute force saldirisinda esik
      #  asildiktan sonra gelen HER SATIR yeni bir alarm uretir: saniyede
      #  50 alarm, telefonunda 3000 bildirim.
      #
      #  Gercek hayatta SIEM projelerini bitiren sey yanlis tespit degil,
      #  BILDIRIM YORGUNLUGUDUR: insan 200. bildirimden sonra hepsini
      #  gormezden gelmeye baslar. O noktadan sonra sistemin teknik olarak
      #  dogru calismasinin hicbir kiymeti kalmaz.
      # ======================================================================
      def silenced?(key, now)
        until_time = @silenced_until[key]
        !until_time.nil? && now < until_time
      end

      def silence!(key, now)
        @silenced_until[key] = now + @cooldown
      end

      def build_alert(entry, measured)
        Alert.new(
          rule:      @name,
          severity:  @severity,
          ip:        entry.ip,
          message:   message_for(entry, measured),
          time:      entry.time,
          count:     measured,
          threshold: @threshold,
          window:    @window,
          details:   details_for(entry, measured),
          # dup: kanit dizisinin O ANKI kopyasini aliyoruz.
          # Kopyalamazsak alarm, canli degisen diziye referans tutar ve
          # 10 dakika sonra baktiginda icinde bambaska satirlar bulursun.
          # Kanit, uretildigi andaki halini KORUMAK zorundadir.
          evidence:  (@evidence[key_for(entry)] || []).dup
        )
      end
    end
  end
end
