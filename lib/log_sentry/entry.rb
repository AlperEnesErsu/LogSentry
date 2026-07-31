# frozen_string_literal: true

# ============================================================================
#  ADIM 2a -- Entry: bir log satirinin veri modeli
# ----------------------------------------------------------------------------
#  Bu dosyada TEK bir sey yapiyoruz: coz'ulmus bir log satirini temsil eden
#  veri kutusunu tanimlamak.
#
#  Neden ayri bir dosya? Cunku bu, sistemin tamaminin konustugu "ortak dil".
#  Parser bunu URETIR, kurallar bunu TUKETIR, veritabani bunu SAKLAR.
#  Ortak dili tek bir yerde tanimlamak, o dili degistirmek gerektiginde
#  tek bir dosyaya dokunmani saglar.
# ============================================================================

require 'time'

module LogSentry
  # --------------------------------------------------------------------------
  #  Struct nedir?
  # --------------------------------------------------------------------------
  #  Ruby'de "sadece veri tasiyan" bir sinif yazmak icin kisa yol.
  #  Asagidaki tek satir, elle yazsan ~30 satir olacak bir sinifi uretir:
  #  kurucu metod, her alan icin okuyucu/yazici metod, ==, to_h, inspect...
  #
  #  keyword_init: true  ->  Entry.new(ip: "1.2.3.4", status: 401)
  #  bu olmasaydi        ->  Entry.new("1.2.3.4", ..., 401)  (sirayla, hatali)
  #
  #  Sira yerine isim kullanmak sadece okunabilirlik degil, GUVENLIK meselesi:
  #  9 alanli bir yapida iki alanin yerini karistirmak cok kolaydir ve
  #  bu hatayi test bile yakalamayabilir.
  # --------------------------------------------------------------------------
  #
  #  DIKKAT -- neden alanin adi "method" degil "http_method"?
  #
  #  Ruby'de her nesnenin dogustan gelen bir `method` metodu vardir
  #  (nesne.method(:isim) -> o metodu bir nesne olarak dondurur).
  #  Struct'a `:method` adli bir alan verirsen bu dogustan gelen metodu
  #  EZERSIN. Kod calisir gibi gorunur, sonra alakasiz bir yerde tuhaf bir
  #  hata alirsin ve saatlerce sebebini ararsin.
  #
  #  Ders: dilin kendi kelime dagarcigini ezmemek icin `class`, `method`,
  #  `hash`, `send`, `object_id`, `freeze` gibi isimleri alan adi olarak
  #  kullanmaktan kacin.
  # --------------------------------------------------------------------------
  Entry = Struct.new(
    # ------------------------------------------------------------------------
    #  ip: KURALLARIN KULLANDIGI ADRES -- yani GERCEK ISTEMCI.
    #
    #  Dogrudan internete acik bir sunucuda bu, nginx'in $remote_addr degeri.
    #  AMA sunucu bir load balancer / ters vekil arkasindaysa $remote_addr
    #  LB'nin adresidir; gercek istemci X-Forwarded-For basligindadir.
    #
    #  Parser bu ayrimi cozup buraya HER ZAMAN gercek istemciyi yaziyor.
    #  Boylece kurallarin hicbiri "LB var mi yok mu" diye bilmek zorunda
    #  kalmiyor -- karmasikligi tek bir yerde (Parser) hapsediyoruz.
    # ------------------------------------------------------------------------
    :ip,          # String  -> "45.155.205.233"    GERCEK istemci
    :proxy_ip,    # String  -> "10.0.0.7"          araya giren LB (yoksa nil)
    :forwarded_for, # String -> ham XFF zinciri    (yoksa nil)
    :time,        # Time    -> 2026-07-29 14:39:25 LOGUN kendi zamani
    :http_method, # String  -> "POST"
    :path,        # String  -> "/login"
    :protocol,    # String  -> "HTTP/1.1"   (nil olabilir)
    :status,      # Integer -> 401          artik SAYI, metin degil
    :bytes,       # Integer -> 178
    :referer,     # String  -> "-"          (nil olabilir)
    :user_agent,  # String  -> "python-requests/2.31.0"
    :raw,         # String  -> satirin dokunulmamis hali (KANIT)
    # Kaydin hangi dosyadan/sunucudan geldigi. Cok sunuculu kurulumlarda
    # "hangi makinede oldu" sorusunun cevabi; tek dosya izlenirken nil.
    :source,
    keyword_init: true
  ) do
    # ------------------------------------------------------------------------
    #  Struct.new'e verilen `do ... end` blogu, uretilen sinifin GOVDESI olur.
    #  Yani asagidaki metodlar Entry sinifinin metodlaridir.
    #
    #  Bu metodlar "sorgu metodu" (predicate) adini alir. Ruby'de bir metodun
    #  adi `?` ile bitiyorsa "bu true/false donduren bir soru" demektir.
    #  Zorunlu degil, gelenek -- ama kodu ingilizce cumle gibi okutur:
    #     if entry.failed_auth?   ->  "eger giris basarisiz ise"
    # ------------------------------------------------------------------------

    # Basarili istek mi? (200-299)
    def success?
      (200..299).cover?(status)
    end

    # Istemci hatasi mi? (400-499) -- yani "sen yanlis yaptin"
    def client_error?
      (400..499).cover?(status)
    end

    # Sunucu hatasi mi? (500-599) -- yani "biz yanlis yaptik"
    def server_error?
      (500..599).cover?(status)
    end

    # Basarisiz kimlik dogrulama mi?
    # BURASI BRUTE FORCE KURALININ TEMELI. 401 = yetkisiz (sifre yanlis),
    # 403 = yasak (sifre dogru ama izin yok / ya da WAF engelledi).
    # Ikisi de "girmeye calisti, giremedi" anlamina gelir.
    def failed_auth?
      status == 401 || status == 403
    end

    # Istek bir vekil/LB uzerinden mi geldi?
    def proxied?
      !proxy_ip.nil?
    end

    # Ayristirilamayan bir istek satiri miydi?
    # Parser bozuk istekleri ATMAZ, isaretler -- cunku bir sunucuya
    # anlamsiz bayt yigini gondermek, basli basina supheli bir davranistir.
    def malformed_request?
      http_method == '-'
    end

    # Veritabanina/JSON'a yazmak icin: ham satiri disari alinmis hali.
    # Ham satir cok yer kaplar; veritabaninda ayri tutulur.
    def to_record
      to_h.reject { |key, _value| key == :raw }
    end

    # Insan icin tek satirlik ozet (ekrana basmak, alarm mesaji icin)
    def summary
      format('%s %s %s -> %d', ip, http_method, path, status)
    end
  end
end
