# frozen_string_literal: true

# ============================================================================
#  ADIM 2b -- Parser: metni veriye ceviren katman
# ----------------------------------------------------------------------------
#  SOZLESME (mimari dokumani, bolum 5):
#    Sana bir metin satiri veririm; bana ya bir Entry ya da nil dondurursun.
#    ASLA COKMEZSIN. Anlamadigin satirda nil don, ama programi durdurma.
#
#  Bu sozlesmenin son cumlesi hayat kurtaricidir: bu kod bir daemon icinde,
#  gunlerce, milyonlarca satirla calisacak. Tek bir bozuk satir yuzunden
#  tum guvenlik izlemesinin durmasi kabul edilemez.
# ============================================================================

require 'time'
require 'ipaddr'
require_relative 'entry'
require_relative 'masker'
require_relative 'client_ip'

module LogSentry
  class Parser
    # ========================================================================
    #  REGEX (Duzenli Ifade) NEDIR?
    # ------------------------------------------------------------------------
    #  Metin icinde kalip arayan mini bir dil. "Bu satir sunun gibi mi
    #  gorunuyor?" diye sorar ve gorunuyorsa parcalarini sana verir.
    #
    #  Kullanacagimiz isaretler:
    #
    #    \S       bosluk OLMAYAN tek karakter   ("Non-Space")
    #    \s       bosluk karakteri (bosluk, tab)
    #    \d       tek rakam (0-9)
    #    +        "bir veya daha fazla"          \d+  -> 1, 42, 178
    #    *        "sifir veya daha fazla"
    #    ?        "olabilir de olmayabilir"      (optional)
    #    [^"]     " OLMAYAN herhangi bir karakter (^ = degilleme)
    #    \A  \z   satirin basi / satirin sonu
    #    ( ... )  YAKALAMA GRUBU -- bu parcayi bana ayrica ver
    #    (?<ad>)  ADLANDIRILMIS yakalama grubu -- bu parcayi "ad" ismiyle ver
    #    (?: ... ) grupla ama YAKALAMA (sadece "sunlardan biri" demek icin)
    #    \[ \]    kose parantezin kendisi (\ ile kacis, cunku [ ozel karakter)
    #
    #  Sondaki /x ("extended" kipi) ne yapar?
    #  Regex icindeki bosluklari ve yorumlari YOK SAYAR. Bu sayede kalibi
    #  alt alta, yorumlu yazabiliriz. Onsuz asagidaki kalip tek satirda,
    #  okunamaz bir karakter cormasi olurdu -- ve 6 ay sonra kendi yazdigin
    #  regex'i anlamamak, yazilim dunyasinin klasik trajedisidir.
    #  DIKKAT: /x kipinde gercek bir bosluk aramak icin \s yazmak ZORUNLU.
    # ========================================================================

    # ------------------------------------------------------------------------
    #  NEDEN /.../x DEGIL DE %r{...}x ?
    #
    #  Ruby'de regex yazmanin varsayilan yolu /.../ seklindedir. Ama /x kipinde
    #  yorum yazdigimizda su tuzaga dusuyoruz:
    #
    #      /\A ... \s+   # 4) [29/Jul/2026:14:39:25 +0300]
    #                            ^ BURADAKI / REGEX'I BITIRIR
    #
    #  Cunku Ruby once satiri okuyup kapanis / isaretini arar; regex'in kendi
    #  # yorumlarini o asamada henuz bilmez. Yorumun icindeki masum bir egik
    #  cizgi tum kalibi bozar.
    #
    #  Cozum: sinirlayiciyi degistir. %r{...} yazarsan kapanis isareti } olur,
    #  / karakteri artik sıradan bir karakterdir -- hem yorumlarda hem kalipta
    #  (HTTP/1.1 yazarken \/ ile kacis yapmaya da gerek kalmaz).
    #
    #  Genel kural: icinde bol miktarda / gecen kaliplarda (URL, yol, tarih)
    #  %r{...} kullan. Ruby'de "leaning toothpick syndrome" (egik kurdan
    #  sendromu) diye anilan okunmaz \/\/\/ yiginini bu onler.
    # ------------------------------------------------------------------------

    # Nginx "combined" / Apache "combined" formati (ikisi ayni formattir):
    #
    #   IP - user [zaman] "istek" durum boyut "referer" "user-agent"
    #
    COMBINED = %r{\A
      (?<ip>\S+)          \s+   # 1) IP adresi           -> 45.155.205.233
      (?<ident>\S+)       \s+   # 2) identd (hep "-")    -> kullanmiyoruz
      (?<user>\S+)        \s+   # 3) HTTP auth kullanici -> genelde "-"
      \[(?<time>[^\]]+)\] \s+   # 4) [29/Jul/2026:14:39:25 +0300]
      "(?<request>[^"]*)" \s+   # 5) "POST /login HTTP/1.1"  (TEK PARCA!)
      (?<status>\d{3})    \s+   # 6) durum kodu -> tam 3 rakam
      (?<bytes>\d+|-)           # 7) yanit boyutu; "-" olabilir (0 bayt)
      (?:\s+"(?<referer>[^"]*)")?   # 8) referer    -- olmayabilir
      (?:\s+"(?<agent>[^"]*)")?     # 9) user-agent -- olmayabilir
      \s*
    \z}x

    # Apache "common" formati: referer ve user-agent YOK.
    # Bunu buraya koymamizin sebebi mimari sozumuzu somutlastirmak:
    # "yarin baska bir log formati gelirse SADECE parser degisir."
    COMMON = %r{\A
      (?<ip>\S+)          \s+
      (?<ident>\S+)       \s+
      (?<user>\S+)        \s+
      \[(?<time>[^\]]+)\] \s+
      "(?<request>[^"]*)" \s+
      (?<status>\d{3})    \s+
      (?<bytes>\d+|-)
      \s*
    \z}x

    # ------------------------------------------------------------------------
    #  LOAD BALANCER / TERS VEKIL ARKASINDAKI FORMAT
    # ------------------------------------------------------------------------
    #  Sunucun bir LB arkasindaysa nginx'in $remote_addr degeri LB'nin
    #  adresidir -- gercek istemci degil. Bu yuzden yaygin uygulama, log
    #  formatinin sonuna X-Forwarded-For basligini eklemektir:
    #
    #    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
    #                    '$status $body_bytes_sent "$http_referer" '
    #                    '"$http_user_agent" "$http_x_forwarded_for"';
    #
    #  Bu format :combined ile AYNI DEGILDIR -- sonda fazladan bir alan var.
    #  :combined kalibi \z ile bittigi icin boyle bir satiri hic eslestirmez;
    #  yani yanlis format secilirse arac SESSIZCE tamamen korlesir.
    #  (Bunu bizzat olctuk: LB'li ortamda 200 saldiri satiri, 0 kayit.)
    # ------------------------------------------------------------------------
    COMBINED_XFF = %r{\A
      (?<ip>\S+)          \s+
      (?<ident>\S+)       \s+
      (?<user>\S+)        \s+
      \[(?<time>[^\]]+)\] \s+
      "(?<request>[^"]*)" \s+
      (?<status>\d{3})    \s+
      (?<bytes>\d+|-)     \s+
      "(?<referer>[^"]*)" \s+
      "(?<agent>[^"]*)"
      (?:\s+"(?<forwarded_for>[^"]*)")?   # X-Forwarded-For zinciri
      \s*
    \z}x

    IIS = %r{\A
      (?<date>\d{4}-\d{2}-\d{2})  \s+
      (?<time>\d{2}:\d{2}:\d{2})  \s+
      (?<ip>\S+)                  \s+
      (?<method>[A-Z]+)           \s+
      (?<path>\S+)                \s+
      (?<status>\d{3})
      (?:\s+(?<bytes>\d+|-))?
      (?:\s+"(?<agent>[^"]*)"|\s+(?<agent>\S+))?
      \s*
    \z}x

    SSH = %r{\A
      (?<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})  \s+
      (?<hostname>\S+)                                  \s+
      sshd\[\d+\]:                                     \s+
      (?<message>.*?)                                   \s+
      from\s+(?<ip>\S+)
      (?:\s+port\s+(?<port>\d+))?
      (?:\s+\S+)?
      \s*
    \z}x

    FORMATS = {
      combined:     COMBINED,
      combined_xff: COMBINED_XFF,
      common:       COMMON,
      iis:          IIS,
      ssh:          SSH
    }.freeze

    # ========================================================================
    #  IKI ASAMALI AYRISTIRMA -- neden?
    # ------------------------------------------------------------------------
    #  Yukaridaki kalipta istek satirini TEK bir parca olarak aliyoruz:
    #      "(?<request>[^"]*)"      ->  POST /login HTTP/1.1
    #  Sonra bunu ikinci bir regex ile parcaliyoruz.
    #
    #  Neden tek hamlede yapmiyoruz? Cunku istek satirinin ICINDE bosluk
    #  olabilir. Gercek hayattan ornekler:
    #
    #      "GET /search?q=hello world HTTP/1.1"   <- kodlanmamis bosluk
    #      "GET /admin HTTP/1.1 extra"            <- bozuk istek
    #      "\x16\x03\x01"                         <- HTTPS istegini HTTP
    #                                                portuna gonderen tarama
    #
    #  Tek hamlede "bosluklara gore ayir" dersen bu satirlarda yanlis veri
    #  uretirsin. Iki asamada yaparsan, ic kisim bozuksa SADECE ic kismi
    #  isaretlersin -- IP, zaman ve durum kodu saglam kalir.
    #
    #  Bu, ayristiricinin en onemli tasarim ilkesidir:
    #  BOZUK BIR PARCA, SAGLAM PARCALARI GOTURMESIN.
    # ========================================================================
    REQUEST_LINE = %r{\A
      (?<http_method>[A-Z]+)      \s+   # GET, POST, HEAD, PROPFIND...
      (?<path>\S+)                      # /login  veya  /a?b=c
      (?:\s+(?<protocol>HTTP/[\d.]+))?  # HTTP/1.1 -- olmayabilir
    \z}x

    # Ayristirma istatistikleri.
    # attr_reader = "bu ic degiskeni disaridan OKUNABILIR yap" demenin kisa yolu.
    # (attr_writer yazma, attr_accessor ikisi birden olurdu -- burada
    #  disaridan yazilmasini istemiyoruz, o yuzden sadece reader.)
    attr_reader :parsed_count, :failed_count, :failed_samples

    # format: :combined veya :common
    # keep_raw: false yaparsan ham satir Entry icinde tutulmaz (bellek tasarrufu),
    #           ama kanit zincirini kaybedersin. Varsayilan: tut.
    # trusted_proxies: kendi vekillerimizin/LB'lerimizin adres araliklari.
    #   Ornek: ['10.0.0.0/8', '172.16.0.0/12']
    #   Bos birakilirsa XFF zinciri KULLANILMAZ (guvenli varsayilan --
    #   sebebi asagida, resolve_client_ip).
    def initialize(format: :combined, keep_raw: true, trusted_proxies: [])
      @format          = format.to_sym
      @trusted_proxies = ClientIP.build_ranges(trusted_proxies, source: 'parser')
      if @format == :json
        @pattern = :json
      else
        @pattern = FORMATS.fetch(@format) do
          raise ArgumentError, "bilinmeyen format: #{format.inspect} " \
                               "(gecerli: #{FORMATS.keys.join(', ')})"
        end
      end
      @keep_raw       = keep_raw
      @parsed_count   = 0
      @failed_count   = 0
      @failed_samples = []   # ilk birkac basarisiz satiri sakla (teshis icin)
    end

    # ------------------------------------------------------------------------
    #  ANA METOD
    #  Girdi : tek bir log satiri (String)
    #  Cikti : Entry  veya  nil
    # ------------------------------------------------------------------------
    def parse(line)
      # chomp: satir sonundaki \n karakterini atar.
      # File.foreach her satiri satir sonu karakteriyle birlikte verir.
      # chomp: satir sonundaki \n (ve Windows'ta \r\n) karakterini atar.
      line = line.chomp
      return nil if line.empty?

      # ----------------------------------------------------------------------
      #  KODLAMA GUVENLIGI -- "asla cokmezsin" sozunun bedeli
      # ----------------------------------------------------------------------
      #  Bir log satiri GECERSIZ UTF-8 baytlari icerebilir. Bu teorik bir
      #  senaryo degil: saldirganlar sunucuya bilincli olarak ham bayt yigini
      #  gonderir (\xFF\xFE gibi) ve nginx bunu logladigi gibi yazar.
      #
      #  Boyle bir metin uzerinde regex calistirirsan Ruby su hatayi firlatir:
      #      ArgumentError: invalid byte sequence in UTF-8
      #
      #  Ve bu, tum daemon'u durdurur. Yani saldirgan, tek bir bozuk istekle
      #  guvenlik izlemesini KAPATABILIR. (Ironik bir zafiyet: izleme aracinin
      #  kendisi hizmet disi birakma saldirisina acik hale gelir.)
      #
      #  scrub: gecersiz baytlari degistirir. Argumansiz cagrilirsa Unicode
      #  degistirme karakterini (U+FFFD) kullanir; biz '?' veriyoruz ki
      #  loglarda ve alarm mesajlarinda okunabilir kalsin.
      #
      #  Neden once valid_encoding? kontrolu yapiyoruz?
      #  scrub her cagrildiginda YENI bir String uretir. Satirlarin %99.99'u
      #  gecerli olacak; hepsi icin bosa bellek ayirmak, saniyede on binlerce
      #  satir isleyen bir yapida olculebilir bir maliyettir. Once ucuz olan
      #  kontrolu yap, pahali olani sadece gerektiginde yap.
      # ----------------------------------------------------------------------
      line = line.scrub('?') unless line.valid_encoding?

      return parse_json_line(line) if @format == :json || line.start_with?('{')

      # match: kalip uyuyorsa MatchData nesnesi, uymuyorsa nil doner.
      match = @pattern.match(line)

      # Kalip hic uymadi -> bu bizim bekledigimiz formatta bir log degil.
      unless match
        record_failure(line, 'format uyusmadi')
        return nil
      end

      time_str = if match.names.include?('date') && match.names.include?('time')
                   "#{match[:date]} #{match[:time]}"
                 else
                   match[:time]
                 end

      time = parse_time(time_str)
      unless time
        record_failure(line, "zaman ayristirilamadi: #{time_str}")
        return nil
      end

      if match.names.include?('request') && match[:request]
        request = parse_request(match[:request])
        http_method = request[:http_method]
        path        = request[:path]
        protocol    = request[:protocol]
      else
        http_method = match.names.include?('method') ? match[:method] : 'POST'
        path        = if match.names.include?('path')
                        match[:path]
                      elsif @format == :ssh
                        '/ssh/login'
                      else
                        '-'
                      end
        protocol    = match.names.include?('protocol') ? match[:protocol] : 'HTTP/1.1'
      end

      @parsed_count += 1

      remote_addr   = match[:ip]
      forwarded_for = capture(match, :forwarded_for)
      client_ip     = resolve_client_ip(remote_addr, forwarded_for)

      status = if match.names.include?('status')
                 match[:status].to_i
               elsif match.names.include?('message')
                 match[:message].include?('Failed') ? 401 : 200
               else
                 200
               end

      bytes_val = match.names.include?('bytes') ? match[:bytes] : nil
      bytes = parse_bytes(bytes_val)

      referer = capture(match, :referer)
      user_agent = if match.names.include?('agent')
                     capture(match, :agent)
                   elsif match.names.include?('message')
                     'sshd'
                   else
                     nil
                   end

      masked_path    = LogSentry::Masker.mask(path)
      masked_referer = referer ? LogSentry::Masker.mask(referer) : nil
      masked_raw     = @keep_raw ? LogSentry::Masker.mask(line) : nil

      Entry.new(
        ip:            client_ip,
        proxy_ip:      (remote_addr unless client_ip == remote_addr),
        forwarded_for: forwarded_for,
        time:          time,
        http_method:   http_method,
        path:          masked_path,
        protocol:      protocol,
        status:        status,
        bytes:         bytes,
        referer:       masked_referer,
        user_agent:    user_agent,
        raw:           masked_raw
      )
    end

    # Kolaylik metodu: bir dosyanin tamamini ayristirip Entry'leri blogla verir.
    # Adim 1'de ogrendigimiz File.foreach mantigi -- bellek sabit kaliyor.
    #
    # block_given? ile "bana blok verildi mi?" diye soruyoruz.
    # Verilmezse Enumerator dondururuz; boylece .first(5), .lazy, .each_slice
    # gibi Ruby'nin tum akis araclari bedavaya calisir.
    def parse_file(path)
      return enum_for(:parse_file, path) unless block_given?

      File.foreach(path) do |line|
        entry = parse(line)
        yield entry if entry     # yield = "bana verilen bloga bunu gonder"
      end
    end

    # Ayristirma basari orani. Bir ayristiricinin kendi hata oranini bilmesi
    # sart: gercek sistemlerde format sessizce degisir (sunucu guncellenir,
    # log formatina yeni bir alan eklenir) ve sen bunu ancak bu orani
    # izliyorsan fark edersin. Aksi halde alarm uretmeyen, "sorunsuz
    # calisiyor gibi gorunen" ama hicbir sey gormeyen bir arac kalir elinde.
    def success_rate
      total = @parsed_count + @failed_count
      return 100.0 if total.zero?

      (@parsed_count * 100.0 / total).round(2)
    end

    def stats
      {
        parsed:       @parsed_count,
        failed:       @failed_count,
        success_rate: success_rate
      }
    end

    private   # ----- buradan asagisi sinifin ic isleri, disaridan cagrilmaz --

    # ========================================================================
    #  GERCEK ISTEMCI ADRESINI BULMAK
    # ------------------------------------------------------------------------
    #  Bu, gorunuste basit ama YANLIS YAPILMASI cok kolay bir istir; ve
    #  yanlis yapildiginda tum IP bazli tespit ise yaramaz hale gelir.
    #
    #  NEDEN "XFF'in ilk adresini al" YANLIS?
    #  Cunku X-Forwarded-For'u ISTEMCI de gonderebilir. Saldirgan istegine
    #      X-Forwarded-For: 8.8.8.8
    #  ekler; LB kendi gordugu adresi bunun SONUNA ekler ve zincir soyle olur:
    #      8.8.8.8, 45.155.205.233
    #  Ilk adresi alirsan saldirganin UYDURDUGU adresi engellersin --
    #  yani saldirgan, istedigi masum IP'yi kara listeye attirabilir.
    #  Buna "XFF spoofing" denir.
    #
    #  DOGRU YONTEM: zinciri SAGDAN SOLA yuru.
    #  En sagdaki adres, bize en yakin olan ve GUVENDIGIMIZ vekilin gordugu
    #  adrestir. Kendi vekillerimizi (trusted_proxies) atlaya atlaya sola
    #  git; guvenmedigin ILK adres gercek istemcidir. Ondan solu saldirganin
    #  uydurabilecegi bolgedir, dokunma.
    #
    #      [8.8.8.8 (uydurma), 45.155.205.233 (gercek), 10.0.0.7 (bizim LB)]
    #                                ^ dogru cevap        ^ guvenilir, atla
    #
    #  GUVENLI VARSAYILAN: trusted_proxies bos ise XFF'e HIC BAKMIYORUZ.
    #  Cunku kimin vekil oldugunu bilmeden zincire guvenmek, saldirganin
    #  kimligini secmesine izin vermektir. Yapilandirilmamis bir sistemde
    #  "yanlis IP'yi engellemek" yerine "vekilin IP'sini gormek" daha az
    #  zararlidir.
    # ========================================================================
    #  NOT: mantigin kendisi lib/log_sentry/client_ip.rb icine tasindi.
    #  Sebep: web arayuzunun hiz siniri da ayni soruyu soruyor ("bu istek
    #  gercekten kimden geldi?") ve orada Rack'in `request.ip`'i
    #  kullaniliyordu -- o ise X-Forwarded-For'a KIM YAZDIGINA bakmadan
    #  guveniyor. Iki farkli cevap veren iki kod yolu birakmak yerine tek
    #  kaynak birakildi.
    def resolve_client_ip(remote_addr, forwarded_for)
      ClientIP.resolve(remote_addr, forwarded_for, @trusted_proxies)
    end

    def trusted_proxy?(address)
      ClientIP.trusted?(address, @trusted_proxies)
    end

    # Nginx zaman formati: 29/Jul/2026:14:39:25 +0300
    #
    # strptime = "string parse time". Format kodlari:
    #   %d gun(01-31)  %b ay kisaltmasi(Jul)  %Y yil(2026)
    #   %H saat  %M dakika  %S saniye  %z saat dilimi(+0300)
    #
    # Saat dilimini (%z) ayristirmak SART. Loglarin farkli sunuculardan
    # gelebilecegi bir dunyada saat dilimini yok saymak, olaylari yanlis
    # siraya dizmene ve saldirilari kacirmana yol acar.
    TIME_FORMAT = '%d/%b/%Y:%H:%M:%S %z'

    def parse_time(str)
      begin
        return Time.strptime(str, TIME_FORMAT)
      rescue ArgumentError, TypeError
      end

      begin
        Time.parse(str)
      rescue StandardError
        nil
      end
    end

    # "POST /login HTTP/1.1"  ->  { http_method: "POST", path: "/login", ... }
    def parse_request(request)
      match = REQUEST_LINE.match(request.to_s)

      if match
        {
          http_method: match[:http_method],
          path:        match[:path],
          protocol:    match[:protocol]
        }
      else
        # Bozuk istek satiri. ATMIYORUZ, ISARETLIYORUZ.
        #
        # Neden? Cunku bir sunucuya anlamsiz bayt yigini gondermek basli
        # basina supheli bir davranistir. Bunu atarsak tam olarak yakalamak
        # istedigimiz tarama davranisina KOR kalmis oluruz.
        #
        # http_method icin nil degil "-" kullaniyoruz: tip tutarliligi.
        # Kurallar entry.path.start_with?(...) gibi cagrilar yapacak; alanlar
        # bazen String bazen nil olursa her kuralda nil kontrolu yapmak
        # zorunda kalirsin. Alanin tipini SABIT tutmak, cagiran tarafin
        # hayatini kurtarir.
        {
          http_method: '-',
          path:        request.to_s,   # ham hali dursun, kanit olarak
          protocol:    nil
        }
      end
    end

    # Nginx, govdesi olmayan yanitlar icin boyut alanina "-" yazar.
    def parse_bytes(str)
      str == '-' ? 0 : str.to_i
    end

    # Adlandirilmis grup kalipta yoksa (ornegin :common formatinda referer
    # tanimli degil) MatchData'ya sormak IndexError firlatir. Bu yuzden
    # once grubun var olup olmadigina bakiyoruz.
    def capture(match, name)
      return nil unless match.names.include?(name.to_s)

      match[name]
    end

    def record_failure(line, reason)
      @failed_count += 1
      return if @failed_samples.size >= 10

      @failed_samples << { line: line, reason: reason }
    end

    def parse_json_line(line)
      hash = JSON.parse(line)
      return record_failure(line, 'gecersiz JSON yapisi') unless hash.is_a?(Hash)

      remote_addr   = hash['ip'] || hash['remote_addr'] || hash['client_ip'] || hash.dig('client', 'ip')
      forwarded_for = hash['forwarded_for'] || hash['x_forwarded_for'] || hash['http_x_forwarded_for']
      client_ip     = resolve_client_ip(remote_addr, forwarded_for)

      time_val = hash['time'] || hash['timestamp'] || hash['time_local'] || hash['@timestamp']
      time     = parse_json_time(time_val)
      unless client_ip && time
        record_failure(line, 'JSON icinde IP veya zaman eksik')
        return nil
      end

      req = hash['request']
      if req
        parsed_req  = parse_request(req)
        http_method = parsed_req[:http_method]
        path        = parsed_req[:path]
        protocol    = parsed_req[:protocol]
      else
        http_method = hash['method'] || hash['http_method'] || '-'
        path        = hash['path'] || hash['uri'] || '-'
        protocol    = hash['protocol']
      end

      status_val = hash['status'] || hash['status_code']
      if status_val.nil?
        record_failure(line, 'JSON icinde status eksik')
        return nil
      end
      status = status_val.to_i

      bytes   = (hash['bytes'] || hash['body_bytes_sent'] || hash['size'] || 0).to_i
      referer = hash['referer'] || hash['http_referer']
      agent   = hash['user_agent'] || hash['http_user_agent'] || hash['agent']

      @parsed_count += 1

      Entry.new(
        ip:            client_ip,
        proxy_ip:      (remote_addr unless client_ip == remote_addr),
        forwarded_for: forwarded_for,
        time:          time,
        http_method:   http_method,
        path:          path,
        protocol:      protocol,
        status:        status,
        bytes:         bytes,
        referer:       referer,
        user_agent:    agent,
        raw:           @keep_raw ? line : nil
      )
    rescue JSON::ParserError
      record_failure(line, 'gecersiz JSON formati')
      nil
    end

    def parse_json_time(val)
      return nil if val.nil?
      return val if val.is_a?(Time)
      return Time.at(val) if val.is_a?(Numeric)

      str = val.to_s.strip
      return nil if str.empty?

      Time.iso8601(str)
    rescue ArgumentError
      parse_time(str)
    end
  end
end
