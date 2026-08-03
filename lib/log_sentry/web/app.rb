# frozen_string_literal: true

# ============================================================================
#  ADIM 7 -- Web arayuzu (Sinatra)
# ----------------------------------------------------------------------------
#  Bu arayuzun ASIL isi "grafik gostermek" degil. Asil isi su soruyu
#  cevaplamak:
#
#      "Bu uyari gercekten saldiri mi, yanlis alarm mi?"
#
#  Cunku bu soruya cevap veremiyorsan alarm eyleme gecirilemez, eyleme
#  gecirilemeyen alarm da gurultudur. Bu yuzden en onemli sayfa dashboard
#  degil, /alerts/:id -- alarmi DOGURAN ham log satirlarini gosteren sayfa.
#
#  ONEMLI GUVENLIK NOTU (bolum: XSS)
#  Bu arayuzun gosterdigi verinin BUYUK KISMI SALDIRGAN TARAFINDAN YAZILMIS.
#  Saldirgan sunucuya istek atarak log dosyasina istedigi metni sokabilir --
#  ve o metin bizim panelimizde gorunur. Ayrintisi asagida.
# ============================================================================

require 'sinatra/base'
require 'json'
require 'erb'
require 'rack'
require_relative '../store'
require_relative '../archiver'
require_relative '../tailer'

module LogSentry
  module Web
    class App < Sinatra::Base
      set :root,          File.dirname(__FILE__)
      set :views,         File.join(File.dirname(__FILE__), 'views')
      set :public_folder, File.join(File.dirname(__FILE__), 'public')

      # Disardan enjekte edilen bagimliliklar (bin/logsentry-web dolduruyor)
      set :store,      nil
      set :archiver,   nil
      set :alert_file, nil
      set :show_exceptions, false
      set :raise_errors,    false
      set :auth_enabled, false
      set :auth_user,    ENV['LOGSENTRY_WEB_USER'] || 'admin'
      set :auth_pass,    ENV['LOGSENTRY_WEB_PASS']
      set :rate_limit_enabled, false
      set :rate_limit_max, 60
      set :rate_limit_window, 60

      RATE_LIMIT_STORE = {}
      RATE_LIMIT_MUTEX = Mutex.new

      def self.check_rate_limit(ip, max, window)
        now = Time.now.to_i
        RATE_LIMIT_MUTEX.synchronize do
          history = (RATE_LIMIT_STORE[ip] ||= [])
          history.reject! { |t| t < (now - window) }
          return false if history.size >= max

          history << now
          true
        end
      end

      before do
        if settings.rate_limit_enabled
          client_ip = request.ip
          unless self.class.check_rate_limit(client_ip, settings.rate_limit_max, settings.rate_limit_window)
            halt 429, { 'Content-Type' => 'text/plain', 'Retry-After' => settings.rate_limit_window.to_s },
                 "429 -- Cok Fazla Istek (Rate Limit Exceeded)\n"
          end
        end

        if settings.auth_enabled || (settings.auth_pass && !settings.auth_pass.to_s.empty?)
          auth = Rack::Auth::Basic::Request.new(request.env)
          unless auth.provided? && auth.basic? && auth.credentials &&
                 auth.credentials == [settings.auth_user, settings.auth_pass]
            headers['WWW-Authenticate'] = 'Basic realm="LogSentry Restricted Area"'
            halt 401, { 'Content-Type' => 'text/plain' }, "401 -- Yetkisiz Erisim (Authentication Required)\n"
          end
        end

        if settings.read_only && !%w[GET HEAD].include?(request.request_method)
          halt 405, { 'Content-Type' => 'text/plain' },
               "405 -- bu arayuz salt okunurdur\n"
        end
      end

      helpers do
        # ====================================================================
        #  h() -- XSS'e karsi tek savunma
        # --------------------------------------------------------------------
        #  SORUN: log verisinin buyuk kismini SALDIRGAN yaziyor.
        #
        #  Saldirgan izlenen sunucuya sunu ister:
        #      GET /<script>alert(document.cookie)</script>
        #
        #  Nginx bunu access.log'a oldugu gibi yazar. Parser'imiz ayristirir,
        #  veritabanina kaydeder, ve bu panel path alanini ekrana basar.
        #  Escape etmezsek tarayici o metni KOD olarak calistirir.
        #
        #  Sonuc: saldirgan, izlenen sunucuya tek bir istek atarak GUVENLIK
        #  PANELINDE kod calistirmis olur. Buna "depolanmis XSS" denir ve
        #  bu senaryoda ozellikle sinsidir: saldirgan panele hic erismiyor,
        #  sadece izlenen sunucuya istek atiyor.
        #
        #  escape_html su donusumleri yapar:
        #      <  ->  &lt;      >  ->  &gt;     &  ->  &amp;
        #      "  ->  &quot;    '  ->  &#39;
        #  Boylece tarayici metni METIN olarak gorur, kod olarak degil.
        #
        #  KURAL: sablonlarda <%= %> ICINDE ASLA cig veri yok, her zaman h().
        # ====================================================================
        def h(text)
          Rack::Utils.escape_html(text.to_s)
        end

        def store
          settings.store
        end

        def severity_class(severity)
          %w[critical high medium low].include?(severity.to_s) ? severity.to_s : 'low'
        end

        def time_fmt(time)
          time.strftime('%Y-%m-%d %H:%M:%S')
        end

        def relative_time(time)
          seconds = (Time.now - time).round
          case seconds
          when (..-1)     then 'gelecekte'
          when 0..59      then "#{seconds} sn once"
          when 60..3599   then "#{seconds / 60} dk once"
          when 3600..86_399 then "#{seconds / 3600} sa once"
          else "#{seconds / 86_400} gun once"
          end
        end

        def number(value)
          # 84000 -> "84.000"  (Turkce binlik ayirici)
          value.to_i.to_s.reverse.scan(/\d{1,3}/).join('.').reverse
        end

        # Sayfalama baglantisi uretirken mevcut filtreleri koruyor.
        # Rack::Utils.build_query, degerleri URL-kodlar -- yani filtre
        # degerindeki & veya = karakterleri baglantiyi bozmaz.
        def page_url(path, overrides = {})
          merged = request.params.merge(overrides.transform_keys(&:to_s))
          merged.reject! { |_k, v| v.nil? || v.to_s.empty? }
          query = Rack::Utils.build_query(merged)
          query.empty? ? path : "#{path}?#{query}"
        end

        # Kullanicidan gelen filtreleri temizle.
        #
        # Bos String'i nil'e ceviriyoruz: "?rule=" seklinde gelen bos filtre
        # SQL'e "rule = ''" olarak gitmesin, hic gitmesin.
        def filter(name)
          value = params[name].to_s.strip
          value.empty? ? nil : value
        end

        def int_param(name, default, max: 1000)
          value = params[name].to_s
          return default unless value.match?(/\A\d+\z/)

          # Ust sinir: kullanici ?limit=99999999 yazarak sunucuyu
          # yormasin. Kullanicidan gelen her sayiya sinir koymak, kod
          # kadar onemli bir aliskanliktir.
          [value.to_i, max].min
        end
      end

      # ======================================================================
      #  DASHBOARD
      # ======================================================================
      get '/' do
        halt 503, erb(:no_store) if store.nil?

        @hours   = int_param('hours', 24, max: 24 * 30)
        @now     = Time.now
        @hourly  = store.hourly_counts(hours: @hours, now: @now)
        @top_ips = store.top_ips(limit: 8, hours: @hours, now: @now)
        @by_rule = store.alert_counts_by_rule(hours: @hours, now: @now)
        @recent  = store.alerts(limit: 10)
        @totals  = store.stats

        erb :dashboard
      end

      # ======================================================================
      #  ALARM LISTESI
      # ======================================================================
      get '/alerts' do
        halt 503, erb(:no_store) if store.nil?

        @page  = [int_param('page', 1), 1].max
        @limit = settings.page_size
        @filters = {
          rule:     filter('rule'),
          severity: filter('severity'),
          ip:       filter('ip')
        }

        # Filtre degerleri SQL metnine hic girmiyor -- Store parametreli
        # sorgu kullaniyor (Adim 6). Yani asagidaki :ip degeri
        # "' OR 1=1 --" olsa bile sadece aranan bir metin olarak kalir.
        @total  = store.count_alerts(**@filters)
        @alerts = store.alerts(**@filters, limit: @limit,
                                           offset: (@page - 1) * @limit)
        @pages = [(@total / @limit.to_f).ceil, 1].max

        erb :alerts
      end

      # ======================================================================
      #  TEK ALARM -- bu arayuzun en onemli sayfasi
      # ----------------------------------------------------------------------
      #  "Gercekten saldiri mi, yanlis alarm mi?" sorusu ancak KANIT gorerek
      #  cevaplanir. Bu sayfa uc sey gosteriyor:
      #    1) alarmi doguran ham log satirlari (kanit)
      #    2) kural neden tetiklendi (olculen deger / esik / pencere)
      #    3) ayni IP'nin cevresindeki diger istekleri (baglam)
      # ======================================================================
      get '/alerts/:id' do
        halt 503, erb(:no_store) if store.nil?

        # to_i ile sayiya cevriliyor; harf iceren bir id 0 olur ve
        # bulunamaz -> 404. Parametre yine de parametreli sorguya gidiyor.
        @alert = store.alert(params[:id].to_i)
        halt 404, erb(:not_found) if @alert.nil?

        # Baglam: alarmin zamani cevresinde ayni IP ne yapti?
        window = @alert[:window].to_i
        @context = store.events(
          ip:   @alert[:ip],
          from: @alert[:time] - window - 60,
          to:   @alert[:time] + 60,
          limit: 100
        )

        # Ayni IP'nin diger alarmlari
        @other_alerts = store.alerts(ip: @alert[:ip], limit: 20)
                             .reject { |a| a[:id] == @alert[:id] }

        erb :alert
      end

      # ======================================================================
      #  ARSIV BUTUNLUGU
      # ======================================================================
      get '/integrity' do
        halt 503, erb(:no_archiver) if settings.archiver.nil?

        @result = settings.archiver.verify
        @stats  = settings.archiver.stats
        @deletions = settings.archiver.deletions.last(20)

        # Butunluk bozulmussa HTTP durum kodu da bunu soylemeli.
        # Boylece "curl -f" ya da bir izleme aracı sayfayi ayristirmadan
        # sorunu anlar. Insan icin sayfa, makine icin durum kodu.
        status(@result[:ok] ? 200 : 500)
        erb :integrity
      end

      # ======================================================================
      #  SSE -- CANLI AKIS
      # ----------------------------------------------------------------------
      #  Klasik web'de tarayici sorar, sunucu cevap verir, baglanti kapanir.
      #  Canli izlemede bunu tersine ceviriyoruz: baglanti ACIK KALIR ve
      #  sunucu haber oldukca yazar.
      #
      #  Neden WebSocket degil? Cunku veri TEK YONLU akiyor (sunucu ->
      #  tarayici). SSE tam bu is icin var: sade bir HTTP yaniti, ozel
      #  protokol yok, tarayici koptugunda kendi kendine yeniden baglanir.
      #
      #  SSE bicimi son derece basit -- her mesaj su sekilde:
      #      data: {"rule":"brute_force",...}\n\n
      #  Iki satir sonu mesajin bittigini soyler.
      #
      #  VE ISIN GUZEL TARAFI: bu akis icin Adim 3'te yazdigimiz Tailer'i
      #  YENIDEN KULLANIYORUZ -- sadece access.log yerine alerts.jsonl'i
      #  izliyor. Dogru mimarinin odulu budur: bileseni bir kez yaz,
      #  ummadigin yerde bedavaya kullan.
      # ======================================================================
      #  Tek bir SSE cercevesini uretir.
      #
      #  Neden ayri bir metod? Cunku /stream rotasi baglantiyi ACIK TUTUYOR --
      #  yani onu normal bir istek gibi test etmek mumkun degil, test sonsuza
      #  kadar bekler. (Bunu bizzat yasadik: test paketi 10 dakika takildi.)
      #
      #  Bicimlendirme mantigini disari alinca hem test edilebilir oluyor hem
      #  de niyeti belgelenmis oluyor. Akisin kendisi canli sunucuyla
      #  dogrulaniyor.
      def self.sse_frame(record)
        # JSON.generate ile YENIDEN uretiyoruz: gelen satirda satir sonu
        # olursa SSE bicimi bozulur (bos satir "mesaj bitti" demektir).
        "data: #{JSON.generate(record)}\n\n"
      end

      get '/stream' do
        halt 503, "alert_file yapilandirilmamis\n" if settings.alert_file.nil?

        content_type 'text/event-stream'
        # Ara sunucularin (nginx) tamponlamasini engelle -- yoksa mesajlar
        # gruplanip gecikmeli ulasir ve "canli" olma ozelligi kaybolur.
        headers 'Cache-Control' => 'no-cache', 'X-Accel-Buffering' => 'no'

        stream(:keep_open) do |out|
          tailer = Tailer.new(settings.alert_file, start: :end)
          queue  = Queue.new

          # ------------------------------------------------------------------
          #  NEDEN AYRI BIR THREAD + KUYRUK?
          # ------------------------------------------------------------------
          #  Ilk surumde Tailer dogrudan bu blogun icinde donuyordu. Canli
          #  video kaydi sirasinda GERCEK BIR KUSUR ortaya cikti: tarayici
          #  sayfalar arasinda gezindikce sunucu yanit vermemeye basladi
          #  ("renderer unresponsive", 30 saniyelik zaman asimlari).
          #
          #  SEBEP: Puma sinirli sayida thread ile calisir (varsayilan 5).
          #  Her SSE baglantisi bir thread'i tutar. Tarayici sekmeyi
          #  kapattiginda ya da baska sayfaya gectiginde baglanti koparir --
          #  ama sunucu bunu ancak YAZMAYA CALISTIGINDA anlar. Yeni alarm
          #  gelmedigi surece hic yazmaya calismaz, yani olu baglanti
          #  thread'i tutmaya DEVAM eder. Bes gezinti = bes thread = sunucu
          #  yanit veremez hale gelir.
          #
          #  COZUM: KALP ATISI (heartbeat). Yeni veri olmasa bile belirli
          #  aralikla bir SSE yorumu gonderiyoruz. Yazma denemesi, kopmus
          #  baglantiyi ANINDA ortaya cikarir ve thread serbest kalir.
          #
          #  Ikinci faydasi: ara sunucular (nginx, yuk dengeleyici) uzun
          #  sure sessiz kalan baglantilari keser. Kalp atisi bunu da onler.
          #
          #  ": " ile baslayan satir SSE'de YORUMDUR -- tarayici onu veri
          #  olarak islemez, sadece baglantinin canli oldugunu anlar.
          # ------------------------------------------------------------------
          reader = Thread.new do
            tailer.each_line { |line| queue << line }
          rescue StandardError
            nil
          end

          # Baglanti koptugunda temizlik. Bu OLMADAN her kapatilan sekme
          # arkada sonsuza kadar donen bir dongu birakir -- "kaynak sizintisi".
          cleanup = lambda do
            tailer.stop
            reader.kill if reader.alive?
          end
          out.callback(&cleanup)
          out.errback(&cleanup)

          # Baglantinin kuruldugunu hemen bildir (tarayici "bagli" yazsin)
          out << "event: hello\ndata: {\"ok\":true}\n\n"

          last_beat = Time.now

          begin
            loop do
              # pop(true) = bloke etmeyen okuma; kuyruk bossa ThreadError.
              # (Queue#pop(timeout:) Ruby 3.2+ gerektiriyor; WSL'de 3.0 var,
              #  o yuzden elle yokluyoruz.)
              line = begin
                queue.pop(true)
              rescue ThreadError
                nil
              end

              if line
                record = begin
                  JSON.parse(line)
                rescue JSON::ParserError
                  nil
                end
                out << self.class.sse_frame(record) if record
                next
              end

              if Time.now - last_beat >= HEARTBEAT_INTERVAL
                out << ": ping\n\n"
                last_beat = Time.now
              end

              # Tailer'in kendi dongusuyle ayni aralik. Bu OLMADAN bir CPU
              # cekirdegini bosa doldururuz (Adim 3'teki "busy wait" dersi).
              sleep 0.2
            end
          rescue IOError, Errno::EPIPE, Errno::ECONNRESET
            # Tarayici koptu -- normal bir durum, hata degil.
            nil
          ensure
            cleanup.call
            out.close
          end
        end
      end

      # ======================================================================
      #  SAGLIK KONTROLU -- izleme araclari icin
      # ======================================================================
      get '/health' do
        content_type :json
        payload = {
          ok:      true,
          version: LogSentry::VERSION,
          store:   store ? store.stats.slice(:events, :alerts, :size_bytes) : nil
        }
        JSON.generate(payload)
      end

      not_found do
        erb :not_found
      end

      error do
        # Yigin izi kullaniciya DEGIL, sunucu loguna.
        e = env['sinatra.error']
        warn "[web] HATA: #{e.class}: #{e.message}"
        e.backtrace&.first(5)&.each { |l| warn "  #{l}" }
        status 500
        erb :error
      end
    end
  end
end
