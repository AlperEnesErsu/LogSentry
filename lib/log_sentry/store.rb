# frozen_string_literal: true

# ============================================================================
#  ADIM 6a -- Store: SQLite depolama katmani (SICAK katman)
# ----------------------------------------------------------------------------
#  Neden veritabani? Cunku Adim 7'de su soruyu soracagiz:
#      "Dun 14:00-15:00 arasi bu IP ne yapti?"
#  Duz metin dosyasinda bu soruyu sormanin makul bir yolu yok. grep ile
#  yaparsin ama 2 GB'lik dosyada her sorgu dakikalar surer ve filtreleme,
#  siralama, sayfalama yapamazsin.
#
#  ONEMLI: bu SICAK katmandir, ARSIV DEGILDIR.
#    * Sicak katman (bu dosya) : son 90 gun, hizli sorgu, silinebilir
#    * Soguk katman (archiver) : yasal sure, ham log, degistirilemez
#  Ham logu asla veritabanina ezdirmiyoruz -- mahkemede "biz bunu
#  ayristirdik, isledik, kendi semamiza soktuk" demek istemezsin.
# ============================================================================

require 'sqlite3'
require 'json'
require 'fileutils'

module LogSentry
  class Store
    SCHEMA_VERSION = 1

    # SQLite'in "diskte dosya yok, her sey RAM'de" ozel yolu
    MEMORY = ':memory:'

    # Kac kayit birikince diske yazalim?
    #
    # BU SAYI PROJENIN EN BUYUK PERFORMANS KARARI. Sebebi asagida (bolum:
    # record_event / flush). Ozetle: her satiri tek tek yazmak, her satirda
    # bir disk senkronizasyonu demektir ve SQLite'i saniyede birkac yuz
    # kayda dusurur. Toplu yazmak bunu yuz binlere cikarir.
    DEFAULT_BATCH_SIZE = 500

    attr_reader :path, :events_written, :alerts_written, :batches

    def initialize(path:, store_all_events: true, batch_size: DEFAULT_BATCH_SIZE)
      # ':memory:' SQLite'in ozel bir yoludur: diskte dosya yok, veritabani
      # tamamen RAM'de yasar. Testlerde vazgecilmez (temizlik gerekmez,
      # milisaniyeler icinde kosar).
      #
      # DIKKAT: bunu File.expand_path'ten GECIRMEMEK gerekiyor -- yoksa
      # ':memory:' bir dosya adi sanilip "C:/.../:memory:" haline gelir ve
      # SQLite "unable to open database file" der. Bu hatayi testler yakaladi.
      @path             = path.to_s == MEMORY ? MEMORY : File.expand_path(path)
      @store_all_events = store_all_events
      @batch_size       = batch_size
      @buffer           = []
      @events_written   = 0
      @alerts_written   = 0
      @batches          = 0

      FileUtils.mkdir_p(File.dirname(@path)) unless @path == MEMORY

      @db = SQLite3::Database.new(@path)
      configure_database
      create_schema
    end

    # ========================================================================
    #  VERITABANI AYARLARI -- iki process'in ayni dosyayi paylasmasi
    # ========================================================================
    def configure_database
      # ----------------------------------------------------------------------
      #  WAL (Write-Ahead Logging) -- mimarimizin calisabilmesi icin SART
      # ----------------------------------------------------------------------
      #  Mimaride uc ayri process var: daemon YAZAR, web OKUR, arsivci TEMIZLER.
      #
      #  SQLite'in varsayilan kipinde (journal_mode=DELETE) bir yazma islemi
      #  TUM veritabanini kilitler. Yani daemon yazarken web arayuzu sorgu
      #  atarsa "SQLITE_BUSY: database is locked" hatasi alir. Kullanicinin
      #  gorecegi sey: rastgele bozulan bir panel.
      #
      #  WAL kipinde yazmalar ayri bir dosyaya (-wal) eklenir ve
      #  OKUYUCULAR YAZICIYI ENGELLEMEZ, yazici da okuyuculari engellemez.
      #  Tek kisit: ayni anda tek yazici olabilir -- bizde zaten tek yazici var.
      #
      #  WAL kalicidir: bir kez ayarlandiginda veritabani dosyasinda saklanir.
      # ----------------------------------------------------------------------
      @db.execute('PRAGMA journal_mode = WAL')

      # ----------------------------------------------------------------------
      #  synchronous = NORMAL
      # ----------------------------------------------------------------------
      #  FULL (varsayilan) : her islemde diske fsync -> en guvenli, en yavas
      #  NORMAL            : WAL ile birlikte, checkpoint aninda fsync
      #  OFF               : hic fsync yok -> hizli ama elektrik kesilirse
      #                      veritabani BOZULABILIR
      #
      #  NORMAL'i seciyoruz cunku bu SICAK katman: buradaki veri kaybi
      #  telafi edilebilir (ham log arsivde duruyor). Ayni tercihi ARSIV
      #  icin yapmazdik.
      #
      #  Guvenlik/performans takaslarini yerine gore vermek gerekir, kural
      #  olarak degil. FileNotifier'da (adim 5) tam tersini yapmistik:
      #  orada sync = true dedik, cunku o dosya kanit dosyasiydi.
      # ----------------------------------------------------------------------
      @db.execute('PRAGMA synchronous = NORMAL')

      # Kilit varsa hemen hata vermek yerine 5 saniye bekle.
      # Uc process ayni dosyayi paylasiyor; kisa suren cakismalar normaldir.
      @db.busy_timeout = 5_000

      # Yabanci anahtar kontrolleri (ilerisi icin; SQLite'ta varsayilan KAPALI)
      @db.execute('PRAGMA foreign_keys = ON')
    end

    # ========================================================================
    #  SEMA
    # ========================================================================
    def create_schema
      # ----------------------------------------------------------------------
      #  ZAMANI NEDEN INTEGER OLARAK TUTUYORUZ?
      #
      #  ts INTEGER = Unix zaman damgasi (1970'ten beri gecen saniye).
      #
      #  Metin olarak ("2026-07-29 14:39:25 +0300") tutmak cazip gorunur ama:
      #    * karsilastirma ve siralama metin karsilastirmasi olur -- farkli
      #      saat dilimlerinden gelen kayitlar YANLIS siralanir
      #    * indeks daha buyuk ve daha yavas olur
      #    * "son 24 saat" gibi araligi hesaplamak zorlasir
      #
      #  Saat dilimi bilgisini kaybetmemek icin alarmlarda ayrica time_iso
      #  alaninda ISO-8601 metnini de tutuyoruz. Yani: SORGULAMA icin sayi,
      #  GOSTERIM icin metin.
      # ----------------------------------------------------------------------
      @db.execute_batch(<<~SQL)
        CREATE TABLE IF NOT EXISTS events (
          id         INTEGER PRIMARY KEY AUTOINCREMENT,
          ts         INTEGER NOT NULL,
          ip         TEXT    NOT NULL,
          method     TEXT,
          path       TEXT,
          status     INTEGER,
          bytes      INTEGER,
          user_agent TEXT
        );

        CREATE TABLE IF NOT EXISTS alerts (
          id         INTEGER PRIMARY KEY AUTOINCREMENT,
          ts         INTEGER NOT NULL,
          time_iso   TEXT    NOT NULL,
          rule       TEXT    NOT NULL,
          severity   TEXT    NOT NULL,
          ip         TEXT    NOT NULL,
          message    TEXT,
          count      INTEGER,
          threshold  INTEGER,
          window     INTEGER,
          details    TEXT,
          evidence   TEXT
        );

        CREATE TABLE IF NOT EXISTS meta (
          key   TEXT PRIMARY KEY,
          value TEXT
        );
      SQL

      # ----------------------------------------------------------------------
      #  INDEKSLER
      # ----------------------------------------------------------------------
      #  Indeks, sozlugun arkasindaki dizin gibidir: aramayi hizlandirir ama
      #  her yazmada guncellenmesi gerekir. Yani OKUMA hizlanir, YAZMA yavaslar.
      #  Bu yuzden "her kolona indeks atalim" yanlistir.
      #
      #  BILESIK INDEKSTE KOLON SIRASI ONEMLIDIR:
      #    (ip, ts) indeksi  ->  "bu IP'nin son 1 saati" sorgusunda kullanilir
      #    (ts, ip) olsaydi  ->  ayni sorguda ise yaramazdi
      #  Kural: once ESITLIK ile filtrelenen kolon, sonra ARALIK ile filtrelenen.
      # ----------------------------------------------------------------------
      @db.execute_batch(<<~SQL)
        CREATE INDEX IF NOT EXISTS idx_events_ts        ON events(ts);
        CREATE INDEX IF NOT EXISTS idx_events_ip_ts     ON events(ip, ts);
        CREATE INDEX IF NOT EXISTS idx_events_status_ts ON events(status, ts);
        CREATE INDEX IF NOT EXISTS idx_alerts_ts        ON alerts(ts);
        CREATE INDEX IF NOT EXISTS idx_alerts_ip_ts     ON alerts(ip, ts);
        CREATE INDEX IF NOT EXISTS idx_alerts_rule_ts   ON alerts(rule, ts);
      SQL

      @db.execute('INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)',
                  ['schema_version', SCHEMA_VERSION.to_s])
    end

    # ========================================================================
    #  YAZMA
    # ========================================================================

    # ------------------------------------------------------------------------
    #  OLAY KAYDI -- tamponlanir
    # ------------------------------------------------------------------------
    #  Her log satirini tek tek INSERT etmek neden felaket?
    #
    #  SQLite'ta her INSERT kendi basina bir "islem" (transaction) olur ve her
    #  islem sonunda diske yazma garantisi (fsync) istenir. Disk fsync'i
    #  milisaniyeler surer. Sonuc: saniyede birkac yuz kayit.
    #
    #  Bizim akisimiz saniyede on binlerce satir isleyebiliyor (adim 4'te
    #  84.000 kayit/saniye olctuk). Yani veritabani, boru hattinin tamamini
    #  yavaslatan tikaniklik noktasi olurdu.
    #
    #  Cozum: kayitlari tamponda biriktir, TEK BIR ISLEM icinde topluca yaz.
    #  500 kayit = 1 fsync yerine 500 fsync. Farki step6_store.rb olcuyor.
    # ------------------------------------------------------------------------
    def record_event(entry)
      return unless @store_all_events

      @buffer << [
        entry.time.to_i, entry.ip, entry.http_method, entry.path,
        entry.status, entry.bytes, entry.user_agent
      ]

      flush if @buffer.size >= @batch_size
    end

    def flush
      return 0 if @buffer.empty?

      rows = @buffer
      @buffer = []

      # db.transaction: blok basarili biterse COMMIT, hata olursa ROLLBACK.
      # Yani ya TUM parti yazilir ya HICBIRI -- yarim yazilmis parti olmaz.
      @db.transaction do
        stmt = @db.prepare(<<~SQL)
          INSERT INTO events (ts, ip, method, path, status, bytes, user_agent)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        SQL
        begin
          # HAZIRLANMIS IFADE (prepared statement) yeniden kullanimi:
          # SQL metnini bir kez ayristirip 500 kez calistiriyoruz.
          # Her seferinde db.execute cagirmak, ayni SQL'i 500 kez
          # ayristirmak demektir.
          rows.each { |row| stmt.execute(row) }
        ensure
          stmt.close
        end
      end

      @events_written += rows.size
      @batches += 1
      rows.size
    end

    # ------------------------------------------------------------------------
    #  ALARM KAYDI -- ANINDA yazilir, tamponlanmaz
    # ------------------------------------------------------------------------
    #  Neden farkli davraniyoruz? Cunku alarmlar:
    #    * cok seyrek (sogutma sayesinde) -> performans sorunu yaratmaz
    #    * cok kiymetli -> tamponda bekleyen bir alarm, cokmede kaybolur
    #  Adim 5'te FileNotifier icin verdigimiz kararin aynisi.
    # ------------------------------------------------------------------------
    def record_alert(alert)
      @db.execute(<<~SQL, [
        INSERT INTO alerts
          (ts, time_iso, rule, severity, ip, message, count, threshold, window,
           details, evidence)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      SQL
                    alert.time.to_i,
                    alert.time.iso8601,
                    alert.rule.to_s,
                    alert.severity.to_s,
                    alert.ip,
                    alert.message,
                    alert.count,
                    alert.threshold,
                    alert.window,
                    JSON.generate(alert.details || {}),
                    JSON.generate(alert.evidence || [])
                  ])
      @alerts_written += 1
      @db.last_insert_row_id
    end

    # ========================================================================
    #  OKUMA -- hepsi PARAMETRELI sorgu
    # ========================================================================
    #  Asagidaki her sorguda deger, SQL metnine YAPISTIRILMIYOR; ? ile
    #  yerlestirilip ayrica gonderiliyor.
    #
    #  YANLIS:  "SELECT * FROM alerts WHERE ip = '#{ip}'"
    #  DOGRU :  "SELECT * FROM alerts WHERE ip = ?", [ip]
    #
    #  Yanlis olanda kullanici ip alanina  ' OR 1=1 --  yazarsa tum kayitlari
    #  goruruz;  '; DROP TABLE alerts; --  yazarsa tablo silinir.
    #
    #  Parametreli sorguda veritabani SQL'i ONCE ayristirir, degeri SONRA
    #  yerlestirir. Deger artik "kod" olarak yorumlanamaz -- sadece veridir.
    #  Ic karakter temizligi (escaping) yapmaya calismak yerine bu yontemi
    #  kullanmak, SQL enjeksiyonuna karsi tek dogru savunmadir.
    #
    #  Adim 7'deki explorer sayfasi bu metodlari cagiracak. SQL enjeksiyonu
    #  arayan bir aracin kendisinin SQL enjeksiyonuna acik olmasi, isin
    #  ironisi olurdu.
    # ========================================================================

    def alert(id)
      row = @db.execute('SELECT * FROM alerts WHERE id = ?', [id]).first
      row && row_to_alert(row)
    end

    # Filtrelenebilir alarm listesi.
    #
    # DIKKAT: filtreler dinamik olarak eklenirken bile deger ASLA SQL metnine
    # girmiyor -- sadece "kolon = ?" parcasi ekleniyor, deger dizisine
    # ayrica konuyor. Kolon adlari bizim kodumuzdan geliyor, kullanicidan degil.
    def alerts(limit: 50, offset: 0, rule: nil, severity: nil, ip: nil,
               from: nil, to: nil)
      where, values = build_filters(rule: rule, severity: severity, ip: ip,
                                    from: from, to: to)

      sql = "SELECT * FROM alerts #{where} ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?"
      @db.execute(sql, values + [limit, offset]).map { |row| row_to_alert(row) }
    end

    def count_alerts(rule: nil, severity: nil, ip: nil, from: nil, to: nil)
      where, values = build_filters(rule: rule, severity: severity, ip: ip,
                                    from: from, to: to)
      @db.execute("SELECT COUNT(*) FROM alerts #{where}", values).first.first
    end

    def events(limit: 100, offset: 0, ip: nil, status: nil, path_like: nil,
               from: nil, to: nil)
      clauses = []
      values  = []

      if ip
        clauses << 'ip = ?'
        values << ip
      end
      if status
        clauses << 'status = ?'
        values << Integer(status)
      end
      if path_like
        # LIKE kaliplarinda da deger parametre olarak gidiyor.
        clauses << 'path LIKE ?'
        values << "%#{path_like}%"
      end
      if from
        clauses << 'ts >= ?'
        values << from.to_i
      end
      if to
        clauses << 'ts <= ?'
        values << to.to_i
      end

      where = clauses.empty? ? '' : "WHERE #{clauses.join(' AND ')}"
      sql = "SELECT * FROM events #{where} ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?"

      @db.execute(sql, values + [limit, offset]).map { |row| row_to_event(row) }
    end

    # Dashboard grafigi icin: saat bazinda istek ve hata sayilari.
    #
    # ts / 3600 tam bolme islemi ile saat kovalari olusturuluyor. Zamani
    # INTEGER tuttugumuz icin bu tek satirda mumkun; metin olsaydi tarih
    # ayristirma fonksiyonlariyla ugrasmak gerekirdi.
    def hourly_counts(hours: 24, now: Time.now)
      since = now.to_i - (hours * 3600)
      @db.execute(<<~SQL, [since]).map do |bucket, total, errors, failed|
        SELECT (ts / 3600) * 3600 AS bucket,
               COUNT(*)                                   AS total,
               SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END) AS errors,
               SUM(CASE WHEN status IN (401, 403) THEN 1 ELSE 0 END) AS failed
        FROM events
        WHERE ts >= ?
        GROUP BY bucket
        ORDER BY bucket
      SQL
        { time: Time.at(bucket), total: total, errors: errors.to_i,
          failed_auth: failed.to_i }
      end
    end

    def top_ips(limit: 10, hours: 24, now: Time.now)
      since = now.to_i - (hours * 3600)
      @db.execute(<<~SQL, [since, limit]).map do |ip, total, failed|
        SELECT ip, COUNT(*) AS total,
               SUM(CASE WHEN status IN (401, 403) THEN 1 ELSE 0 END) AS failed
        FROM events
        WHERE ts >= ?
        GROUP BY ip
        ORDER BY total DESC
        LIMIT ?
      SQL
        { ip: ip, total: total, failed_auth: failed.to_i }
      end
    end

    def alert_counts_by_rule(hours: 24, now: Time.now)
      since = now.to_i - (hours * 3600)
      @db.execute(<<~SQL, [since]).to_h
        SELECT rule, COUNT(*) FROM alerts WHERE ts >= ? GROUP BY rule
      SQL
    end

    # ------------------------------------------------------------------------
    #  DOSYA BOYUTU -- WAL kipinde tek dosyaya bakmak YANLIS SONUC verir
    # ------------------------------------------------------------------------
    #  Bu, demoyu yazarken bizzat karsilastigim bir hata: 3000 kayit yazdiktan
    #  sonra boyut "0.00 MB" gorunuyordu.
    #
    #  Sebep: WAL kipinde yeni veri once <db>-wal dosyasina eklenir. Ana
    #  veritabani dosyasina ancak "checkpoint" aninda aktarilir. Yani sadece
    #  ana dosyaya bakarsan, henuz aktarilmamis TUM veriyi gormezsin.
    #
    #  Uc dosya birlikte veritabanini olusturur:
    #    logsentry.db       ana dosya
    #    logsentry.db-wal   henuz aktarilmamis degisiklikler
    #    logsentry.db-shm   paylasimli hafiza indeksi (process'ler arasi)
    #
    #  Disk kullanimini izleyen bir uyari kurarken bu ayrimi bilmemek,
    #  "veritabani hic buyumuyor" yanilgisina yol acar.
    # ------------------------------------------------------------------------
    def size_bytes
      return nil if @path == MEMORY

      ['', '-wal', '-shm'].sum do |suffix|
        file = "#{@path}#{suffix}"
        File.exist?(file) ? File.size(file) : 0
      end
    end

    def closed?
      @db.closed?
    end

    def stats
      return { path: @path, closed: true } if closed?

      {
        path:            @path,
        size_bytes:      size_bytes,
        events:          @db.execute('SELECT COUNT(*) FROM events').first.first,
        alerts:          @db.execute('SELECT COUNT(*) FROM alerts').first.first,
        events_written:  @events_written,
        alerts_written:  @alerts_written,
        batches:         @batches,
        buffered:        @buffer.size,
        oldest_event:    epoch_to_time(@db.execute('SELECT MIN(ts) FROM events').first.first),
        newest_event:    epoch_to_time(@db.execute('SELECT MAX(ts) FROM events').first.first)
      }
    end

    # ========================================================================
    #  SICAK KATMAN TEMIZLIGI
    # ========================================================================
    #  Suresi gecmis kayitlari veritabanindan siliyoruz. Bu VERI KAYBI DEGIL:
    #  ham log arsivde (soguk katman) yasal suresi boyunca duruyor. Burada
    #  silinen sey, hizli sorgu icin tutulan turevdir.
    #
    #  DIKKAT -- DELETE dosyayi KUCULTMEZ. SQLite silinen yerleri "bos alan"
    #  olarak isaretler ve yeni kayitlar icin kullanir. Dosya boyutunun
    #  gercekten kuculmesi icin VACUUM gerekir; VACUUM ise tum veritabanini
    #  yeniden yazar (yani gecici olarak iki kat yer ister ve kilitler).
    #  Bu yuzden VACUUM'u otomatik yapmiyoruz, istege bagli birakiyoruz.
    def prune!(days:, now: Time.now)
      cutoff = now.to_i - (days * 86_400)

      deleted_events = nil
      deleted_alerts = nil

      @db.transaction do
        @db.execute('DELETE FROM events WHERE ts < ?', [cutoff])
        deleted_events = @db.changes
        @db.execute('DELETE FROM alerts WHERE ts < ?', [cutoff])
        deleted_alerts = @db.changes
      end

      { events: deleted_events, alerts: deleted_alerts,
        cutoff: Time.at(cutoff) }
    end

    # WAL dosyasindaki degisiklikleri ana veritabanina aktar.
    #
    # Normalde SQLite bunu kendisi yapar (WAL ~1000 sayfaya ulasinca). Ama
    # dosya boyutunu OLCMEK istedigimizde elle tetiklemek gerekir: aksi halde
    # veri iki dosyaya dagilmis olur ve olcum yanlis okunur.
    def checkpoint!
      @db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
      size_bytes
    end

    def vacuum!
      # VACUUM bir islem (transaction) icinde calistirilamaz.
      # Once WAL'i bosalt, sonra sikistir -- yoksa VACUUM'un etkisi
      # olcumlerde gorunmez.
      checkpoint!
      @db.execute('VACUUM')
      checkpoint!
      size_bytes
    end

    def close
      flush
      # WAL dosyasindaki degisiklikleri ana veritabanina aktar.
      # Bu olmadan -wal dosyasi buyumeye devam eder.
      @db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
      @db.close
    rescue SQLite3::Exception
      nil
    end

    # Testler ve bakim icin dogrudan erisim
    attr_reader :db

    private

    def build_filters(rule:, severity:, ip:, from:, to:)
      clauses = []
      values  = []

      if rule
        clauses << 'rule = ?'
        values << rule.to_s
      end
      if severity
        clauses << 'severity = ?'
        values << severity.to_s
      end
      if ip
        clauses << 'ip = ?'
        values << ip
      end
      if from
        clauses << 'ts >= ?'
        values << from.to_i
      end
      if to
        clauses << 'ts <= ?'
        values << to.to_i
      end

      [clauses.empty? ? '' : "WHERE #{clauses.join(' AND ')}", values]
    end

    ALERT_COLUMNS = %i[id ts time_iso rule severity ip message count threshold
                       window details evidence].freeze
    EVENT_COLUMNS = %i[id ts ip method path status bytes user_agent].freeze

    def row_to_alert(row)
      h = ALERT_COLUMNS.zip(row).to_h
      h[:time]     = Time.at(h[:ts])
      h[:rule]     = h[:rule].to_sym
      h[:severity] = h[:severity].to_sym
      h[:details]  = safe_json(h[:details], {})
      h[:evidence] = safe_json(h[:evidence], [])
      h
    end

    def row_to_event(row)
      h = EVENT_COLUMNS.zip(row).to_h
      h[:time] = Time.at(h[:ts])
      h
    end

    # Veritabanindaki JSON bozuksa cokmek yerine bos deger don.
    # Veriden gelen hicbir sey programi durdurmamali.
    def safe_json(text, fallback)
      return fallback if text.nil? || text.empty?

      JSON.parse(text, symbolize_names: true)
    rescue JSON::ParserError
      fallback
    end

    def epoch_to_time(value)
      value && Time.at(value)
    end
  end
end
