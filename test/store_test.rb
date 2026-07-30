# frozen_string_literal: true

# ============================================================================
#  Adim 6 testleri: Store (SQLite) ve Archiver (arsiv + hash zinciri)
# ----------------------------------------------------------------------------
#  Calistirmak icin:   ruby test/store_test.rb
#
#  Store testleri cogunlukla ':memory:' veritabani kullaniyor: disk yok,
#  temizlik yok, milisaniyeler icinde kosuyor. Dosya davranisini test etmesi
#  gerekenler (boyut, WAL, VACUUM) gecici dizin kullaniyor.
# ============================================================================

require 'minitest/autorun'
require 'tmpdir'
require 'json'
require 'zlib'
require 'digest'

lib_path = File.expand_path('../lib', __dir__)
lib_path = File.expand_path('./lib') unless File.exist?(File.join(lib_path, 'log_sentry.rb'))
$LOAD_PATH.unshift(lib_path) unless $LOAD_PATH.include?(lib_path)

require 'log_sentry/store'
require 'log_sentry/archiver'
require 'log_sentry/entry'
require 'log_sentry/alert'

class StoreTest < Minitest::Test
  T0 = Time.new(2026, 7, 29, 14, 0, 0, '+03:00')

  def setup
    @store = LogSentry::Store.new(path: ':memory:')
  end

  def teardown
    @store&.close
  end

  def entry(ip: '1.2.3.4', status: 200, path: '/', at: T0, method: 'GET',
            agent: 'Chrome')
    LogSentry::Entry.new(
      ip: ip, time: at, http_method: method, path: path, protocol: 'HTTP/1.1',
      status: status, bytes: 512, referer: '-', user_agent: agent,
      raw: "#{ip} ... #{status}"
    )
  end

  def alert(rule: :brute_force, severity: :high, ip: '45.155.205.233', at: T0)
    LogSentry::Alert.new(
      rule: rule, severity: severity, ip: ip,
      message: 'test uyarisi', time: at,
      count: 11, threshold: 10, window: 60,
      details: { automated: true }, evidence: ['ham satir 401']
    )
  end

  # ==========================================================================
  #  SEMA VE AYARLAR
  # ==========================================================================

  def test_wal_kipi_etkin
    # WAL olmadan mimarimiz calismaz: daemon yazarken web arayuzu sorgu
    # atarsa "database is locked" hatasi alir.
    # (:memory: veritabaninda WAL desteklenmez, o yuzden dosya kullaniyoruz.)
    Dir.mktmpdir do |dir|
      store = LogSentry::Store.new(path: File.join(dir, 'x.db'))
      mode  = store.db.execute('PRAGMA journal_mode').first.first

      assert_equal 'wal', mode.downcase
      store.close
    end
  end

  def test_indeksler_olusturuldu
    names = @store.db.execute(
      "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%'"
    ).flatten

    # (ip, ts) bilesik indeksi olmadan "bu IP'nin son 1 saati" sorgusu
    # tum tabloyu tarar.
    assert_includes names, 'idx_events_ip_ts'
    assert_includes names, 'idx_alerts_rule_ts'
  end

  def test_sema_surumu_kaydedilir
    version = @store.db.execute("SELECT value FROM meta WHERE key = 'schema_version'")
                       .first.first
    assert_equal LogSentry::Store::SCHEMA_VERSION.to_s, version
  end

  def test_ayni_veritabani_ikinci_kez_acilabilir
    # CREATE TABLE IF NOT EXISTS olmadan ikinci acilis coker.
    # Servis her yeniden baslatmada bu yolu gecer.
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'x.db')
      s1 = LogSentry::Store.new(path: path)
      s1.record_alert(alert)
      s1.close

      s2 = LogSentry::Store.new(path: path)
      assert_equal 1, s2.stats[:alerts], 'onceki kayitlar korunmali'
      s2.close
    end
  end

  # ==========================================================================
  #  TOPLU YAZMA
  # ==========================================================================

  def test_olaylar_tamponlanir_ve_toplu_yazilir
    store = LogSentry::Store.new(path: ':memory:', batch_size: 10)

    9.times { store.record_event(entry) }
    assert_equal 0, store.stats[:events], 'parti dolmadan yazilmamali'
    assert_equal 9, store.stats[:buffered]

    store.record_event(entry)   # 10. -> parti doldu
    assert_equal 10, store.stats[:events]
    assert_equal 0,  store.stats[:buffered]
    assert_equal 1,  store.batches

    store.close
  end

  def test_flush_kalan_kayitlari_yazar
    store = LogSentry::Store.new(path: ':memory:', batch_size: 100)
    5.times { store.record_event(entry) }

    assert_equal 5, store.flush
    assert_equal 5, store.stats[:events]
    assert_equal 0, store.flush, 'bos tamponda flush 0 donmeli'

    store.close
  end

  def test_close_bekleyen_kayitlari_kaybetmez
    # Nazik kapanmanin anlami: elindeki isi kaybetmeden birak.
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'x.db')
      store = LogSentry::Store.new(path: path, batch_size: 1000)
      7.times { store.record_event(entry) }
      store.close   # icinde flush var

      reopened = LogSentry::Store.new(path: path)
      assert_equal 7, reopened.stats[:events]
      reopened.close
    end
  end

  def test_store_all_events_kapatilabilir
    # Hafif kurulum: sadece uyarilari sakla, her istegi saklama.
    store = LogSentry::Store.new(path: ':memory:', store_all_events: false)

    100.times { store.record_event(entry) }
    store.flush
    store.record_alert(alert)

    assert_equal 0, store.stats[:events]
    assert_equal 1, store.stats[:alerts], 'uyarilar her zaman kaydedilmeli'
    store.close
  end

  def test_alarmlar_aninda_yazilir
    # Alarmlar tamponlanmaz: seyrek ve kiymetli.
    @store.record_alert(alert)
    assert_equal 1, @store.stats[:alerts]
  end

  # ==========================================================================
  #  ALARM KAYDI VE GERI OKUMA
  # ==========================================================================

  def test_alarm_tum_alanlarla_geri_okunur
    id = @store.record_alert(alert)
    row = @store.alert(id)

    assert_equal :brute_force, row[:rule]
    assert_equal :high,        row[:severity]
    assert_equal '45.155.205.233', row[:ip]
    assert_equal 11,           row[:count]
    assert_equal 10,           row[:threshold]
    assert_equal 60,           row[:window]
    # details ve evidence JSON olarak saklanip Ruby yapisina geri donmeli
    assert_equal true, row[:details][:automated]
    assert_equal ['ham satir 401'], row[:evidence]
  end

  def test_kanit_veritabaninda_korunur
    # Bir uyariyi "eyleme gecirilebilir" yapan sey kanittir.
    # Veritabani turuna gidip geri gelirken kaybolmamali.
    id = @store.record_alert(alert)
    assert_includes @store.alert(id)[:evidence].first, '401'
  end

  def test_saat_dilimi_korunur
    # ts (INTEGER) siralama icin, time_iso (TEXT) gosterim icin.
    # Sadece epoch saklasak "+03:00" bilgisini kaybederdik.
    id = @store.record_alert(alert(at: T0))
    row = @store.alert(id)

    assert_equal T0.to_i, row[:ts]
    assert_match(/\+03:00\z/, row[:time_iso])
  end

  def test_bozuk_json_cokmez
    # Veritabanina elle bozuk veri girmis olabilir (baska bir surum,
    # yarim yazma). Veriden gelen hicbir sey programi durdurmamali.
    @store.db.execute(<<~SQL, [T0.to_i, T0.iso8601])
      INSERT INTO alerts (ts, time_iso, rule, severity, ip, message,
                          count, threshold, window, details, evidence)
      VALUES (?, ?, 'flood', 'high', '1.2.3.4', 'x', 1, 1, 1,
              '{bozuk json', 'yine bozuk')
    SQL

    row = @store.alerts(limit: 1).first
    assert_equal({}, row[:details])
    assert_equal([], row[:evidence])
  end

  # ==========================================================================
  #  SORGULAR VE FILTRELER
  # ==========================================================================

  def test_alarmlar_yeniden_eskiye_siralanir
    @store.record_alert(alert(at: T0))
    @store.record_alert(alert(at: T0 + 100))
    @store.record_alert(alert(at: T0 + 50))

    times = @store.alerts.map { |a| a[:ts] }
    assert_equal times.sort.reverse, times
  end

  def test_filtreler
    @store.record_alert(alert(rule: :brute_force, severity: :high, ip: '1.1.1.1'))
    @store.record_alert(alert(rule: :flood,       severity: :high, ip: '2.2.2.2'))
    @store.record_alert(alert(rule: :path_scan,   severity: :medium, ip: '1.1.1.1'))

    assert_equal 1, @store.alerts(rule: :flood).size
    assert_equal 2, @store.alerts(severity: :high).size
    assert_equal 2, @store.alerts(ip: '1.1.1.1').size
    assert_equal 1, @store.alerts(ip: '1.1.1.1', severity: :medium).size
    assert_equal 3, @store.count_alerts
    assert_equal 1, @store.count_alerts(rule: :path_scan)
  end

  def test_zaman_araligi_filtresi
    @store.record_alert(alert(at: T0))
    @store.record_alert(alert(at: T0 + 3600))
    @store.record_alert(alert(at: T0 + 7200))

    assert_equal 2, @store.alerts(from: T0 + 1800).size
    assert_equal 2, @store.alerts(to: T0 + 3600).size
    assert_equal 1, @store.alerts(from: T0 + 1800, to: T0 + 3600).size
  end

  def test_sayfalama
    5.times { |i| @store.record_alert(alert(at: T0 + i)) }

    page1 = @store.alerts(limit: 2, offset: 0)
    page2 = @store.alerts(limit: 2, offset: 2)

    assert_equal 2, page1.size
    assert_equal 2, page2.size
    # Sayfalar cakismamali
    assert_empty page1.map { |a| a[:id] } & page2.map { |a| a[:id] }
  end

  def test_olay_filtreleri
    @store.record_event(entry(ip: '1.1.1.1', status: 200, path: '/admin'))
    @store.record_event(entry(ip: '1.1.1.1', status: 404, path: '/admin/x'))
    @store.record_event(entry(ip: '2.2.2.2', status: 404, path: '/'))
    @store.flush

    assert_equal 2, @store.events(ip: '1.1.1.1').size
    assert_equal 2, @store.events(status: 404).size
    assert_equal 1, @store.events(ip: '1.1.1.1', status: 404).size
    assert_equal 2, @store.events(path_like: 'admin').size
  end

  # ==========================================================================
  #  SQL ENJEKSIYONU
  # ==========================================================================

  def test_sql_enjeksiyonu_etkisiz
    # SQL enjeksiyonu arayan bir aracin kendisinin SQL enjeksiyonuna acik
    # olmasi, isin ironisi olurdu.
    3.times { @store.record_alert(alert) }

    payloads = ["' OR 1=1 --", "'; DROP TABLE alerts; --", "1' UNION SELECT * FROM alerts --"]

    payloads.each do |evil|
      result = @store.alerts(ip: evil)
      assert_empty result, "enjeksiyon calisti: #{evil}"
    end

    # Tablo hala yerinde mi?
    assert_equal 3, @store.count_alerts, 'tablo silinmis olabilir'
  end

  def test_enjeksiyon_olay_sorgusunda_da_etkisiz
    @store.record_event(entry)
    @store.flush

    assert_empty @store.events(ip: "' OR 1=1 --")
    # LIKE kalibinda da deger parametre olarak gidiyor
    assert_empty @store.events(path_like: "%' OR 1=1 --")
    assert_equal 1, @store.stats[:events]
  end

  # ==========================================================================
  #  DASHBOARD SORGULARI (Adim 7 icin)
  # ==========================================================================

  def test_top_ips
    5.times { @store.record_event(entry(ip: '5.5.5.5')) }
    2.times { @store.record_event(entry(ip: '6.6.6.6', status: 401)) }
    @store.flush

    top = @store.top_ips(limit: 5, hours: 24, now: T0 + 60)

    assert_equal '5.5.5.5', top.first[:ip]
    assert_equal 5, top.first[:total]
    assert_equal 0, top.first[:failed_auth]
    assert_equal 2, top.last[:failed_auth]
  end

  def test_hourly_counts
    # Ayni saat kovasinda 3, sonraki saatte 1 kayit
    3.times { @store.record_event(entry(at: T0)) }
    @store.record_event(entry(at: T0 + 3700, status: 500))
    @store.flush

    buckets = @store.hourly_counts(hours: 24, now: T0 + 7200)

    assert_equal 2, buckets.size
    assert_equal 3, buckets.first[:total]
    assert_equal 1, buckets.last[:errors]
  end

  def test_alert_counts_by_rule
    2.times { @store.record_alert(alert(rule: :brute_force)) }
    @store.record_alert(alert(rule: :flood))

    counts = @store.alert_counts_by_rule(hours: 24, now: T0 + 60)
    assert_equal 2, counts['brute_force']
    assert_equal 1, counts['flood']
  end

  # ==========================================================================
  #  SICAK KATMAN TEMIZLIGI
  # ==========================================================================

  def test_prune_eski_kayitlari_siler
    @store.record_event(entry(at: T0 - (100 * 86_400)))   # 100 gun once
    @store.record_event(entry(at: T0))                     # bugun
    @store.flush
    @store.record_alert(alert(at: T0 - (100 * 86_400)))
    @store.record_alert(alert(at: T0))

    result = @store.prune!(days: 90, now: T0)

    assert_equal 1, result[:events]
    assert_equal 1, result[:alerts]
    assert_equal 1, @store.stats[:events], 'yeni kayit korunmali'
    assert_equal 1, @store.stats[:alerts]
  end

  def test_prune_veri_kaybi_degildir_ham_log_arsivde
    # Bu test bir DAVRANISI degil, bir SOZLESMEYI belgeliyor:
    # sicak katmandan silmek, kaydin yok olmasi anlamina gelmez.
    # (Arsiv tarafi ArchiverTest'te dogrulaniyor.)
    @store.record_event(entry(at: T0 - (365 * 86_400)))
    @store.flush
    @store.prune!(days: 90, now: T0)

    assert_equal 0, @store.stats[:events]
  end

  def test_dosya_boyutu_wal_dosyasini_da_sayar
    # DEMO YAZARKEN KARSILASILAN GERCEK HATA:
    # 3000 kayit yazdiktan sonra boyut "0.00 MB" gorunuyordu, cunku veri
    # henuz -wal dosyasindaydi. Sadece ana dosyaya bakan bir disk uyarisi
    # "veritabani hic buyumuyor" yanilgisina yol acar.
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'x.db')
      store = LogSentry::Store.new(path: path, batch_size: 100)
      500.times { store.record_event(entry) }
      store.flush

      main_only = File.size(path)
      reported  = store.size_bytes

      assert_operator reported, :>, main_only,
                      'boyut olcumu WAL dosyasini da icermeli'
      store.close
    end
  end

  def test_vacuum_dosyayi_kucultur
    Dir.mktmpdir do |dir|
      store = LogSentry::Store.new(path: File.join(dir, 'x.db'), batch_size: 500)
      3_000.times { store.record_event(entry) }
      store.flush
      before = store.checkpoint!

      store.prune!(days: 0, now: T0 + 86_400)
      after_delete = store.checkpoint!
      after_vacuum = store.vacuum!

      # DELETE dosyayi kucultmez: SQLite yerleri "bos sayfa" olarak isaretler.
      assert_operator after_delete, :>=, before * 0.9,
                      'DELETE dosyayi kucultmemeli'
      assert_operator after_vacuum, :<, after_delete,
                      'VACUUM dosyayi kucultmeli'
      store.close
    end
  end
end

# ============================================================================
#  ARCHIVER
# ============================================================================
class ArchiverTest < Minitest::Test
  def with_archiver(retention: 730)
    Dir.mktmpdir do |dir|
      archive_dir = File.join(dir, 'archive')
      archiver = LogSentry::Archiver.new(directory: archive_dir,
                                        retention_days: retention)
      yield archiver, dir, archive_dir
    end
  end

  def make_log(dir, name, lines: 100)
    path = File.join(dir, name)
    File.open(path, 'w') do |f|
      lines.times do |i|
        f.puts "10.0.0.#{i % 10} - - [29/Jul/2026:14:00:#{format('%02d', i % 60)} +0300] " \
               '"GET / HTTP/1.1" 200 512 "-" "Chrome"'
      end
    end
    path
  end

  # --------------------------------------------------------------------------
  #  ARSIVLEME
  # --------------------------------------------------------------------------

  def test_dosya_sikistirilir_ve_muhurlenir
    with_archiver do |archiver, dir, archive_dir|
      source = make_log(dir, 'access.log', lines: 500)
      original_size = File.size(source)

      entry = archiver.archive_file(source)

      assert File.exist?(File.join(archive_dir, entry[:file]))
      assert entry[:file].end_with?('.gz')
      assert_equal 500, entry[:lines]
      assert_equal original_size, entry[:bytes]
      assert_operator entry[:stored_bytes], :<, entry[:bytes],
                      'sikistirma ise yaramis olmali'
      assert_match(/\A[0-9a-f]{64}\z/, entry[:sha256])
    end
  end

  def test_kaynak_dosya_tasinir
    with_archiver do |archiver, dir, _archive_dir|
      source = make_log(dir, 'access.log')
      archiver.archive_file(source, move: true)

      refute File.exist?(source), 'kaynak silinmeliydi'
    end
  end

  def test_kaynak_korunabilir
    with_archiver do |archiver, dir, _archive_dir|
      source = make_log(dir, 'access.log')
      archiver.archive_file(source, move: false)

      assert File.exist?(source), 'move: false ile kaynak korunmali'
    end
  end

  def test_arsivlenen_icerik_geri_okunabilir
    # Arsiv, okunamayan bir kutu degil: adli incelemede ham log gerekir.
    with_archiver do |archiver, dir, archive_dir|
      source = make_log(dir, 'access.log', lines: 50)
      # binread: Windows'ta File.read metin kipinde \r\n -> \n cevirisi yapar.
      # Arsivci dosyayi BAYT BAYT kopyaliyor, o yuzden karsilastirmayi da
      # bayt seviyesinde yapmak gerekiyor. (Adim 3'te Tailer'i 'rb' modunda
      # acmamizin sebebi de tam olarak bu ceviriydi.)
      original = File.binread(source)

      entry = archiver.archive_file(source)
      restored = Zlib::GzipReader.open(File.join(archive_dir, entry[:file]), &:read)

      assert_equal original, restored, 'arsivden geri okunan icerik birebir olmali'
    end
  end

  def test_olmayan_dosya_hata_verir
    with_archiver do |archiver, _dir, _archive_dir|
      assert_raises(ArgumentError) { archiver.archive_file('/olmayan/dosya.log') }
    end
  end

  # --------------------------------------------------------------------------
  #  HASH ZINCIRI
  # --------------------------------------------------------------------------

  def test_zincir_kuruluyor
    with_archiver do |archiver, dir, _archive_dir|
      e1 = archiver.archive_file(make_log(dir, 'g1.log'))
      e2 = archiver.archive_file(make_log(dir, 'g2.log'))
      e3 = archiver.archive_file(make_log(dir, 'g3.log'))

      # Ilk kayit genesis'ten baslar
      assert_equal LogSentry::Archiver::GENESIS, e1[:prev_chain]
      # Her kayit oncekinin zincirini isaret eder
      assert_equal e1[:chain], e2[:prev_chain]
      assert_equal e2[:chain], e3[:prev_chain]
      # Zincir degeri = SHA256(onceki_zincir + dosya_ozeti)
      assert_equal Digest::SHA256.hexdigest("#{e2[:chain]}#{e3[:sha256]}"), e3[:chain]
    end
  end

  def test_saglam_arsiv_dogrulanir
    with_archiver do |archiver, dir, _archive_dir|
      3.times { |i| archiver.archive_file(make_log(dir, "g#{i}.log")) }

      result = archiver.verify

      assert result[:ok], 'saglam arsiv dogrulanmali'
      assert_equal 3, result[:count]
      assert(result[:entries].all? { |e| e[:ok] })
    end
  end

  def test_bos_arsiv_dogrulanir
    with_archiver do |archiver, _dir, _archive_dir|
      result = archiver.verify
      assert result[:ok]
      assert_equal 0, result[:count]
    end
  end

  # --------------------------------------------------------------------------
  #  KURCALAMA TESPITI -- bu dosyanin varlik sebebi
  # --------------------------------------------------------------------------

  def test_dosya_icerigi_degistirilirse_yakalanir
    with_archiver do |archiver, dir, archive_dir|
      archiver.archive_file(make_log(dir, 'g1.log'))
      entry = archiver.archive_file(make_log(dir, 'g2.log', lines: 200))
      archiver.archive_file(make_log(dir, 'g3.log'))

      # Saldirgan GECERLI bir gzip uretiyor -- dosyayi bozmuyor, iceriginden
      # kendi satirlarini siliyor. Sadece "gzip acilabiliyor mu" diye bakan
      # bir kontrol bunu YAKALAMAZ.
      victim = File.join(archive_dir, entry[:file])
      lines = Zlib::GzipReader.open(victim, &:read).lines
      Zlib::GzipWriter.open(victim) { |gz| gz.write(lines.first(100).join) }

      assert_nothing_raised_gzip(victim)

      result = archiver.verify
      refute result[:ok], 'degistirilmis dosya yakalanmali'

      bad = result[:entries].find { |e| e[:file] == entry[:file] }
      refute bad[:ok]
      assert_match(/DEGISTIRILMIS/, bad[:reason])

      # Diger kayitlar etkilenmemeli -- hangi dosyanin bozuldugunu bilmek gerekir
      others = result[:entries].reject { |e| e[:file] == entry[:file] }
      assert(others.all? { |e| e[:ok] })
    end
  end

  def test_manifest_ozeti_de_guncellenirse_zincir_yakalar
    # AKILLI SALDIRGAN: "dosyayi degistirdim, ozet uyusmuyor. O zaman
    # manifest'teki ozeti de guncelleyeyim."
    #
    # Zincir tam bu senaryo icin var.
    with_archiver do |archiver, dir, archive_dir|
      archiver.archive_file(make_log(dir, 'g1.log'))
      entry = archiver.archive_file(make_log(dir, 'g2.log', lines: 200))
      archiver.archive_file(make_log(dir, 'g3.log'))

      victim = File.join(archive_dir, entry[:file])
      lines = Zlib::GzipReader.open(victim, &:read).lines
      Zlib::GzipWriter.open(victim) { |gz| gz.write(lines.first(100).join) }

      # Manifest kaydini "duzelt"
      manifest = File.join(archive_dir, 'manifest.jsonl')
      records = File.readlines(manifest)
      target_index = records.index { |l| l.include?(entry[:file]) }
      record = JSON.parse(records[target_index], symbolize_names: true)
      record[:sha256] = Digest::SHA256.hexdigest(Zlib::GzipReader.open(victim, &:read))
      record[:stored_sha256] = Digest::SHA256.file(victim).hexdigest
      records[target_index] = "#{JSON.generate(record)}\n"
      File.write(manifest, records.join)

      result = archiver.verify

      refute result[:ok], 'zincir bu senaryoyu yakalamali'
      bad = result[:entries].find { |e| e[:file] == entry[:file] }
      assert_match(/ZINCIR/, bad[:reason])
    end
  end

  def test_ortadaki_kayit_silinirse_zincir_kopar
    with_archiver do |archiver, dir, archive_dir|
      archiver.archive_file(make_log(dir, 'g1.log'))
      middle = archiver.archive_file(make_log(dir, 'g2.log'))
      archiver.archive_file(make_log(dir, 'g3.log'))

      manifest = File.join(archive_dir, 'manifest.jsonl')
      records = File.readlines(manifest).reject { |l| l.include?(middle[:file]) }
      File.write(manifest, records.join)

      result = archiver.verify
      refute result[:ok], 'silinen kayit zinciri koparmali'
    end
  end

  def test_arsiv_dosyasi_silinirse_yakalanir
    with_archiver do |archiver, dir, archive_dir|
      entry = archiver.archive_file(make_log(dir, 'g1.log'))
      File.delete(File.join(archive_dir, entry[:file]))

      result = archiver.verify
      refute result[:ok]
      assert_equal 'dosya yok', result[:entries].first[:reason]
    end
  end

  def test_bozuk_gzip_yakalanir
    with_archiver do |archiver, dir, archive_dir|
      entry = archiver.archive_file(make_log(dir, 'g1.log'))
      File.write(File.join(archive_dir, entry[:file]), 'bu gzip degil')

      result = archiver.verify
      refute result[:ok]
    end
  end

  # --------------------------------------------------------------------------
  #  SAKLAMA SURESI
  # --------------------------------------------------------------------------

  def test_yeni_arsivler_silinmez
    with_archiver(retention: 730) do |archiver, dir, _archive_dir|
      archiver.archive_file(make_log(dir, 'g1.log'))

      result = archiver.prune!
      assert_equal 0, result[:count], 'yeni arsiv silinmemeli'
    end
  end

  def test_suresi_gecen_arsivler_silinir
    with_archiver(retention: 0) do |archiver, dir, archive_dir|
      entry = archiver.archive_file(make_log(dir, 'g1.log'))
      path = File.join(archive_dir, entry[:file])
      assert File.exist?(path)

      # retention_days: 0 -> kesim tarihi "simdi", muhur zamani gecmiste kalir
      sleep 0.01
      result = archiver.prune!

      assert_equal 1, result[:count]
      refute File.exist?(path), 'suresi gecen arsiv silinmeliydi'
    end
  end

  def test_dry_run_hicbir_sey_silmez
    with_archiver(retention: 0) do |archiver, dir, archive_dir|
      entry = archiver.archive_file(make_log(dir, 'g1.log'))
      sleep 0.01

      result = archiver.prune!(dry_run: true)

      assert_equal 1, result[:count], 'silinecekleri raporlamali'
      assert File.exist?(File.join(archive_dir, entry[:file])),
             'dry_run modunda dosya silinmemeli'
      assert_empty archiver.deletions, 'dry_run silme kaydi yazmamali'
    end
  end

  def test_silme_islemi_kaydedilir
    # "Bu log nerede?" sorusunun cevabi "bilmiyorum" olmamali.
    with_archiver(retention: 0) do |archiver, dir, _archive_dir|
      entry = archiver.archive_file(make_log(dir, 'g1.log'))
      sleep 0.01
      archiver.prune!

      deletions = archiver.deletions
      assert_equal 1, deletions.size
      assert_equal entry[:file], deletions.first[:file]
      assert_match(/saklama suresi/, deletions.first[:reason])
      assert deletions.first[:deleted_at]
      # Silinen dosyanin ozeti de kayitta duruyor -- "bu log hic olmadi"
      # denemez.
      assert_equal entry[:sha256], deletions.first[:sha256]
    end
  end

  def test_silme_kayitlari_zincir_dogrulamasini_bozmaz
    # Silme kayitlari ayri bir olay turudur (type: deletion) ve arsiv
    # zincirinin parcasi degildir.
    with_archiver(retention: 0) do |archiver, dir, _archive_dir|
      archiver.archive_file(make_log(dir, 'g1.log'))
      sleep 0.01
      archiver.prune!

      result = archiver.verify
      # Dosya silindigi icin "dosya yok" diyecek, ama zincir mantigi
      # bozulmamis olmali.
      assert_equal 1, result[:count]
      assert_equal 'dosya yok', result[:entries].first[:reason]
    end
  end

  # --------------------------------------------------------------------------
  #  ISTATISTIK
  # --------------------------------------------------------------------------

  def test_stats
    with_archiver do |archiver, dir, _archive_dir|
      archiver.archive_file(make_log(dir, 'g1.log', lines: 300))
      archiver.archive_file(make_log(dir, 'g2.log', lines: 300))

      s = archiver.stats
      assert_equal 2, s[:archives]
      assert_equal 0, s[:deletions]
      assert_equal 730, s[:retention_days]
      assert_operator s[:stored_bytes], :<, s[:raw_bytes]
      refute_equal LogSentry::Archiver::GENESIS, s[:head_chain]
    end
  end

  def test_bozuk_manifest_satiri_atlanir
    with_archiver do |archiver, dir, archive_dir|
      archiver.archive_file(make_log(dir, 'g1.log'))
      File.open(File.join(archive_dir, 'manifest.jsonl'), 'a') do |f|
        f.puts 'bu gecerli JSON degil {{{'
      end

      # Bozuk satir cokmeye yol acmamali, sadece atlanmali.
      assert_equal 1, archiver.read_manifest.size
    end
  end

  private

  # gzip'in gercekten acilabildigini dogrula (yani "bozuk dosya" degil,
  # DEGISTIRILMIS dosya ile ugrastigimizi kanitla)
  def assert_nothing_raised_gzip(path)
    Zlib::GzipReader.open(path, &:read)
    pass
  rescue Zlib::GzipFile::Error
    flunk 'test verisi gecerli bir gzip olmali'
  end
end
