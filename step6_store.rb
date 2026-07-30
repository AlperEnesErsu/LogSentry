# frozen_string_literal: true

# ============================================================================
#  ADIM 6 -- Gosterim / ogrenme dosyasi
# ----------------------------------------------------------------------------
#  Kullanim:  ruby step6_store.rb [log_dosyasi]
#
#  Gecici bir veritabani ve gecici bir arsiv dizini kullanir; projedeki
#  gercek db/ ve archive/ dizinlerine dokunmaz.
# ============================================================================

require 'tmpdir'
require 'fileutils'
require_relative 'lib/log_sentry/store'
require_relative 'lib/log_sentry/archiver'
require_relative 'lib/log_sentry/parser'
require_relative 'lib/log_sentry/engine'

LOG_PATH = ARGV[0] || File.expand_path('logs/access.log', __dir__)
abort("HATA: #{LOG_PATH} yok. Once: ruby tools/log_generator.rb") unless File.exist?(LOG_PATH)

def title(text)
  puts "\n#{'=' * 76}"
  puts text
  puts '=' * 76
end

def sub(text)
  puts "\n#{'-' * 76}"
  puts text
  puts '-' * 76
end

Dir.mktmpdir('logsentry-demo') do |tmp|
  # ==========================================================================
  title '[1] TOPLU YAZMA (BATCHING) -- Adim 6\'nin en buyuk performans karari'
  # ==========================================================================

  puts <<~EXPLAIN

    SQLite'ta her INSERT kendi basina bir islem (transaction) olur ve her
    islem sonunda diske yazma garantisi (fsync) istenir. Disk fsync'i
    milisaniyeler surer.

    Ayni 2000 kaydi iki yontemle yaziyoruz:
      A) her kayit ayri islem       (batch_size: 1)
      B) 500'luk partiler halinde   (batch_size: 500)

  EXPLAIN

  parser  = LogSentry::Parser.new
  entries = parser.parse_file(LOG_PATH).first(2000)
  puts "  Ayristirilan kayit: #{entries.size}"

  results = {}

  [1, 500].each do |batch|
    store = LogSentry::Store.new(path: File.join(tmp, "bench-#{batch}.db"),
                                 batch_size: batch)
    t0 = Time.now
    entries.each { |e| store.record_event(e) }
    store.flush
    elapsed = Time.now - t0
    results[batch] = elapsed
    store.close

    puts format('  batch_size %-4d : %8.1f ms   (%s kayit/saniye)',
                batch, elapsed * 1000,
                (entries.size / elapsed).round.to_s
                  .reverse.scan(/\d{1,3}/).join('.').reverse)
  end

  if results[1] && results[500]
    puts format("\n  FARK: %.1f kat hizli", results[1] / results[500])
  end

  puts <<~NOTE

    Adim 4'te boru hattini 84.000 kayit/saniye olcmustuk. Toplu yazma
    olmadan veritabani, tum akisi yavaslatan tikaniklik noktasi olurdu.

    Bedeli: tamponda bekleyen kayitlar cokme aninda kaybolabilir. Bu yuzden
    ALARMLAR tamponlanmiyor -- onlar seyrek ve kiymetli. Ayni takasi Adim
    5'te FileNotifier icin de yapmistik.
  NOTE

  # ==========================================================================
  title '[2] TUM LOGU DEPOLA ve SORGULA'
  # ==========================================================================

  db_path = File.join(tmp, 'logsentry.db')
  store   = LogSentry::Store.new(path: db_path)
  engine  = LogSentry::Engine.from_config(File.expand_path('config/logsentry.yml', __dir__))
  parser2 = LogSentry::Parser.new

  t0 = Time.now
  alert_count = 0
  parser2.parse_file(LOG_PATH) do |entry|
    store.record_event(entry)
    engine.process(entry).each do |alert|
      store.record_alert(alert)
      alert_count += 1
    end
  end
  store.flush
  ingest = Time.now - t0

  wal_size = store.stats[:size_bytes]
  # WAL'i ana dosyaya aktar -- yoksa boyut olcumu yaniltici olur.
  store.checkpoint!

  s = store.stats
  puts format("\n  Sure          : %.0f ms", ingest * 1000)
  puts "  Yazilan olay  : #{s[:events]}"
  puts "  Yazilan uyari : #{s[:alerts]}"
  puts "  Parti sayisi  : #{s[:batches]}"
  puts format('  Boyut (WAL dahil, checkpoint ONCESI) : %.2f MB', wal_size / 1024.0 / 1024)
  puts format('  Boyut (checkpoint SONRASI)           : %.2f MB', s[:size_bytes] / 1024.0 / 1024)
  puts format('  Bayt/kayit    : %.1f', s[:size_bytes].to_f / s[:events])
  puts '  (Aradaki fark WAL dosyasidir -- veri henuz ana dosyaya aktarilmamis)'
  puts "  Zaman araligi : #{s[:oldest_event]} - #{s[:newest_event]}"

  # ---------------------------------------------------------------------------
  sub 'SORGULAR -- "duz metin dosyasinda bunu yapamazdik"'
  # ---------------------------------------------------------------------------

  now = s[:newest_event] + 1

  bench = lambda do |label, &block|
    t = Time.now
    result = block.call
    puts format('  %-46s %6.2f ms', label, (Time.now - t) * 1000)
    result
  end

  puts
  top = bench.call('en cok istek yapan 5 IP (son 24 saat)') do
    store.top_ips(limit: 5, hours: 24, now: now)
  end

  high = bench.call('sadece HIGH seviye uyarilar') do
    store.alerts(severity: :high, limit: 100)
  end

  scan_ip = bench.call('tek bir IP\'nin 404 alan istekleri') do
    store.events(ip: '193.34.76.101', status: 404, limit: 50)
  end

  hourly = bench.call('saat bazinda trafik grafigi (dashboard verisi)') do
    store.hourly_counts(hours: 24, now: now)
  end

  by_rule = bench.call('kural bazinda uyari dagilimi') do
    store.alert_counts_by_rule(hours: 24, now: now)
  end

  puts "\n  EN COK ISTEK YAPAN IP'LER"
  top.each do |row|
    puts format('    %-18s %6d istek  %4d basarisiz giris',
                row[:ip], row[:total], row[:failed_auth])
  end

  puts "\n  KURAL BAZINDA UYARI"
  by_rule.each { |rule, count| puts format('    %-14s %4d', rule, count) }

  puts "\n  HIGH SEVIYE UYARI: #{high.size} adet"
  puts "  193.34.76.101'in 404 alan istekleri: #{scan_ip.size} adet"
  puts "  Grafik icin saat kovasi: #{hourly.size} adet"

  # ---------------------------------------------------------------------------
  sub 'TEK BIR UYARININ DETAYI -- Adim 7\'deki /alerts/:id sayfasi'
  # ---------------------------------------------------------------------------

  first = store.alerts(limit: 1, severity: :high).first
  if first
    detail = store.alert(first[:id])
    puts "\n  id        : #{detail[:id]}"
    puts "  kural     : #{detail[:rule]} (#{detail[:severity]})"
    puts "  IP        : #{detail[:ip]}"
    puts "  zaman     : #{detail[:time_iso]}"
    puts "  mesaj     : #{detail[:message]}"
    puts "  detay     : #{detail[:details].inspect}"
    puts '  KANIT     :'
    detail[:evidence].first(3).each { |raw| puts "     #{raw[0, 88]}" }
    puts "\n  Veritabanindan geri okundugunda kanit KORUNMUS durumda."
    puts '  "Bu gercekten saldiri mi?" sorusu ancak boyle cevaplanir.'
  end

  # ---------------------------------------------------------------------------
  sub 'SQL ENJEKSIYONU -- parametreli sorgu neyi onluyor?'
  # ---------------------------------------------------------------------------

  evil = "' OR 1=1 --"
  safe_result = store.alerts(ip: evil, limit: 100)

  puts <<~EXPLAIN

    Kullanicinin IP filtresine sunu yazdigini varsayalim:
        #{evil}

    YANLIS kod:  "... WHERE ip = '\#{ip}'"
       -> SQL su hale gelir: WHERE ip = '' OR 1=1 --'
       -> kosul her zaman DOGRU olur, TUM kayitlar dokulur.

    Bizim kod :  "... WHERE ip = ?", [ip]
       -> deger SQL metnine hic girmez, veri olarak gonderilir.

    Sonuc: #{safe_result.size} kayit dondu (dogru cevap 0, cunku boyle bir IP yok)
  EXPLAIN

  # ==========================================================================
  title '[3] ARSIVLEME -- soguk katman, hash zinciri'
  # ==========================================================================

  archive_dir = File.join(tmp, 'archive')
  archiver = LogSentry::Archiver.new(directory: archive_dir, retention_days: 730)

  # Arsivlenecek uc "gunluk" log dosyasi hazirla
  sources = 3.times.map do |i|
    path = File.join(tmp, "access-gun#{i + 1}.log")
    FileUtils.cp(LOG_PATH, path)
    path
  end

  puts
  sources.each_with_index do |src, i|
    entry = archiver.archive_file(src, move: true, label: "access-gun#{i + 1}.log")
    ratio = 100 - (entry[:stored_bytes] * 100.0 / entry[:bytes])
    puts format('  %d) %-34s %7d -> %6d bayt  (%%%.1f tasarruf)',
                i + 1, entry[:file], entry[:bytes], entry[:stored_bytes], ratio)
    puts format('     sha256(ham) : %s', entry[:sha256])
    puts format('     onceki      : %s', entry[:prev_chain][0, 32] + '...')
    puts format('     ZINCIR      : %s', entry[:chain])
    puts
  end

  puts <<~NOTE
    Dikkat: her kaydin ZINCIR degeri, kendinden oncekinin zincirini de
    iceriyor:
        chain[n] = SHA256( chain[n-1] + sha256[n] )

    gzip tasarrufu bu kadar yuksek cunku log satirlari birbirine cok benziyor.
    2 yillik saklama icin sikistirma bir tercih degil, zorunluluk.
  NOTE

  # ---------------------------------------------------------------------------
  sub 'BUTUNLUK DENETIMI -- saglam durum'
  # ---------------------------------------------------------------------------

  result = archiver.verify
  puts
  result[:entries].each do |e|
    puts format('  [%s] %s', e[:ok] ? 'OK  ' : 'HATA', e[:file])
  end
  puts "\n  SONUC: #{result[:ok] ? 'BUTUNLUK SAGLAM' : 'BOZULMUS'}"

  # ---------------------------------------------------------------------------
  sub 'KURCALAMA DENEMESI 1 -- arsiv dosyasinin icerigini degistir'
  # ---------------------------------------------------------------------------

  victim = File.join(archive_dir, archiver.read_manifest[1][:file])
  puts "\n  Kurbanm: #{File.basename(victim)}"
  puts '  Saldirgan gzip icerigini degistiriyor (izini silmek icin)...'

  # Gecerli bir gzip uretiyoruz -- yani "bozuk dosya" degil, DEGISTIRILMIS dosya.
  # Saldirgan boyle yapar: dosyayi bozmaz, iceriginden kendi satirlarini siler.
  require 'zlib'
  original_lines = Zlib::GzipReader.open(victim, &:read).lines
  cleaned = original_lines.reject { |l| l.include?('45.155.205.233') }
  Zlib::GzipWriter.open(victim) { |gz| gz.write(cleaned.join) }

  puts format('  %d satir -> %d satir (saldirganin kendi kayitlari silindi)',
              original_lines.size, cleaned.size)

  result = archiver.verify
  puts
  result[:entries].each do |e|
    line = format('  [%s] %s', e[:ok] ? 'OK  ' : 'HATA', e[:file])
    line += "  <-- #{e[:reason]}" if e[:reason]
    puts line
  end
  puts "\n  SONUC: #{result[:ok] ? 'BUTUNLUK SAGLAM' : 'BUTUNLUK BOZULMUS -- YAKALANDI'}"

  puts <<~NOTE

    Saldirgan gecerli bir gzip uretti, dosya sorunsuz aciliyor. Ama HAM
    icerigin SHA-256 ozeti artik manifest'teki degerle uyusmuyor.
  NOTE

  # ---------------------------------------------------------------------------
  sub 'KURCALAMA DENEMESI 2 -- manifest kaydini da guncelle'
  # ---------------------------------------------------------------------------

  puts <<~EXPLAIN

    Akilli saldirgan sunu dusunur: "dosyayi degistirdim, ozet uyusmuyor.
    O zaman manifest'teki ozeti de guncelleyeyim."

    Deneyelim: 2. kaydin sha256 ve stored_sha256 degerlerini gercek
    degerlerle degistiriyoruz.
  EXPLAIN

  manifest_path = File.join(archive_dir, 'manifest.jsonl')
  lines = File.readlines(manifest_path)
  require 'json'
  require 'digest'

  record = JSON.parse(lines[1], symbolize_names: true)
  new_raw = Digest::SHA256.hexdigest(Zlib::GzipReader.open(victim, &:read))
  new_stored = Digest::SHA256.file(victim).hexdigest
  record[:sha256] = new_raw
  record[:stored_sha256] = new_stored
  lines[1] = "#{JSON.generate(record)}\n"
  File.write(manifest_path, lines.join)

  result = archiver.verify
  puts
  result[:entries].each do |e|
    line = format('  [%s] %s', e[:ok] ? 'OK  ' : 'HATA', e[:file])
    line += "  <-- #{e[:reason]}" if e[:reason]
    puts line
  end
  puts "\n  SONUC: #{result[:ok] ? 'BUTUNLUK SAGLAM' : 'BUTUNLUK BOZULMUS -- YINE YAKALANDI'}"

  puts <<~NOTE

    ISTE ZINCIRIN DEGERI BURADA.

    Dosya ozeti artik dogru, ama 2. kaydin ZINCIR degeri yanlis: cunku
    zincir sha256'dan hesaplaniyor ve sha256 degisti. Ustelik 3. kaydin
    prev_chain'i eski degeri isaret ediyor.

    Saldirganin basarili olmasi icin 2. kayittan SONRAKI TUM kayitlari
    yeniden hesaplamasi gerekir. Gercek bir sistemde bu zincirin basi
    (head) baska bir yerde saklanir (yazdirilir, e-posta ile gonderilir,
    yetkili zaman damgasi saglayicisina imzalatilir) -- o zaman tum
    zinciri yeniden yazmak da ise yaramaz.

    Bu mekanizmanin adi HASH ZINCIRI. Blok zincirinin de temelinde bu var.
  NOTE

  # ==========================================================================
  title '[4] SAKLAMA SURESI -- iki yonlu kisit'
  # ==========================================================================

  short = LogSentry::Archiver.new(
    directory: archive_dir,
    manifest: File.join(archive_dir, 'manifest.jsonl'),
    retention_days: 730
  )

  puts "\n  Bugun silinecek arsiv (730 gun) -- DENEME modu:"
  dry = short.prune!(dry_run: true)
  puts "    kesim tarihi : #{dry[:cutoff].strftime('%Y-%m-%d')}"
  puts "    silinecek    : #{dry[:count]} arsiv (yeni olusturuldular, dogru)"

  puts "\n  Simdi saklama suresini 0 gun yapip tekrar deniyoruz:"
  zero = LogSentry::Archiver.new(
    directory: archive_dir,
    manifest: File.join(archive_dir, 'manifest.jsonl'),
    retention_days: 0
  )
  pruned = zero.prune!
  puts "    silinen      : #{pruned[:count]} arsiv"
  puts "    silme kaydi  : #{zero.deletions.size} adet manifest'e yazildi"

  puts <<~NOTE

    SILME ISLEMI DE BIR OLAYDIR ve manifest'e kaydediliyor. "Bu log nerede?"
    sorusunun cevabi "bilmiyorum" olmamali; "su tarihte saklama suresi
    dolduğu icin silindi" olmali.

    Ve suresi iki yonden kisitli oldugunu hatirla:
        cok KISA -> 5651 kapsaminda yukumluluk ihlali
        cok UZUN -> IP kisisel veri oldugu icin KVKK ihlali
    (Hukuki gorus degildir -- kendi kategorin icin mevzuati teyit et.)
  NOTE

  # ==========================================================================
  title '[5] SICAK KATMAN TEMIZLIGI'
  # ==========================================================================

  # checkpoint! ile WAL'i ana dosyaya aktariyoruz -- yoksa olcum yaniltici
  # olur, cunku veri iki dosyaya dagilmis durumda kalir.
  mb = ->(bytes) { format('%.2f MB', bytes / 1024.0 / 1024) }

  store.checkpoint!
  before = store.stats
  pruned = store.prune!(days: 0, now: now + 86_400)
  store.checkpoint!
  after = store.stats

  puts
  puts format('  Once   : %-5d olay, %-3d uyari, %s',
              before[:events], before[:alerts], mb.call(before[:size_bytes]))
  puts format('  Silinen: %d olay, %d uyari', pruned[:events], pruned[:alerts])
  puts format('  Sonra  : %-5d olay, %-3d uyari, %s',
              after[:events], after[:alerts], mb.call(after[:size_bytes]))

  puts <<~NOTE

    DIKKAT: kayit sayisi sifirlandi ama DOSYA neredeyse hic kuculmedi.
    SQLite silinen yerleri "bos sayfa" olarak isaretler ve yeni kayitlar icin
    yeniden kullanir. Dosyanin gercekten kuculmesi icin VACUUM gerekir --
    ama VACUUM tum veritabanini yeniden yazar (gecici olarak iki kat yer
    ister ve veritabanini kilitler), o yuzden otomatik yapmiyoruz.
  NOTE

  puts format('  VACUUM sonrasi: %s', mb.call(store.vacuum!))

  store.close

  title 'SONUC'
  puts <<~SUMMARY

    Iki katmanli depolama kuruldu:

      SICAK  db/logsentry.db      son 90 gun    hizli sorgu     silinebilir
      SOGUK  archive/*.log.gz     yasal sure    ham + muhurlu   degistirilemez

    Ikisi ayni seyi yapmiyor: biri SORGU icin, digeri KANIT icin.
    Ham logu asla veritabanina ezdirmiyoruz.

    Adim 7: bu sorgularin ustune bir web arayuzu.

  SUMMARY
end
