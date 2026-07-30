# frozen_string_literal: true

# ============================================================================
#  Demo/test ortami hazirlayici
# ----------------------------------------------------------------------------
#  Web arayuzunu gosterebilmek icin gercekci bir veri kumesi kurar:
#
#    1) Temiz baslangic (db, alerts.jsonl, archive, state)
#    2) 24 SAATE yayilmis log uretir -- dashboard grafiginin dolu gorunmesi
#       icin. (tools/log_generator.rb son 1 saati uretiyor; grafikte tek
#       cubuk cikiyor.)
#    3) Boru hattini bir kez calistirip veritabanini doldurur
#    4) Bir arsiv olusturup muhurler (Butunluk sayfasi icin)
#
#  Kullanim:  ruby tools/demo_env.rb
# ============================================================================

require 'fileutils'
require_relative '../lib/log_sentry'
require_relative '../lib/log_sentry/store'
require_relative '../lib/log_sentry/archiver'

ROOT = File.expand_path('..', __dir__)
Dir.chdir(ROOT)

def step(text)
  puts "\n== #{text}"
end

# ---------------------------------------------------------------------------
step 'Temizlik'
# ---------------------------------------------------------------------------
%w[db/logsentry.db db/logsentry.db-wal db/logsentry.db-shm
   logs/alerts.jsonl logs/.logsentry.state logs/logsentry.log
   logs/logsentry.pid].each do |f|
  next unless File.exist?(f)

  File.delete(f)
  puts "  silindi: #{f}"
end
FileUtils.rm_rf('archive')
FileUtils.mkdir_p(%w[db logs archive])

# ---------------------------------------------------------------------------
step '24 saate yayilmis log uretiliyor'
# ---------------------------------------------------------------------------
# Kendi ureteci burada yaziyoruz cunku tools/log_generator.rb sadece son
# 1 saati uretiyor -- dashboard grafiginde tek cubuk cikardi.

NORMAL_IPS   = %w[10.0.0.5 10.0.0.12 88.243.11.7 176.33.4.90 212.156.7.21
                  95.70.128.44 78.186.55.3].freeze
NORMAL_PATHS = ['/', '/about', '/products', '/products/42', '/api/v1/users',
                '/api/v1/orders', '/static/css/main.css', '/static/js/app.js',
                '/images/logo.png', '/favicon.ico'].freeze
SENSITIVE    = ['/admin', '/admin/login', '/wp-login.php', '/wp-admin', '/.env',
                '/phpmyadmin', '/.git/config', '/config.php.bak', '/backup.zip'].freeze
AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/128.0'
].freeze

BRUTE_IP = '45.155.205.233'
SCAN_IP  = '193.34.76.101'
FLOOD_IP = '5.188.206.14'

def line(ip, time, method, path, status, agent)
  format('%s - - [%s] "%s %s HTTP/1.1" %d %d "-" "%s"',
         ip, time.strftime('%d/%b/%Y:%H:%M:%S %z'),
         method, path, status, rand(200..15_000), agent)
end

lines = []
now   = Time.now
start = now - (24 * 3600)

# Saat saat gezip her saate trafik koyuyoruz. Gece saatlerinde daha az,
# gunduz daha cok -- gercek bir sitenin gunluk deseni.
(0...24).each do |hour_offset|
  hour_start = start + (hour_offset * 3600)
  local_hour = hour_start.hour

  volume = case local_hour
           when 0..5   then 25    # gece
           when 6..8   then 70
           when 9..17  then 140   # is saatleri
           when 18..21 then 110
           else             50
           end

  volume.times do
    t = hour_start + rand(3600)
    status = case rand(100)
             when 0..90  then 200
             when 91..95 then 304
             when 96..98 then 404
             else             500
             end
    lines << [t, line(NORMAL_IPS.sample, t, %w[GET GET GET POST].sample,
                      NORMAL_PATHS.sample, status, AGENTS.sample)]
  end

  # Saldirilar: gunun belirli saatlerinde
  # Brute force -- 3 ayri dalga
  if [4, 11, 19].include?(local_hour)
    burst = hour_start + rand(3000)
    30.times do |i|
      t = burst + (i * rand(1..3))
      lines << [t, line(BRUTE_IP, t, 'POST', '/login', 401,
                        'python-requests/2.31.0')]
    end
  end

  # Dizin taramasi
  if [2, 9, 15, 22].include?(local_hour)
    scan_start = hour_start + rand(3000)
    SENSITIVE.shuffle.each_with_index do |path, i|
      t = scan_start + (i * rand(1..4))
      lines << [t, line(SCAN_IP, t, 'GET', path, [404, 403].sample,
                        'sqlmap/1.8#stable (https://sqlmap.org)')]
    end
  end

  # Flood -- tek saniyede yogun istek
  next unless [7, 14, 20].include?(local_hour)

  flood_at = hour_start + rand(3000)
  160.times { lines << [flood_at, line(FLOOD_IP, flood_at, 'GET', '/', 200, 'curl/8.4.0')] }
end

# Zaman sirasina diz -- gercek bir log dosyasi siralidir ve kayan pencere
# mantigi bunu varsayar.
lines.sort_by! { |(t, _)| t }
File.write('logs/access.log', lines.map { |(_, l)| l }.join("\n") + "\n")

puts "  #{lines.size} satir yazildi (24 saat)"
puts format('  boyut: %.2f MB', File.size('logs/access.log') / 1024.0 / 1024)

# ---------------------------------------------------------------------------
step 'Boru hatti calistiriliyor (parse -> kural -> depolama)'
# ---------------------------------------------------------------------------
config = YAML.load_file('config/logsentry.yml')
supervisor = LogSentry::Supervisor.new(
  config: config, config_path: 'config/logsentry.yml',
  from_begin: true, once: true, quiet: true
)
supervisor.run

# DIKKAT: supervisor.run kapanirken Store'u da kapatiyor (nazik kapanma).
# Kapali bir veritabanina sorgu atmak "prepare called on a closed database"
# hatasi verir -- ilk denemede tam bunu yasadik. Istatistigi okumak icin
# veritabanini yeniden aciyoruz.
stats = LogSentry::Store.new(path: config.dig('storage', 'database'))
puts "  olay   : #{stats.stats[:events]}"
puts "  uyari  : #{stats.stats[:alerts]}"
stats.close

# ---------------------------------------------------------------------------
step 'Arsiv olusturuluyor (Butunluk sayfasi icin)'
# ---------------------------------------------------------------------------
archiver = LogSentry::Archiver.new(directory: 'archive', retention_days: 730)

# Uc "gunluk" arsiv olusturup zinciri gorunur kilalim
3.times do |i|
  tmp = "logs/access-#{Time.now.strftime('%Y%m%d')}-#{i + 1}.log"
  FileUtils.cp('logs/access.log', tmp)
  entry = archiver.archive_file(tmp, move: true, label: "access-gun#{i + 1}.log")
  puts "  #{entry[:file]}  zincir: #{entry[:chain][0, 16]}..."
end

result = archiver.verify
puts "  butunluk: #{result[:ok] ? 'SAGLAM' : 'BOZUK'} (#{result[:count]} kayit)"

puts <<~DONE

  ================================================================
  Demo ortami hazir.

  Web arayuzunu baslat:
      ruby bin/logsentry-web

  Canli akisi beslemek icin (ayri terminal):
      ruby tools/live_writer.rb --attack brute --rps 12
      ruby bin/logsentry            # alarmlari alerts.jsonl'a yazar
  ================================================================
DONE
