# frozen_string_literal: true

# ============================================================================
#  Sahte (dummy) Nginx access.log ureteci
# ----------------------------------------------------------------------------
#  Amac: Gercek bir sunucuya ihtiyac duymadan, uzerinde calisabilecegimiz
#  gercekci bir web sunucusu log dosyasi olusturmak.
#
#  Uretilen format "Nginx combined" formatidir. Gercek hayatta karsina
#  cikacak olan tam olarak budur:
#
#  IP - kullanici [zaman] "METOD /yol PROTOKOL" durum boyut "referer" "user-agent"
#
#  Ornek:
#  10.0.0.5 - - [29/Jul/2026:10:15:32 +0300] "GET /index.html HTTP/1.1" 200 1043 "-" "Mozilla/5.0"
#
#  Kullanim:
#    ruby tools/log_generator.rb                  # 2000 satir -> logs/access.log
#    ruby tools/log_generator.rb 50000            # 50.000 satir
#    ruby tools/log_generator.rb 50000 logs/x.log # ozel cikti dosyasi
# ============================================================================

require 'fileutils'

# --- Ayarlar ---------------------------------------------------------------

LINE_COUNT  = (ARGV[0] || 2_000).to_i
OUTPUT_PATH = ARGV[1] || File.expand_path('../logs/access.log', __dir__)

# Normal ziyaretcilerin IP havuzu
NORMAL_IPS = %w[
  10.0.0.5 10.0.0.12 10.0.0.31 88.243.11.7 176.33.4.90
  212.156.7.21 95.70.128.44 78.186.55.3
].freeze

# Saldirgan IP'ler -- ileride kural motorumuzun yakalamasi gereken adresler
BRUTE_FORCE_IP = '45.155.205.233'  # Ayni IP'den yogun 401 (hatali giris)
SCANNER_IP     = '193.34.76.101'   # /admin, /wp-login.php gibi dizinleri tariyor
FLOOD_IP       = '5.188.206.14'    # Saniyede yuzlerce istek (DDoS belirtisi)

# Normal trafikte gezilen sayfalar
NORMAL_PATHS = [
  '/', '/index.html', '/about', '/products', '/products/42',
  '/static/css/main.css', '/static/js/app.js', '/api/v1/users',
  '/api/v1/orders', '/favicon.ico', '/images/logo.png'
].freeze

# Saldirganlarin denedigi hassas dizinler
SENSITIVE_PATHS = [
  '/admin', '/admin/login', '/wp-login.php', '/wp-admin', '/.env',
  '/phpmyadmin', '/.git/config', '/config.php.bak', '/backup.zip'
].freeze

USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/128.0',
  'curl/8.4.0',
  'python-requests/2.31.0',
  'sqlmap/1.8#stable (https://sqlmap.org)'
].freeze

# --- Yardimci metodlar -----------------------------------------------------

# Nginx'in kullandigi zaman damgasi formati: [29/Jul/2026:10:15:32 +0300]
def nginx_time(time)
  time.strftime('%d/%b/%Y:%H:%M:%S %z')
end

# Tek bir log satirini birlestirir.
def log_line(ip:, time:, method:, path:, status:, size: nil, agent: nil)
  size  ||= rand(200..15_000)
  agent ||= USER_AGENTS.sample
  format(
    '%<ip>s - - [%<time>s] "%<method>s %<path>s HTTP/1.1" %<status>d %<size>d "-" "%<agent>s"',
    ip: ip, time: nginx_time(time), method: method,
    path: path, status: status, size: size, agent: agent
  )
end

# Normal, zararsiz bir ziyaretci istegi
def normal_request(time)
  status = case rand(100)
           when 0..89  then 200   # cogunlukla basarili
           when 90..95 then 304   # tarayici cache'i
           when 96..98 then 404   # olmayan sayfa
           else             500   # nadiren sunucu hatasi
           end

  log_line(
    ip: NORMAL_IPS.sample,
    time: time,
    method: %w[GET GET GET GET POST].sample,
    path: NORMAL_PATHS.sample,
    status: status
  )
end

# --- Uretim ----------------------------------------------------------------

FileUtils.mkdir_p(File.dirname(OUTPUT_PATH))

# Loglar "simdi"den geriye dogru degil, ileriye dogru aksin diye
# baslangic zamanini 1 saat geriye aliyoruz.
clock = Time.now - 3600
lines_written = 0

File.open(OUTPUT_PATH, 'w') do |file|
  while lines_written < LINE_COUNT
    # Zaman her satirda biraz ilerlesin (gercek trafik gibi)
    clock += rand(0..3)

    roll = rand(100)

    case roll
    # ---- %4 ihtimalle: Brute force patlamasi -----------------------------
    # Ayni IP, ayni saniyeler icinde /login adresine ust uste 401 aliyor.
    when 0..3
      12.times do
        break if lines_written >= LINE_COUNT

        clock += rand(0..1)
        file.puts log_line(
          ip: BRUTE_FORCE_IP, time: clock, method: 'POST',
          path: '/login', status: 401, size: 178,
          agent: 'python-requests/2.31.0'
        )
        lines_written += 1
      end

    # ---- %3 ihtimalle: Dizin/panel taramasi ------------------------------
    when 4..6
      SENSITIVE_PATHS.sample(4).each do |path|
        break if lines_written >= LINE_COUNT

        clock += rand(0..1)
        file.puts log_line(
          ip: SCANNER_IP, time: clock, method: 'GET',
          path: path, status: [404, 403, 401].sample, size: 162,
          agent: 'sqlmap/1.8#stable (https://sqlmap.org)'
        )
        lines_written += 1
      end

    # ---- %2 ihtimalle: DDoS belirtisi ------------------------------------
    # Tek saniye icinde ayni IP'den 150+ istek.
    when 7..8
      burst_time = clock
      150.times do
        break if lines_written >= LINE_COUNT

        file.puts log_line(
          ip: FLOOD_IP, time: burst_time, method: 'GET',
          path: '/', status: 200, size: 512, agent: 'curl/8.4.0'
        )
        lines_written += 1
      end

    # ---- Geri kalan %91: normal trafik -----------------------------------
    else
      file.puts normal_request(clock)
      lines_written += 1
    end
  end
end

size_mb = (File.size(OUTPUT_PATH) / 1024.0 / 1024.0).round(2)
puts "OK  #{lines_written} satir yazildi"
puts "    Dosya : #{OUTPUT_PATH}"
puts "    Boyut : #{size_mb} MB"
