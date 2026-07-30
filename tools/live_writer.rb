# frozen_string_literal: true

# ============================================================================
#  Canli log yazici -- bir web sunucusunu simule eder
# ----------------------------------------------------------------------------
#  Bu betik durmadan log satiri yazar. Amaci, tools/watch.rb ile ayni anda
#  calistirip "iki terminal" denemesi yapabilmen.
#
#  Kullanim:
#    ruby tools/live_writer.rb                     # normal trafik
#    ruby tools/live_writer.rb --attack brute      # sifre deneme saldirisi
#    ruby tools/live_writer.rb --attack scan       # dizin taramasi
#    ruby tools/live_writer.rb --attack flood      # DDoS belirtisi
#    ruby tools/live_writer.rb --rps 20            # saniyede 20 istek
#    ruby tools/live_writer.rb --file /tmp/x.log
#
#  Durdurmak icin: Ctrl-C
# ============================================================================

require 'fileutils'
require 'optparse'

options = { attack: nil, rps: 3, file: File.expand_path('../logs/access.log', __dir__) }

OptionParser.new do |o|
  o.on('--attack TYPE', 'brute | scan | flood') { |v| options[:attack] = v }
  o.on('--rps N', Integer, 'saniyedeki istek sayisi') { |v| options[:rps] = v }
  o.on('--file PATH', 'yazilacak dosya') { |v| options[:file] = File.expand_path(v) }
end.parse!

NORMAL_IPS   = %w[10.0.0.5 10.0.0.12 88.243.11.7 176.33.4.90 212.156.7.21].freeze
NORMAL_PATHS = ['/', '/about', '/products', '/api/v1/users', '/static/css/main.css'].freeze
SENSITIVE    = ['/admin', '/wp-login.php', '/.env', '/.git/config', '/phpmyadmin'].freeze

BRUTE_IP = '45.155.205.233'
SCAN_IP  = '193.34.76.101'
FLOOD_IP = '5.188.206.14'

FileUtils.mkdir_p(File.dirname(options[:file]))

def line(ip:, method: 'GET', path: '/', status: 200, agent: 'Mozilla/5.0 Chrome/126.0')
  format('%s - - [%s] "%s %s HTTP/1.1" %d %d "-" "%s"',
         ip, Time.now.strftime('%d/%b/%Y:%H:%M:%S %z'),
         method, path, status, rand(200..9000), agent)
end

running = true
Signal.trap('INT') { running = false }

count = 0
delay = 1.0 / options[:rps]

puts "Yaziliyor : #{options[:file]}"
puts "Mod       : #{options[:attack] || 'normal'}"
puts "Hiz       : ~#{options[:rps]} istek/saniye"
puts 'Durdurmak icin Ctrl-C'
puts

# 'a' modu = append. Bir web sunucusu logu her zaman boyle yazar.
# sync = true: her yazmadan sonra diske bosalt. Bu OLMADAN Ruby satirlari
# tamponda bekletir ve izleyen taraf hicbir sey gormez -- gercek sunucular
# da bu yuzden log yazarken tamponsuz calisir.
File.open(options[:file], 'a') do |f|
  f.sync = true

  while running
    case options[:attack]
    when 'brute'
      # Ayni IP'den ust uste basarisiz giris
      f.puts line(ip: BRUTE_IP, method: 'POST', path: '/login', status: 401,
                  agent: 'python-requests/2.31.0')
    when 'scan'
      f.puts line(ip: SCAN_IP, path: SENSITIVE.sample, status: [404, 403].sample,
                  agent: 'sqlmap/1.8#stable')
    when 'flood'
      # Tek turda cok istek -> saniyedeki hacmi patlat
      50.times { f.puts line(ip: FLOOD_IP, agent: 'curl/8.4.0') }
      count += 49
    else
      f.puts line(ip: NORMAL_IPS.sample, path: NORMAL_PATHS.sample,
                  status: [200, 200, 200, 200, 304, 404].sample)
    end

    count += 1
    print "\rYazilan satir: #{count}"
    sleep delay
  end
end

puts "\nDurduruldu. Toplam #{count} satir yazildi."
