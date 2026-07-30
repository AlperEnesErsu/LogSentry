# frozen_string_literal: true

# ============================================================================
#  ADIM 2 -- Gosterim / ogrenme dosyasi
# ----------------------------------------------------------------------------
#  Kullanim:  ruby step2_parser.rb [log_dosyasi]
# ============================================================================

require_relative 'lib/log_sentry/parser'

LOG_PATH = ARGV[0] || File.expand_path('logs/access.log', __dir__)

def title(text)
  puts "\n#{'=' * 74}"
  puts text
  puts '=' * 74
end

parser = LogSentry::Parser.new

# ---------------------------------------------------------------------------
title('[1] BIR SATIRIN ANATOMISI -- metin dunyasindan veri dunyasina')
# ---------------------------------------------------------------------------

sample = '45.155.205.233 - - [29/Jul/2026:14:39:25 +0300] ' \
         '"POST /login HTTP/1.1" 401 178 "-" "python-requests/2.31.0"'

puts "\nGIRDI (tek bir String -- uzerinde matematik yapilamaz):"
puts "  #{sample}"

entry = parser.parse(sample)

puts "\nCIKTI (Entry nesnesi -- her alan dogru tipte):"
puts format('  %-12s %-28s %s', 'ALAN', 'DEGER', 'RUBY TIPI')
puts '  ' + '-' * 60
entry.to_h.each do |field, value|
  next if field == :raw

  puts format('  %-12s %-28s %s', field, value.inspect, value.class)
end

puts "\nArtik SORU SORABILIYORUZ (metinle bunlari yapamazdik):"
puts "  entry.status > 400        -> #{entry.status > 400}"
puts "  entry.failed_auth?        -> #{entry.failed_auth?}"
puts "  entry.time.hour           -> #{entry.time.hour}"
puts "  entry.time + 60           -> #{entry.time + 60}   (1 dakika sonrasi)"
puts "  entry.summary             -> #{entry.summary}"

# ---------------------------------------------------------------------------
title('[2] ADIM 1\'DEKI HILE NEDEN CALISMIYORDU?')
# ---------------------------------------------------------------------------

puts <<~EXPLAIN

  Adim 1'de durum kodunu soyle almistik:

      status = line.split(' ')[8]     # "9. kelime durum kodudur"

  Bu, satirdaki bosluk sayisinin HER ZAMAN ayni oldugunu varsayiyor.
  Asagidaki satirlar bu varsayimi kiriyor -- ve hepsi gercek hayatta,
  ozellikle SALDIRI trafiginde gorulen satirlardir:

EXPLAIN

cases = [
  ['Normal satir (referans)',
   '10.0.0.5 - - [29/Jul/2026:10:00:00 +0300] "GET / HTTP/1.1" 200 1043 "-" "Chrome"'],

  ['Yolda kodlanmamis BOSLUK',
   '10.0.0.9 - - [29/Jul/2026:10:00:01 +0300] "GET /search?q=hello world HTTP/1.1" 200 512 "-" "Chrome"'],

  ['Bozuk istek (TLS istegi HTTP portuna)',
   '193.34.76.101 - - [29/Jul/2026:10:00:02 +0300] "\\x16\\x03\\x01" 400 0 "-" "-"'],

  ['Boyut alani "-" (govdesiz yanit)',
   '10.0.0.5 - - [29/Jul/2026:10:00:03 +0300] "HEAD / HTTP/1.1" 304 - "-" "curl/8.4.0"'],

  ['Tamamen alakasiz satir (bozuk log)',
   'bu bir log satiri degil, cop veri']
]

puts format('  %-38s %-12s %-12s', 'DURUM', 'HILE [8]', 'PARSER')
puts '  ' + '-' * 70

cases.each do |label, line|
  naive = line.split(' ')[8] || '(yok)'

  p2 = LogSentry::Parser.new
  result = p2.parse(line)

  parser_out = if result.nil?
                 'nil (atildi)'
               else
                 result.status.to_s
               end

  correct = result && naive == result.status.to_s
  mark = if result.nil?
           'v dogru red'
         elsif correct
           'v'
         else
           'X HILE YANILDI'
         end

  puts format('  %-38s %-12s %-12s %s', label, naive, parser_out, mark)
end

puts <<~NOTE

  Dikkat: 2. satirda hile "world" kelimesini durum kodu sandi.
  Bu bir cokme uretmez -- SESSIZCE yanlis veri uretir. Guvenlik
  araclarinda sessiz yanlis, cokmekten daha tehlikelidir: arac
  calisiyor gorunur ama hicbir sey gormez.

  Parser'in bozuk istegi (3. satir) nasil ele aldigina bak:

NOTE

broken = LogSentry::Parser.new.parse(cases[2][1])
puts "  ip          : #{broken.ip}      <- SAGLAM"
puts "  status      : #{broken.status}              <- SAGLAM"
puts "  time        : #{broken.time}   <- SAGLAM"
puts "  http_method : #{broken.http_method.inspect}             <- isaretlendi"
puts "  path        : #{broken.path.inspect}   <- ham hali kanit olarak duruyor"
puts "  malformed_request? -> #{broken.malformed_request?}"
puts "\n  Bozuk parca, saglam parcalari goturmedi. Ayristiricinin"
puts '  en onemli tasarim ilkesi budur.'

# ---------------------------------------------------------------------------
title('[3] TUM DOSYAYI AYRISTIR')
# ---------------------------------------------------------------------------

unless File.exist?(LOG_PATH)
  abort("\nHATA: #{LOG_PATH} yok. Once: ruby tools/log_generator.rb")
end

file_parser = LogSentry::Parser.new

# Analiz sayaclari. Hepsi Hash.new(0) -- ilk artista hata vermez.
by_ip       = Hash.new(0)
by_status   = Hash.new(0)
failed_auth = Hash.new(0)
by_path     = Hash.new(0)
agents      = Hash.new(0)
first_time  = nil
last_time   = nil

started = Time.now

file_parser.parse_file(LOG_PATH) do |e|
  by_ip[e.ip]             += 1
  by_status[e.status]     += 1
  by_path[e.path]         += 1
  agents[e.user_agent]    += 1
  failed_auth[e.ip]       += 1 if e.failed_auth?

  first_time ||= e.time
  last_time = e.time
end

elapsed = Time.now - started
stats = file_parser.stats

puts "\nDosya   : #{LOG_PATH}"
puts "Sure    : #{(elapsed * 1000).round(1)} ms"
puts "Hiz     : #{(stats[:parsed] / elapsed).round.to_s.reverse.scan(/\d{1,3}/).join('.').reverse} satir/saniye"
puts "Basarili: #{stats[:parsed]}"
puts "Basarisiz: #{stats[:failed]}"
puts "Basari orani: #{stats[:success_rate]}%"
puts "Zaman araligi: #{first_time.strftime('%H:%M:%S')} - #{last_time.strftime('%H:%M:%S')}"

if file_parser.failed_samples.any?
  puts "\nAyristirilamayan ornek satirlar:"
  file_parser.failed_samples.first(3).each do |f|
    puts "  [#{f[:reason]}] #{f[:line][0, 60]}"
  end
end

# ---------------------------------------------------------------------------
title('[4] ILK GERCEK ISTIHBARAT -- veri artik soru sorulabilir durumda')
# ---------------------------------------------------------------------------

total = stats[:parsed]

puts "\nEN COK ISTEK YAPAN IP'LER"
by_ip.sort_by { |_ip, n| -n }.first(6).each do |ip, n|
  pct = (n * 100.0 / total).round(1)
  flag = pct > 20 ? '  <-- tek IP trafigin bestte birinden fazlasi!' : ''
  puts format('  %-18s %6d  %5.1f%%%s', ip, n, pct, flag)
end

puts "\nEN COK BASARISIZ GIRIS DENEYEN IP'LER  (401 + 403)"
if failed_auth.empty?
  puts '  (yok)'
else
  failed_auth.sort_by { |_ip, n| -n }.first(5).each do |ip, n|
    puts format('  %-18s %6d', ip, n)
  end
end

puts "\nSUPHELI USER-AGENT'LAR"
suspicious = agents.select do |ua, _n|
  ua.to_s.match?(/sqlmap|nikto|nmap|masscan|python-requests|curl|wget|scan/i)
end
if suspicious.empty?
  puts '  (yok)'
else
  suspicious.sort_by { |_ua, n| -n }.each do |ua, n|
    puts format('  %-45s %6d', ua[0, 45], n)
  end
end

puts "\nHASSAS DIZINLERE YAPILAN ISTEKLER"
sensitive = by_path.select { |p, _n| p.match?(%r{^/(admin|wp-|\.env|\.git|phpmyadmin|config|backup)}i) }
if sensitive.empty?
  puts '  (yok)'
else
  sensitive.sort_by { |_p, n| -n }.each do |path, n|
    puts format('  %-28s %6d', path, n)
  end
end

title('SONUC')
puts <<~SUMMARY

  Adim 1'de elimizde 3000 satir METIN vardi.
  Adim 2'den sonra elimizde 3000 tane SORGULANABILIR NESNE var.

  Yukaridaki tablolarda saldirganlar gozle secilebiliyor -- ama bunu
  biz gozumuzle yaptik ve dosyanin TAMAMI bittikten sonra yaptik.

  Adim 3: dosya bitmeyecek, canli akacak.
  Adim 4: bu kararlari goz yerine kurallar verecek, o anda.

SUMMARY
