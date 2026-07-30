# frozen_string_literal: true

# ============================================================================
#  ADIM 4 -- Gosterim / ogrenme dosyasi
# ----------------------------------------------------------------------------
#  Kullanim:  ruby step4_engine.rb [log_dosyasi]
# ============================================================================

require_relative 'lib/log_sentry/engine'
require_relative 'lib/log_sentry/parser'

LOG_PATH    = ARGV[0] || File.expand_path('logs/access.log', __dir__)
CONFIG_PATH = File.expand_path('config/logsentry.yml', __dir__)

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

# ---------------------------------------------------------------------------
title '[1] MOTOR YAPILANDIRMADAN KURULUYOR'
# ---------------------------------------------------------------------------

engine = LogSentry::Engine.from_config(CONFIG_PATH)

puts "\nYapilandirma: #{CONFIG_PATH}"
puts "Yuklenen kural sayisi: #{engine.rules.size}\n\n"
puts format('  %-14s %-10s %8s %10s %10s', 'KURAL', 'ONEM', 'PENCERE', 'ESIK', 'SOGUTMA')
puts '  ' + '-' * 60
engine.rules.each do |rule|
  puts format('  %-14s %-10s %6d sn %10d %7d sn',
              rule.name, rule.severity, rule.window, rule.threshold, rule.cooldown)
end

puts <<~NOTE

  Bu degerlerin hicbiri kodda gomulu degil -- config/logsentry.yml'dan
  okundu. "10 cok dusuk, 25 yapalim" dedigimizde kodu yeniden yayinlamak
  yerine dosyayi degistirip servisi yeniden baslatmak yeterli.
NOTE

# ---------------------------------------------------------------------------
title '[2] MOTORUN TUM MANTIGI -- tek satir'
# ---------------------------------------------------------------------------

puts <<~CODE

      def process(entry)
        @rules.filter_map { |rule| rule.call(entry) }
      end

  Icinde tek bir `if rule.is_a?(BruteForce)` yok. Motor, kurallarin ne
  yaptigini BILMIYOR; sadece sozlesmeye guveniyor:
  "sana Entry veririm, bana Alert veya nil dondurursun."

  Yarin 20 kural daha eklesen bu satir aynen kalir. Buna POLIMORFIZM denir.
CODE

# ---------------------------------------------------------------------------
title '[3] LOGU ISLE -- kararlari artik goz degil KOD veriyor'
# ---------------------------------------------------------------------------

unless File.exist?(LOG_PATH)
  abort("\nHATA: #{LOG_PATH} yok. Once: ruby tools/log_generator.rb")
end

parser = LogSentry::Parser.new
alerts = []

started = Time.now
parser.parse_file(LOG_PATH) do |entry|
  engine.process(entry).each { |alert| alerts << alert }
end
elapsed = Time.now - started

puts "\nDosya      : #{LOG_PATH}"
puts "Islenen    : #{engine.processed_count} kayit"
puts format('Sure       : %.1f ms  (~%d kayit/saniye)',
            elapsed * 1000, (engine.processed_count / elapsed).round)
puts "URETILEN UYARI: #{alerts.size}"

# ---------------------------------------------------------------------------
sub 'URETILEN UYARILAR (onem sirasina gore)'
# ---------------------------------------------------------------------------

if alerts.empty?
  puts "\n  (hic uyari uretilmedi)"
else
  alerts
    .sort_by { |a| [-a.severity_rank, a.time] }
    .each { |a| puts "  #{a.to_line}" }
end

# ---------------------------------------------------------------------------
sub 'BIR UYARININ ANATOMISI -- "neden alarm verdim?"'
# ---------------------------------------------------------------------------

sample = alerts.find { |a| a.rule == :brute_force } || alerts.first

if sample
  puts <<~EXPLAIN

    Bir uyari gordugunde ilk soracagin sey su olacak:
    "gercekten saldiri mi, yanlis alarm mi?"

    Bu soruya ancak KANIT gorerek cevap verilebilir. Bu yuzden her Alert,
    kendisini doguran ham log satirlarini tasiyor.

  EXPLAIN

  puts "  kural      : #{sample.rule}"
  puts "  onem       : #{sample.severity}"
  puts "  IP         : #{sample.ip}"
  puts "  zaman      : #{sample.time}"
  puts "  olculen    : #{sample.count}  (esik: #{sample.threshold}, pencere: #{sample.window} sn)"
  puts "  mesaj      : #{sample.message}"
  puts '  detaylar   :'
  sample.details.each { |k, v| puts "      #{k}: #{v.inspect}" }
  puts '  KANIT (alarmi doguran ham satirlar):'
  sample.evidence.each { |raw| puts "      #{raw[0, 96]}" }
end

# ---------------------------------------------------------------------------
sub 'PATHSCAN NEDEN FARKLI? -- sayi degil CESITLILIK'
# ---------------------------------------------------------------------------

scan_alert = alerts.find { |a| a.rule == :path_scan }

if scan_alert
  puts <<~EXPLAIN

    Diger iki kural HACIM olcuyor. PathScan CESITLILIK olcuyor:

      /admin adresine 50 istek        -> muhtemelen yer imi / bozuk bot
                                         cesitlilik = 1, alarm YOK

      5 farkli hassas dizine 1'er     -> KESFETME davranisi.
                                         cesitlilik = 5, ALARM
    Toplam istek cok az olsa bile niyet acik. Hacim bazli bir kural bunu
    asla yakalamaz.

  EXPLAIN
  puts "  #{scan_alert.ip} adresinin dokundugu dizinler:"
  scan_alert.details[:probed_paths].each { |p| puts "      #{p}" }
end

# ---------------------------------------------------------------------------
sub 'SOGUTMA (COOLDOWN) OLMASA NE OLURDU?'
# ---------------------------------------------------------------------------

# Ayni logu sogutmasiz bir motorla tekrar isleyip farki olcuyoruz.
noisy = LogSentry::Engine.new(
  rules: [
    LogSentry::Rules::BruteForce.new(window: 60, threshold: 10, cooldown: 0),
    LogSentry::Rules::Flood.new(window: 1, threshold: 100, cooldown: 0),
    LogSentry::Rules::PathScan.new(window: 300, threshold: 3, cooldown: 0)
  ]
)

noisy_count = 0
LogSentry::Parser.new.parse_file(LOG_PATH) do |entry|
  noisy_count += noisy.process(entry).size
end

puts
puts format('  Sogutma 120 sn : %6d uyari', alerts.size)
puts format('  Sogutma  0 sn  : %6d uyari', noisy_count)
if alerts.size.positive?
  puts format('  Fark           : %6.1f kat', noisy_count.to_f / alerts.size)
end

puts <<~NOTE

  Ikisi de teknik olarak DOGRU. Ama ikincisi kullanilamaz: telefonuna
  #{noisy_count} bildirim duserse 200.'den sonra hepsini gormezden
  gelmeye baslarsin. Gercek hayatta SIEM projelerini bitiren sey yanlis
  tespit degil, BILDIRIM YORGUNLUGUDUR.
NOTE

# ---------------------------------------------------------------------------
sub 'BELLEK -- kayan pencere gercekten sinirli mi?'
# ---------------------------------------------------------------------------

puts
puts format('  %-14s %10s %10s %14s %10s',
            'KURAL', 'BAKILAN', 'UYARI', 'TAKIP EDILEN', 'EN BUYUK')
puts format('  %-14s %10s %10s %14s %10s',
            '', 'KAYIT', '', 'ANAHTAR', 'PENCERE')
puts '  ' + '-' * 62
engine.rules.each do |rule|
  s = rule.stats
  puts format('  %-14s %10d %10d %14d %10d',
              s[:rule], s[:evaluated], s[:alerts], s[:tracked_keys], s[:largest_window])
end

puts <<~NOTE

  "TAKIP EDILEN ANAHTAR" = su anda hafizada penceresi tutulan IP sayisi.
  "EN BUYUK PENCERE"     = tek bir IP icin tutulan en fazla olay sayisi.

  Iki sayi da SINIRLI kaliyor -- dosya 3000 satir da olsa 3 milyar da olsa.
  Ustunde iki tavan var:
      MAX_EVENTS_PER_KEY = #{LogSentry::Rules::Base::MAX_EVENTS_PER_KEY}  (bir IP cok istek atarsa)
      MAX_KEYS           = #{LogSentry::Rules::Base::MAX_KEYS}  (cok fazla FARKLI IP gelirse)

  Ikincisi kritik: DDoS'u tespit etmek icin yazdigin kod, DDoS'un kendisi
  tarafindan RAM tuketilerek oldurulemez.
NOTE

title 'SONUC'
puts <<~SUMMARY

  Adim 2'de saldirganlari tablolara bakip GOZUMUZLE secmistik.
  Artik kararlari kod veriyor -- ve gerekcesiyle birlikte veriyor.

  Elimizdeki boru hatti:
      dosya -> TAILER -> PARSER -> ENGINE -> (uyari)
                                             ^ su an sadece ekrana basiyoruz

  Adim 5: bu uyarilar arka planda calisan bir servisten cikip
          telefonuna bildirim olarak gidecek.

SUMMARY
