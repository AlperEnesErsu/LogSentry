# frozen_string_literal: true

# ============================================================================
#  Canli izleyici -- Tailer + Parser'i birlikte calistirir
# ----------------------------------------------------------------------------
#  Boru hattinin su ana kadar insa edilmis hali:
#
#      dosya -> TAILER (adim 3) -> PARSER (adim 2) -> ENGINE (adim 4) -> ekran
#
#  Adim 5'te son istasyon eklenecek: NOTIFIERS (telefonuna bildirim).
#
#  Kullanim:
#    ruby tools/watch.rb                      # logs/access.log
#    ruby tools/watch.rb /tmp/x.log
#    ruby tools/watch.rb --from-begin         # dosyayi bastan oku
#    ruby tools/watch.rb --quiet              # SADECE alarmlari goster
#
#  Durdurmak icin: Ctrl-C
# ============================================================================

require_relative '../lib/log_sentry/tailer'
require_relative '../lib/log_sentry/parser'
require_relative '../lib/log_sentry/engine'

from_begin = ARGV.delete('--from-begin')
quiet      = ARGV.delete('--quiet')
path = ARGV[0] ? File.expand_path(ARGV[0]) : File.expand_path('../logs/access.log', __dir__)

CONFIG = File.expand_path('../config/logsentry.yml', __dir__)

parser = LogSentry::Parser.new
engine = LogSentry::Engine.from_config(CONFIG)
tailer = LogSentry::Tailer.new(path, start: from_begin ? :begin : :end)
alerts = []

# Ctrl-C bastiginda cokerek degil, NAZIKCE cikiyoruz.
# Adim 5'te bunu SIGTERM icin de yapacagiz (graceful shutdown).
Signal.trap('INT') do
  # Sinyal isleyicisi icinde puts yapmak Ruby'de guvenli degildir
  # (kesintiye ugrayan bir I/O'nun ortasina girebilir), o yuzden sadece
  # bayragi indiriyoruz. Ozet mesajini asagida, dongu bittikten sonra
  # yazdiriyoruz.
  tailer.stop
end

puts '=' * 74
puts " IZLENIYOR: #{path}"
puts " Baslangic: #{from_begin ? 'dosyanin basi' : 'dosyanin sonu (tail -f gibi)'}"
puts " Kurallar : #{engine.rules.map(&:name).join(', ')}"
puts " Mod      : #{quiet ? 'sadece alarmlar' : 'tum kayitlar + alarmlar'}"
puts ' Durdurmak icin Ctrl-C'
puts '=' * 74
puts

start = Time.now

tailer.each_line do |line|
  entry = parser.parse(line)

  if entry.nil?
    puts "  [X] #{line[0, 70]}" unless quiet
    next
  end

  unless quiet
    # Gozle secilebilmesi icin basit isaretler
    mark =
      if entry.failed_auth?          then '[401]'
      elsif entry.malformed_request? then '[BOZUK]'
      elsif entry.server_error?      then '[500]'
      elsif entry.client_error?      then '[4xx]'
      else                                '     '
      end

    puts format('  %s %-8s %-16s %-6s %-30s %d',
                mark,
                entry.time.strftime('%H:%M:%S'),
                entry.ip,
                entry.http_method,
                entry.path[0, 30],
                entry.status)
  end

  # ---- ADIM 4: kural motoru ----
  engine.process(entry).each do |alert|
    alerts << alert
    puts
    puts '  ' + ('!' * 70)
    puts format('  !! %-6s %-16s %s',
                alert.severity.to_s.upcase, alert.ip, alert.message)
    puts format('  !! kural: %-14s olculen: %d / esik: %d / pencere: %d sn',
                alert.rule, alert.count, alert.threshold, alert.window)
    alert.details.each { |k, v| puts "  !! #{k}: #{v.inspect}" }
    puts '  !! KANIT:'
    alert.evidence.each { |raw| puts "  !!   #{raw[0, 64]}" }
    puts '  ' + ('!' * 70)
    puts
  end
end

elapsed = Time.now - start
stats   = tailer.stats

puts
puts '=' * 74
puts format(' Sure          : %.1f saniye', elapsed)
puts " Okunan satir  : #{stats[:lines_read]}"
puts " Okunan bayt   : #{stats[:bytes_read]}"
puts " Rotasyon      : #{stats[:rotations]}"
puts " Kesilme       : #{stats[:truncations]}"
puts " Ayristirma    : #{parser.parsed_count} basarili / #{parser.failed_count} basarisiz " \
     "(%#{parser.success_rate})"
puts " URETILEN UYARI: #{alerts.size}"
unless alerts.empty?
  alerts.group_by(&:rule).each do |rule, list|
    puts format('   - %-14s %d', rule, list.size)
  end
end
puts " Takip edilen anahtar: #{engine.tracked_keys}"
puts '=' * 74
