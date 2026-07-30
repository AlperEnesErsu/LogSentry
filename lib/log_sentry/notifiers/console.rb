# frozen_string_literal: true

# ============================================================================
#  ADIM 5b -- ConsoleNotifier: ekrana yazar
# ============================================================================

require_relative 'base'

module LogSentry
  module Notifiers
    class Console < Base
      # ANSI renk kodlari. Terminal bunlari renk olarak yorumlar.
      # \e[31m = kirmizi baslat, \e[0m = varsayilana don.
      COLORS = {
        critical: "\e[1;37;41m",  # beyaz yazi, kirmizi zemin
        high:     "\e[1;31m",     # parlak kirmizi
        medium:   "\e[1;33m",     # sari
        low:      "\e[0;36m"      # camgobegi
      }.freeze
      RESET = "\e[0m"

      def initialize(color: true, io: $stdout, **opts)
        super(**opts)
        # Renkleri sadece gercek bir terminale yaziyorsak kullaniyoruz.
        #
        # tty? = "bu cikis bir terminale mi bagli?"
        # Cikti bir dosyaya veya pipe'a yonlendirilmisse (logsentry > out.log)
        # renk kodlari metnin icine cop olarak yazilir: "\e[1;31mHIGH\e[0m".
        # Daemon modunda cikti her zaman dosyaya gider, yani bu kontrol
        # olmadan log dosyalarimiz okunamaz hale gelirdi.
        @color = color && io.tty?
        @io    = io
      end

      private

      def deliver(alert)
        tint = @color ? COLORS.fetch(alert.severity, '') : ''
        off  = @color ? RESET : ''

        @io.puts
        @io.puts "#{tint}#{'=' * 72}#{off}"
        @io.puts format('%sUYARI  %-8s  %s%s',
                        tint, alert.severity.to_s.upcase, alert.rule, off)
        @io.puts "#{'-' * 72}"
        @io.puts format('  zaman   : %s', alert.time)
        @io.puts format('  kaynak  : %s', alert.ip)
        @io.puts format('  durum   : %s', alert.message)
        @io.puts format('  olculen : %d  (esik: %d, pencere: %d sn)',
                        alert.count, alert.threshold, alert.window)

        if alert.details && !alert.details.empty?
          @io.puts '  detay   :'
          alert.details.each { |key, value| @io.puts "      #{key}: #{value.inspect}" }
        end

        if alert.evidence && !alert.evidence.empty?
          @io.puts '  kanit   :'
          alert.evidence.each { |raw| @io.puts "      #{raw[0, 100]}" }
        end

        @io.puts "#{tint}#{'=' * 72}#{off}"

        # flush: tamponu hemen bosalt.
        #
        # Ruby cikti tamponlar. Terminale yazarken satir satir bosaltir ama
        # DOSYAYA yazarken 8 KB dolana kadar bekler. Daemon modunda cikti
        # dosyaya gittigi icin, bu olmadan alarm dosyaya dakikalar sonra
        # duserdi -- ya da process cokerse HIC dusmezdi.
        @io.flush
      end
    end
  end
end
