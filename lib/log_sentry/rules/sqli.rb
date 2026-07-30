# frozen_string_literal: true

# ============================================================================
#  Rules::Sqli -- SQL Injection (SQLi) Saldırı Tespiti Kuralı
# ----------------------------------------------------------------------------
#  Aynı IP adresinden belirlenen zaman penceresi içinde SQL enjeksiyonu
#  örünntüsü içeren istekler geldiğinde kritik düzeyde uyarı üretir.
# ============================================================================

require_relative 'base'

module LogSentry
  module Rules
    class Sqli < Base
      DEFAULT_PATTERNS = [
        /union\s+select/i,
        /\bor\s+1\s*=\s*1\b/i,
        /'\s*or\s*'/i,
        /information_schema/i,
        /sleep\(\d+\)/i,
        /benchmark\(/i,
        /drop\s+table/i,
        /concat\(/i,
        /into\s+outfile/i
      ].freeze

      # Dokuz ayri kalibi TEK bir regex'te birlestiriyoruz.
      #
      # Neden? Bu kural HER log satirinda calisiyor. Dizi uzerinde donup
      # 9 kez match? cagirmak, metni 9 kez bastan taramak demektir.
      # Regexp.union tek gecisde hepsini arar ve her kalibin kendi
      # bayraklarini (/i) korur.
      PATTERN = Regexp.union(DEFAULT_PATTERNS).freeze

      def initialize(severity: :critical, **opts)
        super(severity: severity, **opts)
      end

      # payload_matches? Base'de: ham satiri ve (gerekiyorsa) yuzde
      # kodlamasi cozulmus halini tarar; ikisini de kodlama hatalarina
      # karsi temizler.
      def interested?(entry)
        payload_matches?(entry, PATTERN)
      end

      def value_for(entry)
        entry.path
      end

      def message_for(entry, measured)
        format('%d saniyede %d adet SQL Injection tespit edildi (son istek: %s)',
               @window, measured, entry.path[0..50])
      end

      def details_for(entry, _measured)
        {
          target_path: entry.path,
          user_agent:  entry.user_agent,
          detected_type: 'SQL Injection'
        }
      end
    end
  end
end
