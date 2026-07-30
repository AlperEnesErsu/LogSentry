# frozen_string_literal: true

# ============================================================================
#  Rules::Sqli -- SQL Injection (SQLi) Saldırı Tespiti Kuralı
# ----------------------------------------------------------------------------
#  Aynı IP adresinden belirlenen zaman penceresi içinde SQL enjeksiyonu
#  örünntüsü içeren istekler geldiğinde kritik düzeyde uyarı üretir.
# ============================================================================

require 'cgi'
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

      def initialize(severity: :critical, **opts)
        super(severity: severity, **opts)
        @patterns = DEFAULT_PATTERNS
      end

      def interested?(entry)
        text = "#{entry.path} #{entry.raw}"
        decoded = CGI.unescape(text) rescue text
        @patterns.any? { |pattern| pattern.match?(text) || pattern.match?(decoded) }
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
