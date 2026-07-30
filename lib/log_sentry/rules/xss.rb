# frozen_string_literal: true

# ============================================================================
#  Rules::Xss -- Cross-Site Scripting (XSS) ve Komut Enjeksiyonu Tespiti
# ----------------------------------------------------------------------------
#  Aynı IP adresinden HTML/JS zararlı kodları veya sistem komutları içeren
#  istekler tespit edildiğinde yüksek önem düzeyinde uyarı üretir.
# ============================================================================

require 'cgi'
require_relative 'base'

module LogSentry
  module Rules
    class Xss < Base
      DEFAULT_PATTERNS = [
        /<script\b[^>]*>/i,
        /javascript:/i,
        /onload\s*=/i,
        /onerror\s*=/i,
        /eval\(/i,
        /document\.cookie/i,
        /\/etc\/passwd/i,
        /cmd\.exe/i,
        /;\s*cat\s+/i
      ].freeze

      def initialize(severity: :high, **opts)
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
        format('%d saniyede %d adet XSS/Komut enjeksiyonu denemesi tespit edildi',
               @window, measured)
      end

      def details_for(entry, _measured)
        {
          target_path: entry.path,
          user_agent:  entry.user_agent,
          detected_type: 'XSS / Command Injection'
        }
      end
    end
  end
end
