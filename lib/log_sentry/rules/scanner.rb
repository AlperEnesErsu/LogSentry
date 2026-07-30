# frozen_string_literal: true

# ============================================================================
#  Rules::Scanner -- Otomatik Tarayıcı / Saldırı Aracı Tespiti Kuralı
# ----------------------------------------------------------------------------
#  User-Agent başlığı bilinen otomatik zafiyet tarama araçları (sqlmap, nikto,
#  nmap, gobuster vb.) ile eşleşen istekleri yakalar.
# ============================================================================

require_relative 'base'

module LogSentry
  module Rules
    class Scanner < Base
      DEFAULT_AGENTS = [
        'sqlmap', 'nikto', 'nmap', 'gobuster', 'dirbuster',
        'masscan', 'zgrab', 'netsparker', 'acunetix', 'wpscan'
      ].freeze

      def initialize(agents: DEFAULT_AGENTS, severity: :medium, **opts)
        super(severity: severity, **opts)
        @agents = Array(agents).map(&:downcase)
      end

      def interested?(entry)
        agent = entry.user_agent.to_s.downcase
        return false if agent.empty? || agent == '-'

        @agents.any? { |tool| agent.include?(tool) }
      end

      def value_for(entry)
        entry.user_agent
      end

      def message_for(entry, measured)
        format('%d saniyede %d adet otomatik tarayıcı isteği (User-Agent: %s)',
               @window, measured, entry.user_agent[0..40])
      end

      def details_for(entry, _measured)
        {
          user_agent: entry.user_agent,
          detected_tool: entry.user_agent,
          last_path: entry.path
        }
      end
    end
  end
end
