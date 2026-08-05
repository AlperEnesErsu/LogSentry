# frozen_string_literal: true

require_relative 'base'
require_relative '../enrichers/geoip'

module LogSentry
  module Rules
    class ImpossibleTravel < Base
      def initialize(severity: :high, window: 3600, **opts)
        super(window: window, threshold: 0, severity: severity, **opts)
        @last_seen = {}
        @mutex = Mutex.new
      end

      def interested?(entry)
        return false if entry.user_agent.nil? || entry.user_agent.empty?
        return false if automated_agent?(entry.user_agent)

        true
      end

      def call(entry)
        @evaluated_count += 1
        return nil unless interested?(entry)

        user_agent = entry.user_agent
        country = LogSentry::Enrichers::GeoIP.lookup(entry.ip)

        return nil if country == 'LOCAL' || country == 'UNKNOWN'

        now = entry.time
        alert = nil

        @mutex.synchronize do
          last = @last_seen[user_agent]

          if last && last[:country] != country
            time_diff = (now - last[:time]).abs

            if time_diff < @window && time_diff > 0
              key = user_agent
              unless silenced?(key, now)
                silence!(key, now)
                @alert_count += 1

                alert = LogSentry::Alert.new(
                  rule: @name,
                  severity: @severity,
                  ip: entry.ip,
                  message: format('Imkansiz seyahat tespiti: %s ayni User-Agent ile %d saniyede %s -> %s seyahat etti.',
                                  entry.ip, time_diff.to_i, last[:country], country),
                  time: now,
                  count: 1,
                  threshold: 0,
                  window: @window,
                  details: {
                    user_agent: user_agent,
                    from_country: last[:country],
                    to_country: country,
                    from_ip: last[:ip],
                    to_ip: entry.ip,
                    time_difference_seconds: time_diff.to_i
                  },
                  evidence: [last[:raw], entry.raw].compact
                )
              end
            end
          end

          @last_seen[user_agent] = {
            country: country,
            time: now,
            ip: entry.ip,
            raw: entry.raw
          }
        end

        alert
      end

      def extra_signature
        nil
      end

      private

      AUTOMATION_HINTS = /curl|wget|python|go-http|java|ruby|perl|libwww|
                          httpie|postman|hydra|medusa|patator|sqlmap|zabbix|prometheus|uptime|ping/xi

      def automated_agent?(agent)
        return false if agent.nil?

        AUTOMATION_HINTS.match?(agent)
      end
    end
  end
end
