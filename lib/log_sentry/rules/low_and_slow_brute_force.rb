# frozen_string_literal: true

require_relative 'base'

module LogSentry
  module Rules
    class LowAndSlowBruteForce < Base
      DEFAULT_STATUSES = [401, 403].freeze

      def initialize(store: nil, statuses: DEFAULT_STATUSES, severity: :high, **opts)
        # We pass a threshold to super, but we override call anyway.
        # Typically window is larger (e.g., 24 hours = 86400 seconds)
        super(severity: severity, **opts)
        @store = store
        @statuses = Array(statuses).map(&:to_i)
        @mutex = Mutex.new
        @last_seen_time = {}
      end

      def interested?(entry)
        @statuses.include?(entry.status)
      end

      def call(entry)
        @evaluated_count += 1
        return nil unless interested?(entry)

        now = entry.time
        key = key_for(entry)

        measured = nil

        @mutex.synchronize do
          if @store
            # SQLite tamponunu temizle ki son istek de veritabanına yazılsın
            @store.flush

            # Veritabanından son pencere içindeki başarısız giriş denemelerini say
            cutoff = now.to_i - @window
            status_placeholders = @statuses.map { '?' }.join(', ')
            
            sql = "SELECT COUNT(*) FROM events WHERE ip = ? AND status IN (#{status_placeholders}) AND ts >= ? AND ts <= ?"
            params = [entry.ip] + @statuses + [cutoff, now.to_i]

            begin
              measured = @store.db.execute(sql, params).first.first
            rescue StandardError => e
              warn "[LowAndSlow] SQL hatası, RAM penceresine dönülüyor: #{e.message}"
              measured = nil
            end

            if measured
              # Kanıt tamponunu yönet
              ev = (@evidence[key] ||= [])
              ev << entry.raw if entry.raw
              ev.shift while ev.size > 10

              # Bellek sızıntısını önlemek için son görülme zamanlarını kaydet ve temizle
              @last_seen_time[key] = now
              if @last_housekeeping.nil? || (now - @last_housekeeping) >= HOUSEKEEPING_INTERVAL
                @last_housekeeping = now
                cutoff_time = now - @window
                @last_seen_time.delete_if do |k, last_time|
                  if last_time < cutoff_time
                    @evidence.delete(k)
                    true
                  else
                    false
                  end
                end
                @silenced_until.delete_if { |_k, until_time| until_time < now }
              end
            end
          end

          # Eğer veritabanı yoksa veya hata oluştuysa RAM tabanlı kayan pencereyi kullan
          if measured.nil?
            track(key, now, value_for(entry), entry.raw)
            measured = measure(key)
          end
        end

        return nil unless measured > @threshold
        return nil if silenced?(key, now)

        silence!(key, now)
        @alert_count += 1

        build_alert(entry, measured)
      end

      def extra_signature
        [@statuses, @store.nil?]
      end

      def message_for(entry, measured)
        format('Yavas brute force tespiti: %d saniyede %d basarisiz giris denemesi (IP: %s)',
               @window, measured, entry.ip)
      end

      def details_for(entry, _measured)
        {
          last_path:   entry.path,
          user_agent:  entry.user_agent,
          db_backed:   !@store.nil?
        }
      end
    end
  end
end
