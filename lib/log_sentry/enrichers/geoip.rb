# frozen_string_literal: true

require 'ipaddr'

module LogSentry
  module Enrichers
    class GeoIP
      # Fast LRU Cache for IP -> Country code
      CACHE_SIZE = 10_000
      @cache = {}
      @mutex = Mutex.new

      PRIVATE_RANGES = [
        IPAddr.new('10.0.0.0/8'),
        IPAddr.new('172.16.0.0/12'),
        IPAddr.new('192.168.0.0/16'),
        IPAddr.new('127.0.0.0/8'),
        IPAddr.new('::1/128'),
        IPAddr.new('fc00::/7')
      ].freeze

      def self.lookup(ip_str)
        return 'LOCAL' if ip_str.nil? || ip_str.empty?

        @mutex.synchronize do
          return @cache[ip_str] if @cache.key?(ip_str)

          country = resolve(ip_str)
          @cache[ip_str] = country
          @cache.shift if @cache.size > CACHE_SIZE
          country
        end
      end

      def self.clear_cache!
        @mutex.synchronize { @cache.clear }
      end

      private_class_method def self.resolve(ip_str)
        ip = IPAddr.new(ip_str)
        return 'LOCAL' if PRIVATE_RANGES.any? { |range| range.include?(ip) }

        # Mocked deterministic offline lookup for external IPs (or Cloudflare/DNS IP ranges)
        first_octet = ip_str.split('.').first.to_i rescue 0
        case first_octet
        when 1, 104 then 'US'
        when 45, 185 then 'RU'
        when 88, 176, 212 then 'TR'
        when 5, 31, 95 then 'DE'
        else 'GLOBAL'
        end
      rescue IPAddr::InvalidAddressError, ArgumentError
        'UNKNOWN'
      end
    end
  end
end
