# frozen_string_literal: true

require 'set'
require_relative 'base'

module LogSentry
  module Rules
    class ThreatIntel < Base
      # High-risk malicious IP threat intelligence feed (mocked/configurable)
      DEFAULT_BLACKLIST = Set.new([
        '45.155.205.233',
        '185.220.101.5',
        '198.51.100.1'
      ]).freeze

      def initialize(store: nil, blacklist: nil, severity: :critical, window: 60, threshold: 0, **opts)
        super(window: window, threshold: threshold, severity: severity, **opts)
        @store = store
        @blacklist = blacklist ? Set.new(blacklist) : DEFAULT_BLACKLIST
      end

      def interested?(entry)
        if @store && @store.threat_ip?(entry.ip)
          return true
        end

        @blacklist.include?(entry.ip)
      end

      def message_for(entry, _measured)
        format('Tehdit istihbarat listesinde kayitli zararli IP tespit edildi: %s', entry.ip)
      end

      def details_for(entry, _measured)
        {
          ip: entry.ip,
          category: 'Threat Intelligence Blacklist / Tor Exit Node'
        }
      end

      def extra_signature
        [@blacklist.to_a.sort, @store.nil?]
      end
    end
  end
end
