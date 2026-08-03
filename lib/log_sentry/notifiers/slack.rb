# frozen_string_literal: true

require_relative 'webhook'

module LogSentry
  module Notifiers
    class Slack < Webhook
      def initialize(url_env: 'LOGSENTRY_SLACK_WEBHOOK_URL', url: nil, **opts)
        super(url: url, url_env: url_env, format: :slack, **opts)
      end
    end
  end
end
