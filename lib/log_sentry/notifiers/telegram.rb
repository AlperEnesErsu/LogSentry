# frozen_string_literal: true

require_relative 'webhook'

module LogSentry
  module Notifiers
    class Telegram < Webhook
      def initialize(token_env: 'LOGSENTRY_TELEGRAM_BOT_TOKEN', chat_id_env: 'LOGSENTRY_TELEGRAM_CHAT_ID', **opts)
        token = ENV[token_env]
        url = token ? "https://api.telegram.org/bot#{token}/sendMessage" : nil
        super(url: url, format: :telegram, chat_id_env: chat_id_env, **opts)
      end
    end
  end
end
