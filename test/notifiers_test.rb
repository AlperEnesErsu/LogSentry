# frozen_string_literal: true

require 'minitest/autorun'

lib_path = File.expand_path('../lib', __dir__)
lib_path = File.expand_path('./lib') unless File.exist?(File.join(lib_path, 'log_sentry.rb'))
$LOAD_PATH.unshift(lib_path) unless $LOAD_PATH.include?(lib_path)

require 'log_sentry/alert'
require 'log_sentry/notifiers/telegram'
require 'log_sentry/notifiers/slack'

class NotifiersTest < Minitest::Test
  def setup
    @alert = LogSentry::Alert.new(
      rule: :sqli,
      severity: :critical,
      ip: '10.0.0.1',
      message: 'SQL Injection tespit edildi',
      time: Time.now,
      count: 1,
      threshold: 0,
      window: 60,
      details: {},
      evidence: []
    )
  end

  def test_telegram_notifier_initialization
    ENV['LOGSENTRY_TELEGRAM_BOT_TOKEN'] = 'test_token'
    ENV['LOGSENTRY_TELEGRAM_CHAT_ID']   = 'test_chat'
    notifier = LogSentry::Notifiers::Telegram.new

    refute_nil notifier
    assert_equal :telegram, notifier.instance_variable_get(:@format)
  ensure
    ENV.delete('LOGSENTRY_TELEGRAM_BOT_TOKEN')
    ENV.delete('LOGSENTRY_TELEGRAM_CHAT_ID')
  end

  def test_slack_notifier_initialization
    ENV['LOGSENTRY_SLACK_WEBHOOK_URL'] = 'https://hooks.slack.com/services/test'
    notifier = LogSentry::Notifiers::Slack.new

    refute_nil notifier
    assert_equal :slack, notifier.instance_variable_get(:@format)
  ensure
    ENV.delete('LOGSENTRY_SLACK_WEBHOOK_URL')
  end
end
