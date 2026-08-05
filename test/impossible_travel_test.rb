# frozen_string_literal: true

require 'minitest/autorun'
lib_path = File.expand_path('../lib', __dir__)
lib_path = File.expand_path('./lib') unless File.exist?(File.join(lib_path, 'log_sentry.rb'))
$LOAD_PATH.unshift(lib_path) unless $LOAD_PATH.include?(lib_path)

require 'log_sentry/entry'
require 'log_sentry/alert'
require 'log_sentry/enrichers/geoip'
require 'log_sentry/rules/impossible_travel'

class ImpossibleTravelTest < Minitest::Test
  def setup
    LogSentry::Enrichers::GeoIP.clear_cache!
    LogSentry::Enrichers::GeoIP.load_ranges([
      { subnet: '88.243.0.0/16', country: 'TR' },
      { subnet: '45.155.0.0/16', country: 'RU' },
      { subnet: '198.51.100.0/24', country: 'US' }
    ])
    @rule = LogSentry::Rules::ImpossibleTravel.new(window: 3600, cooldown: 60)
  end

  def teardown
    LogSentry::Enrichers::GeoIP.clear_cache!
  end

  def test_skips_local_and_unknown_countries
    entry1 = LogSentry::Entry.new(
      ip: '127.0.0.1', # LOCAL
      time: Time.now,
      user_agent: 'Mozilla/5.0 Chrome',
      raw: 'raw1'
    )
    assert_nil @rule.call(entry1)

    entry2 = LogSentry::Entry.new(
      ip: '8.8.4.4', # UNKNOWN
      time: Time.now,
      user_agent: 'Mozilla/5.0 Chrome',
      raw: 'raw2'
    )
    assert_nil @rule.call(entry2)
  end

  def test_skips_automated_bots
    entry1 = LogSentry::Entry.new(
      ip: '88.243.1.1', # TR
      time: Time.now,
      user_agent: 'python-requests/2.31.0', # automated
      raw: 'raw1'
    )
    assert_nil @rule.call(entry1)
  end

  def test_triggers_impossible_travel_alert
    t0 = Time.now

    entry1 = LogSentry::Entry.new(
      ip: '88.243.1.1', # TR
      time: t0,
      user_agent: 'Mozilla/5.0 Chrome',
      raw: 'raw1'
    )
    assert_nil @rule.call(entry1)

    # 10 minutes later, same User-Agent from US
    entry2 = LogSentry::Entry.new(
      ip: '198.51.100.5', # US
      time: t0 + 600,
      user_agent: 'Mozilla/5.0 Chrome',
      raw: 'raw2'
    )

    alert = @rule.call(entry2)
    refute_nil alert
    assert_equal :impossible_travel, alert.rule
    assert_equal 'US', alert.details[:to_country]
    assert_equal 'TR', alert.details[:from_country]
    assert_equal 600, alert.details[:time_difference_seconds]
  end

  def test_respects_cooldown
    t0 = Time.now

    entry1 = LogSentry::Entry.new(ip: '88.243.1.1', time: t0, user_agent: 'Mozilla/5.0 Chrome', raw: 'raw1')
    @rule.call(entry1)

    entry2 = LogSentry::Entry.new(ip: '198.51.100.5', time: t0 + 10, user_agent: 'Mozilla/5.0 Chrome', raw: 'raw2')
    alert = @rule.call(entry2)
    refute_nil alert # Triggers first alert

    # Third entry right after (should be in cooldown)
    entry3 = LogSentry::Entry.new(ip: '45.155.1.1', time: t0 + 20, user_agent: 'Mozilla/5.0 Chrome', raw: 'raw3')
    assert_nil @rule.call(entry3)
  end
end
