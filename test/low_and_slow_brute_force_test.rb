# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
lib_path = File.expand_path('../lib', __dir__)
lib_path = File.expand_path('./lib') unless File.exist?(File.join(lib_path, 'log_sentry.rb'))
$LOAD_PATH.unshift(lib_path) unless $LOAD_PATH.include?(lib_path)

require 'log_sentry/entry'
require 'log_sentry/alert'
require 'log_sentry/store'
require 'log_sentry/rules/low_and_slow_brute_force'

class LowAndSlowBruteForceTest < Minitest::Test
  T0 = Time.new(2026, 7, 29, 14, 0, 0, '+03:00')

  def setup
    @dir = Dir.mktmpdir('logsentry-lowslow')
    @db_path = File.join(@dir, 'test.db')
    @store = LogSentry::Store.new(path: @db_path)
  end

  def teardown
    @store&.close
    FileUtils.remove_entry(@dir) if @dir && File.exist?(@dir)
  end

  def test_ram_fallback_when_store_nil
    rule = LogSentry::Rules::LowAndSlowBruteForce.new(store: nil, window: 60, threshold: 2, cooldown: 10)

    # 1st failed attempt
    entry1 = LogSentry::Entry.new(ip: '1.2.3.4', time: T0, status: 401, raw: 'raw1')
    assert_nil rule.call(entry1)

    # 2nd failed attempt
    entry2 = LogSentry::Entry.new(ip: '1.2.3.4', time: T0 + 10, status: 401, raw: 'raw2')
    assert_nil rule.call(entry2)

    # 3rd failed attempt (Threshold = 2, so 3 attempts triggers alert)
    entry3 = LogSentry::Entry.new(ip: '1.2.3.4', time: T0 + 20, status: 401, raw: 'raw3')
    alert = rule.call(entry3)

    refute_nil alert
    assert_equal :low_and_slow_brute_force, alert.rule
    assert_equal 3, alert.count
  end

  def test_sqlite_backed_counting
    rule = LogSentry::Rules::LowAndSlowBruteForce.new(store: @store, window: 3600, threshold: 3, cooldown: 60)

    # Insert 3 failed logins to Store
    3.times do |i|
      entry = LogSentry::Entry.new(
        ip: '99.99.99.99',
        time: T0 + (i * 10),
        http_method: 'POST',
        path: '/login',
        status: 401,
        bytes: 100,
        user_agent: 'Chrome',
        raw: "failed login #{i}"
      )
      @store.record_event(entry)
    end
    @store.flush

    # 4th failed login triggers rule
    trigger_entry = LogSentry::Entry.new(
      ip: '99.99.99.99',
      time: T0 + 40,
      http_method: 'POST',
      path: '/login',
      status: 401,
      bytes: 100,
      user_agent: 'Chrome',
      raw: 'triggering failed login'
    )
    # We record it first so it's in the DB count
    @store.record_event(trigger_entry)

    alert = rule.call(trigger_entry)
    refute_nil alert
    assert_equal :low_and_slow_brute_force, alert.rule
    assert_equal 4, alert.count
  end
end
