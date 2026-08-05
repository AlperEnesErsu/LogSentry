# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'time'
lib_path = File.expand_path('../lib', __dir__)
lib_path = File.expand_path('./lib') unless File.exist?(File.join(lib_path, 'log_sentry.rb'))
$LOAD_PATH.unshift(lib_path) unless $LOAD_PATH.include?(lib_path)

require 'log_sentry/entry'
require 'log_sentry/alert'
require 'log_sentry/store'
require 'log_sentry/rules/threat_intel'

class ThreatIntelDbTest < Minitest::Test
  T0 = Time.new(2026, 7, 29, 14, 0, 0, '+03:00')

  def setup
    @dir = Dir.mktmpdir('logsentry-threatdb')
    @db_path = File.join(@dir, 'test.db')
    @store = LogSentry::Store.new(path: @db_path)
    @rule = LogSentry::Rules::ThreatIntel.new(store: @store, window: 60, threshold: 0, blacklist: ['8.8.8.8'])
  end

  def teardown
    @store&.close
    FileUtils.remove_entry(@dir) if @dir && File.exist?(@dir)
  end

  def test_store_threat_intel_methods
    refute @store.threat_ip?('1.1.1.1')

    @store.add_threat_ip('1.1.1.1', 'tor')
    assert @store.threat_ip?('1.1.1.1')

    @store.clear_threat_intel!(source: 'tor')
    refute @store.threat_ip?('1.1.1.1')
  end

  def test_rule_uses_database
    # 1.1.1.1 is not in the static blacklist (which only contains 8.8.8.8 here)
    entry_clean = LogSentry::Entry.new(ip: '1.1.1.1', time: T0, status: 200)
    assert_nil @rule.call(entry_clean)

    # Register in DB
    @store.add_threat_ip('1.1.1.1', 'tor')

    entry_threat = LogSentry::Entry.new(ip: '1.1.1.1', time: T0, status: 200)
    alert = @rule.call(entry_threat)
    refute_nil alert
    assert_equal :threat_intel, alert.rule
  end

  def test_rule_falls_back_to_static_blacklist_when_db_present_but_no_match
    # 8.8.8.8 is in the static blacklist
    entry = LogSentry::Entry.new(ip: '8.8.8.8', time: T0, status: 200)
    alert = @rule.call(entry)

    refute_nil alert
    assert_equal :threat_intel, alert.rule
  end

  def test_rule_falls_back_to_static_blacklist_when_db_nil
    rule_no_db = LogSentry::Rules::ThreatIntel.new(store: nil, window: 60, threshold: 0, blacklist: ['9.9.9.9'])
    
    entry_threat = LogSentry::Entry.new(ip: '9.9.9.9', time: T0, status: 200)
    alert = rule_no_db.call(entry_threat)

    refute_nil alert
    assert_equal :threat_intel, alert.rule
  end
end
