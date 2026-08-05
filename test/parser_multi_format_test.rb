# frozen_string_literal: true

require 'minitest/autorun'
lib_path = File.expand_path('../lib', __dir__)
lib_path = File.expand_path('./lib') unless File.exist?(File.join(lib_path, 'log_sentry.rb'))
$LOAD_PATH.unshift(lib_path) unless $LOAD_PATH.include?(lib_path)

require 'log_sentry/parser'
require 'log_sentry/entry'

class ParserMultiFormatTest < Minitest::Test
  def test_iis_log_parsing
    parser = LogSentry::Parser.new(format: :iis)

    line = '2026-07-01 10:00:05 66.66.66.66 POST /login 401 123 "Mozilla/5.0"'
    entry = parser.parse(line)

    refute_nil entry
    assert_equal '66.66.66.66', entry.ip
    assert_equal 'POST', entry.http_method
    assert_equal '/login', entry.path
    assert_equal 401, entry.status
    assert_equal 123, entry.bytes
    assert_equal 'Mozilla/5.0', entry.user_agent
    assert_equal Time.new(2026, 7, 1, 10, 0, 5), entry.time
  end

  def test_ssh_log_parsing_failed
    parser = LogSentry::Parser.new(format: :ssh)

    line = 'Jul 29 14:39:25 server sshd[12345]: Failed password for invalid user admin from 198.51.100.5 port 54321 ssh2'
    entry = parser.parse(line)

    refute_nil entry
    assert_equal '198.51.100.5', entry.ip
    assert_equal 'POST', entry.http_method
    assert_equal '/ssh/login', entry.path # Default path
    assert_equal 401, entry.status # Failed -> 401
    assert_equal 'sshd', entry.user_agent
    assert_equal 'sshd', entry.user_agent
  end

  def test_ssh_log_parsing_accepted
    parser = LogSentry::Parser.new(format: :ssh)

    line = 'Jul 29 14:39:25 server sshd[12345]: Accepted password for root from 1.2.3.4 port 12345 ssh2'
    entry = parser.parse(line)

    refute_nil entry
    assert_equal '1.2.3.4', entry.ip
    assert_equal 'POST', entry.http_method
    assert_equal '/ssh/login', entry.path
    assert_equal 200, entry.status # Accepted -> 200
  end
end
