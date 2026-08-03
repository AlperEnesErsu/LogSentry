# frozen_string_literal: true

require 'minitest/autorun'

lib_path = File.expand_path('../lib', __dir__)
lib_path = File.expand_path('./lib') unless File.exist?(File.join(lib_path, 'log_sentry.rb'))
$LOAD_PATH.unshift(lib_path) unless $LOAD_PATH.include?(lib_path)

require 'log_sentry/enrichers/geoip'

class GeoIPTest < Minitest::Test
  def setup
    LogSentry::Enrichers::GeoIP.clear_cache!
  end

  def test_local_ip_resolution
    assert_equal 'LOCAL', LogSentry::Enrichers::GeoIP.lookup('127.0.0.1')
    assert_equal 'LOCAL', LogSentry::Enrichers::GeoIP.lookup('10.0.0.5')
    assert_equal 'LOCAL', LogSentry::Enrichers::GeoIP.lookup('192.168.1.1')
  end

  def test_public_ip_resolution
    assert_equal 'TR', LogSentry::Enrichers::GeoIP.lookup('88.243.11.7')
    assert_equal 'RU', LogSentry::Enrichers::GeoIP.lookup('45.155.205.233')
  end

  def test_cache_hits
    assert_equal 'TR', LogSentry::Enrichers::GeoIP.lookup('88.243.11.7')
    # Second lookup should hit cache
    assert_equal 'TR', LogSentry::Enrichers::GeoIP.lookup('88.243.11.7')
  end
end
