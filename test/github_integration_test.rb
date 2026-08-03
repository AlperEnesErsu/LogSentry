# frozen_string_literal: true

require 'minitest/autorun'
require 'json'
require 'openssl'
require 'rack/mock'

lib_path = File.expand_path('../lib', __dir__)
lib_path = File.expand_path('./lib') unless File.exist?(File.join(lib_path, 'log_sentry.rb'))
$LOAD_PATH.unshift(lib_path) unless $LOAD_PATH.include?(lib_path)

require 'log_sentry'
require 'log_sentry/web/app'
require 'log_sentry/fetchers/github'

class GitHubIntegrationTest < Minitest::Test
  def setup
    @app = LogSentry::Web::App
    @request = Rack::MockRequest.new(@app)
  end

  def test_github_webhook_receive_ping_event
    payload = JSON.generate({
      zen: 'Responsive is better than fast.',
      repository: { full_name: 'AlperEnesErsu/LogSentry' },
      sender: { login: 'AlperEnesErsu' }
    })

    res = @request.post('/webhooks/github',
      input: payload,
      'CONTENT_TYPE' => 'application/json',
      'HTTP_X_GITHUB_EVENT' => 'ping'
    )

    assert_equal 200, res.status
    data = JSON.parse(res.body)
    assert_equal 'ok', data['status']
    assert_equal 'ping', data['event']
    assert_equal 'AlperEnesErsu/LogSentry', data['repo']
  end

  def test_github_webhook_hmac_signature_verification
    ENV['LOGSENTRY_GITHUB_WEBHOOK_SECRET'] = 'mysecret'
    payload = JSON.generate({ repository: { full_name: 'test/repo' } })

    # 1. Invalid signature -> 401
    res_bad = @request.post('/webhooks/github',
      input: payload,
      'CONTENT_TYPE' => 'application/json',
      'HTTP_X_HUB_SIGNATURE_256' => 'sha256=invalid'
    )
    assert_equal 401, res_bad.status

    # 2. Valid signature -> 200
    valid_sig = 'sha256=' + OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha256'), 'mysecret', payload)
    res_good = @request.post('/webhooks/github',
      input: payload,
      'CONTENT_TYPE' => 'application/json',
      'HTTP_X_HUB_SIGNATURE_256' => valid_sig,
      'HTTP_X_GITHUB_EVENT' => 'push'
    )
    assert_equal 200, res_good.status
  ensure
    ENV.delete('LOGSENTRY_GITHUB_WEBHOOK_SECRET')
  end

  def test_github_fetcher_nil_repo
    events = LogSentry::Fetchers::GitHub.fetch_events(repo: nil)
    assert_equal [], events
  end
end
