# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'

lib_path = File.expand_path('../lib', __dir__)
lib_path = File.expand_path('./lib') unless File.exist?(File.join(lib_path, 'log_sentry.rb'))
$LOAD_PATH.unshift(lib_path) unless $LOAD_PATH.include?(lib_path)

require 'log_sentry'
require 'log_sentry/web/app'
require 'log_sentry/store'
require 'rack/mock'

class WebAuthTest < Minitest::Test
  def setup
    @dir = Dir.mktmpdir('logsentry-webauth')
    @store = LogSentry::Store.new(path: File.join(@dir, 'test.db'))

    @app = LogSentry::Web::App
    @app.set :store, @store
    @app.set :auth_enabled, true
    @app.set :auth_user, 'admin'
    @app.set :auth_pass, 'adminpass'
    @app.set :auth_viewer_user, 'viewer'
    @app.set :auth_viewer_pass, 'viewerpass'
    @app.set :read_only, false # Allow post requests for testing RBAC
    @app.set :rate_limit_enabled, false

    # Dummy POST route inside app for RBAC testing
    @app.post '/test-write' do
      'OK'
    end

    @request = Rack::MockRequest.new(@app)
  end

  def teardown
    @app.set :auth_enabled, false
    @store.close
    FileUtils.remove_entry(@dir) if File.exist?(@dir)
  end

  def test_unauthorized_access
    res = @request.get('/')
    assert_equal 401, res.status
    assert_match(/WWW-Authenticate/i, res.headers.keys.join(','))
  end

  def test_admin_access_get
    env = { 'HTTP_AUTHORIZATION' => 'Basic ' + ["admin:adminpass"].pack('m0') }
    res = @request.get('/', env)
    assert_equal 200, res.status
  end

  def test_admin_access_post
    env = { 'HTTP_AUTHORIZATION' => 'Basic ' + ["admin:adminpass"].pack('m0') }
    res = @request.post('/test-write', env)
    assert_equal 200, res.status
  end

  def test_viewer_access_get
    env = { 'HTTP_AUTHORIZATION' => 'Basic ' + ["viewer:viewerpass"].pack('m0') }
    res = @request.get('/', env)
    assert_equal 200, res.status
  end

  def test_viewer_denied_post
    env = { 'HTTP_AUTHORIZATION' => 'Basic ' + ["viewer:viewerpass"].pack('m0') }
    res = @request.post('/test-write', env)
    # RBAC halts with 403
    assert_equal 403, res.status
    assert_match(/Yetkiniz bu islem icin yetersizdir/, res.body)
  end
end
