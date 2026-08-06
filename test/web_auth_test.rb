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
    @app.set :auth_exempt_paths, LogSentry::Web::App::DEFAULT_AUTH_EXEMPT_PATHS
    @app.set :metrics_token, nil
    @store.close
    FileUtils.remove_entry(@dir) if File.exist?(@dir)
  end

  def admin_env
    { 'HTTP_AUTHORIZATION' => 'Basic ' + ['admin:adminpass'].pack('m0') }
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

  # ==========================================================================
  #  MAKINE UCLARI -- auth acikken de erisilebilir olmali
  # --------------------------------------------------------------------------
  #  Bu testlerin varlik sebebi somut bir ariza: auth ozelligi eklendiginde
  #  before-filter'i /webhooks/github disindaki HER yolu korumaya basladi.
  #  Sonuc: `web.auth.enabled: true` yazan herkesin docker healthcheck'i
  #  401 aliyor ve konteyner sonsuza kadar "unhealthy" gorunuyordu --
  #  hicbir hata mesaji uretmeden.
  # ==========================================================================

  def test_health_auth_acikken_kimliksiz_erisilebilir
    res = @request.get('/health')
    assert_equal 200, res.status, 'healthcheck auth yuzunden kilitlenmemeli'
    assert_equal true, JSON.parse(res.body)['ok']
  end

  def test_metrics_auth_acikken_kimliksiz_erisilebilir
    res = @request.get('/metrics')
    assert_equal 200, res.status, 'Prometheus kazicisi Basic auth tasimaz'
    assert_match(/logsentry_up 1/, res.body)
  end

  # Muafiyet, sayaclari herkese acmak DEGIL: kimliksiz istekte /health
  # yalnizca {ok, version} donmeli, olay/alarm sayilari gorunmemeli.
  def test_health_kimliksiz_istekte_sayaclari_gizler
    body = JSON.parse(@request.get('/health').body)
    refute body.key?('store'), 'kimliksiz /health sayac sizdirmamali'
    assert body.key?('version')
  end

  def test_health_kimlikli_istekte_sayaclari_gosterir
    body = JSON.parse(@request.get('/health', admin_env).body)
    assert body.key?('store'), 'kimligini kanitlayan sayaclari gorebilmeli'
  end

  # Muaf olmayan yollar korunmaya devam etmeli -- muafiyet listesi
  # yanlislikla genislerse bu test yakalar.
  def test_muafiyet_diger_yollari_acmaz
    assert_equal 401, @request.get('/alerts').status
    assert_equal 401, @request.get('/explorer').status
  end

  # --- /metrics tasiyici token ----------------------------------------------

  def test_metrics_token_tanimliysa_zorunlu
    @app.set :metrics_token, 'gizli-token'
    assert_equal 401, @request.get('/metrics').status
  end

  def test_metrics_token_dogruysa_gecer
    @app.set :metrics_token, 'gizli-token'
    res = @request.get('/metrics', 'HTTP_AUTHORIZATION' => 'Bearer gizli-token')
    assert_equal 200, res.status
  end

  def test_metrics_token_yanlissa_reddedilir
    @app.set :metrics_token, 'gizli-token'
    res = @request.get('/metrics', 'HTTP_AUTHORIZATION' => 'Bearer yanlis')
    assert_equal 401, res.status
  end

  # ==========================================================================
  #  BOS PAROLA HICBIR ZAMAN GECERLI DEGIL
  # --------------------------------------------------------------------------
  #  Onceki surumde auth_enabled: true ama parola tanimsizken
  #  secure_compare(password, "") calisiyordu -- yani "admin" adiyla ve BOS
  #  parolayla giris yapilabiliyordu. Auth'u ACMAK onu KAPATIYORDU.
  # ==========================================================================
  def test_bos_parola_ile_giris_yapilamaz
    @app.set :auth_pass, nil
    @app.set :auth_viewer_pass, nil
    env = { 'HTTP_AUTHORIZATION' => 'Basic ' + ['admin:'].pack('m0') }
    assert_equal 401, @request.get('/', env).status
  ensure
    @app.set :auth_pass, 'adminpass'
    @app.set :auth_viewer_pass, 'viewerpass'
  end
end
