# frozen_string_literal: true

# ============================================================================
#  ADIM 7 -- Web Arayüzü (Sinatra & SSE Canlı Akış) Öğrenme Dosyası
# ----------------------------------------------------------------------------
#  Kullanım:  ruby step7_web.rb [port]
#
#  Bu adımda, izleme motorunun SQLite veritabanına ve alarmlara yazdığı
#  verilerin Sinatra web uygulaması üzerinden nasıl görselleştirildiği ve
#  Server-Sent Events (SSE) ile canlı akış sağlandığı gösterilmektedir.
# ============================================================================

lib_path = File.expand_path('lib', __dir__)
lib_path = File.expand_path('./lib') unless File.exist?(File.join(lib_path, 'log_sentry.rb'))
$LOAD_PATH.unshift(lib_path) unless $LOAD_PATH.include?(lib_path)

require 'log_sentry'
require 'log_sentry/store'
require 'log_sentry/archiver'
require 'log_sentry/web/app'

PORT        = (ARGV[0] || 4567).to_i
config_path = File.expand_path('config/logsentry.yml', __dir__)
config_path = File.expand_path('config/logsentry.yml') unless File.exist?(config_path)
CONFIG_PATH = config_path

def title(text)
  puts "\n#{'=' * 76}"
  puts text
  puts '=' * 76
end

title '[1] SINATRA WEB UYGULAMASI HAZIRLANIYOR'

config = YAML.load_file(CONFIG_PATH)
db_path = config.dig('storage', 'database') || 'db/logsentry.db'
alert_file = config['alert_file'] || 'logs/alerts.jsonl'

store = LogSentry::Store.new(path: db_path) if File.exist?(db_path)
archiver = LogSentry::Archiver.new(directory: config.dig('archive', 'directory') || 'archive')

# Sinatra uygulama ayarları
LogSentry::Web::App.set :store, store
LogSentry::Web::App.set :archiver, archiver
LogSentry::Web::App.set :alert_file, alert_file
LogSentry::Web::App.set :read_only, true
LogSentry::Web::App.set :port, PORT
LogSentry::Web::App.set :bind, '127.0.0.1'

puts <<~TEXT
  Web Sunucusu Başlatılıyor:
    URL             : http://127.0.0.1:#{PORT}
    Veritabanı      : #{db_path}
    Salt Okunur     : #{LogSentry::Web::App.settings.read_only}
    SSE Canlı Yayın : http://127.0.0.1:#{PORT}/stream

  Tarayıcınızdan açıp Dashboard, Alarmlar ve Explorer ekranlarını inceleyebilirsiniz.
  Durdurmak için Ctrl-C tuşlarına basınız.
TEXT

LogSentry::Web::App.run!
