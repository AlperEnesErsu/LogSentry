# frozen_string_literal: true

# ============================================================================
#  ADIM 5 -- Notifiers ve Supervisor (Bildirim ve Orkestrasyon) Öğrenme Dosyası
# ----------------------------------------------------------------------------
#  Kullanım:  ruby step5_notifiers.rb [log_dosyasi]
#
#  Bu adımda, boru hattının (Tailer -> Parser -> Engine) ürettiği alarmların
#  bildirim kanallarına (Console, File, Webhook) aktarılması ve tüm boru
#  hattının Supervisor (Orkestratör) tarafından yönetilmesi gösterilmektedir.
# ============================================================================

lib_path = File.expand_path('lib', __dir__)
lib_path = File.expand_path('./lib') unless File.exist?(File.join(lib_path, 'log_sentry.rb'))
$LOAD_PATH.unshift(lib_path) unless $LOAD_PATH.include?(lib_path)

require 'log_sentry'

config_path = File.expand_path('config/logsentry.yml', __dir__)
config_path = File.expand_path('config/logsentry.yml') unless File.exist?(config_path)
CONFIG_PATH = config_path

log_path = ARGV[0] || File.expand_path('logs/access.log', __dir__)
log_path = File.expand_path('logs/access.log') unless File.exist?(log_path)
LOG_PATH = log_path

def title(text)
  puts "\n#{'=' * 76}"
  puts text
  puts '=' * 76
end

# ---------------------------------------------------------------------------
title '[1] BİLDİRİM KANALLARI (NOTIFIERS)'
# ---------------------------------------------------------------------------

puts <<~TEXT
  LogSentry, tespit edilen tehditleri birden fazla kanala gönderebilir:
    1. ConsoleNotifier : Ekrana renkli ve biçimlendirilmiş çıktı verir.
    2. FileNotifier    : Alarmları logs/alerts.jsonl dosyasına JSONL formatında yazar.
    3. WebhookNotifier : Telegram veya Slack API'ye HTTP POST isteği gönderir.
TEXT

console_notifier = LogSentry::Notifiers::Console.new(color: true)
file_notifier    = LogSentry::Notifiers::File.new(path: 'logs/demo_alerts.jsonl')

# Test alarmları oluşturalım
alert = LogSentry::Alert.new(
  rule:        :brute_force,
  severity:    :high,
  ip:          '192.168.1.100',
  message:     '60 saniye içinde 15 başarısız giriş denemesi (HTTP 401)',
  count:       15,
  window:      60,
  threshold:   10,
  time:        Time.now,
  evidence:    ['POST /login HTTP/1.1 401']
)

puts "\n[Bildirim Gönderiliyor]"
console_notifier.notify(alert)
file_notifier.notify(alert)

puts "\nFileNotifier Çıktısı (logs/demo_alerts.jsonl):"
puts File.read('logs/demo_alerts.jsonl')
file_notifier.close
File.delete('logs/demo_alerts.jsonl') if File.exist?('logs/demo_alerts.jsonl')

# ---------------------------------------------------------------------------
title '[2] SUPERVISOR: BORU HATTININ DÜMENİ'
# ---------------------------------------------------------------------------

puts <<~TEXT
  Supervisor, bağımsız parçaları (Tailer, Parser, Engine, Notifiers)
  birbirine bağlar. Hiçbir bileşen diğerini doğrudan tanımaz; sadece
  Supervisor hepsini organize eder.

  --once modu ile dosya sonuna gelindiğinde otomatik sonlanır.
TEXT

supervisor = LogSentry::Supervisor.new(
  config: YAML.load_file(CONFIG_PATH),
  config_path: CONFIG_PATH,
  log_file: LOG_PATH,
  from_begin: true,
  once: true,
  quiet: false
)

puts "İzleme başlatılıyor..."
supervisor.run

puts "\n[Çalışma İstatistikleri]"
puts JSON.pretty_generate(supervisor.stats)
