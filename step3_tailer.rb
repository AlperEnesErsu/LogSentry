# frozen_string_literal: true

# ============================================================================
#  ADIM 3 -- Gosterim / ogrenme dosyasi
# ----------------------------------------------------------------------------
#  Bu betik, bir web sunucusunun log yazmasini SIMULE eder ve ayni anda o
#  dosyayi canli izler. Boylece gercek bir sunucuya ihtiyac duymadan tum
#  kenar durumlari (yarim satir, kesilme, rotasyon, yeniden baslatma)
#  gozumuzle gorebiliyoruz.
#
#  Kullanim:
#    ruby step3_tailer.rb                  # logs/live.log uzerinde
#    ruby step3_tailer.rb /tmp/live.log    # baska bir yolda
#
#  DOSYA SISTEMI UYARISI (bunu yasadik):
#  Faz 3 ve 4 (kesilme/rotasyon) gercek dosya sistemi davranisina baglidir
#  ve HER YERDE AYNI CALISMAZ:
#
#    Windows (NTFS)      : acik dosya tasinamaz/kesilemez -> fazlar atlanir
#    WSL + /mnt/c (DrvFs): Windows diskinin WSL'e baglanmis hali. inode ve
#                          rename semantigi gercek Linux gibi DEGIL --
#                          rotasyon dogru algilanmaz. Yaniltici sonuc verir.
#    Gercek Linux FS     : dogru davranis. WSL icinde /tmp bunlardan biridir.
#
#  Bu yuzden rotasyon testini WSL'de /tmp uzerinde yapiyoruz:
#      wsl -d Ubuntu-22.04 ruby step3_tailer.rb /tmp/live.log
#
#  Ders: bir izleme aracini, KOSACAGI dosya sisteminde test etmek zorundasin.
#  "Benim makinemde calisiyor" cumlesinin en sik sebeplerinden biri budur.
# ============================================================================

require_relative 'lib/log_sentry/tailer'
require_relative 'lib/log_sentry/parser'

LIVE_LOG   = ARGV[0] ? File.expand_path(ARGV[0]) : File.expand_path('logs/live.log', __dir__)
STATE_FILE = "#{LIVE_LOG}.pos"

# Temiz baslangic
[LIVE_LOG, STATE_FILE, "#{LIVE_LOG}.1"].each { |f| File.delete(f) if File.exist?(f) }
File.write(LIVE_LOG, '')

def phase(number, title)
  puts "\n#{'─' * 74}"
  puts " FAZ #{number}: #{title}"
  puts '─' * 74
end

def note(text)
  text.each_line { |l| puts "   #{l.chomp}" }
end

# Sunucunun log yazmasini simule eder.
# 'a' modu = append (sona ekle). Bir web sunucusu logu hep boyle yazar.
def emit(path, ip:, method: 'GET', route: '/', status: 200, agent: 'Chrome/126.0')
  stamp = Time.now.strftime('%d/%b/%Y:%H:%M:%S %z')
  File.open(path, 'a') do |f|
    f.puts format('%s - - [%s] "%s %s HTTP/1.1" %d %d "-" "%s"',
                  ip, stamp, method, route, status, rand(200..9000), agent)
  end
end

# ---------------------------------------------------------------------------
#  Tailer'i AYRI BIR THREAD'de calistiriyoruz.
#
#  Neden? Cunku each_line SONSUZ bir dongudur -- ana thread'de cagirsak
#  betigin geri kalani hic calismaz. Gercek serviste bu dogru davranistir
#  (program zaten sadece izleme yapacak), ama burada ayni anda hem yazip
#  hem okumamiz gerekiyor.
#
#  Queue (Thread::Queue), thread'ler arasi guvenli veri aktarimi icin
#  Ruby'nin hazir yapisi. Iki thread ayni diziye yazip okusa veri bozulabilir
#  (race condition); Queue bunu kendi icinde kilitleyerek onler.
# ---------------------------------------------------------------------------
parser   = LogSentry::Parser.new
received = Thread::Queue.new

tailer = LogSentry::Tailer.new(
  LIVE_LOG,
  start: :end,             # tail -f gibi: gecmisi degil, bundan sonrasini izle
  poll_interval: 0.05,     # gosterim icin hizli; uretimde 0.2 makul
  state_file: STATE_FILE
)

reader = Thread.new do
  tailer.each_line { |line| received << line }
end

# Thread'in dosyayi acip sonuna konumlanmasini bekle.
# Beklemezsek ilk satirlari kacirabiliriz -- ve bu bir HATA olmazdi,
# start: :end tam olarak bunu soyluyor ("bundan sonrasini izle").
# Ama gosterimde kafa karistirir, o yuzden hazir olmasini bekliyoruz.
sleep 0.3

# Kuyrugu bosaltip gorulen satirlari ekrana basar.
def drain(queue, parser)
  count = 0
  until queue.empty?
    line  = queue.pop
    entry = parser.parse(line)
    count += 1

    if entry.nil?
      puts "   [X] AYRISTIRILAMADI: #{line[0, 60]}"
    else
      flag = entry.failed_auth? ? '  <-- basarisiz giris' : ''
      puts format('   [>] %-15s %-6s %-22s %d%s',
                  entry.ip, entry.http_method, entry.path, entry.status, flag)
    end
  end
  count
end

puts '=' * 74
puts ' ADIM 3 -- CANLI IZLEME (tail -f mantigi)'
puts '=' * 74
note "Izlenen dosya : #{LIVE_LOG}"
note "Konum kaydi   : #{STATE_FILE}"

# ===========================================================================
phase 1, 'Normal canli akis'
# ===========================================================================
note <<~TEXT
  Dosyaya satir satir yaziyoruz. Tailer dosyanin sonuna yapismis halde
  bekliyor ve her yeni satiri aninda yakaliyor.
TEXT
puts

5.times do |i|
  emit(LIVE_LOG, ip: "10.0.0.#{i + 1}", route: ['/', '/about', '/api/v1/users'].sample)
  sleep 0.15
end
sleep 0.3
drain(received, parser)

# ===========================================================================
phase 2, 'YARIM SATIR -- en sinsi hata'
# ===========================================================================
note <<~TEXT
  Sunucu satiri yazmanin ORTASINDA. Diske sadece yarisi dustu.
  (Gercek hayatta yuksek trafikte surekli olur.)

  Naif bir tailer bu yarim satiri hemen Parser'a verir; kalip uymaz,
  atilir. Sonra kalan yarisi AYRI bir satir gibi gelir, o da atilir.
  Sonuc: 1 gercek olay -> 2 bozuk kayit -> ISTEK KAYBI.
TEXT
puts

# Satir sonu karakteri OLMADAN yaziyoruz -- yarim satir
half = '45.155.205.233 - - [' + Time.now.strftime('%d/%b/%Y:%H:%M:%S %z') +
       '] "POST /log'
File.open(LIVE_LOG, 'a') { |f| f.write(half) }

sleep 0.4
seen = drain(received, parser)
note seen.zero? ? '[v] Hicbir sey uretilmedi -- tampon bekliyor. DOGRU.' \
                : "[X] #{seen} satir uretildi, olmamaliydi!"

note 'Simdi sunucu satirin geri kalanini yaziyor...'
puts
File.open(LIVE_LOG, 'a') { |f| f.puts 'in HTTP/1.1" 401 178 "-" "python-requests/2.31.0"' }
sleep 0.3
drain(received, parser)
note '[v] Iki parca birlestirildi ve TEK, saglam bir kayit uretildi.'

# ===========================================================================
phase 3, 'KESILME (logrotate copytruncate modu)'
# ===========================================================================
note <<~TEXT
  logrotate "copytruncate" modunda dosyayi kopyalar, sonra ICERIGINI
  sifirlar. Dosya ayni kalir (inode degismez) ama boyut 0 olur.

  Bizim okuma konumumuz artik dosya boyutundan BUYUK. Bunu fark etmezsek
  bir daha hicbir sey okuyamayiz -- cunku dosyanin sonundan otesini
  bekliyor oluruz.
TEXT
puts

before = File.size(LIVE_LOG)

truncated = begin
  File.truncate(LIVE_LOG, 0)     # <- copytruncate simulasyonu
  true
rescue SystemCallError => e
  note "[!] Bu platformda simule edilemiyor: #{e.class}"
  note '    Windows, BASKA bir process tarafindan acik tutulan dosyanin'
  note '    kesilmesine izin vermez. Ayni kisit rotasyon icin de gecerli'
  note '    (Faz 4). Bu yuzden logrotate tarzi log yonetimi Windows'
  note '    sunucularinda zaten farkli calisir.'
  note '    Gercek testi WSL/Linux tarafinda:'
  note '      wsl -d Ubuntu-22.04 ruby step3_tailer.rb'
  false
end

if truncated
  note "Dosya boyutu: #{before} bayt -> #{File.size(LIVE_LOG)} bayt"
  sleep 1.3                      # rotasyon kontrolu saniyede bir calisiyor

  emit(LIVE_LOG, ip: '88.243.11.7', route: '/products')
  emit(LIVE_LOG, ip: '88.243.11.7', route: '/products/42')
  sleep 0.4
  seen = drain(received, parser)
  note seen == 2 ? '[v] Kesilme algilandi, basa donuldu, yeni satirlar gorunuyor.' \
                 : "[X] #{seen} satir gorundu (2 olmaliydi)"
  note "Sayaclar: kesilme=#{tailer.truncations}"
end

# ===========================================================================
phase 4, 'ROTASYON (logrotate create modu)'
# ===========================================================================
note <<~TEXT
  logrotate varsayilan modda dosyayi YENIDEN ADLANDIRIR ve yerine yeni,
  bos bir dosya olusturur:

      access.log -> access.log.1
      access.log <- yeni bos dosya

  Unix'te dosya tutucusu ISME degil INODE'a baglidir. Bizim acik
  tutucumuz TASINAN dosyayi isaret etmeye devam eder. Fark etmezsek
  yeni dosyaya yazilan hicbir seyi gormeyiz -- ama servis "calisiyor"
  gorunur. Izleme sistemlerinin en klasik, en sinsi arizasi budur.
TEXT
puts

rotated = begin
  File.rename(LIVE_LOG, "#{LIVE_LOG}.1")
  File.write(LIVE_LOG, '')
  true
rescue SystemCallError => e
  note "[!] Bu platformda simule edilemiyor: #{e.class}"
  note '    Windows, ACIK bir dosyanin yeniden adlandirilmasina izin vermez.'
  note '    Bu yuzden Windows sunucularinda logrotate tarzi rotasyon zaten'
  note '    farkli calisir. Gercek testi WSL/Linux tarafinda yapacagiz:'
  note '      wsl -d Ubuntu-22.04 ruby step3_tailer.rb'
  false
end

if rotated
  sleep 1.3
  emit(LIVE_LOG, ip: '193.34.76.101', route: '/admin', status: 403,
       agent: 'sqlmap/1.8#stable')
  sleep 0.4
  seen = drain(received, parser)
  note seen == 1 ? '[v] Rotasyon algilandi, YENI dosya izlenmeye baslandi.' \
                 : "[X] #{seen} satir gorundu (1 olmaliydi)"
  note "Sayaclar: rotasyon=#{tailer.rotations}, yeniden_acma=#{tailer.reopens}"
end

# ===========================================================================
phase 5, 'YENIDEN BASLATMA GUVENLIGI (checkpoint)'
# ===========================================================================
note <<~TEXT
  Servisi guncellemek icin durdurup yeniden baslatiyoruz. Arada gecen
  surede yazilan satirlara ne olacak?

    Konum kaydi YOKSA -> o satirlar sonsuza kadar kaybolur.
                         Tam o anda saldiri varsa hic gormedin.
    Konum kaydi VARSA -> tam biraktigin yerden devam.

  Filebeat'in "registry", Promtail'in "positions.yaml" dosyasi bu isi yapar.
TEXT
puts

tailer.stop
reader.join
note "Servis durdu. Toplam okunan satir: #{tailer.lines_read}"
note "Kaydedilen konum: #{File.read(STATE_FILE)}"

note 'Servis KAPALIYKEN 3 satir daha yaziliyor (saldirgan bunu bekler)...'
3.times { emit(LIVE_LOG, ip: '45.155.205.233', method: 'POST', route: '/login', status: 401) }
puts

tailer2 = LogSentry::Tailer.new(
  LIVE_LOG, start: :end, poll_interval: 0.05, state_file: STATE_FILE
)
reader2 = Thread.new { tailer2.each_line { |line| received << line } }
sleep 0.5

seen = drain(received, parser)
# Parantez SART: `note if ...` yazsaydin Ruby bunu "note'u sadece kosul
# dogruysa cagir" (modifier-if) diye okur ve sozdizimi hatasi verir.
note(if seen == 3
       '[v] Kapaliyken yazilan 3 satir da yakalandi -- HICBIRI KAYBOLMADI.'
     else
       "[X] #{seen} satir yakalandi (3 olmaliydi)"
     end)
note 'Dikkat: start: :end demis olmamiza ragmen gecmisi okudu.'
note 'Cunku kayitli konum, baslangic ayarindan ONCELIKLIDIR.'

tailer2.stop
reader2.join

# ===========================================================================
puts "\n#{'=' * 74}"
puts ' SONUC'
puts '=' * 74
note <<~TEXT

  Toplam istatistikler (ilk tailer):
    okunan satir     : #{tailer.lines_read}
    okunan bayt      : #{tailer.bytes_read}
    kesilme          : #{tailer.truncations}
    rotasyon         : #{tailer.rotations}
    tampon bosaltma  : #{tailer.partial_flushes}

  Artik elimizde HIC BITMEYEN bir veri akisi var.
  Bu, "script" ile "servis" arasindaki siniri gectigimiz an.

  Adim 4: bu akan kayitlari kurallardan gecirecegiz -- ve kararlari
  bizim gozumuz degil, kod verecek.
TEXT

# Temizlik
[LIVE_LOG, STATE_FILE, "#{LIVE_LOG}.1"].each { |f| File.delete(f) if File.exist?(f) }
