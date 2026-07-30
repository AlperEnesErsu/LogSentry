# frozen_string_literal: true

# ============================================================================
#  ADIM 1 -- Dosya Okuma (File I/O)
# ----------------------------------------------------------------------------
#  Bu dosyanin tek bir amaci var: "buyuk bir dosyayi nasil okumaliyiz?"
#  sorusunun cevabini elle gorup hissetmek.
#
#  Kullanim:  ruby step1_reader.rb [log_dosyasi]
# ============================================================================

LOG_PATH = ARGV[0] || File.expand_path('logs/access.log', __dir__)

abort("HATA: #{LOG_PATH} bulunamadi. Once: ruby tools/log_generator.rb") unless File.exist?(LOG_PATH)

puts '=' * 70
puts "Dosya : #{LOG_PATH}"
puts "Boyut : #{(File.size(LOG_PATH) / 1024.0).round(1)} KB"
puts '=' * 70

# ---------------------------------------------------------------------------
# YANLIS YOL: File.read
# ---------------------------------------------------------------------------
# File.read dosyanin TAMAMINI tek bir String olarak RAM'e cikarir.
# 300 KB'lik test dosyamizda sorun yok. Ama gercek bir sunucuda access.log
# rahatlikla 2-3 GB olur -- ve o an 3 GB'lik bir String yaratmaya calisirsin.
# Sunucunun RAM'i yetmezse process OOM-killer tarafindan oldurulur.
# ---------------------------------------------------------------------------
puts "\n[1] YANLIS YOL -> File.read (hepsini birden RAM'e al)"

t0 = Time.now
whole_file = File.read(LOG_PATH)
elapsed_read = Time.now - t0

puts "    Sure           : #{(elapsed_read * 1000).round(1)} ms"
puts "    RAM'de tutulan : #{(whole_file.bytesize / 1024.0).round(1)} KB  <-- tek bir String"
puts "    Satir sayisi   : #{whole_file.lines.size}"
puts '    NOT: Dosya 3 GB olsaydi bu satir 3 GB RAM isterdi.'

whole_file = nil   # referansi birak, GC toplayabilsin
GC.start

# ---------------------------------------------------------------------------
# DOGRU YOL: File.foreach
# ---------------------------------------------------------------------------
# File.foreach dosyayi bir "stream" gibi ele alir: her seferinde RAM'de
# yalnizca TEK bir satir bulunur. Blok bittiginde o satir cop olur, GC toplar.
# Dosya 3 GB de olsa 3 TB de olsa RAM tuketimi sabit kalir.
#
# Ayrica File.foreach blok verildiginde dosyayi otomatik kapatir --
# File.open + ensure + close ile ugrasmana gerek yok.
# ---------------------------------------------------------------------------
puts "\n[2] DOGRU YOL -> File.foreach (satir satir, akis halinde)"

line_count      = 0
byte_count      = 0
longest_line    = 0
status_tally    = Hash.new(0)   # varsayilan degeri 0 olan hash: ilk artista hata vermez

t0 = Time.now

File.foreach(LOG_PATH) do |line|
  line_count += 1
  byte_count += line.bytesize
  longest_line = line.bytesize if line.bytesize > longest_line

  # Adim 2'de bunu duzgun bir Regex ile yapacagiz.
  # Simdilik kaba bir yaklasim: satiri bosluklara bolup HTTP durum kodunun
  # oturdugu alani aliyoruz. ("... HTTP/1.1" 200 1043 ...)
  parts  = line.split(' ')
  status = parts[8]
  status_tally[status] += 1
end

elapsed_foreach = Time.now - t0

puts "    Sure           : #{(elapsed_foreach * 1000).round(1)} ms"
puts "    Islenen satir  : #{line_count}"
puts "    Toplam bayt    : #{(byte_count / 1024.0).round(1)} KB"
puts "    RAM'de tutulan : #{longest_line} bayt  <-- sadece en uzun TEK satir"

# ---------------------------------------------------------------------------
# Ilk analiz ciktimiz: HTTP durum kodu dagilimi
# ---------------------------------------------------------------------------
puts "\n[3] HTTP durum kodu dagilimi"
status_tally.sort_by { |_code, count| -count }.each do |code, count|
  pct = (count * 100.0 / line_count).round(1)
  bar = '#' * (pct / 2).round
  label = case code
          when '200' then 'OK'
          when '304' then 'Not Modified'
          when '401' then 'Unauthorized   <-- brute force adayi'
          when '403' then 'Forbidden'
          when '404' then 'Not Found      <-- tarama adayi'
          when '500' then 'Server Error'
          else            '?'
          end
  puts format('    %-5s %6d  %5.1f%%  %-12s %s', code, count, pct, bar, label)
end

puts "\n" + '=' * 70
puts 'Sonuc: iki yontem de ayni sonucu uretti, ama foreach sabit RAM kullandi.'
puts '=' * 70
