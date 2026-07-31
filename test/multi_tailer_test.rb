# frozen_string_literal: true

# ============================================================================
#  MultiTailer testleri -- coklu dosya ve tarihli rotasyon
# ----------------------------------------------------------------------------
#  Calistirmak icin:   ruby test/multi_tailer_test.rb
#
#  Bu testler GERCEK dosya sistemi kullaniyor (Tailer testleri gibi):
#  kesif, tarihli rotasyon ve thread yonetimi taklit edilemez.
#  Zamana bagli olduklari icin kisa beklemeler var; her biri saniyeler surer.
# ============================================================================

require 'minitest/autorun'
require 'tmpdir'
require 'fileutils'

lib_path = File.expand_path('../lib', __dir__)
lib_path = File.expand_path('./lib') unless File.exist?(File.join(lib_path, 'log_sentry.rb'))
$LOAD_PATH.unshift(lib_path) unless $LOAD_PATH.include?(lib_path)

require 'log_sentry/multi_tailer'

class MultiTailerTest < Minitest::Test
  # Kesif araligini testlerde kisaltmak icin sabitleri geciyoruz.
  # (Sabitleri degistirmek yerine kisa beklemelerle calisiyoruz.)
  POLL = 0.05

  def collect(pattern, seconds:, start: :end, state_dir: nil)
    lines = []
    # discovery_interval kisaltiliyor: varsayilan 10 saniye ile bu paket
    # 51 saniye suruyordu. Yavas test, bir sure sonra kosulmayan testtir.
    tailer = LogSentry::MultiTailer.new(pattern, start: start,
                                                 state_dir: state_dir,
                                                 poll_interval: POLL,
                                                 discovery_interval: 0.3)
    thread = Thread.new do
      tailer.each_line { |line, source| lines << [line.chomp, source] }
    end

    yield(tailer) if block_given?

    sleep seconds
    tailer.stop
    thread.join(3)
    [lines, tailer]
  end

  def write(path, text)
    File.open(path, 'a') do |f|
      f.sync = true
      f.puts text
    end
  end

  # --------------------------------------------------------------------------
  #  TEMEL DAVRANIS
  # --------------------------------------------------------------------------

  def test_birden_fazla_dosyayi_ayni_anda_okur
    Dir.mktmpdir do |dir|
      a = File.join(dir, 'access-a.log')
      b = File.join(dir, 'access-b.log')
      File.write(a, "")
      File.write(b, "")

      lines, = collect(File.join(dir, 'access-*.log'), seconds: 2) do |_t|
        sleep 0.5
        write(a, 'birinci dosyadan')
        write(b, 'ikinci dosyadan')
      end

      texts = lines.map(&:first)
      assert_includes texts, 'birinci dosyadan'
      assert_includes texts, 'ikinci dosyadan'
    end
  end

  def test_kaynak_dosya_bilgisi_tasinir
    # Cok sunuculu kurulumda "hangi makinede oldu" bilgisi olmadan alarm
    # eksik kalir.
    Dir.mktmpdir do |dir|
      a = File.join(dir, 'access-a.log')
      File.write(a, '')

      lines, = collect(File.join(dir, 'access-*.log'), seconds: 1.5) do
        sleep 0.4
        write(a, 'satir')
      end

      refute_empty lines
      assert_equal a, lines.first[1]
    end
  end

  # --------------------------------------------------------------------------
  #  TARIHLI ROTASYON -- bu dosyanin varlik sebebi
  # --------------------------------------------------------------------------

  def test_calisirken_ortaya_cikan_dosya_yakalanir
    # GECE YARISI SENARYOSU.
    #
    # Tarihli rotasyonda ertesi gunun dosyasi calisma sirasinda olusur.
    # Tek bir yolu izleyen yapilandirma bu andan sonra sessizce kor kalir:
    # dosya duruyor, hata yok, ama yeni satirlar baska yere gidiyor.
    Dir.mktmpdir do |dir|
      bugun = File.join(dir, 'access-2026-07-31.log')
      File.write(bugun, '')
      yarin = File.join(dir, 'access-2026-08-01.log')

      lines, tailer = collect(File.join(dir, 'access-*.log'), seconds: 3) do
        sleep 0.5
        write(bugun, 'bugunun satiri')

        # Gece yarisi: yeni gunun dosyasi olusuyor.
        sleep 0.5
        File.write(yarin, "")
        write(yarin, 'yarinin satiri')
      end

      texts = lines.map(&:first)
      assert_includes texts, 'bugunun satiri'
      assert_includes texts, 'yarinin satiri',
                      'calisirken olusan dosya kesfedilmeli -- yoksa gece yarisi kor kalinir'
      assert_operator tailer.files_seen, :>=, 2
    end
  end

  def test_sonradan_olusan_dosya_BASTAN_okunur
    # INCE AMA KRITIK AYRIM.
    #
    # start: :end ile baslasak bile, SONRADAN ortaya cikan bir dosya bastan
    # okunmali. Aksi halde dosyanin olustugu an ile bizim onu fark ettigimiz
    # an arasindaki satirlar kaybolur -- ve tarihli rotasyonda bu, her gecenin
    # ilk satirlarini kaybetmek demektir.
    Dir.mktmpdir do |dir|
      mevcut = File.join(dir, 'access-1.log')
      File.write(mevcut, "eski satir\n")

      yeni = File.join(dir, 'access-2.log')

      lines, = collect(File.join(dir, 'access-*.log'), seconds: 3, start: :end) do
        sleep 0.5
        # Yeni dosya, biz fark etmeden ONCE icerik aliyor.
        File.write(yeni, "kesiften onceki satir\n")
      end

      texts = lines.map(&:first)
      refute_includes texts, 'eski satir',
                      'baslangicta var olan dosyada start: :end gecerli olmali'
      assert_includes texts, 'kesiften onceki satir',
                      'sonradan olusan dosya bastan okunmali'
    end
  end

  # --------------------------------------------------------------------------
  #  KAYNAK YONETIMI
  # --------------------------------------------------------------------------

  def test_stop_tum_dosyalari_birakir
    Dir.mktmpdir do |dir|
      3.times { |i| File.write(File.join(dir, "access-#{i}.log"), '') }

      _lines, tailer = collect(File.join(dir, 'access-*.log'), seconds: 1.5)

      refute tailer.running?
      assert_equal 0, tailer.stats[:watched], 'kapanista tum dosyalar birakilmali'
    end
  end

  def test_bir_dosyanin_silinmesi_digerlerini_durdurmaz
    Dir.mktmpdir do |dir|
      a = File.join(dir, 'access-a.log')
      b = File.join(dir, 'access-b.log')
      File.write(a, '')
      File.write(b, '')

      lines, = collect(File.join(dir, 'access-*.log'), seconds: 3) do
        sleep 0.6
        write(b, 'once b')
        sleep 0.3
        begin
          File.delete(a)
        rescue StandardError
          nil
        end
        sleep 0.3
        write(b, 'sonra b')
      end

      texts = lines.map(&:first)
      assert_includes texts, 'sonra b',
                      'bir dosya silinse de digerleri okunmaya devam etmeli'
    end
  end

  def test_eslesen_dosya_yoksa_cokmez
    Dir.mktmpdir do |dir|
      lines, tailer = collect(File.join(dir, 'olmayan-*.log'), seconds: 1)

      assert_empty lines
      assert_equal 0, tailer.stats[:watched]
    end
  end

  def test_stats_dondurur
    Dir.mktmpdir do |dir|
      File.write(File.join(dir, 'access-a.log'), '')

      _lines, tailer = collect(File.join(dir, 'access-*.log'), seconds: 1.5) do
        sleep 0.5
        write(File.join(dir, 'access-a.log'), 'satir')
      end

      s = tailer.stats
      assert_equal File.join(dir, 'access-*.log'), s[:pattern]
      assert_operator s[:files_seen], :>=, 1
      assert_operator s[:lines_read], :>=, 1
    end
  end

  # --------------------------------------------------------------------------
  #  KONUM KAYDI
  # --------------------------------------------------------------------------

  def test_her_dosya_kendi_konum_kaydini_tutar
    # Ortak tek bir state dosyasi kullanilsaydi dosyalar birbirinin
    # konumunu ezer ve yeniden baslatmada veri kaybi/tekrari olurdu.
    Dir.mktmpdir do |dir|
      state = File.join(dir, 'state')
      2.times { |i| File.write(File.join(dir, "access-#{i}.log"), "satir#{i}\n") }

      _lines, = collect(File.join(dir, 'access-*.log'), seconds: 8,
                                                        start: :begin, state_dir: state)

      files = Dir.glob(File.join(state, '*')).size
      assert_operator files, :>=, 2, 'her dosya icin ayri konum kaydi olmali'
    end
  end
end
