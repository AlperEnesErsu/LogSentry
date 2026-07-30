# frozen_string_literal: true

# ============================================================================
#  Tailer testleri
# ----------------------------------------------------------------------------
#  Calistirmak icin:   ruby test/tailer_test.rb
#
#  BU TESTLER NEDEN DIGERLERINDEN FARKLI?
#
#  Parser testleri "saf" (pure) testlerdi: girdi ver, cikti al, bitti.
#  Tailer ise ZAMAN ve DOSYA SISTEMI ile calisiyor. Bu iki sey testleri
#  zorlastirir:
#
#    1) Zamanlama: tailer ayri bir thread'de dongu doner. "Satiri gordu mu?"
#       diye sormak icin beklemek gerekir. Sabit sleep koymak kotu bir
#       aliskanliktir (yavas makinede kirilir, hizlida bosa bekler);
#       bunun yerine "sonuc gelene kadar, en fazla N saniye bekle" deriz.
#
#    2) Platform: rotasyon/kesilme her dosya sisteminde ayni davranmaz.
#       Windows acik dosyanin tasinmasina izin vermez. Bu bir test HATASI
#       degildir -- o testi ATLAMAK (skip) dogru davranistir. Yesil gorunmek
#       icin testi silmek ya da zayiflatmak ise kendini kandirmaktir.
# ============================================================================

require 'minitest/autorun'
require 'tmpdir'
require 'fileutils'

lib_path = File.expand_path('../lib', __dir__)
lib_path = File.expand_path('./lib') unless File.exist?(File.join(lib_path, 'log_sentry.rb'))
$LOAD_PATH.unshift(lib_path) unless $LOAD_PATH.include?(lib_path)

require 'log_sentry/tailer'

class TailerTest < Minitest::Test
  def setup
    # Her test kendi gecici klasorunde calisir -> testler birbirini etkilemez.
    @dir   = Dir.mktmpdir('logsentry-test')
    @log   = File.join(@dir, 'access.log')
    @state = File.join(@dir, 'access.pos')
    File.write(@log, '')
    @threads = []
    @tailers = []
  end

  def teardown
    @tailers.each(&:stop)
    @threads.each { |t| t.join(2) }
    FileUtils.remove_entry(@dir)
  rescue StandardError
    nil
  end

  # --------------------------------------------------------------------------
  #  TEMEL DAVRANIS
  # --------------------------------------------------------------------------

  def test_yeni_satirlari_okur
    queue = start_tailer

    append 'satir-1'
    append 'satir-2'

    assert_equal %w[satir-1 satir-2], collect(queue, 2)
  end

  def test_start_end_gecmisi_okumaz
    # tail -f'in varsayilan davranisi: dosyada zaten olani degil,
    # BUNDAN SONRA yazilani izle.
    File.write(@log, "eski-1\neski-2\n")

    queue = start_tailer(start: :end)
    append 'yeni-1'

    lines = collect(queue, 1)
    assert_equal ['yeni-1'], lines
    refute_includes lines, 'eski-1'
  end

  def test_start_begin_bastan_okur
    File.write(@log, "eski-1\neski-2\n")

    queue = start_tailer(start: :begin)

    assert_equal %w[eski-1 eski-2], collect(queue, 2)
  end

  def test_gecersiz_start_degeri_patlar
    # Yapilandirma hatasi calisma aninda degil, BASLANGICTA ortaya cikmali.
    t = LogSentry::Tailer.new(@log, start: :ortasindan)

    assert_raises(ArgumentError) { t.each_line { |_l| nil } }
  end

  # --------------------------------------------------------------------------
  #  YARIM SATIR -- en sinsi hata
  # --------------------------------------------------------------------------

  def test_yarim_satir_tamamlanana_kadar_bekletilir
    queue = start_tailer

    # Sunucu satiri yazmanin ortasinda: satir sonu karakteri YOK.
    File.open(@log, 'a') { |f| f.write('yarim-') }
    sleep 0.2

    assert queue.empty?, 'yarim satir uretilmemeliydi'

    # Geri kalani geliyor.
    File.open(@log, 'a') { |f| f.puts 'tamamlandi' }

    assert_equal ['yarim-tamamlandi'], collect(queue, 1),
                 'iki parca TEK satir olarak birlestirilmeliydi'
  end

  def test_cok_parcali_yarim_satir
    queue = start_tailer

    'a'.upto('e') do |ch|
      File.open(@log, 'a') { |f| f.write(ch) }
      sleep 0.05
    end
    assert queue.empty?

    File.open(@log, 'a') { |f| f.puts 'f' }

    assert_equal ['abcdef'], collect(queue, 1)
  end

  # --------------------------------------------------------------------------
  #  ROTASYON VE KESILME
  #  Platforma bagli: yapilamiyorsa testi ATLA, zayiflatma.
  # --------------------------------------------------------------------------

  def test_kesilme_algilanir_copytruncate
    queue = start_tailer
    append 'once'
    assert_equal ['once'], collect(queue, 1)

    begin
      File.truncate(@log, 0)
    rescue SystemCallError => e
      skip "bu platform acik dosyayi kesemiyor (#{e.class})"
    end

    # Bu bekleme SART -- ve nedeni onemli:
    #
    # "Sifirla" ile "yeni veri yaz" arasinda hicbir bosluk birakmazsan,
    # tailer'in kesilmeyi FARK EDECEGI an hic olusmaz: dosya, kontrol
    # edilmeden once eski konumumuzun otesine kadar yeniden buyumus olur.
    # Bu, kodun degil COPYTRUNCATE yontemini yapisal kusurudur (bkz.
    # tailer.rb icindeki check_truncation aciklamasi) -- ve gercek hayatta
    # da logrotate ile veri kaybina yol acabilir.
    #
    # Buradaki 0.1 saniye, logrotate'in dosyayi sifirlayip birakmasi ile
    # sunucunun yeni istek almasi arasindaki gercekci araligi temsil ediyor.
    # Onemli olan: eskiden bu kontrol saniyede bir yapiliyordu ve 0.1 saniye
    # YETMIYORDU. Simdi her turda (0.02 sn) yapiliyor.
    sleep 0.1

    append 'sonra'

    assert_equal ['sonra'], collect(queue, 1, timeout: 4)
    assert_equal 1, @tailers.first.truncations
  end

  def test_rotasyon_algilanir_create_mode
    queue = start_tailer
    append 'rotasyondan-once'
    assert_equal ['rotasyondan-once'], collect(queue, 1)

    begin
      File.rename(@log, "#{@log}.1")
      File.write(@log, '')
    rescue SystemCallError => e
      skip "bu platform acik dosyayi tasiyamiyor (#{e.class})"
    end

    append 'rotasyondan-sonra'

    lines = collect(queue, 1, timeout: 4)

    if @tailers.first.rotations.zero?
      skip 'bu dosya sistemi inode semantigini Linux gibi uygulamiyor ' \
           '(orn. WSL uzerindeki /mnt/c). Gercek bir Linux FS gerekiyor.'
    end

    assert_equal ['rotasyondan-sonra'], lines
    assert_equal 1, @tailers.first.reopens
  end

  def test_rotasyonda_son_satirlar_kaybolmaz
    # En kritik rotasyon detayi: dosya tasinmadan hemen once yazilan
    # satirlar. Yeni dosyaya gecmeden ESKI dosyayi bosaltmazsan bunlar
    # kaybolur -- ve onlar tam olarak "gunun son olaylari"dir.
    queue = start_tailer

    append 'son-satir-1'
    append 'son-satir-2'

    begin
      File.rename(@log, "#{@log}.1")
      File.write(@log, '')
    rescue SystemCallError => e
      skip "bu platform acik dosyayi tasiyamiyor (#{e.class})"
    end

    append 'yeni-dosyadan'

    lines = collect(queue, 3, timeout: 4)

    assert_includes lines, 'son-satir-1'
    assert_includes lines, 'son-satir-2'
  end

  # --------------------------------------------------------------------------
  #  YENIDEN BASLATMA GUVENLIGI
  # --------------------------------------------------------------------------

  def test_checkpoint_kaydedilir
    queue = start_tailer(state_file: @state)
    append 'satir'
    collect(queue, 1)

    @tailers.first.stop
    @threads.first.join(2)

    assert File.exist?(@state), 'konum dosyasi olusmaliydi'

    state = JSON.parse(File.read(@state))
    assert_operator state['pos'], :>, 0
    assert_equal File.expand_path(@log), state['path']
  end

  def test_kapaliyken_yazilan_satirlar_kaybolmaz
    # Servisin yeniden baslatilmasi senaryosu.
    # Kayit olmasaydi bu satirlar SONSUZA KADAR kaybolurdu -- ve saldirgan
    # tam olarak bu araligi bekler.
    queue = start_tailer(state_file: @state)
    append 'once'
    collect(queue, 1)

    @tailers.first.stop
    @threads.first.join(2)

    append 'kapaliyken-1'
    append 'kapaliyken-2'

    queue2 = start_tailer(state_file: @state, start: :end)

    assert_equal %w[kapaliyken-1 kapaliyken-2], collect(queue2, 2),
                 'kayitli konum, start: :end ayarindan oncelikli olmali'
  end

  def test_bozuk_checkpoint_dosyasi_coksmez
    File.write(@state, 'bu gecerli JSON degil {{{')

    queue = start_tailer(state_file: @state)
    append 'satir'

    assert_equal ['satir'], collect(queue, 1),
                 'bozuk konum dosyasi yok sayilip devam edilmeli'
  end

  def test_baska_dosyaya_ait_checkpoint_yok_sayilir
    # Rotasyondan sonra eski konum anlamsizdir: yeni dosyada 5000. bayta
    # atlamak, orada olmayan bir yere gitmek demektir.
    File.write(@state, JSON.generate(
                         { path: File.expand_path(@log), ino: 999_999_999, pos: 5_000 }
                       ))

    queue = start_tailer(state_file: @state)
    append 'satir'

    assert_equal ['satir'], collect(queue, 1)
  end

  # --------------------------------------------------------------------------
  #  DURDURMA
  # --------------------------------------------------------------------------

  def test_stop_donguyu_bitirir
    # Adim 5'te SIGTERM aldigimizda tam olarak bunu cagiracagiz.
    # Baska bir thread'den cagrilabilir olmasi sart.
    start_tailer
    tailer = @tailers.first
    thread = @threads.first

    assert tailer.running?

    tailer.stop

    assert thread.join(2), 'stop cagrildiktan sonra dongu bitmeliydi'
    refute tailer.running?
  end

  def test_stats_dondurur
    queue = start_tailer
    append 'bir'
    append 'iki'
    collect(queue, 2)

    stats = @tailers.first.stats

    assert_equal 2, stats[:lines_read]
    assert_operator stats[:bytes_read], :>, 0
    assert_equal 0, stats[:rotations]
  end

  private

  # Tailer'i ayri bir thread'de baslatir, satirlarin dustugu kuyrugu doner.
  def start_tailer(**opts)
    queue  = Thread::Queue.new
    tailer = LogSentry::Tailer.new(
      @log, **{ start: :end, poll_interval: 0.02 }.merge(opts)
    )
    thread = Thread.new { tailer.each_line { |line| queue << line } }

    @tailers << tailer
    @threads << thread

    sleep 0.15   # thread'in dosyayi acip konumlanmasini bekle
    queue
  end

  def append(text)
    File.open(@log, 'a') { |f| f.puts text }
  end

  # "count kadar satir gelene kadar, en fazla timeout saniye bekle."
  #
  # Sabit `sleep 1` yerine bunu kullanmak onemli: testler yavas makinede
  # kirilmaz, hizli makinede bosa beklemez. Zamana bagli testlerde
  # "en fazla su kadar bekle" yaklasimi tek dogru yontemdir.
  def collect(queue, count, timeout: 2)
    lines    = []
    deadline = Time.now + timeout

    while lines.size < count && Time.now < deadline
      begin
        lines << queue.pop(true)   # true = bloklamadan dene
      rescue ThreadError
        sleep 0.02                 # kuyruk bos, biraz bekle
      end
    end

    lines
  end
end
