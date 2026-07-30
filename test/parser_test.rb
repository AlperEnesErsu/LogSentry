# frozen_string_literal: true

# ============================================================================
#  Parser testleri
# ----------------------------------------------------------------------------
#  Calistirmak icin:   ruby test/parser_test.rb
#
#  minitest, Ruby ile birlikte gelir -- disaridan hicbir sey kurmuyoruz.
#
#  NEDEN TEST YAZIYORUZ?
#  Parser bu sistemin en kritik parcasi. Bir kural yanlis calisirsa tek bir
#  saldiri turunu kacirirsin. Ama parser yanlis calisirsa TUM sistem korlesir
#  -- ve en kotusu, sessizce korlesir. Cikti uretmeye devam eder, sadece
#  ciktilar yanlistir.
#
#  Test yazmanin asil degeri "kod calisiyor mu" degil, ILERIDE BOZULDUGUNDA
#  HABER ALMAKTIR. 3 hafta sonra regex'e yeni bir alan eklerken eski
#  davranisi kirdiginda, bu dosya sana ANINDA soyler.
# ============================================================================

require 'minitest/autorun'

lib_path = File.expand_path('../lib', __dir__)
lib_path = File.expand_path('./lib') unless File.exist?(File.join(lib_path, 'log_sentry.rb'))
$LOAD_PATH.unshift(lib_path) unless $LOAD_PATH.include?(lib_path)

require 'log_sentry/parser'

class ParserTest < Minitest::Test
  # setup, HER testten once yeniden calisir. Boylece her test temiz bir
  # parser ile baslar ve testler birbirini etkilemez. (Test bagimsizligi:
  # bir testin sonucu, diger testlerin calisip calismamasina bagli olmamali.)
  def setup
    @parser = LogSentry::Parser.new
  end

  # --------------------------------------------------------------------------
  #  MUTLU YOL -- her sey yolundayken
  # --------------------------------------------------------------------------

  def test_normal_satiri_ayristirir
    line = '45.155.205.233 - - [29/Jul/2026:14:39:25 +0300] ' \
           '"POST /login HTTP/1.1" 401 178 "-" "python-requests/2.31.0"'

    e = @parser.parse(line)

    refute_nil e, 'gecerli satir nil dondu'
    assert_equal '45.155.205.233',         e.ip
    assert_equal 'POST',                   e.http_method
    assert_equal '/login',                 e.path
    assert_equal 'HTTP/1.1',               e.protocol
    assert_equal 401,                      e.status
    assert_equal 178,                      e.bytes
    assert_equal 'python-requests/2.31.0', e.user_agent
  end

  def test_status_ve_bytes_sayi_olarak_gelir
    # Bu testin varlik sebebi: "401" ile 401 farkli seylerdir.
    # Metinle status > 400 karsilastirmasi yapilamaz.
    e = parse_status(200)

    assert_kind_of Integer, e.status
    assert_kind_of Integer, e.bytes
    assert_kind_of Time,    e.time
  end

  def test_zaman_dilimi_korunur
    e = @parser.parse(
      '1.2.3.4 - - [29/Jul/2026:14:39:25 +0300] "GET / HTTP/1.1" 200 5 "-" "x"'
    )

    assert_equal 2026,     e.time.year
    assert_equal 7,        e.time.month
    assert_equal 29,       e.time.day
    assert_equal 14,       e.time.hour
    # +0300 = UTC'den 3 saat ileri = 10800 saniye.
    # Saat dilimini yok saymak, farkli sunuculardan gelen olaylari yanlis
    # siraya dizmene ve saldiri penceresini kacirmana yol acar.
    assert_equal 10_800,   e.time.utc_offset
  end

  def test_query_string_iceren_yol
    e = @parser.parse(
      '1.2.3.4 - - [29/Jul/2026:14:39:25 +0300] ' \
      '"GET /search?q=test&page=2 HTTP/1.1" 200 512 "-" "Chrome"'
    )

    assert_equal '/search?q=test&page=2', e.path
  end

  def test_ipv6_adresi
    # \S+ kalibi IPv6'yi da yakalar. Test etmezsek bunu varsaymis oluruz.
    e = @parser.parse(
      '2001:db8::1 - - [29/Jul/2026:14:39:25 +0300] "GET / HTTP/1.1" 200 5 "-" "x"'
    )

    refute_nil e
    assert_equal '2001:db8::1', e.ip
  end

  # --------------------------------------------------------------------------
  #  ZOR YOL -- gercek hayatta olan pislikler
  #  Bir ayristiricinin kalitesi mutlu yolda degil, BURADA belli olur.
  # --------------------------------------------------------------------------

  def test_bozuk_istek_satiri_isaretlenir_ama_atilmaz
    # TLS istegini duz HTTP portuna gonderen bir tarama araci.
    # Bu satiri atmak, tam olarak yakalamak istedigimiz davranisa kor kalmaktir.
    e = @parser.parse(
      '193.34.76.101 - - [29/Jul/2026:14:39:25 +0300] "\x16\x03\x01" 400 0 "-" "-"'
    )

    refute_nil e, 'bozuk istek satiri tum kaydi cope atmamali'
    assert e.malformed_request?
    assert_equal '-',             e.http_method
    assert_equal '193.34.76.101', e.ip      # <- saglam parcalar korundu
    assert_equal 400,             e.status
  end

  def test_yolda_bosluk_olan_satir
    # Adim 1'deki split(' ')[8] hilesinin yanildigi satir.
    # Parser'in istek satirini TEK parca alip sonra ayirmasinin sebebi bu.
    e = @parser.parse(
      '1.2.3.4 - - [29/Jul/2026:14:39:25 +0300] ' \
      '"GET /search?q=hello world HTTP/1.1" 200 512 "-" "Chrome"'
    )

    refute_nil e
    assert_equal 200, e.status, 'durum kodu bosluktan etkilenmemeli'
  end

  def test_bytes_tire_ise_sifir
    # Nginx govdesiz yanitlarda (304, HEAD) boyut alanina "-" yazar.
    # "-".to_i => 0 zaten, ama bunu ACIKCA test etmek niyeti belgeler.
    e = @parser.parse(
      '1.2.3.4 - - [29/Jul/2026:14:39:25 +0300] "HEAD / HTTP/1.1" 304 - "-" "curl"'
    )

    assert_equal 0, e.bytes
  end

  def test_protokolsuz_istek
    # HTTP/0.9 tarzi eski/bozuk istekler
    e = @parser.parse(
      '1.2.3.4 - - [29/Jul/2026:14:39:25 +0300] "GET /" 200 5 "-" "x"'
    )

    refute_nil e
    assert_equal 'GET', e.http_method
    assert_equal '/',   e.path
    assert_nil   e.protocol
  end

  # --------------------------------------------------------------------------
  #  REDDEDILMESI GEREKENLER
  # --------------------------------------------------------------------------

  def test_alakasiz_satir_nil_doner
    assert_nil @parser.parse('bu bir log satiri degil')
    assert_equal 1, @parser.failed_count
  end

  def test_bos_satir_nil_doner
    assert_nil @parser.parse('')
    assert_nil @parser.parse("\n")
    # Bos satir bir HATA degildir (dosya sonunda sikca olur),
    # bu yuzden basarisiz sayacini artirmamali.
    assert_equal 0, @parser.failed_count
  end

  def test_gecersiz_zaman_damgasi_reddedilir
    # Zamani ayristirilamayan kayit kural motoru icin ISE YARAMAZ:
    # tum kurallar zaman penceresi kullaniyor.
    e = @parser.parse(
      '1.2.3.4 - - [BOZUK ZAMAN] "GET / HTTP/1.1" 200 5 "-" "x"'
    )

    assert_nil e
    assert_equal 1, @parser.failed_count
  end

  def test_gecersiz_utf8_baytlari_coksmez
    # GERCEK BIR ZAFIYETIN TESTI.
    # Saldirgan sunucuya ham bayt yigini gonderir, nginx bunu logladigi gibi
    # yazar. Bu satirda regex calistirmak ArgumentError firlatir ve TUM
    # daemon'u durdurur -- yani saldirgan tek istekle izlemeyi kapatabilir.
    line = "1.2.3.4 - - [29/Jul/2026:14:39:25 +0300] " \
           "\"GET /\xFF\xFE HTTP/1.1\" 200 5 \"-\" \"x\""

    refute line.valid_encoding?, 'test verisi gercekten gecersiz olmali'

    e = @parser.parse(line)

    refute_nil e, 'gecersiz bayt kaydi cope atmamali'
    assert_equal '1.2.3.4', e.ip
    assert_equal 200,       e.status
    assert e.path.include?('?'), 'gecersiz baytlar temizlenmis olmali'
  end

  def test_parse_asla_coksmez
    # SOZLESME TESTI: mimari dokumani bolum 5.
    # "ASLA COKMEZSIN" sozunu veriyoruz -- bu test o sozu baglayici kilar.
    # Daemon icinde gunlerce calisacak bir kodda tek bir bozuk satirin
    # tum guvenlik izlemesini durdurmasi kabul edilemez.
    garbage = [
      '', ' ', "\t", 'a', '"""', '[[[', '\\', "\x00\x01\x02",
      '1.2.3.4 - -', '- - - - - - - - -',
      'A' * 10_000,
      '1.2.3.4 - - [] "" 999 -'
    ]

    garbage.each do |line|
      @parser.parse(line)   # herhangi biri hata firlatirsa test cokerek uyarir
    end

    pass
  end

  # --------------------------------------------------------------------------
  #  ISTATISTIK / GOZLEMLENEBILIRLIK
  # --------------------------------------------------------------------------

  def test_basari_orani_hesaplanir
    2.times { parse_status(200) }
    2.times { @parser.parse('cop') }

    assert_equal 2,    @parser.parsed_count
    assert_equal 2,    @parser.failed_count
    assert_equal 50.0, @parser.success_rate
  end

  def test_basarisiz_ornekler_sinirlanir
    # Sinirsiz buyuyen bir dizi, bir daemon icinde RAM'i bitirir.
    # Adim 1'deki File.read hatasinin bir baska kiligi.
    100.times { @parser.parse('cop') }

    assert_equal 100, @parser.failed_count
    assert_equal 10,  @parser.failed_samples.size, 'ornek listesi sinirli olmali'
  end

  # --------------------------------------------------------------------------
  #  FORMAT DEGISTIRILEBILIRLIGI
  #  Mimari sozu: "yarin baska log formati gelirse SADECE parser degisir."
  # --------------------------------------------------------------------------

  def test_common_format
    parser = LogSentry::Parser.new(format: :common)
    e = parser.parse('1.2.3.4 - - [29/Jul/2026:14:39:25 +0300] "GET / HTTP/1.1" 200 512')

    refute_nil e
    assert_equal 200, e.status
    assert_nil   e.user_agent   # common formatta bu alan yok
  end

  def test_bilinmeyen_format_baslangicta_patlar
    # Yapilandirma hatasi, calisma aninda degil BASLANGICTA ortaya cikmali.
    # Gece 3'te alarm uretmesi gereken bir servis, yanlis ayarla sessizce
    # baslamamalidir.
    assert_raises(ArgumentError) { LogSentry::Parser.new(format: :apache_ozel) }
  end

  # --------------------------------------------------------------------------
  #  ENTRY DAVRANISLARI
  # --------------------------------------------------------------------------

  def test_entry_sorgu_metodlari
    assert parse_status(200).success?
    assert parse_status(404).client_error?
    assert parse_status(500).server_error?

    assert parse_status(401).failed_auth?
    assert parse_status(403).failed_auth?
    refute parse_status(200).failed_auth?
    refute parse_status(404).failed_auth?, '404 basarisiz giris DEGILDIR'
  end

  def test_ham_satir_kanit_olarak_saklanir
    line = '1.2.3.4 - - [29/Jul/2026:14:39:25 +0300] "GET / HTTP/1.1" 200 5 "-" "x"'
    e = @parser.parse(line)

    # Kanit zinciri: bir alarmin "gercekten saldiri mi?" sorusuna ancak
    # ham satirlari gostererek cevap verebiliriz.
    assert_equal line, e.raw
    # Veritabanina yazarken ham satiri disari aliyoruz (yer kaplamasin).
    refute_includes e.to_record.keys, :raw
  end

  def test_keep_raw_kapatilabilir
    parser = LogSentry::Parser.new(keep_raw: false)
    e = parser.parse('1.2.3.4 - - [29/Jul/2026:14:39:25 +0300] "GET / HTTP/1.1" 200 5 "-" "x"')

    assert_nil e.raw
  end

  private

  # Test yardimcisi: sadece durum kodu degisen bir satir uretir.
  # Testlerde tekrari azaltmak, testleri de bakimi yapilabilir kilar.
  def parse_status(status)
    @parser.parse(
      "1.2.3.4 - - [29/Jul/2026:14:39:25 +0300] \"GET / HTTP/1.1\" #{status} 512 \"-\" \"x\""
    )
  end
end
