# frozen_string_literal: true

# ============================================================================
#  ADIM 4e -- PathScan: hassas dizin/panel taramasi tespiti
# ----------------------------------------------------------------------------
#  "Ayni IP, <window> saniye icinde <threshold>'dan fazla FARKLI hassas
#   dizine dokunursa uyari uret."
#
#  BU KURAL DIGERLERINDEN FARKLI: sayi degil, CESITLILIK olcuyor.
#
#  Neden? Cunku niyet farki burada:
#
#    /admin adresine 50 kez istek     -> muhtemelen yer imi, bozuk bir
#                                        istemci, ya da unutulmus bir bot.
#                                        Cesitlilik = 1
#
#    /admin, /.env, /wp-login.php,    -> KESFETME davranisi. Bu kisi ne
#    /phpmyadmin, /.git/config           aradigini bilmiyor, NE BULACAGINI
#    adreslerine 1'er kez                arastiriyor. Cesitlilik = 5
#
#  Ikinci desen bir insanin gezinme sekli DEGILDIR. Bir tarama aracinin
#  imzasidir. Toplam istek sayisi cok az olsa bile (5 istek!) niyet
#  aciktir -- ve hacim bazli bir kural bunu asla yakalamaz.
#
#  Bu, SIEM mantiginin ozunu gosteren en guzel ornek: onemli olan olay
#  SAYISI degil, olaylarin birlikte OLUSTURDUGU DESEN.
# ============================================================================

require_relative 'base'

module LogSentry
  module Rules
    class PathScan < Base
      # Saldirganlarin sirayla yokladigi klasik hedefler.
      # Bu liste yapilandirmadan (config/logsentry.yml) gelir; buradaki
      # sadece makul bir varsayilan.
      DEFAULT_PATHS = [
        '/admin', '/wp-login.php', '/wp-admin', '/.env', '/.git',
        '/phpmyadmin', '/config.php', '/backup', '/.aws', '/.ssh',
        '/vendor', '/actuator', '/console', '/shell', '/cgi-bin'
      ].freeze

      def initialize(paths: DEFAULT_PATHS, severity: :medium, **opts)
        super(severity: severity, **opts)
        @paths = Array(paths).map(&:downcase)
      end

      # Yol, hassas listedeki bir onekle basliyor mu?
      #
      # start_with? kullaniyoruz cunku saldirgan tam eslesme denemez:
      # /admin yerine /admin/login, /admin/index.php, /admin?debug=1 gelir.
      #
      # downcase: buyuk/kucuk harf oyunuyla filtreyi atlamak, en eski
      # kacinma tekniklerinden biridir (/ADMIN, /Admin).
      def interested?(entry)
        path = entry.path.to_s.downcase
        @paths.any? { |sensitive| path.start_with?(sensitive) }
      end

      # Sicak yenilemede karsilastirilacak kurala ozel ayar.
      def extra_signature
        @paths
      end

      # ISTE FARK BURADA: pencereye YOLU yaziyoruz...
      def value_for(entry)
        normalize(entry.path)
      end

      # ...ve olay sayisi yerine FARKLI DEGER sayisini olcuyoruz.
      #
      # Base'deki measure sadece `list.size` donduruyordu. Burada ezip
      # `uniq.size` diyoruz. Tek metod ezmesiyle kuralin karakteri
      # tamamen degisiyor -- polimorfizmin somut faydasi budur.
      def measure(key)
        events = @events[key] || []
        events.map { |(_time, value)| value }.uniq.size
      end

      def message_for(_entry, measured)
        format('%d saniyede %d farkli hassas dizin denemesi (tarama davranisi)',
               @window, measured)
      end

      # Base#call, details_for'u build_alert icinden cagiriyor ve oraya
      # anahtari gecirmiyor. Anahtari bilmek icin call'i hafifce sarip
      # bir kenara yaziyoruz (asagiya bak).
      #
      # Alternatifi Base#details_for imzasina key eklemek olurdu -- ama o
      # zaman TUM alt siniflar etkilenirdi. Tek bir kuralin ihtiyaci icin
      # ortak sozlesmeyi bozmamak daha temiz.
      def call(entry)
        @last_key = key_for(entry)
        super
      end

      def details_for(_entry, _measured)
        probed = (@events[@last_key] || []).map { |(_time, value)| value }.uniq

        {
          # Alarmi inceleyen kisinin ilk soracagi sey: "hangi dizinler?"
          # Kanit gostermeyen alarm gurultudur.
          probed_paths: probed,
          watched_path_count: @paths.size
        }
      end

      private

      # Sorgu dizesini atiyoruz: /admin?a=1 ile /admin?a=2 ayni hedeftir.
      # Bunu yapmasak saldirgan sorgu dizesini degistirerek cesitliligi
      # yapay olarak sisirebilir -- ya da tersine, biz ayni dizini birden
      # cok farkli hedef sayarak yanlis alarm uretebiliriz.
      def normalize(path)
        path.to_s.downcase.split('?').first.to_s
      end
    end
  end
end
