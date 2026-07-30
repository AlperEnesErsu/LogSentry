# frozen_string_literal: true

# ============================================================================
#  ADIM 4c -- BruteForce: sifre deneme saldirisi tespiti
# ----------------------------------------------------------------------------
#  "Ayni IP adresinden <window> saniye icinde <threshold>'dan fazla
#   basarisiz kimlik dogrulama olursa uyari uret."
#
#  Bu dosyanin ne kadar KISA oldugu dikkat cekici olmali. Kayan pencere,
#  sogutma, bellek sinirlari, kanit toplama -- hepsi Base'de. Burada
#  sadece BU kurala ozgu karar var.
# ============================================================================

require_relative 'base'

module LogSentry
  module Rules
    class BruteForce < Base
      # Hangi durum kodlari "basarisiz giris" sayilir?
      #
      #   401 Unauthorized -> kimlik dogrulanamadi (sifre yanlis)
      #   403 Forbidden    -> kimlik dogru ama izin yok / WAF engelledi
      #
      # 404'u DAHIL ETMIYORUZ. Cok onemli bir ayrim: 404 "olmayan sayfa"
      # demektir, giris denemesi degil. Dahil edersen normal gezinen
      # kullanicilar (kirik link, eski yer imi) alarm uretir ve aracin
      # yanlis pozitif orani kullanilamaz hale gelir.
      DEFAULT_STATUSES = [401, 403].freeze

      def initialize(statuses: DEFAULT_STATUSES, severity: :high, **opts)
        super(severity: severity, **opts)
        @statuses = Array(statuses).map(&:to_i)
      end

      def interested?(entry)
        @statuses.include?(entry.status)
      end

      # Sicak yenilemede karsilastirilacak kurala ozel ayar.
      def extra_signature
        @statuses
      end

      def message_for(entry, measured)
        format('%d saniyede %d basarisiz giris denemesi (son hedef: %s)',
               @window, measured, entry.path)
      end

      def details_for(entry, _measured)
        {
          last_path:   entry.path,
          user_agent:  entry.user_agent,
          # Otomatik bir arac mi, tarayici mi? Bu ayrim mudahale kararini
          # degistirir: tarayici ise muhtemelen sifresini unutmus bir
          # kullanici, arac ise saldirgan.
          automated:   automated_agent?(entry.user_agent)
        }
      end

      private

      # Basit ama pratikte cok ise yarayan bir sinyal. Kesin kanit degil
      # (user-agent kolayca taklit edilir) -- ama alarma bakan insanin
      # onceligini belirlemesine yardim eder.
      AUTOMATION_HINTS = /curl|wget|python|go-http|java|ruby|perl|libwww|
                          httpie|postman|hydra|medusa|patator|sqlmap/xi

      def automated_agent?(agent)
        return false if agent.nil?

        AUTOMATION_HINTS.match?(agent)
      end
    end
  end
end
