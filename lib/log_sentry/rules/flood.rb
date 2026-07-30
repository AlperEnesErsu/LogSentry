# frozen_string_literal: true

# ============================================================================
#  ADIM 4d -- Flood: DDoS belirtisi tespiti
# ----------------------------------------------------------------------------
#  "Ayni IP adresinden <window> saniye icinde <threshold>'dan fazla istek
#   gelirse uyari uret."
#
#  Dikkat: bu kural bir DDoS'u TESPIT ETMEZ, BELIRTISINI tespit eder.
#  Gercek bir DDoS binlerce farkli IP'den gelir ve tek tek hicbiri bu
#  esigi asmaz. Bizim yakaladigimiz sey tek kaynakli asiri trafik:
#  ya kotu yazilmis bir bot, ya agresif bir tarayici, ya da gercekten
#  tek makineden yapilan bir saldiri (DoS -- ilk D olmadan).
#
#  Dagitik olani yakalamak icin IP basina degil TOPLAM trafige bakan bir
#  kural gerekir. Bunu bilincli olarak kapsam disinda tutuyoruz, ama
#  aradaki farki bilmek onemli: "DDoS tespit ediyorum" demek, yapmadigin
#  bir seyi iddia etmek olur.
# ============================================================================

require_relative 'base'

module LogSentry
  module Rules
    class Flood < Base
      def initialize(severity: :high, **opts)
        super(severity: severity, **opts)
      end

      # Her istek sayilir -- basarili, basarisiz, fark etmez.
      # Flood'da onemli olan ICERIK degil HACIM.
      def interested?(_entry)
        true
      end

      def message_for(_entry, measured)
        rate = (measured.to_f / @window).round
        format('%d saniyede %d istek (~%d istek/saniye) -- olagandisi hacim',
               @window, measured, rate)
      end

      def details_for(entry, measured)
        {
          rate_per_second: (measured.to_f / @window).round(1),
          last_path:       entry.path,
          user_agent:      entry.user_agent
        }
      end
    end
  end
end
