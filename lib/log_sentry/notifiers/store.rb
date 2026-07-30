# frozen_string_literal: true

# ============================================================================
#  ADIM 6c -- StoreNotifier: uyariyi veritabanina yazar
# ----------------------------------------------------------------------------
#  Bu dosyanin ne kadar kisa oldugu, Adim 5'te kurdugumuz sozlesmenin
#  degerini gosteriyor. Yeni bir kanal eklemek icin tek is: deliver metodunu
#  yazmak. Hata yalitimi, sayaclar, kapanma yonetimi Base'den geliyor.
#
#  Neden ayri bir notifier? Supervisor dogrudan store.record_alert diye de
#  cagirabilirdi. Ama o zaman veritabani hatasi (disk dolu, dosya kilitli)
#  dogrudan boru hattina sizardi. Notifier olarak sarinca Base'in hata
#  yalitimi bedavaya geliyor: veritabani yazamasa bile izleme durmaz ve
#  alarm hala ekrana + JSONL'e + Telegram'a gider.
# ============================================================================

require_relative 'base'

module LogSentry
  module Notifiers
    class Store < Base
      def initialize(store:, **opts)
        super(**opts)
        @store = store
        @name  = 'store'
      end

      # Store'un yasam dongusu Supervisor'a ait; burada kapatmiyoruz.
      # Ayni Store nesnesini olay kaydi icin de kullaniyoruz -- notifier
      # onu kapatsa, olay yazma da bozulurdu.
      def close; end

      private

      def deliver(alert)
        @store.record_alert(alert)
      end
    end
  end
end
