# frozen_string_literal: true

# ============================================================================
#  ADIM 5a -- Notifiers::Base: bildirim kanallarinin ortak atasi
# ----------------------------------------------------------------------------
#  SOZLESME (mimari dokumani, bolum 5):
#    Sana bir Alert veririm; onu kendi kanalina iletirsin.
#    Gonderemezsen (internet yoksa vs.) hata firlatip TUM SISTEMI DURDURMAZSIN.
#
#  Bu son cumle bu dosyanin butun varlik sebebi.
#
#  Dusun: Telegram sunucusu 30 saniye cevap vermiyor. Eger bu hata yukari
#  dogru yayilirsa daemon coker. Yani "bildirim gonderememek" yuzunden
#  "izlemeyi tamamen kaybetmek" gibi absurd bir sonuc olusur.
#
#  Dogru davranis: bildirim gidemedi, LOGA yaz, devam et. Izleme kritik;
#  bildirim onemli ama kritik degil. Bir sistemin hangi parcasinin
#  vazgecilebilir oldugunu bilmek, saglam sistem tasariminin temelidir.
# ============================================================================

module LogSentry
  module Notifiers
    class Base
      attr_reader :name, :sent_count, :failed_count, :last_error

      def initialize(**_opts)
        # Isimsiz sinif (Class.new(Base)) icin `name` nil doner.
        # Rules::Base'de ayni tuzaga dusmustuk -- ayni cozum.
        @name         = self.class.name&.split('::')&.last&.downcase || 'anonymous'
        @sent_count   = 0
        @failed_count = 0
        @last_error   = nil
      end

      # ----------------------------------------------------------------------
      #  DIS KAPI. Daemon her zaman BUNU cagirir, deliver'i degil.
      #
      #  Buradaki `rescue StandardError` bilincli olarak COK GENIS. Normalde
      #  genis rescue kotu bir aliskanliktir (gercek hatalari saklar), ama
      #  burada tam olarak istedigimiz sey bu: bu katmanda olusabilecek
      #  HICBIR hata yukari cikmasin.
      #
      #  Neden Exception degil StandardError? Cunku Interrupt (Ctrl-C),
      #  SignalException ve NoMemoryError StandardError'un altinda DEGILDIR.
      #  Onlari yakalamak istemiyoruz -- Ctrl-C'yi yutan bir program
      #  kapatilamaz hale gelir.
      #
      #  ONEMLI AYRINTI: NotImplementedError de StandardError'un altinda
      #  DEGILDIR (ScriptError'un altindadir). Yani asagidaki deliver
      #  metodunu doldurmayi unutan bir alt sinif YAZILIRSA, hata buradan
      #  yutulmaz ve program coker.
      #
      #  Bu ISTEDIGIMIZ davranis: bu bir CALISMA ZAMANI arizasi degil,
      #  PROGRAMCI HATASIDIR. "Internet yok" gecici bir durumdur, yutulur;
      #  "metodu yazmayi unutmusum" ise sessizce yutulmasi gereken bir sey
      #  degil -- gurultuyle patlamali ki hemen fark edilsin.
      #
      #  Ruby'nin istisna hiyerarsisi bu ayrimi tasarim olarak yapar:
      #      Exception
      #        +-- ScriptError -> NotImplementedError, SyntaxError, LoadError
      #        +-- NoMemoryError, SignalException, Interrupt
      #        +-- StandardError -> IOError, ArgumentError, Errno::*, ...
      #  `rescue` argumansiz yazildiginda SADECE StandardError yakalar.
      # ----------------------------------------------------------------------
      def notify(alert)
        deliver(alert)
        @sent_count += 1
        true
      rescue StandardError => e
        @failed_count += 1
        @last_error    = "#{e.class}: #{e.message}"
        warn "[notifier:#{@name}] gonderilemedi -- #{@last_error}"
        false
      end

      def stats
        { notifier: @name, sent: @sent_count, failed: @failed_count,
          last_error: @last_error }
      end

      # Kapanirken cagirilir (dosyayi kapat, bekleyen istegi bitir vb.)
      def close; end

      private

      # Alt siniflarin dolduracagi kisim.
      def deliver(_alert)
        raise NotImplementedError, "#{self.class} deliver metodunu tanimlamali"
      end
    end
  end
end
