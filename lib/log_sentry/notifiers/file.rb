# frozen_string_literal: true

# ============================================================================
#  ADIM 5c -- FileNotifier: uyarilari JSONL dosyasina yazar
# ----------------------------------------------------------------------------
#  NEDEN JSONL?
#
#  JSONL = "JSON Lines": her satirda tam bir JSON nesnesi.
#
#      {"rule":"brute_force","ip":"45.155.205.233",...}
#      {"rule":"flood","ip":"5.188.206.14",...}
#
#  Duz bir JSON dizisi ([{...},{...}]) olsaydi, dosyanin sonuna yeni kayit
#  eklemek icin kapanis parantezini silip, virgul koyup, yeniden yazmak
#  gerekirdi -- yani her alarmda TUM dosyayi yeniden yazmak. 2 yillik bir
#  arsivde bu imkansiz.
#
#  JSONL ile ekleme islemi sadece "sona bir satir yaz". Ustelik:
#    - `tail -f alerts.jsonl` ile insan izleyebilir
#    - satir satir makine ayristirabilir (bizim Tailer'imiz dahil!)
#    - dosyanin ortasi bozulsa geri kalan satirlar hala okunabilir
#
#  Adim 7'de web arayuzu canli akis icin tam olarak bu dosyayi izleyecek --
#  ve bunu yapmak icin Adim 3'te yazdigimiz Tailer'i yeniden kullanacak.
# ============================================================================

require 'json'
require 'fileutils'
require_relative 'base'

module LogSentry
  module Notifiers
    class File < Base
      def initialize(path:, **opts)
        super(**opts)
        @path = ::File.expand_path(path)
        FileUtils.mkdir_p(::File.dirname(@path))

        # 'a' = append (sona ekle). Asla uzerine yazmiyoruz.
        @file = ::File.open(@path, 'a')

        # sync = true: her yazmada isletim sistemine hemen aktar.
        #
        # Neden? Cunku bu dosya bir KANIT dosyasi. Process cokerse ya da
        # sunucu elektrik kesilirse, tamponda bekleyen alarmlar kaybolur --
        # ve kaybolan sey tam olarak "cokmeden hemen once ne oldu?"
        # sorusunun cevabidir.
        #
        # Bedeli: her alarmda bir sistem cagrisi. Alarmlar seyrek oldugu
        # icin (sogutma sayesinde) bu bedel onemsiz. Ama HER LOG SATIRINI
        # boyle yazsaydik ciddi bir yavaslama olurdu -- ayni tercihi orada
        # yapmazdik. Guvenlik/performans takaslarini yerine gore vermek
        # gerekir, kural olarak degil.
        @file.sync = true
      end

      def close
        @file&.close
      rescue IOError
        nil
      end

      private

      def deliver(alert)
        @file.puts(JSON.generate(alert.to_record))
      end
    end
  end
end
