# frozen_string_literal: true

# ============================================================================
#  ADIM 5d -- WebhookNotifier: Telegram / Slack / genel HTTP bildirimi
# ----------------------------------------------------------------------------
#  Bu dosya, aracin "telefonuna bildirim atan" kismi. Ama asil ogretici
#  tarafi HTTP istegi atmak degil -- onu 5 satirda yazabilirdik.
#  Asil mesele SU DORT SEY:
#
#    1) SIR YONETIMI     : token dosyaya yazilmaz, ortam degiskeninden gelir
#    2) ZAMAN ASIMI      : cevap gelmezse sonsuza kadar beklenmez
#    3) HATA YALITIMI    : bildirim gidemezse izleme durmaz
#    4) HIZ SINIRI       : API'yi kendi alarmlarimizla bogmayiz
#
#  Bu dordu, "calisan kod" ile "uretimde durabilen kod" arasindaki farktir.
# ============================================================================

require 'net/http'
require 'uri'
require 'json'
require_relative 'base'

module LogSentry
  module Notifiers
    class Webhook < Base
      # Desteklenen bicimler. Her servis farkli bir JSON govdesi bekler.
      FORMATS = %i[generic slack telegram].freeze

      # Dakikada en fazla kac bildirim gonderilsin?
      #
      # Sogutma (Adim 4) alarm sayisini zaten kisiyor, ama bu ikinci bir
      # emniyet kemeri: cok sayida FARKLI IP'den alarm gelirse sogutma
      # devreye girmez (her IP kendi anahtarina sahip) ve API'yi bogabiliriz.
      # Telegram'in kendi hiz siniri da vardir; asarsan gecici olarak
      # engellenirsin -- yani asiri gonderme, hic gonderememeye donusur.
      DEFAULT_RATE_LIMIT = 20

      def initialize(url: nil, url_env: nil, format: :generic, timeout: 5,
                     chat_id_env: 'LOGSENTRY_TELEGRAM_CHAT_ID',
                     rate_limit: DEFAULT_RATE_LIMIT, **opts)
        super(**opts)

        @format = format.to_sym
        unless FORMATS.include?(@format)
          raise ArgumentError,
                "bilinmeyen webhook bicimi: #{format.inspect} " \
                "(gecerli: #{FORMATS.join(', ')})"
        end

        # ------------------------------------------------------------------
        #  SIR YONETIMI
        # ------------------------------------------------------------------
        #  Webhook adresi bir SIRDIR: icinde token vardir ve o token ile
        #  herkes senin adina mesaj gonderebilir.
        #
        #  Bu yuzden config/logsentry.yml'da adresin KENDISI degil, onu
        #  tutan ORTAM DEGISKENININ ADI yazili:
        #      url_env: LOGSENTRY_WEBHOOK_URL
        #
        #  Neden bu kadar onemli? Cunku yapilandirma dosyalari git'e
        #  girer. Git gecmisi silinmez -- bir kez commit ettigin token,
        #  sonradan dosyadan cikarsan bile gecmiste durmaya devam eder.
        #  Sizan sirlarin en yaygin sebebi budur.
        # ------------------------------------------------------------------
        @url = url || (url_env && ENV[url_env])
        @url_env = url_env

        if @url.nil? || @url.to_s.strip.empty?
          raise ArgumentError,
                "webhook adresi yok. #{url_env} ortam degiskenini ayarla:\n" \
                "  export #{url_env}='https://...'"
        end

        @uri     = URI.parse(@url)
        @timeout = timeout.to_f
        @chat_id = ENV[chat_id_env]

        if @format == :telegram && (@chat_id.nil? || @chat_id.empty?)
          raise ArgumentError,
                "Telegram icin #{chat_id_env} ortam degiskeni gerekli"
        end

        @rate_limit    = rate_limit
        @window_start  = Time.now
        @window_count  = 0
        @dropped_count = 0
      end

      # Loglarda ve hata mesajlarinda adresi ASLA oldugu gibi gostermiyoruz.
      # Kendi log dosyana token yazmak, sirri dosyaya yazmakla aynidir --
      # ustelik log dosyalari genelde daha az korunur ve daha cok paylasilir.
      def safe_url
        # YOLUN TAMAMINI maskeliyoruz.
        #
        # Ilk denememde "sadece uzun gorunen son parcayi maskele" gibi zeki
        # bir kalip yazmistim ve test onu ANINDA yakaladi: Telegram
        # adresinde token SON parca degil, ORTADA duruyor:
        #     /bot123456:GIZLI_TOKEN/sendMessage
        # Kalip "sendMessage"i maskeleyip token'i aciga cikardi.
        #
        # Ders: sir maskelemede "neyi gizleyecegimi tahmin edeyim"
        # yaklasimi yanlistir. Dogru yaklasim "neyi gostermek GUVENLI,
        # onun disindakini gizle" (allow-list). Burada guvenli olan sey
        # sema ve sunucu adi; geri kalan her sey gider.
        "#{@uri.scheme}://#{@uri.host}/***"
      end

      def stats
        super.merge(dropped: @dropped_count, url: safe_url)
      end

      private

      def deliver(alert)
        return if rate_limited?

        response = post(build_payload(alert))

        # 2xx disi her sey basarisiz. Net::HTTP istegi "basarili" saysa bile
        # sunucu "seni engelledim" demis olabilir -- durum kodunu kontrol
        # etmeden gonderdim varsaymak klasik bir hatadir.
        unless response.is_a?(Net::HTTPSuccess)
          raise "HTTP #{response.code} -- #{response.body.to_s[0, 200]}"
        end

        response
      end

      # ----------------------------------------------------------------------
      #  HIZ SINIRI: kayan pencerenin basit hali (Adim 4'teki fikrin aynisi)
      # ----------------------------------------------------------------------
      def rate_limited?
        now = Time.now

        if now - @window_start >= 60
          @window_start = now
          @window_count = 0
        end

        if @window_count >= @rate_limit
          @dropped_count += 1
          # Sinira takilinca SESSIZ kalmiyoruz. Bildirim gonderemedigini
          # bilmek, bildirimin kendisi kadar onemli.
          warn "[notifier:webhook] dakika siniri (#{@rate_limit}) asildi, " \
               "bildirim dusuruldu (toplam: #{@dropped_count})"
          return true
        end

        @window_count += 1
        false
      end

      # ----------------------------------------------------------------------
      #  HTTP ISTEGI
      # ----------------------------------------------------------------------
      def post(payload)
        http = Net::HTTP.new(@uri.host, @uri.port)
        http.use_ssl = (@uri.scheme == 'https')

        # ZAMAN ASIMLARI -- bunlar olmadan kod uretime cikmaz.
        #
        # open_timeout : baglanti kurulamiyorsa ne kadar bekleyelim
        # read_timeout : baglandi ama cevap gelmiyorsa ne kadar bekleyelim
        #
        # Varsayilan degerler cok uzundur (60 sn civari). Bir bildirim
        # yuzunden 60 saniye beklemek demek, o 60 saniyede gelen loglarin
        # islenmemesi demek. Kuyruk birikir, alarm gecikir.
        http.open_timeout = @timeout
        http.read_timeout = @timeout

        request = Net::HTTP::Post.new(@uri.request_uri)
        request['Content-Type'] = 'application/json'
        request.body = JSON.generate(payload)

        http.request(request)
      end

      # ----------------------------------------------------------------------
      #  GOVDE BICIMLERI -- her servis farkli sey bekler
      # ----------------------------------------------------------------------
      def build_payload(alert)
        case @format
        when :telegram then telegram_payload(alert)
        when :slack    then slack_payload(alert)
        else                generic_payload(alert)
        end
      end

      # Telegram Bot API: POST https://api.telegram.org/bot<TOKEN>/sendMessage
      def telegram_payload(alert)
        {
          chat_id: @chat_id,
          text: <<~MSG.strip,
            #{severity_icon(alert.severity)} *LogSentry — #{alert.rule}*

            *Kaynak:* `#{alert.ip}`
            *Durum:* #{alert.message}
            *Olculen:* #{alert.count} (esik: #{alert.threshold}, #{alert.window} sn)
            *Zaman:* #{alert.time.strftime('%Y-%m-%d %H:%M:%S %z')}
          MSG
          parse_mode: 'Markdown',
          # Bildirim sesi sadece ciddi alarmlarda calsin.
          # Gece 3'te telefonun her orta seviye uyaride calmasi, aracin
          # kapatilmasiyla sonuclanir.
          disable_notification: alert.severity_rank < 2
        }
      end

      # Slack Incoming Webhook
      def slack_payload(alert)
        {
          text: "#{severity_icon(alert.severity)} LogSentry — #{alert.rule}",
          blocks: [
            { type: 'header',
              text: { type: 'plain_text',
                      text: "#{severity_icon(alert.severity)} #{alert.rule} — #{alert.ip}" } },
            { type: 'section',
              fields: [
                { type: 'mrkdwn', text: "*Durum:*\n#{alert.message}" },
                { type: 'mrkdwn', text: "*Onem:*\n#{alert.severity}" },
                { type: 'mrkdwn', text: "*Olculen:*\n#{alert.count} / #{alert.threshold}" },
                { type: 'mrkdwn', text: "*Zaman:*\n#{alert.time.strftime('%H:%M:%S')}" }
              ] }
          ]
        }
      end

      # Kendi servisine gonderiyorsan: ham Alert kaydi.
      def generic_payload(alert)
        alert.to_record
      end

      def severity_icon(severity)
        case severity
        when :critical then '🔴'
        when :high     then '🚨'
        when :medium   then '⚠️'
        else                '🔵'
        end
      end
    end
  end
end
