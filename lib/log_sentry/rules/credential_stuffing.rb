# frozen_string_literal: true

# ============================================================================
#  Rules::CredentialStuffing -- dagitik giris denemesi tespiti
# ----------------------------------------------------------------------------
#  BU KURAL, DIGERLERINDEN FARKLI BIR SORUYU SORUYOR.
#
#  BruteForce "bu IP kac kez denedi?" diye sorar ve IP basina sayar. Ama
#  onunde bir load balancer / WAF varsa ve o, 5. basarisiz denemede IP'yi
#  karantinaya aliyorsa, tek bir IP'nin sayaci ASLA yuksek bir esige
#  ulasamaz. Saldirgan da bunu bilir ve davranisini degistirir:
#
#      3000 farkli IP  x  her biri 3-4 deneme  =  10.000 deneme
#      ...ve IP basina sayan hicbir kural bunu gormez.
#
#  Buna "credential stuffing" (calinmis parola listesiyle toplu deneme) ya
#  da dagitik brute force denir. Karantina kuralinin oldugu her ortamda
#  saldirinin ALACAGI SEKIL budur -- yani korunma, saldiriyi engellemez,
#  BICIMINI degistirir.
#
#  Cozum: sayaci IP'den HEDEFE tasimak.
#
#      anahtar = giris yolu (/login)         IP degil
#      olculen = o yola vuran FARKLI IP sayisi
#
#  Normal bir sitede /login adresine 5 dakikada kac farkli IP gelir?
#  Kucuk/orta bir kurumda onlarca. Yuzlerce farkli IP'nin BASARISIZ giris
#  yapmasi ise normal degildir.
#
#  DIKKAT: bu kural digerlerinden daha kolay yanlis pozitif uretir --
#  ofisin tamami tek NAT arkasindaysa tersine, tek IP'den cok kullanici
#  gelir (bu kurali TETIKLEMEZ, ama BruteForce'u tetikleyebilir). Esigi
#  kendi trafiginize gore ayarlayin; varsayilanlar tahmindir, olcum degil.
# ============================================================================

require_relative 'base'

module LogSentry
  module Rules
    class CredentialStuffing < Base
      # Yalnizca kimlik dogrulama uclarindaki basarisizliklari sayiyoruz.
      # Tum 401'leri saymak, API anahtari suresi dolmus istemcilerin
      # gurultusunu iceri alirdi.
      DEFAULT_PATHS = ['/login', '/signin', '/auth', '/session', '/oauth',
                       '/wp-login.php', '/user/login', '/api/login',
                       '/admin/login'].freeze

      DEFAULT_STATUSES = [401, 403].freeze

      def initialize(paths: DEFAULT_PATHS, statuses: DEFAULT_STATUSES,
                     severity: :high, **opts)
        super(severity: severity, **opts)
        @paths    = Array(paths).map(&:downcase)
        @statuses = Array(statuses).map(&:to_i)
      end

      def interested?(entry)
        return false unless @statuses.include?(entry.status)

        path = normalize(entry.path)
        @paths.any? { |login| path.start_with?(login) }
      end

      # ANAHTAR IP DEGIL, HEDEF YOL.
      #
      # Base varsayilan olarak entry.ip'ye gore grupluyor; burada onu
      # eziyoruz. Tek metod ezmesiyle kuralin baktigi eksen degisiyor:
      # "bir IP ne yapti" yerine "bir hedefe ne oldu".
      def key_for(entry)
        normalize(entry.path)
      end

      # Pencereye IP yaziyoruz...
      def value_for(entry)
        entry.ip
      end

      # ...ve olay sayisi yerine FARKLI IP sayisini olcuyoruz.
      # (PathScan'de yaptigimizin aynisi, farkli bir eksende.)
      def measure(key)
        events = @events[key] || []
        events.map { |(_time, ip)| ip }.uniq.size
      end

      def message_for(entry, measured)
        format('%d saniyede %d FARKLI IP adresinden %s adresine basarisiz ' \
               'giris (dagitik deneme)',
               @window, measured, normalize(entry.path))
      end

      def details_for(entry, _measured)
        ips = (@events[key_for(entry)] || []).map { |(_t, ip)| ip }.uniq

        {
          target_path:  normalize(entry.path),
          distinct_ips: ips.size,
          # Alarmi inceleyen kisinin ilk soracagi sey: "hangi adresler?"
          # Hepsini tasimiyoruz -- 3000 IP'lik bir liste ne belleksel ne
          # insani bir fayda saglar. Ornek yeter, tamami veritabaninda.
          sample_ips:   ips.last(10),
          # Ayni /24 blogundan mi geliyorlar? Tek bir botnet ya da tek bir
          # saglayici olabilir -- mudahale kararini degistirir.
          distinct_subnets: ips.filter_map { |ip| ip.split('.').first(3).join('.') if ip.count('.') == 3 }
                               .uniq.size
        }
      end

      # Alarm, tek bir IP'ye degil bir HEDEFE ait. Alert nesnesinin ip
      # alanina hedefi yaziyoruz ki panelde anlamli gorunsun.
      def build_alert(entry, measured)
        alert = super
        alert.ip = "#{normalize(entry.path)} (#{measured} IP)"
        alert
      end

      private

      def normalize(path)
        path.to_s.downcase.split('?').first.to_s
      end
    end
  end
end
