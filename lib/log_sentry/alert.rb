# frozen_string_literal: true

# ============================================================================
#  ADIM 4a -- Alert: bir uyarinin veri modeli
# ----------------------------------------------------------------------------
#  Entry, "ne oldu"yu tasiyordu. Alert, "bu neden onemli"yi tasiyor.
#
#  Bu iki sey arasindaki fark, bir log aracini SIEM yapan seyin ta kendisi:
#    Entry  ->  gozlem   (45.155.205.233, /login, 401)
#    Alert  ->  YARGI    (bu IP sifre deniyor, mudahale et)
# ============================================================================

require 'time'
require 'json'

module LogSentry
  # Bir alarma kac ham satiri kanit olarak ekleyecegiz?
  #
  # Neden sinirli? Cunku bir DDoS alarminda 150.000 satirin hepsini
  # tasimanin ne belleksel ne insani bir faydasi var. Ilk birkac ornek
  # "bu gercekten saldiri mi?" sorusunu cevaplamaya yeter.
  # (Adim 1-3 boyunca tekrarladigimiz dersin dorduncu tekrari:
  #  bir daemon icinde sinirsiz buyuyen hicbir yapiya yer yoktur.)
  MAX_EVIDENCE = 5

  Alert = Struct.new(
    :rule,      # Symbol  -> :brute_force        hangi kural uretti
    :severity,  # Symbol  -> :high               onem derecesi
    :ip,        # String  -> "45.155.205.233"    kim
    :message,   # String  -> insan icin ozet
    :time,      # Time    -> LOGUN zamani (bizim saatimiz degil)
    :count,     # Integer -> 11                  olculen deger
    :threshold, # Integer -> 10                  asilan esik
    :window,    # Integer -> 60                  hangi zaman penceresinde
    :details,   # Hash    -> kurala ozel ek bilgi
    :evidence,  # Array   -> alarmi DOGURAN ham log satirlari
    keyword_init: true
  ) do
    SEVERITY_ORDER = { low: 0, medium: 1, high: 2, critical: 3 }.freeze

    # Onem siralamasi icin. Uyarilari "en ciddi ustte" diye siralamak
    # istedigimizde sembolleri karsilastiramayiz, sayiya cevirmemiz gerekir.
    def severity_rank
      SEVERITY_ORDER.fetch(severity, 0)
    end

    # Ayni IP + ayni kural = ayni "olay". Sogutma (cooldown) mekanizmasi
    # bu anahtar uzerinden calisir. Bu olmadan tek bir saldiri telefonuna
    # binlerce bildirim yagdirir.
    def key
      "#{rule}:#{ip}"
    end

    # Tek satirlik, terminale basilabilir hal
    def to_line
      format('[%s] %-12s %-16s %s',
             time.strftime('%H:%M:%S'), severity.to_s.upcase, ip, message)
    end

    # JSONL dosyasina ve (Adim 6'da) veritabanina yazilacak hal.
    # Zamani ISO-8601 olarak yaziyoruz: saat dilimi bilgisini KAYBETMEYEN,
    # siralanabilir ve her dilin ayristirabildigi tek standart bicim.
    def to_record
      {
        rule:      rule,
        severity:  severity,
        ip:        ip,
        message:   message,
        time:      time.iso8601,
        count:     count,
        threshold: threshold,
        window:    window,
        details:   details,
        evidence:  evidence
      }
    end

    def to_json(*args)
      to_record.to_json(*args)
    end
  end
end
