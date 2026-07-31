# frozen_string_literal: true

# ============================================================================
#  ADIM 4f -- Engine: kural motoru
# ----------------------------------------------------------------------------
#  Mimari dokumaninda (bolum 5) su iddiada bulunmustuk:
#
#    "Butun kurallar ayni sozlesmeye uydugu icin, motor kurallarin ne
#     yaptigini bilmek zorunda degildir. Motorun tum kodu pratikte
#     su kadardir:
#         @rules.filter_map { |rule| rule.call(entry) }
#     Yarin 20 kural daha eklesen bu satir ayni kalir."
#
#  Bu dosya o iddianin tutuldugu yer. Asagida process metoduna bak:
#  gercekten tek satir. Icinde tek bir `if rule.is_a?(BruteForce)` yok.
#
#  Buna POLIMORFIZM denir: farkli nesnelerin ayni cagriya kendi bildikleri
#  gibi cevap vermesi. Cagiran taraf farki bilmez, bilmesi de gerekmez.
# ============================================================================

require 'yaml'
require_relative 'entry'
require_relative 'rules/brute_force'
require_relative 'rules/credential_stuffing'
require_relative 'rules/flood'
require_relative 'rules/path_scan'
require_relative 'rules/sqli'
require_relative 'rules/xss'
require_relative 'rules/scanner'

module LogSentry
  class Engine
    # Yapilandirma dosyasindaki isimleri sinif'lara baglayan tablo.
    # Yeni bir kural eklemek = yeni bir dosya + buraya bir satir.
    RULE_CLASSES = {
      'brute_force' => Rules::BruteForce,
      'credential_stuffing' => Rules::CredentialStuffing,
      'flood'       => Rules::Flood,
      'path_scan'   => Rules::PathScan,
      'sqli'        => Rules::Sqli,
      'xss'         => Rules::Xss,
      'scanner'     => Rules::Scanner
    }.freeze

    DEFAULT_COOLDOWN = 120

    attr_reader :rules, :processed_count, :alert_count

    def initialize(rules:)
      raise ArgumentError, 'en az bir kural gerekli' if rules.empty?

      @rules           = rules
      @processed_count = 0
      @alert_count     = 0
    end

    # ------------------------------------------------------------------------
    #  YAPILANDIRMADAN MOTOR URETME
    # ------------------------------------------------------------------------
    #  Esikleri koda gomek yerine YAML'dan okuyoruz. Kurumsal sistemlerde
    #  kural esikleri HER ZAMAN kodun disindadir: "10 cok dusuk, 25 yapalim"
    #  dedigimizde kodu yeniden yayinlamak yerine dosyayi degistirip servisi
    #  yeniden baslatmak yeterli olmali.
    # ------------------------------------------------------------------------
    #  reuse: onceki bir Engine. Verildiginde, ayari DEGISMEMIS kurallarin
    #  nesneleri oldugu gibi devralinir.
    #
    #  Neden? Cunku SIGHUP ile yapilandirmayi yenilerken kurallari bastan
    #  kurmak, kayan pencereleri ve sogutma kayitlarini SILER. Devam eden bir
    #  saldirida sayaclar sifirlanir ya da ayni alarm tekrar duser -- ki bunu
    #  canli testte bizzat gorduk. Ayari aynen duran bir kuralin hafizasini
    #  atmak icin hicbir sebep yok.
    def self.from_config(config, reuse: nil)
      config = YAML.load_file(config) if config.is_a?(String)

      global_cooldown = config['cooldown'] || DEFAULT_COOLDOWN
      rule_configs    = config['rules'] || {}

      rules = rule_configs.filter_map do |name, opts|
        opts ||= {}
        next unless opts['enabled']

        klass = RULE_CLASSES[name]

        # Bilinmeyen kural adi -> BASLANGICTA patla.
        #
        # Neden sessizce yok saymiyoruz? Cunku en olasi senaryo yapilandirma
        # dosyasinda yazim hatasi ("brute_fore"). Sessizce yok sayarsak
        # servis sorunsuz baslar, ama o kural HIC CALISMAZ ve bunu aylarca
        # fark etmezsin. Gece 3'te alarm uretmesi gereken bir servis, eksik
        # yapilandirmayla sessizce baslamamalidir.
        unless klass
          raise ArgumentError,
                "bilinmeyen kural: #{name.inspect} " \
                "(gecerli: #{RULE_CLASSES.keys.join(', ')})"
        end

        fresh = build_rule(klass, opts, global_cooldown)

        # Ayari birebir ayni olan bir kural onceki motorda varsa, YENISINI
        # ATIP ESKISINI kullaniyoruz. Boylece pencereler ve sogutma korunur.
        existing = reuse&.rules&.find { |r| r.signature == fresh.signature }
        existing || fresh
      end

      new(rules: rules)
    end

    def self.build_rule(klass, opts, global_cooldown)
      kwargs = {
        window:    Integer(opts.fetch('window')),
        threshold: Integer(opts.fetch('threshold')),
        cooldown:  Integer(opts['cooldown'] || global_cooldown)
      }

      # Kurala ozel, istege bagli ayarlar.
      kwargs[:statuses] = opts['statuses']          if opts['statuses']
      kwargs[:paths]    = opts['paths']             if opts['paths']
      kwargs[:severity] = opts['severity'].to_sym   if opts['severity']

      klass.new(**kwargs)
    end
    private_class_method :build_rule

    # ------------------------------------------------------------------------
    #  ANA METOD
    #  Girdi : bir Entry
    #  Cikti : Alert dizisi (bos olabilir)
    # ------------------------------------------------------------------------
    #  filter_map: her elemani donustur, nil olanlari ELE.
    #  Yani "map + compact" ama tek gecisde ve ara dizi uretmeden.
    #
    #  Iste iddia edilen tek satir. Motorun kurallarin isleyisi hakkinda
    #  hicbir bilgisi yok; sadece sozlesmeye guveniyor.
    # ------------------------------------------------------------------------
    def process(entry)
      @processed_count += 1
      alerts = @rules.filter_map { |rule| rule.call(entry) }
      @alert_count += alerts.size
      alerts
    end

    # Kolaylik: bir Entry akisini isleyip alarmlari bloga verir.
    # Adim 5'te daemon tam olarak bunu cagiracak.
    def run(entries)
      return enum_for(:run, entries) unless block_given?

      entries.each do |entry|
        process(entry).each { |alert| yield alert }
      end
    end

    def stats
      {
        processed: @processed_count,
        alerts:    @alert_count,
        rules:     @rules.map(&:stats)
      }
    end

    # Bellek gozlemi: su anda kac anahtar takip ediliyor?
    # Bir daemon'da bu sayiyi izleyebilmek sart -- surekli buyuyorsa
    # bir yerde sinir calismiyor demektir.
    def tracked_keys
      @rules.sum(&:tracked_keys)
    end
  end
end
