# frozen_string_literal: true

# ============================================================================
#  Allowlist -- bilinen ve beklenen trafigi alarm uretmeden gecirme
# ----------------------------------------------------------------------------
#  NEDEN GEREKLI? Kurumsal bir ortamda alarm uretmesi BEKLENEN ama zararsiz
#  olan trafik her zaman vardir:
#
#    - Load balancer'in saglik kontrolu: saniyede birkac kez /health'e
#      vurur. Flood kuralinin esigini rahatlikla asar.
#    - Izleme sistemleri (Zabbix, Nagios, Prometheus blackbox): duzenli,
#      yuksek hacimli, hep ayni uctan.
#    - Kurum ici zafiyet tarayicilari: PLANLI olarak /admin, /.env gibi
#      yollari tarar -- yani PathScan ve Scanner kurallarini kasten
#      tetikler. Guvenlik ekibinin kendi taramasi, saldiri degildir.
#    - Uptime/SLA olcum servisleri, arama motoru botlari.
#
#  Bunlar filtrelenmezse ne olur? Panel surekli alarm gosterir, kimse
#  bakmaz, ve GERCEK alarm o gurultunun icinde kaybolur. Adim 4'te
#  ogrendigimiz sey: SIEM projelerini bitiren sey yanlis tespit degil,
#  BILDIRIM YORGUNLUGUDUR. Allowlist, o yorgunlugun en yaygin kaynagini
#  keser.
#
#  TASARIM KARARI: NEREDE FILTRELENMELI?
#
#  Iki secenek vardi:
#    a) Parser'da: kaydi hic uretme
#    b) Engine'de: kaydi uret, ama kurallara sokma
#
#  (b) secildi. Cunku allowlist'teki bir adresin ne yaptigini GORMEK
#  isteriz -- veritabanina yazilsin, panelde aranabilsin, arsivde dursun.
#  Yalnizca ALARM URETMESIN. "Gormezden gelmek" ile "kaydetmemek" ayni
#  sey degildir; ikincisi adli inceleme icin veri kaybidir.
#
#  GUVENLIK NOTU: allowlist bir GUVENLIK ZAFIYETIDIR eger genis tutulursa.
#  Bir saldirgan allowlist'teki bir adresi ele gecirirse ya da user-agent'i
#  taklit ederse gorunmez olur. Bu yuzden:
#    - IP araliklarini dar tut (tek adres / kucuk CIDR)
#    - User-agent'a GUVENME: taklit edilmesi bir satir koddur. Yalnizca
#      gurultu azaltmak icin, o da IP ile BIRLIKTE kullanilmali.
#    - Filtrelenen kayit sayisini izle: aniden artiyorsa birileri
#      allowlist'i kalkan olarak kullaniyor olabilir.
# ============================================================================

require 'ipaddr'

module LogSentry
  class Allowlist
    attr_reader :skipped_count

    # ips        : IP adresleri veya CIDR araliklari  ['10.0.0.5', '192.168.1.0/24']
    # paths      : yol onekleri                        ['/health', '/metrics']
    # user_agents: user-agent kaliplari (metin icerir) ['Zabbix', 'Pingdom']
    #
    # ONEMLI: bu uc olcut VE degil, VEYA ile birlesir -- yani herhangi biri
    # eslesirse kayit muaf tutulur. Bu bilincli: saglik kontrolu genelde
    # sadece yola gore, izleme sistemi sadece IP'ye gore tanimlanir.
    def initialize(ips: [], paths: [], user_agents: [])
      @ranges = build_ranges(ips)
      @paths  = Array(paths).map { |p| p.to_s.downcase }
      @agents = Array(user_agents).map { |a| a.to_s.downcase }
      @skipped_count = 0
      @skipped_by = Hash.new(0)
    end

    def empty?
      @ranges.empty? && @paths.empty? && @agents.empty?
    end

    # Bu kayit alarm uretmekten muaf mi?
    def allowed?(entry)
      reason = match_reason(entry)
      return false if reason.nil?

      @skipped_count += 1
      @skipped_by[reason] += 1
      true
    end

    def stats
      {
        rules:      { ips: @ranges.size, paths: @paths.size, agents: @agents.size },
        skipped:    @skipped_count,
        skipped_by: @skipped_by.dup
      }
    end

    private

    def match_reason(entry)
      return :ip         if ip_allowed?(entry.ip)
      return :path       if path_allowed?(entry.path)
      return :user_agent if agent_allowed?(entry.user_agent)

      nil
    end

    def ip_allowed?(ip)
      return false if @ranges.empty? || ip.nil?

      addr = IPAddr.new(ip)
      @ranges.any? { |range| range.include?(addr) }
    rescue IPAddr::InvalidAddressError, ArgumentError
      # Gecerli bir IP degilse muaf TUTMA. Allowlist'in varsayilani
      # "izin verme" olmali: supheye dusuldugunde kaydi kurallara sok.
      false
    end

    def path_allowed?(path)
      return false if @paths.empty?

      normalized = path.to_s.downcase.split('?').first.to_s
      @paths.any? { |allowed| normalized == allowed || normalized.start_with?("#{allowed}/") }
    end

    def agent_allowed?(agent)
      return false if @agents.empty? || agent.nil?

      lowered = agent.downcase
      @agents.any? { |allowed| lowered.include?(allowed) }
    end

    def build_ranges(list)
      Array(list).filter_map do |cidr|
        IPAddr.new(cidr.to_s)
      rescue IPAddr::InvalidAddressError, ArgumentError
        warn "[allowlist] gecersiz IP/CIDR yok sayildi: #{cidr.inspect}"
        nil
      end
    end
  end
end
