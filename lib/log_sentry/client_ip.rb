# frozen_string_literal: true

require 'ipaddr'

module LogSentry
  # ==========================================================================
  #  ClientIP -- "bu istek GERCEKTEN kimden geldi?"
  # --------------------------------------------------------------------------
  #  Bu mantik once yalnizca Parser'in icindeydi: nginx logundaki
  #  $remote_addr + X-Forwarded-For zincirinden gercek istemciyi cikarmak
  #  icin. Sonra web arayuzune bir hiz siniri (rate limit) eklendi ve orada
  #  Rack'in `request.ip` degeri kullanildi.
  #
  #  Sorun: Rack'in `request.ip`'i X-Forwarded-For'a bakar ve BASLIGI KIMIN
  #  YAZDIGINI bilmez. Yani hiz sinirini IP basina uygularken saldirgan
  #  her istekte farkli bir XFF yazarak siniri tamamen atlayabilir --
  #  ustelik ustune, baskasinin IP'sini yazarak MASUM birini limitletebilir.
  #
  #  Proje bu problemi log tarafinda zaten dogru cozmustu (trusted_proxies).
  #  Ayni cozumun web tarafinda kullanilmamasi bir tutarsizlikti. Bu modul
  #  mantigi TEK BIR YERE tasiyor; iki taraf da buradan okuyor.
  # ==========================================================================
  module ClientIP
    module_function

    # ------------------------------------------------------------------------
    #  X-Forwarded-For zincirinden gercek istemciyi cikar
    # ------------------------------------------------------------------------
    #  YANLIS YONTEM: zincirin ILK adresini al.
    #  Cunku o adresi ISTEMCI yazmis olabilir:
    #
    #      X-Forwarded-For: 8.8.8.8          <- saldirganin uydurdugu
    #      ...LB kendi gordugunu ekler:  8.8.8.8, 45.155.205.233
    #
    #  Ilk adresi almak, saldirganin istedigi masum IP'yi kara listeye
    #  attirmasina izin verir. Buna "XFF spoofing" denir.
    #
    #  DOGRU YONTEM: zinciri SAGDAN SOLA yuru.
    #  En sagdaki adres, bize en yakin olan ve GUVENDIGIMIZ vekilin gordugu
    #  adrestir. Kendi vekillerimizi atlaya atlaya sola git; guvenmedigin
    #  ILK adres gercek istemcidir. Ondan solu saldirganin uydurabilecegi
    #  bolgedir, dokunma.
    #
    #      [8.8.8.8 (uydurma), 45.155.205.233 (gercek), 10.0.0.7 (bizim LB)]
    #                                ^ dogru cevap        ^ guvenilir, atla
    #
    #  GUVENLI VARSAYILAN: trusted_proxies bos ise XFF'e HIC BAKMIYORUZ.
    #  Kimin vekil oldugunu bilmeden zincire guvenmek, saldirganin kimligini
    #  secmesine izin vermektir. Yapilandirilmamis bir sistemde "yanlis
    #  IP'yi engellemek" yerine "vekilin IP'sini gormek" daha az zararlidir.
    # ------------------------------------------------------------------------
    def resolve(remote_addr, forwarded_for, trusted_proxies)
      return remote_addr if trusted_proxies.nil? || trusted_proxies.empty?
      return remote_addr if forwarded_for.nil?

      chain = forwarded_for.to_s.strip
      return remote_addr if chain.empty? || chain == '-'

      # Tam zincir: XFF listesi + en sonda bize baglanan adres.
      addresses = chain.split(',').map(&:strip).reject(&:empty?)
      addresses << remote_addr

      # Sagdan sola: guvenilir vekilleri atla, ilk guvenilmeyeni al.
      client = addresses.reverse.find { |addr| !trusted?(addr, trusted_proxies) }

      # Zincirdeki herkes bizim vekilimizse (ic trafik) en soldakini al.
      client || addresses.first
    end

    def trusted?(address, trusted_proxies)
      ip = IPAddr.new(address.to_s)
      trusted_proxies.any? { |range| range.include?(ip) }
    rescue IPAddr::InvalidAddressError, ArgumentError
      # Gecerli bir IP degilse guvenilir SAYMA. XFF'e cop yazmak, zincir
      # yurumesini bozmaya calismanin bilinen bir yoludur.
      false
    end

    # CIDR metinlerini IPAddr araliklarina cevirir.
    # Gecersiz girdi SESSIZCE yutulmaz: yanlis yazilmis bir vekil araligi,
    # o vekilin arkasindaki herkesi tek bir IP gibi gostermek demektir.
    def build_ranges(list, source: 'config')
      Array(list).filter_map do |cidr|
        IPAddr.new(cidr.to_s)
      rescue IPAddr::InvalidAddressError, ArgumentError
        warn "[#{source}] gecersiz trusted_proxies girdisi yok sayildi: #{cidr.inspect}"
        nil
      end
    end
  end
end
