# frozen_string_literal: true

# ============================================================================
#  ADIM 5e -- Daemon: process'i arka plana cekmek
# ----------------------------------------------------------------------------
#  "Kodum calisiyor" ile "servisim ayakta" arasindaki fark bu dosyada.
#
#  SORUN: `ruby bin/logsentry` yazdiginda program terminali isgal eder.
#  Terminali kapatinca, SSH baglantin kopunca ya da oturumun sonlaninca
#  program da olur. Cunku:
#
#    - Program terminale bagli (controlling TTY)
#    - Program senin oturumunun (session) bir parcasi
#    - Oturum kapaninca cekirdek o oturumdaki process'lere SIGHUP gonderir
#
#  COZUM: process'i oturumdan KOPARMAK. Buna "daemonization" denir.
#  Unix'te klasik yontem su uc adimdir:
#
#    1) fork()   -> cocuk process yarat, EBEVEYNI OLDUR
#                   Boylece process artik terminalin cocugu degil; kabuk
#                   (shell) onu beklemez ve hemen sana prompt doner.
#
#    2) setsid() -> YENI bir oturum (session) ac ve o oturumun lideri ol.
#                   Bu adim terminal baglantisini kesin olarak koparir.
#                   Artik controlling TTY'si yoktur; terminal kapaninca
#                   SIGHUP almaz.
#
#    3) stdin/stdout/stderr'i yeniden yonlendir
#                   Terminal yoksa bu uc akisin isaret ettigi yer de yok.
#                   Kapatmadan birakirsan ilk `puts` cagrisinda EIO hatasi
#                   alirsin -- ya da daha kotusu, kapatilmis bir dosya
#                   tanimlayicisina (fd) yazarsin.
#
#  Ruby bu ucunu tek cagrida yapar: Process.daemon
#
#  DIKKAT: Process.daemon Windows'ta YOKTUR (NotImplementedError). Cunku
#  Windows'un process modeli farklidir: fork yok, oturum/TTY kavrami yok.
#  Windows'ta karsiligi "Windows Service"tir ve tamamen farkli bir API'dir.
#  Bu yuzden bu adimi WSL'de calistiriyoruz.
# ============================================================================

require 'fileutils'

module LogSentry
  module Daemon
    module_function

    # Bu platformda daemonlasabilir miyiz?
    def supported?
      Process.respond_to?(:daemon)
    end

    # ------------------------------------------------------------------------
    #  ARKA PLANA CEKIL
    # ------------------------------------------------------------------------
    def daemonize!(log_file:)
      unless supported?
        raise NotImplementedError,
              "Process.daemon bu platformda yok (#{RUBY_PLATFORM}). " \
              'Daemon modu icin WSL/Linux kullan.'
      end

      log_file = ::File.expand_path(log_file)
      FileUtils.mkdir_p(::File.dirname(log_file))

      # Process.daemon(nochdir, noclose)
      #
      # nochdir = true  -> calisma dizinini DEGISTIRME
      #   Varsayilan davranis "/" dizinine gecmektir. Bunun sebebi: bir
      #   daemon calisma dizinini mesgul tutarsa o disk bolumu unmount
      #   edilemez. Ama biz true veriyoruz, cunku yapilandirmadaki yollar
      #   (logs/access.log gibi) goreli. Dizini degistirsek dosyalari
      #   bulamazdik.
      #   Uretimde dogru yaklasim: tum yollari MUTLAK hale getir, sonra
      #   "/" dizinine gec. Ogrenme projesinde goreli yollar daha rahat.
      #
      # noclose = true  -> stdin/stdout/stderr'i SEN KAPATMA
      #   Varsayilan davranis ucunu /dev/null'a baglamaktir; yani tum
      #   ciktin cope gider. Biz true verip kapatmasini engelliyoruz ve
      #   asagida kendi log dosyamiza yonlendiriyoruz.
      Process.daemon(true, true)

      redirect_io(log_file)
      log_file
    end

    def redirect_io(log_file)
      # stdin -> /dev/null
      #
      # Daemon'un terminali yok; okuyacagi bir klavye de yok. Ama kod bir
      # yerde yanlislikla gets cagirirsa sonsuza kadar bloke olur.
      # /dev/null'a baglamak, o cagrinin ANINDA EOF donmesini saglar.
      #
      # ::File::NULL, platforma gore "/dev/null" veya "NUL" degerini verir.
      $stdin.reopen(::File::NULL)

      # stdout ve stderr -> log dosyasi (append)
      $stdout.reopen(log_file, 'a')
      $stderr.reopen($stdout)

      # sync = true: tamponlama yapma.
      #
      # Terminale yazarken Ruby her satirda tamponu bosaltir. DOSYAYA
      # yazarken 8 KB birikene kadar bekler. Bu olmadan bir daemon'un
      # loglari dakikalarca gorunmez -- ve process cokerse tamponda
      # bekleyen satirlar tamamen kaybolur. Yani "cokmeden hemen once ne
      # oldu?" bilgisini, tam ihtiyac duydugun anda kaybedersin.
      $stdout.sync = true
      $stderr.sync = true
    end

    # ========================================================================
    #  PID DOSYASI
    # ------------------------------------------------------------------------
    #  Process arka plana cekildikten sonra onunla nasil konusacaksin?
    #  Elinde bir pencere yok, Ctrl-C basacagin bir terminal yok.
    #  Tek yol: process kimligini (PID) bilip ona SINYAL gondermek.
    #
    #  Bu yuzden daemon, dogar dogmaz kendi PID'ini bir dosyaya yazar:
    #      logs/logsentry.pid   ->  "48213"
    #
    #  Sonra "logsentry --stop" komutu bu dosyayi okur ve o PID'e SIGTERM
    #  gonderir. systemd, docker, monit -- hepsi ayni mantikla calisir.
    # ========================================================================
    class PidFile
      attr_reader :path

      def initialize(path)
        @path = ::File.expand_path(path)
      end

      # Dosyadaki PID (yoksa nil)
      def read
        return nil unless ::File.exist?(@path)

        value = ::File.read(@path).strip
        value.empty? ? nil : Integer(value)
      rescue ArgumentError, Errno::ENOENT
        # Bozuk icerik ("abc") ya da tam o anda silinmis dosya.
        nil
      end

      # ----------------------------------------------------------------------
      #  O PID GERCEKTEN YASIYOR MU?
      # ----------------------------------------------------------------------
      #  Buna "bayat (stale) PID dosyasi" problemi denir ve bilinmedigi
      #  zaman saatler kaybettiren klasik bir tuzaktir:
      #
      #  Sunucu aniden kapanir (elektrik, OOM killer, kill -9). Daemon
      #  dosyayi silme sansi bulamaz. Sunucu acilir, servisi baslatmaya
      #  calisirsin ve "zaten calisiyor" der -- ama calismiyor. Uzerine
      #  bir de yeni PID, bambaska bir process'e ait olabilir.
      #
      #  Cozum: Process.kill(0, pid)
      #  0 numarali "sinyal" aslinda sinyal DEGILDIR: hicbir sey gondermez,
      #  sadece "bu PID'e sinyal gonderebilir miydim?" diye sorar.
      #    - Errno::ESRCH -> boyle bir process yok  (bayat dosya)
      #    - Errno::EPERM -> process VAR ama baskasinin (yani yasiyor)
      #    - hata yok     -> process var ve bizim
      # ----------------------------------------------------------------------
      def alive?
        pid = read
        return false if pid.nil?

        Process.kill(0, pid)
        true
      rescue Errno::ESRCH
        false
      rescue Errno::EPERM
        true
      end

      # Kendi PID'imizi yaz. Baska bir ornek calisiyorsa hata firlat.
      def acquire!
        if alive?
          raise "LogSentry zaten calisiyor (PID #{read}). " \
                "Durdurmak icin: bin/logsentry --stop"
        end

        if ::File.exist?(@path)
          warn "[daemon] bayat PID dosyasi temizlendi: #{@path} (PID #{read})"
          ::File.delete(@path)
        end

        FileUtils.mkdir_p(::File.dirname(@path))
        ::File.write(@path, Process.pid.to_s)
        Process.pid
      end

      def release
        return unless ::File.exist?(@path)

        # Sadece BIZE aitse sil. Baska bir ornek dosyayi devraldiysa
        # onun kaydini silmek, o ornegi yonetilemez hale getirir.
        ::File.delete(@path) if read == Process.pid
      rescue Errno::ENOENT
        nil
      end

      # Calisan ornege sinyal gonder.
      def signal(name)
        pid = read
        raise "PID dosyasi yok veya bos: #{@path}" if pid.nil?
        raise "PID #{pid} calismiyor (bayat dosya)" unless alive?

        Process.kill(name, pid)
        pid
      end
    end
  end
end
