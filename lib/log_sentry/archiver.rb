# frozen_string_literal: true

# ============================================================================
#  ADIM 6b -- Archiver: SOGUK katman (yasal saklama + butunluk)
# ----------------------------------------------------------------------------
#  Store hizli SORGU icin. Bu dosya KANIT icin.
#
#  5651 sayili Kanun ve ilgili yonetmelikler kapsamindaysan trafik
#  kayitlarini belirli bir sure saklamak zorundasin. Ve mevzuatin cogu
#  kisinin kacirdigi ikinci sarti var: sadece saklamak yetmez, kayitlarin
#  DOGRULUGUNU, BUTUNLUGUNU ve GIZLILIGINI de saglamak gerekir. Yani
#  "sonradan degistirilmedi" iddiasini KANITLAYABILMEN lazim.
#
#  Bu dosya o kaniti uretiyor.
#
#  NOT: Bu bir hukuki gorus degildir. Kesin sure ve yukumluluk icin kendi
#  kategorin (erisim saglayici / yer saglayici / toplu kullanim saglayici)
#  uzerinden mevzuati ve hukuk tarafini teyit et. Buradaki tasarim, "boyle
#  bir yukumluluk varsa mimari nasil olmali" sorusunun cevabidir.
#
#  SAKLAMA SURESI IKI YONLU BIR KISITTIR:
#    * cok KISA -> 5651 kapsaminda yukumluluk ihlali
#    * cok UZUN -> IP adresi kisisel veri oldugu icin KVKK ihlali
#  "Garanti olsun diye sonsuza kadar tutalim" yaklasimi da hatalidir.
# ============================================================================

require 'digest'
require 'zlib'
require 'json'
require 'fileutils'
require 'time'

module LogSentry
  class Archiver
    # Zincirin baslangic degeri. Ilk kaydin "oncesi" olmadigi icin
    # uzerinde anlastigimiz sabit bir baslangic noktasi gerekiyor.
    GENESIS = ('0' * 64)

    # Dosyayi parca parca okurken kullanilacak tampon boyutu.
    # 2 GB'lik bir logun SHA-256'sini hesaplamak icin onu RAM'e almiyoruz --
    # Adim 1'de ogrendigimiz seyin ta kendisi, farkli bir kilikta.
    CHUNK = 64 * 1024

    attr_reader :directory, :manifest_path, :retention_days

    def initialize(directory:, manifest: nil, retention_days: 730,
                   compress: true, seal: true)
      @directory      = File.expand_path(directory)
      @manifest_path  = File.expand_path(manifest || File.join(@directory, 'manifest.jsonl'))
      @retention_days = retention_days
      @compress       = compress
      @seal           = seal

      FileUtils.mkdir_p(@directory)
      FileUtils.mkdir_p(File.dirname(@manifest_path))
    end

    # ========================================================================
    #  1) ARSIVLE
    # ------------------------------------------------------------------------
    #  Bir log dosyasini arsive tasir: sikistirir, muhurler, manifest'e yazar.
    #
    #  move: true  -> kaynak dosya arsivlendikten sonra silinir (rotasyon
    #                 sonrasi birakilan access.log.1 gibi dosyalar icin)
    #        false -> kaynak korunur (canli dosyanin kopyasini almak icin)
    # ========================================================================
    def archive_file(source, move: true, label: nil)
      source = File.expand_path(source)
      raise ArgumentError, "dosya yok: #{source}" unless File.exist?(source)

      # --- Kaynagin ozeti ve satir sayisi ---------------------------------
      # Sikistirmadan ONCE hesapliyoruz: kanitlanan sey HAM icerigin
      # butunlugudur, sikistirilmis halinin degil. Yarin gzip yerine baska
      # bir sikistirma kullanirsak ozet degismemeli.
      source_digest, line_count = digest_and_count(source)

      name   = label || File.basename(source)
      stamp  = Time.now.strftime('%Y%m%d-%H%M%S')
      target = File.join(@directory, "#{name}.#{stamp}#{@compress ? '.gz' : ''}")

      if @compress
        compress_file(source, target)
      else
        FileUtils.cp(source, target)
      end

      stored_digest = file_digest(target)
      entry = seal_entry(
        file:          File.basename(target),
        source:        source,
        sha256:        source_digest,       # HAM icerigin ozeti
        stored_sha256: stored_digest,       # diskteki dosyanin ozeti
        bytes:         File.size(source),
        stored_bytes:  File.size(target),
        lines:         line_count
      )

      # Kaynagi ancak arsiv dosyasi diskte DOGRULANDIKTAN sonra siliyoruz.
      # Once silip sonra yazmak, arada bir hata olursa veriyi tamamen
      # kaybetmek demektir.
      if move
        raise "arsiv dosyasi dogrulanamadi: #{target}" unless verify_entry(entry)[:ok]

        File.delete(source)
      end

      entry
    end

    # ------------------------------------------------------------------------
    #  GOSTERIM/DEMO amacli: canli log dosyasini dondur ve arsivle.
    #
    #  DURUSTLUK NOTU: uretimde bu isi SEN yapmazsin, logrotate yapar --
    #  cunku dosyayi yeniden adlandirdiktan sonra sunucuya (nginx) yeni
    #  dosyaya gecmesi icin sinyal gonderilmesi gerekir; bu da sunucu
    #  yapilandirmasinin isidir. Bizim Tailer'imiz (adim 3) rotasyonu
    #  zaten algiliyor, yani bu islem izlemeyi bozmaz.
    # ------------------------------------------------------------------------
    def roll_and_archive!(log_path)
      log_path = File.expand_path(log_path)
      return nil unless File.exist?(log_path) && File.size(log_path).positive?

      rolled = "#{log_path}.rolled-#{Time.now.strftime('%Y%m%d-%H%M%S')}"
      File.rename(log_path, rolled)
      archive_file(rolled, move: true, label: File.basename(log_path))
    end

    # ========================================================================
    #  2) DOGRULA -- butunluk denetimi
    # ------------------------------------------------------------------------
    #  Iki sey kontrol ediliyor:
    #
    #  a) DOSYA BUTUNLUGU: her arsiv dosyasinin ozeti yeniden hesaplanip
    #     manifest'teki degerle karsilastiriliyor.
    #
    #  b) ZINCIR BUTUNLUGU: her kayit, kendinden oncekinin zincir degerini
    #     icerir. Ortadaki tek bir kaydi degistirmek isteyen birinin
    #     SONRAKI TUM kayitlari da yeniden hesaplamasi gerekir.
    #
    #     chain[n] = SHA256( chain[n-1] + sha256[n] )
    #
    #     Bu fikrin adi HASH ZINCIRI; blok zincirinin de temelinde bu yatar.
    #     Kurumsal log urunlerinin "degistirilemez kayit" (tamper-evident)
    #     iddiasi bunun uzerine kuruludur.
    #
    #  UYUSMAZLIK BULUNURSA BU KENDI BASINA BIR GUVENLIK OLAYIDIR.
    #  Loglarini degistiren biri varsa, bunu bilmen gerekir -- ve genelde
    #  loglarini degistiren kisi, orada izini silmek isteyen kisidir.
    # ========================================================================
    def verify
      entries = read_manifest
      results = []
      prev_chain = GENESIS
      ok = true

      entries.each_with_index do |entry, index|
        file_result  = verify_entry(entry)
        chain_ok     = entry[:prev_chain] == prev_chain
        expected     = chain_value(prev_chain, entry[:sha256])
        chain_valid  = entry[:chain] == expected

        entry_ok = file_result[:ok] && chain_ok && chain_valid
        ok &&= entry_ok

        results << {
          index:      index,
          file:       entry[:file],
          exists:     file_result[:exists],
          digest_ok:  file_result[:digest_ok],
          chain_ok:   chain_ok && chain_valid,
          ok:         entry_ok,
          reason:     failure_reason(file_result, chain_ok, chain_valid)
        }

        prev_chain = entry[:chain]
      end

      { ok: ok, entries: results, count: entries.size,
        head: entries.last&.dig(:chain) }
    end

    # Tek bir manifest kaydinin dosyasini dogrula.
    def verify_entry(entry)
      path = File.join(@directory, entry[:file])
      return { ok: false, exists: false, digest_ok: false } unless File.exist?(path)

      # Diskteki dosyanin ozeti degismis mi?
      stored_ok = entry[:stored_sha256].nil? ||
                  file_digest(path) == entry[:stored_sha256]

      # Sikistirmayi acip HAM icerigin ozetini de dogrula.
      # Sadece sikistirilmis dosyanin ozetine bakmak yeterli olmazdi:
      # saldirgan icerigi degistirip yeniden sikistirabilir ve manifest'teki
      # stored_sha256'yi de guncelleyebilir. Ham ozet, zincire giren degerdir.
      raw_ok = if entry[:sha256]
                 raw_digest(path) == entry[:sha256]
               else
                 true
               end

      { ok: stored_ok && raw_ok, exists: true, digest_ok: stored_ok && raw_ok }
    end

    # ========================================================================
    #  3) TEMIZLE -- saklama suresi
    # ------------------------------------------------------------------------
    #  Suresi gecmis arsivleri sil. SILME ISLEMI DE BIR OLAYDIR: manifest'e
    #  kayit dusuyoruz. "Bu dosya nerede?" sorusunun cevabi "bilmiyorum"
    #  olmamali; "12 Agustos'ta saklama suresi dolduğu icin silindi" olmali.
    #
    #  Silme kaydi da zincire giriyor -- yani birisi "bu log hic olmadi"
    #  diyemez, silindigi zincirde yazili.
    # ========================================================================
    def prune!(now: Time.now, dry_run: false)
      cutoff  = now - (@retention_days * 86_400)
      entries = read_manifest
      removed = []

      entries.each do |entry|
        next if entry[:deleted]

        sealed = begin
          Time.iso8601(entry[:sealed_at].to_s)
        rescue ArgumentError
          nil
        end
        next if sealed.nil? || sealed >= cutoff

        path = File.join(@directory, entry[:file])
        removed << { file: entry[:file], sealed_at: entry[:sealed_at],
                     bytes: (File.size(path) if File.exist?(path)) }

        next if dry_run

        File.delete(path) if File.exist?(path)
        append_manifest(
          type:       'deletion',
          file:       entry[:file],
          reason:     "saklama suresi doldu (#{@retention_days} gun)",
          deleted_at: now.iso8601,
          sha256:     entry[:sha256]
        )
      end

      { cutoff: cutoff, removed: removed, count: removed.size, dry_run: dry_run }
    end

    # ========================================================================
    #  MANIFEST
    # ========================================================================

    def read_manifest
      return [] unless File.exist?(@manifest_path)

      File.readlines(@manifest_path).filter_map do |line|
        line = line.strip
        next if line.empty?

        record = begin
          JSON.parse(line, symbolize_names: true)
        rescue JSON::ParserError
          nil
        end
        next if record.nil?
        # Silme kayitlari zincirin parcasi degil, ayri bir olay turudur.
        next if record[:type] == 'deletion'

        record
      end
    end

    def deletions
      return [] unless File.exist?(@manifest_path)

      File.readlines(@manifest_path).filter_map do |line|
        record = begin
          JSON.parse(line.strip, symbolize_names: true)
        rescue JSON::ParserError
          nil
        end
        record if record && record[:type] == 'deletion'
      end
    end

    def head_chain
      read_manifest.last&.dig(:chain) || GENESIS
    end

    def stats
      entries = read_manifest
      {
        directory:      @directory,
        manifest:       @manifest_path,
        archives:       entries.size,
        deletions:      deletions.size,
        retention_days: @retention_days,
        stored_bytes:   entries.sum { |e| e[:stored_bytes].to_i },
        raw_bytes:      entries.sum { |e| e[:bytes].to_i },
        head_chain:     head_chain,
        oldest:         entries.first&.dig(:sealed_at),
        newest:         entries.last&.dig(:sealed_at)
      }
    end

    private

    def seal_entry(**fields)
      prev = head_chain
      sha  = fields[:sha256]

      entry = fields.merge(
        sealed_at:  Time.now.iso8601,
        prev_chain: prev,
        chain:      chain_value(prev, sha)
      )

      append_manifest(**entry) if @seal
      entry
    end

    def chain_value(prev_chain, sha256)
      Digest::SHA256.hexdigest("#{prev_chain}#{sha256}")
    end

    # Manifest'e ekleme: JSONL, sadece append.
    #
    # 'a' modu ve sync: manifest, arsivin kendisi kadar kiymetli. Kayitsiz
    # bir arsiv dosyasi, butunlugu kanitlanamayan bir dosyadir.
    def append_manifest(**record)
      File.open(@manifest_path, 'a') do |f|
        f.sync = true
        f.puts JSON.generate(record)
      end
    end

    # ------------------------------------------------------------------------
    #  OZET HESAPLAMA -- akis halinde
    # ------------------------------------------------------------------------
    #  Digest::SHA256.hexdigest(File.read(path)) yazmak cazip ama 2 GB'lik
    #  bir logda 2 GB RAM ister. Adim 1'in dersi, dorduncu kez.
    #  Dosyayi 64 KB'lik parcalar halinde okuyup ozete besliyoruz.
    # ------------------------------------------------------------------------
    def file_digest(path)
      digest = Digest::SHA256.new
      File.open(path, 'rb') do |f|
        while (chunk = f.read(CHUNK))
          digest << chunk
        end
      end
      digest.hexdigest
    end

    # Ham icerigin ozeti + satir sayisi (tek gecisde)
    def digest_and_count(path)
      digest = Digest::SHA256.new
      lines  = 0

      File.open(path, 'rb') do |f|
        f.each_line do |line|
          digest << line
          lines += 1
        end
      end

      [digest.hexdigest, lines]
    end

    # Arsivlenmis dosyanin HAM icerigi (gerekiyorsa acarak) ozeti
    def raw_digest(path)
      digest = Digest::SHA256.new

      if path.end_with?('.gz')
        Zlib::GzipReader.open(path) do |gz|
          while (chunk = gz.read(CHUNK))
            digest << chunk
          end
        end
      else
        return file_digest(path)
      end

      digest.hexdigest
    rescue Zlib::GzipFile::Error
      # Bozuk gzip -> ozet hesaplanamaz -> dogrulama basarisiz olsun.
      'BOZUK'
    end

    # Sikistirma da akis halinde: kaynagi parca parca okuyup gzip'e yaziyoruz.
    def compress_file(source, target)
      Zlib::GzipWriter.open(target) do |gz|
        gz.mtime = File.mtime(source)
        gz.orig_name = File.basename(source)
        File.open(source, 'rb') do |f|
          while (chunk = f.read(CHUNK))
            gz.write(chunk)
          end
        end
      end
    end

    def failure_reason(file_result, chain_ok, chain_valid)
      return 'dosya yok' unless file_result[:exists]
      return 'DOSYA DEGISTIRILMIS (ozet uyusmuyor)' unless file_result[:digest_ok]
      return 'ZINCIR KOPUK (onceki kayit degismis veya silinmis)' unless chain_ok
      return 'ZINCIR DEGERI YANLIS (manifest kaydi degistirilmis)' unless chain_valid

      nil
    end
  end
end
