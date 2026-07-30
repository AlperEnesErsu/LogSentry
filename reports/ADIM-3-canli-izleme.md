# ADIM 3 RAPORU — Gerçek Zamanlı İzleme (`tail -f` Mantığı)

**Durum:** ✅ Tamamlandı
**Test:** 15 test — WSL ✅ (32 doğrulama) / Windows ✅ (24 doğrulama, **3 atlama**)
**Üretilen dosyalar:** `lib/log_sentry/tailer.rb`, `step3_tailer.rb`,
`test/tailer_test.rb`, `tools/live_writer.rb`, `tools/watch.rb`

---

## 1. Kavramsal sıçrama

Bu adım, projedeki en önemli zihinsel geçiş:

| | **Log analizi** (Adım 1–2) | **İzleme** (Adım 3+) |
|---|---|---|
| Veri | dün olan, sabit | şu an olan, akıyor |
| Program | başlar, biter | **hiç bitmez** |
| Soru | "ne oldu?" | "şu an ne oluyor?" |
| Değer | adli inceleme | **müdahale şansı** |

Adım 1'de program dosyayı okuyup çıktı. Şimdi dosyanın sonuna geldiğinde
**kapanmıyor**, bekliyor. Bu küçük fark aracı "rapor üreten script"ten
"izleme sistemine" dönüştürür. Prometheus, Datadog, Filebeat — hepsinin
kaputunun altında bu döngü var.

## 2. Ana döngü

Her turda:

1. Okunacak yeni satır var mı? Varsa hepsini oku ve bloğa ver
2. Dosya döndürülmüş/kesilmiş mi? Kontrol et
3. Konumu kaydet (checkpoint)
4. **Biraz uyu** (`sleep 0.2`)

4. adım olmadan `while true; file.gets; end` yazarsan program bir CPU
çekirdeğini %100 doldurur ve hiçbir şey yapmaz. Buna **busy wait** (meşgul
bekleme) denir. `sleep`, işletim sistemine "beni 200 ms uyut, bu süre boyunca
işlemciyi başkasına ver" demektir.

## 3. Yarım satır problemi

En sinsi hata kaynağı. Sunucu tam bizim okuduğumuz anda satırın yarısını
yazmış olabilir:

```
45.155.205.233 - - [29/Jul/2026:14:39:25 +0300] "POST /log
```

`gets` bunu satır olarak döndürür — çünkü dosya sonuna gelmiştir. Parser'a
verirsen ya `nil` döner (kayıp) ya da yanlış ayrıştırır.

**Çözüm:** satır sonu karakteri yoksa veriyi tamponda beklet, bir sonraki
turda gelen parçayla birleştir. `MAX_PARTIAL_BYTES = 1 MB` sınırı var —
satır sonu hiç gelmezse tampon sonsuza büyümesin. (*Adım 1'in dersi, üçüncü
kez.*)

## 4. Rotasyon ve kesilme — iki farklı problem

`logrotate` gece 3'te log dosyasını değiştirir. İki yöntemi var ve **ikisi
farklı tespit gerektirir**:

### 4.1 `create` modu (varsayılan)

```
access.log  →  access.log.1     (yeniden adlandırılır)
yeni boş access.log oluşturulur
```

Biz eski dosyayı **açık tutmaya devam ediyoruz** — Unix'te açık bir dosya
yeniden adlandırılsa da aynı dosyadır. Sonuç: yeni satırları hiç görmeyiz,
sessizce kör kalırız.

**Tespit:** yoldaki dosyanın inode'u, bizim açık tuttuğumuzunkinden farklı mı?

```ruby
[stat.dev, stat.ino]   # dosyanın gerçek kimliği
```

### 4.2 `copytruncate` modu

```
access.log kopyalanır, sonra İÇİ BOŞALTILIR (aynı inode)
```

İnode aynı kaldığı için yukarıdaki kontrol işe yaramaz.

**Tespit:** dosya boyutu bizim okuma konumumuzdan küçük mü? Küçükse kesilme
olmuş, başa dön.

## 5. Testin bulduğu gerçek veri kaybı

Kesilme kontrolü ilk yazılışta **saniyede bir** çalışıyordu. Test şunu buldu:
kesilme ile bir sonraki kontrol arasında yazılan satırlar kaybediliyor. Kontrol
her okuma turuna alındı.

Ayrıca rotasyon anında eski dosyada kalan son satırlar için: yeni dosyaya
geçmeden önce **eskisini sonuna kadar oku**. Bu olmadan her rotasyonda birkaç
satır kaybedilir.

## 6. Dürüst sınır

`copytruncate` yönteminde **kaçınılmaz** bir yarış durumu (race condition) var:
kopyalama ile boşaltma arasında yazılan satırlar hem eski hem yeni tarafta
kaybolabilir. Bu bizim kodumuzun kusuru değil, **yöntemin yapısal kusurudur** —
`logrotate`'in kendi dokümantasyonu da bunu söyler. Doğru çözüm sunucu
tarafında `create` moduna geçmektir.

Bunu raporlamak önemli: bir izleme aracının sınırlarını bilmemek, o sınırın
içine düştüğünde yanlış güven duymaya yol açar.

## 7. Checkpoint — yeniden başlatma güvenliği

Servis yeniden başlatıldığında ne olur? Baştan okursa **aynı alarmları tekrar
üretir**; sondan başlarsa **kapalı olduğu süredeki saldırıyı kaçırır**.

Çözüm: konumu (inode + offset) bir dosyaya kaydet, açılışta oradan devam et.

İki kritik ayrıntı:

- **Konum, satır işlendikten SONRA kaydedilir.** Önce kaydedilse, çökme
  anında işlenmemiş satır "işlendi" sayılır ve **kaybolur**. Bu sırayla en
  kötü senaryo bir satırın iki kez işlenmesidir — alarm tekrarı, veri kaybından
  iyidir.
- **Atomik yazma:** önce geçici dosyaya yaz, sonra `rename` ile yerine taşı.
  Doğrudan yazarken çökersen yarım JSON kalır ve bir sonraki açılışta konumu
  okuyamazsın.

Checkpoint başka bir dosyaya aitse (inode uyuşmuyorsa) yok sayılıyor.

## 8. Diğer kararlar

- **`'rb'` (binary) modu** — metin modunda Windows `\r\n` çevirisi yapar ve
  bayt sayımı ile gerçek konum kayar; `seek` hesapları bozulur.
- **FAT32/exFAT ve ağ sürücülerinde `ino` 0 gelir** — o durumda inode tabanlı
  rotasyon tespiti güvenilir değil, boyut tabanlı yönteme düşülüyor.
- **Dosya henüz yoksa bekle** — servis, izleyeceği log dosyasından önce
  başlayabilir. Hata verip çıkmak yerine dosya oluşana kadar bekliyor.

## 9. Atlanan testler dürüstlük göstergesidir

Windows'ta 3 test atlanıyor:

```
test_kesilme_algilanir_copytruncate     → açık dosya kesilemiyor
test_rotasyon_algilanir_create_mode     → açık dosya taşınamıyor
test_rotasyonda_son_satirlar_kaybolmaz  → aynı sebep
```

Bu testler `skip` ile atlanıyor, sahte geçmiyor. Yeşil görünmek için testi
yalancı yapmak, testin tüm değerini yok eder. WSL'de üçü de gerçekten koşuyor
ve geçiyor.

`/mnt/c` (Windows diskinin WSL'e bağlanmış hali) inode semantiğini Linux gibi
uygulamadığı için rotasyon testleri orada da atlanıyor — `/tmp` kullanmak
gerekiyor.

## 10. Yan araçlar

`tools/live_writer.rb` — bir web sunucusunu simüle eder, durmadan log yazar:

```bash
ruby tools/live_writer.rb --attack brute --rps 8
```

`f.sync = true` kritik: bu olmadan Ruby satırları tamponda bekletir ve izleyen
taraf hiçbir şey görmez. Gerçek sunucular da log yazarken bu yüzden tamponsuz
çalışır.

`tools/watch.rb` — Tailer + Parser (+ Adım 4'ten sonra Engine) birlikte.

## 11. Gerçek dünya karşılığı

Filebeat/Promtail'in log okuma katmanının aynısı: inode takibi, offset
kaydı, rotasyon tespiti, kısmi satır tamponlama. `logrotate` ile yaşamayı
öğrenmek, üretimde log toplama kurmanın en pratik parçası.

## 12. Çalıştırma

```bash
ruby step3_tailer.rb
```

```bash
ruby test/tailer_test.rb --verbose
```

Rotasyonu gerçekten görmek için (WSL, `/tmp` şart):

```bash
wsl -d Ubuntu-22.04 ruby step3_tailer.rb /tmp/live.log
```
