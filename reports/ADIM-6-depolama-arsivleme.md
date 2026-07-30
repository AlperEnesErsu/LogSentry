# ADIM 6 RAPORU — Depolama ve Arşivleme (Sıcak + Soğuk Katman)

**Durum:** ✅ Tamamlandı
**Test:** 47 test, 136 doğrulama — Windows ✅ / WSL ✅
**Üretilen dosyalar:** `lib/log_sentry/store.rb`, `lib/log_sentry/archiver.rb`,
`lib/log_sentry/notifiers/store.rb`, `bin/logsentry-archive`, `step6_store.rb`,
`test/store_test.rb`
**Yeni bağımlılık:** `sqlite3` gem (Windows 2.9.5 / WSL 2.0.4)

---

## 1. Neden iki ayrı katman?

| | **SICAK** — `db/logsentry.db` | **SOĞUK** — `archive/*.log.gz` |
|---|---|---|
| Ne | ayrıştırılmış veri (SQLite) | ham log, dokunulmamış |
| Süre | 90 gün | yasal süre (config: 730 gün) |
| Amaç | **hızlı sorgu** | **kanıt** |
| Sorgulanabilir | evet, milisaniyeler | hayır |
| Silinebilir | evet, veri kaybı değil | süre sonunda, kayıtlı olarak |

Ham logu asla veritabanına ezdirmiyoruz. Mahkemede *"biz bunu ayrıştırdık,
işledik, kendi şemamıza soktuk"* demek istemezsin — ham kayıt dokunulmamış
haliyle durmalı.

Sıcak katmandan silmek **veri kaybı değildir**: ham log arşivde duruyor.
Silinen şey hızlı sorgu için tutulan türevdir.

---

## 2. Adım 6'nın en büyük performans kararı: toplu yazma

SQLite'ta her `INSERT` kendi başına bir işlem olur ve her işlem sonunda diske
yazma garantisi (fsync) istenir. Ölçüm:

```
batch_size 1    :  115.3 ms   (17.339 kayıt/saniye)
batch_size 500  :    9.9 ms   (201.165 kayıt/saniye)
FARK            :  11.6 kat
```

Adım 4'te boru hattını 84.000 kayıt/saniye ölçmüştük. Toplu yazma olmadan
veritabanı **tüm akışı yavaşlatan tıkanıklık noktası** olurdu.

Bedeli: tamponda bekleyen kayıtlar çökme anında kaybolabilir. Bu yüzden
**alarmlar tamponlanmıyor** — onlar seyrek (soğutma sayesinde) ve kıymetli.
Adım 5'te `FileNotifier` için verdiğimiz kararın aynısı.

### İki ayrıntı

**Hazırlanmış ifade yeniden kullanımı:** SQL metnini bir kez ayrıştırıp 500 kez
çalıştırıyoruz. Her seferinde `db.execute` çağırmak aynı SQL'i 500 kez
ayrıştırmak demektir.

**Periyodik boşaltma:** Sakin bir gecede saatte 50 istek gelirse parti dolmaz ve
kayıtlar saatlerce diske yazılmaz — web arayüzünde "hiç veri yok" görünür.
Supervisor 5 saniyede bir tamponu boşaltıyor. Aynı desen Filebeat/Fluentd'de
`flush_interval` olarak geçer.

---

## 3. WAL kipi — mimarinin çalışabilmesi için şart

```ruby
@db.execute('PRAGMA journal_mode = WAL')
```

Mimaride üç process var: daemon **yazar**, web **okur**, arşivci **temizler**.

SQLite'ın varsayılan kipinde bir yazma işlemi tüm veritabanını kilitler. Yani
daemon yazarken web arayüzü sorgu atarsa `SQLITE_BUSY: database is locked`
alır — kullanıcının göreceği şey rastgele bozulan bir panel.

WAL kipinde yazmalar ayrı bir dosyaya eklenir ve **okuyucular yazıcıyı
engellemez.** Tek kısıt: aynı anda tek yazıcı — bizde zaten tek yazıcı var.

`synchronous = NORMAL` seçildi: bu sıcak katman, buradaki veri kaybı telafi
edilebilir (ham log arşivde). Arşiv için aynı tercihi yapmazdık. **Güvenlik ve
performans takasları yerine göre verilir, kural olarak değil.**

`busy_timeout = 5000`: kısa süren çakışmalarda hemen hata vermek yerine bekle.

---

## 4. Şema kararları

### Zaman neden `INTEGER`?

`ts INTEGER` = Unix zaman damgası. Metin olarak tutmak cazip görünür ama:

- karşılaştırma metin karşılaştırması olur → farklı saat dilimlerinden gelen
  kayıtlar **yanlış sıralanır**
- indeks daha büyük ve yavaş olur
- "son 24 saat" aralığını hesaplamak zorlaşır

Saat dilimini kaybetmemek için alarmlarda ayrıca `time_iso` alanında ISO-8601
metni tutuluyor: **sorgulama için sayı, gösterim için metin.**

Bu sayede saatlik grafik verisi tek satırda çıkıyor:

```sql
SELECT (ts / 3600) * 3600 AS bucket, COUNT(*) ... GROUP BY bucket
```

### Bileşik indekste kolon sırası

```sql
CREATE INDEX idx_events_ip_ts ON events(ip, ts);
```

`(ip, ts)` indeksi *"bu IP'nin son 1 saati"* sorgusunda kullanılır. `(ts, ip)`
olsaydı aynı sorguda **işe yaramazdı**. Kural: önce eşitlikle filtrelenen kolon,
sonra aralıkla filtrelenen.

İndeks okumayı hızlandırır ama her yazmada güncellenir — yani yazma yavaşlar.
"Her kolona indeks atalım" yanlıştır.

---

## 5. SQL enjeksiyonu — tek doğru savunma

```ruby
# YANLIŞ
"SELECT * FROM alerts WHERE ip = '#{ip}'"
# DOĞRU
"SELECT * FROM alerts WHERE ip = ?", [ip]
```

Yanlış olanda kullanıcı `' OR 1=1 --` yazarsa tüm kayıtlar dökülür;
`'; DROP TABLE alerts; --` yazarsa tablo silinir.

Parametreli sorguda veritabanı SQL'i **önce** ayrıştırır, değeri **sonra**
yerleştirir. Değer artık kod olarak yorumlanamaz. Karakter temizliği (escaping)
yapmaya çalışmak yerine bu yöntemi kullanmak tek doğru savunmadır.

Üç saldırı yüküyle test edildi; tablonun hâlâ yerinde olduğu da doğrulandı.
LIKE kalıplarında bile değer parametre olarak gidiyor.

> SQL enjeksiyonu arayan bir aracın kendisinin SQL enjeksiyonuna açık olması,
> işin ironisi olurdu.

---

## 6. Arşivleme ve hash zinciri

### Akış

```
1) ÖZET AL     ham içeriğin SHA-256'sı (sıkıştırmadan ÖNCE)
2) SIKIŞTIR    gzip → ölçülen tasarruf: %96.1
3) MÜHÜRLE     manifest.jsonl'a zincirli kayıt
4) DOĞRULA     arşiv dosyası diskte sağlam mı?
5) SİL         kaynağı ancak 4. adım geçtikten sonra
```

Özet **sıkıştırmadan önce** alınıyor: kanıtlanan şey ham içeriğin bütünlüğüdür,
sıkıştırılmış halinin değil. Yarın gzip yerine başka bir yöntem kullanılsa özet
değişmemeli.

Kaynak dosya ancak arşiv **doğrulandıktan sonra** siliniyor. Önce silip sonra
yazmak, arada bir hata olursa veriyi tamamen kaybetmek demektir.

### Zincir

```
chain[n] = SHA256( chain[n-1] + sha256[n] )
```

Ölçülen çıktı:

```
1) access-gun1.log.gz   313493 -> 12221 bayt (%96.1)
   önceki : 000000000000...      ← genesis
   ZİNCİR : 15331e38dab4b19b...
2) access-gun2.log.gz
   önceki : 15331e38dab4b19b...  ← 1'in zinciri
   ZİNCİR : 2aa6abc3d7130856...
3) access-gun3.log.gz
   önceki : 2aa6abc3d7130856...  ← 2'nin zinciri
   ZİNCİR : 6735c0565c11fd73...
```

gzip tasarrufunun bu kadar yüksek olması log satırlarının birbirine çok
benzemesinden. 2 yıllık saklama için sıkıştırma bir tercih değil, zorunluluk.

---

## 7. İki kurcalama senaryosu — ölçülmüş sonuçlar

### Senaryo 1: saldırgan arşiv içeriğini değiştirir

Saldırgan **geçerli bir gzip** üretiyor — dosyayı bozmuyor, içeriğinden kendi
satırlarını siliyor (3000 → 2604 satır). Sadece *"gzip açılabiliyor mu"* diye
bakan bir kontrol bunu **yakalamaz**.

```
[OK  ] access-gun1.log.gz
[HATA] access-gun2.log.gz  <-- DOSYA DEGISTIRILMIS (ozet uyusmuyor)
[OK  ] access-gun3.log.gz
SONUÇ: BÜTÜNLÜK BOZULMUŞ -- YAKALANDI
```

Diğer kayıtlar etkilenmiyor — hangi dosyanın bozulduğunu bilmek gerekir.

### Senaryo 2: manifest'teki özeti de günceller

Akıllı saldırgan düşünür: *"dosyayı değiştirdim, özet uyuşmuyor. O zaman
manifest'teki özeti de güncelleyeyim."*

```
[HATA] access-gun2.log.gz  <-- ZINCIR DEGERI YANLIS (manifest kaydi degistirilmis)
SONUÇ: BÜTÜNLÜK BOZULMUŞ -- YİNE YAKALANDI
```

**Zincirin değeri tam burada.** Dosya özeti artık doğru, ama zincir değeri
`sha256`'dan hesaplandığı için yanlış — ve 3. kaydın `prev_chain`'i eski değeri
işaret ediyor. Saldırganın başarılı olması için o kayıttan **sonraki tüm**
kayıtları yeniden hesaplaması gerekir.

Gerçek bir sistemde zincirin başı (head) başka bir yerde saklanır — yazdırılır,
e-posta ile gönderilir, yetkili zaman damgası sağlayıcısına imzalatılır. O zaman
tüm zinciri yeniden yazmak da işe yaramaz.

Bu mekanizmanın adı **hash zinciri**; blok zincirinin de temelinde bu var.
Kurumsal log ürünlerinin "değiştirilemez kayıt" (tamper-evident) iddiası bunun
üzerine kuruludur.

### Test edilen diğer kurcalama biçimleri

| Senaryo | Sonuç |
|---|---|
| Arşiv dosyası silinir | `dosya yok` |
| Ortadaki manifest kaydı silinir | zincir kopar |
| Manifest'e bozuk JSON satırı eklenir | satır atlanır, çökme yok |
| Dosya geçerli gzip olmaktan çıkar | yakalanır |

---

## 8. Saklama süresi — iki yönlü kısıt

```
     │◀── ihlal ──▶│◀──── uygun aralık ────▶│◀── ihlal ──▶│
─────┼─────────────┼────────────────────────┼─────────────▶
     0        yasal alt sınır          amaç sonu       süresiz
              (5651: sakla)            (KVKK: sil)
```

**IP adresi KVKK'ya göre kişisel veridir** — "garanti olsun diye süresiz
tutalım" yaklaşımı da ihlaldir. Config'de tek bir yerde tanımlı:
`archive.retention_days: 730`.

> Bu bir hukuki görüş değildir. Kesin süre ve yükümlülük için kendi kategorin
> (erişim sağlayıcı / yer sağlayıcı / ticari toplu kullanım sağlayıcı) üzerinden
> mevzuatı ve hukuk tarafını teyit et.

### Silme işlemi de bir olaydır

```json
{"type":"deletion","file":"access-...gz","reason":"saklama suresi doldu (730 gun)",
 "deleted_at":"2026-07-30T13:52:00+03:00","sha256":"2b6001ba..."}
```

*"Bu log nerede?"* sorusunun cevabı "bilmiyorum" olmamalı; *"şu tarihte saklama
süresi dolduğu için silindi"* olmalı. Silinen dosyanın özeti de kayıtta duruyor —
yani kimse "bu log hiç olmadı" diyemez.

`--dry-run` ile neyin silineceği önce görülebiliyor. Silme kayıtları arşiv
zincirinin parçası değil (`type: deletion`), ayrı bir olay türü.

---

## 9. Sıcak katman temizliği — `DELETE` dosyayı küçültmez

Ölçüm:

```
Önce   : 3000 olay, 24 uyarı, 0.45 MB
Silinen: 3000 olay, 24 uyarı
Sonra  : 0    olay, 0  uyarı, 0.45 MB   ← boyut aynı!
VACUUM sonrası:                0.08 MB
```

SQLite silinen yerleri "boş sayfa" olarak işaretler ve yeni kayıtlar için
yeniden kullanır. Dosyanın gerçekten küçülmesi için `VACUUM` gerekir — ama
`VACUUM` tüm veritabanını yeniden yazar (geçici olarak iki kat yer ister ve
kilitler), o yüzden otomatik yapılmıyor, `--vacuum` ile isteğe bağlı.

---

## 10. Bulunan hatalar

| Bulgu | Tür | Nasıl bulundu |
|---|---|---|
| `':memory:'` yolu `File.expand_path`'ten geçirilince `C:/.../:memory:` haline geliyor ve SQLite açamıyordu | gerçek kusur | test (27 hata birden) |
| `size_bytes` sadece ana dosyaya bakıyordu; WAL kipinde veri `-wal` dosyasında olduğu için 3000 kayıttan sonra boyut **0.00 MB** görünüyordu | gerçek kusur | demo çıktısı |
| `--once` modu, okuma thread'inin ölmesini bekliyordu; Tailer bilinçli olarak dosya sonunda ölmediği için komut **sonsuza kadar bekledi** | gerçek kusur | canlı deneme (komut 5 dakikada timeout'a düştü) |
| Arşiv karşılaştırma testi Windows'un `\r\n` çevirisine takılıyordu | test hatası | test |

Üçüncüsü öğretici: **"bitti" tanımı olmayan bir akışta "bitti"yi kendin
tanımlamak zorundasın.** `ONCE_IDLE_TIMEOUT = 1.5` saniye eklendi — belirli süre
yeni satır gelmezse dosya bitti sayılıyor.

İkincisi de pratikte önemli: disk kullanımını izleyen bir uyarı sadece ana
dosyaya bakarsa *"veritabanı hiç büyümüyor"* yanılgısına düşer. Üç dosya birlikte
veritabanını oluşturur: `.db`, `.db-wal`, `.db-shm`.

---

## 11. Boru hattına bağlanma

```
dosya → TAILER → PARSER → ENGINE → NOTIFIERS → ekran/JSONL/Telegram
                    ↓                    ↓
                  STORE ←──────── StoreNotifier
                (olaylar)          (uyarılar)
```

Üç bilinçli karar:

**`StoreNotifier` ayrı bir kanal.** Supervisor doğrudan `store.record_alert`
çağırabilirdi, ama o zaman veritabanı hatası (disk dolu, dosya kilitli) boru
hattına sızardı. Notifier olarak sarılınca Adım 5'te kurduğumuz **hata yalıtımı
bedavaya geliyor**: veritabanı yazamasa bile alarm hâlâ ekrana, JSONL'e ve
Telegram'a gidiyor.

**`sqlite3` yoksa servis durmuyor.** `require` dosyanın başında değil,
`build_store` içinde — yani depolama yapılandırılmamışsa gem hiç yüklenmiyor.
Adım 1–5'in "sıfır bağımlılık" özelliği korunuyor.

**Store en sonda kapatılıyor.** `close` içinde `flush` var; sırayı ters yapsak
`StoreNotifier` kapalı bir veritabanına yazmaya çalışırdı.

---

## 12. `bin/logsentry-archive` — cron görevi

Daemon'un parçası **değil**, ayrı process. Sebebi: daemon milisaniyeler
ölçeğinde çalışan bir akış işleyicisi; arşivleme günde bir kez çalışan,
dakikalar sürebilen bir toplu iş. İkisini aynı process'e koymak, arşivleme
sırasında izlemenin gecikmesi demek olurdu.

```bash
bin/logsentry-archive --verify | --stats | --roll | --prune | --prune-db | --vacuum | --all
```

`--verify` bütünlük bozulmuşsa **sıfır olmayan çıkış kodu** (2) döndürüyor — cron
bu betiği çalıştırdığında izleme sisteminin (ya da en azından cron mail'inin)
haber almasını sağlar. Bütünlük uyuşmazlığı kendi başına bir güvenlik olayıdır:
**loglarını değiştiren kişi, genelde orada izini silmek isteyen kişidir.**

Cron kurulumu:

```
15 3 * * * cd /opt/logsentry && bin/logsentry-archive --all >> logs/archive.log 2>&1
```

---

## 13. Ölçülen sorgu performansı

3000 olay + 24 uyarı içeren veritabanında:

| Sorgu | Süre |
|---|---|
| en çok istek yapan 5 IP (son 24 saat) | 0.41 ms |
| sadece HIGH seviye uyarılar | 0.73 ms |
| tek bir IP'nin 404 alan istekleri | 0.12 ms |
| saatlik trafik grafiği (dashboard verisi) | 0.47 ms |
| kural bazında uyarı dağılımı | 0.02 ms |

Bu sorguların hepsi Adım 7'deki web arayüzünün ihtiyaç duyduğu veriler.

---

## 14. Uçtan uca doğrulama

```
$ ruby bin/logsentry --from-begin --once --quiet
[daemon] bayat PID dosyasi temizlendi: logs/logsentry.pid (PID 7976)
[13:52:23] LogSentry v0.6.0 basladi (PID 17928)
[13:52:23] bildirim : file, store
[13:52:25] --once: 1.5 saniyedir yeni satir yok, cikiliyor
[13:52:25] toplam 24 uyari uretildi, 3000 satir okundu
```

Oluşan dosyalar: `db/logsentry.db` (432 KB), `logs/alerts.jsonl` (21.3 KB),
`logs/.logsentry.state`.

Bonus: ilk satır, Adım 5'te yazdığımız **bayat PID temizleme** mekanizmasının
gerçek bir senaryoda (takılan process'i `taskkill` ile öldürdükten sonra)
çalıştığını gösteriyor.

---

## 15. Gerçek dünya karşılığı

SQLite'ı üretimde doğru ayarlamak (WAL, busy_timeout, synchronous), toplu yazma
ile akış işleme, indeks tasarımı, parametreli sorgu disiplini, log saklama
politikası, tamper-evident arşivleme, cron tabanlı bakım işleri.

---

## 16. Çalıştırma

```bash
ruby step6_store.rb
```

```bash
ruby test/store_test.rb
```

```bash
ruby bin/logsentry --from-begin --once --quiet
```

```bash
ruby bin/logsentry-archive --stats
```
