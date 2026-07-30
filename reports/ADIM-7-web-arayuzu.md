# ADIM 7 RAPORU — Web Arayüzü (Sinatra + SSE)

**Durum:** ✅ Tamamlandı
**Test:** 33 test, 106 doğrulama — Windows ✅ / WSL ✅ · **canlı tarayıcı testi + video kaydı** ✅
**Üretilen dosyalar:** `lib/log_sentry/web/app.rb`, `web/views/*.erb` (8 şablon),
`web/public/{app.css,app.js}`, `bin/logsentry-web`, `tools/demo_env.rb`,
`test/web_test.rb`, `docs/logsentry-web-demo.gif`
**Yeni bağımlılıklar:** `sinatra` 4.2.1, `puma` 8.0.2

---

## 1. Bu arayüzün asıl işi

Grafik göstermek değil. Asıl işi şu soruyu cevaplamak:

> **"Bu uyarı gerçekten saldırı mı, yanlış alarm mı?"**

Bu soruya cevap veremiyorsan alarm eyleme geçirilemez, eyleme geçirilemeyen
alarm da gürültüdür. Bu yüzden en önemli sayfa dashboard değil, **`/alerts/:id`** —
alarmı doğuran ham log satırlarını gösteren sayfa.

## 2. Teknoloji seçimleri ve nedenleri

| Katman | Seçim | Neden |
|---|---|---|
| Web çatısı | Sinatra 4.2 (modüler) | Rails aşırı büyük; rotalar İngilizce cümle gibi okunur |
| Sunucu | Puma 8 | **Thread'li olması SSE için zorunlu** (aşağıya bak) |
| Canlı akış | SSE | Veri tek yönlü akıyor; WebSocket gereğinden karmaşık |
| Grafik | elle SVG | Dış kütüphane yok; çubuk grafiğin nasıl çizildiğini görmek öğretici |
| Şablon | ERB + `h()` | Otomatik escaping'e güvenmek yerine açık escaping |

**Sıfır dış varlık (asset):** ne CDN, ne Google Fonts, ne CSS çerçevesi. Bir
güvenlik paneli internete çıkamayan bir sunucuda da çalışmalı; üstelik her dış
kaynak, panele kod enjekte edebilecek yeni bir taraf demektir. Testlerden biri
bunu doğruluyor (`refute_includes css.body, 'http://'`).

## 3. Rotalar

```
GET /                 Dashboard: 4 özet kartı, 24 saatlik SVG grafik,
                      en çok istek yapan IP'ler, kural dağılımı, canlı akış
GET /alerts           Filtrelenebilir liste (kural/önem/IP) + sayfalama
GET /alerts/:id       ★ KANIT SAYFASI — neden alarm verildi + ham satırlar + bağlam
GET /integrity        Arşiv hash zinciri doğrulaması
GET /stream           SSE veri ucu
GET /health           JSON sağlık kontrolü (izleme araçları için)
```

Mimaride planlanan `/explorer`, `/ips/:ip` ve CSV indirme **bilinçli olarak
kapsam dışı** bırakıldı — dar kapsam kararı. Öğretici değerin tamamı yukarıdaki
dörtte.

---

## 4. En büyük güvenlik konusu: depolanmış XSS

Bu panelde gösterilen verinin **büyük kısmını saldırgan yazıyor.** Saldırgan
izlenen sunucuya şunu ister:

```
GET /<script>alert(document.cookie)</script>
```

Nginx bunu `access.log`'a olduğu gibi yazar → Parser ayrıştırır → Store kaydeder
→ panel ekrana basar. Escape etmezsek tarayıcı o metni **kod olarak çalıştırır.**

> Saldırgan, **panele hiç erişmeden**, sadece izlenen sunucuya bir istek atarak
> güvenlik panelinde kod çalıştırmış olur.

Savunma tek: her `<%= %>` içinde `h()`:

```ruby
def h(text)
  Rack::Utils.escape_html(text.to_s)
end
```

Saldırgan-kontrollü alanların hepsi test edildi — **6 XSS testi**:

| Alan | Test |
|---|---|
| Alarm mesajı (içinde `entry.path` geçiyor) | ✅ |
| Kanıt bloğu (ham log satırı — en dolaysız alan) | ✅ |
| Olay `path` alanı | ✅ |
| IP alanı (`\S+` ile ayrıştırılıyor, gerçek IP olmak zorunda değil) | ✅ |
| User-Agent alanı | ✅ |
| Filtre değeri (`value="..."` içine basılıyor — `"` ile attribute'dan çıkma) | ✅ |

Testler hem yükün ham haliyle **görünmediğini** hem de `&lt;script&gt;` olarak
**kaçışlandığını** doğruluyor. Yalnız birincisini test etmek yeterli olmazdı:
alan hiç basılmıyor olsa da test geçerdi.

### Tarayıcı tarafında da aynı ilke

`app.js` içinde `innerHTML` **yok**, sadece `textContent`. SSE ile gelen alarm
verisi de saldırgan etkisi altında; sunucudaki `h()`'nin tarayıcı karşılığı
`textContent`'tir. CSS sınıf adı için ise allow-list kullanılıyor (Adım 5'teki
token maskeleme dersinin aynısı: "neyi engelleyeyim" değil, "neyi kabul etmek
güvenli").

---

## 5. Diğer güvenlik kararları

**Salt okunurluk.** `before` filtresi GET/HEAD dışındaki her şeyi 405 ile
reddediyor. Kodda yanlışlıkla bir yazma rotası eklenirse bile geçerli olan bir
emniyet kemeri. Yazma yetkisi olmayan panel, ele geçirilse bile hasar veremez.

**Yığın izi sızdırmıyor.** `show_exceptions: false` + özel `error` bloğu. Yığın
izi dosya yollarını, gem sürümlerini ve kod yapısını açığa çıkarır — saldırgan
için değerli bilgi. Sunucu loguna yazılıyor, kullanıcıya sade mesaj gidiyor.
Testi var: yanıt gövdesinde ne hata mesajı ne dosya yolu bulunuyor.

**Sadece localhost.** `bind: 127.0.0.1` varsayılan. Başka bir adres verilirse
`bin/logsentry-web` açık uyarı basıyor (engellemiyor — kullanıcının kararı).

**Kullanıcı girdisine üst sınır.** `?hours=999999999` ya da `?limit=99999999`
ile sunucuyu yormak mümkün olmasın diye her sayısal parametre kırpılıyor.
Geçersiz değerler varsayılana düşüyor, çökme yok.

**Parametreli sorgu.** Filtre değerleri Adım 6'daki Store üzerinden gidiyor,
SQL metnine hiç girmiyor. Web katmanında da iki enjeksiyon yüküyle test edildi.

---

## 6. SSE — ve canlı testin bulduğu gerçek kusur

Klasik web'de tarayıcı sorar, sunucu cevap verir, bağlantı kapanır. Canlı
izlemede bunu tersine çeviriyoruz: bağlantı **açık kalır**, sunucu haber oldukça
yazar. Biçim son derece basit:

```
data: {"rule":"brute_force",...}\n\n
```

**Güzel taraf:** bu akış için Adım 3'te yazdığımız `Tailer` yeniden kullanılıyor
— sadece `access.log` yerine `alerts.jsonl` izleniyor. Doğru mimarinin ödülü:
bileşeni bir kez yaz, ummadığın yerde bedavaya kullan.

### Kusur: Puma thread'leri tükeniyordu

Canlı video kaydı sırasında tarayıcı sayfalar arasında gezindikçe sunucu yanıt
vermemeye başladı — **30 saniyelik `renderer unresponsive` zaman aşımları**,
her sayfa geçişinde bir kez.

**Sebep:** Puma varsayılan olarak 5 thread ile çalışır. Her SSE bağlantısı bir
thread'i tutar. Tarayıcı sayfadan ayrıldığında bağlantı kopar — **ama sunucu
bunu ancak yazmaya çalıştığında anlar.** Yeni alarm gelmediği sürece hiç yazmaya
çalışmaz, yani ölü bağlantı thread'i tutmaya devam eder. Beş gezinti = beş
thread = sunucu yanıt veremez.

**Çözüm — iki parça birlikte:**

1. **Kalp atışı (heartbeat).** Yeni veri olmasa bile 10 saniyede bir SSE yorumu
   gönderiliyor (`: ping\n\n`). Yazma denemesi kopmuş bağlantıyı anında ortaya
   çıkarır ve thread serbest kalır. İkinci faydası: nginx gibi ara sunucular
   uzun süre sessiz kalan bağlantıları keser — kalp atışı bunu da önler.
2. **Thread sayısı 2:16.** Eş zamanlı izleyiciye yer açar.

İkisi birlikte gerekli: sadece thread artırmak sızıntıyı geciktirir, sadece kalp
atışı eş zamanlı kullanıcı sayısını sınırlı tutar.

Kalp atışını göndermek için Tailer'ı ayrı bir thread'e alıp kuyruk üzerinden
okumak gerekti — Tailer'ın kendi döngüsü boştayken kontrol geri vermiyor.
(`Queue#pop(timeout:)` Ruby 3.2+ gerektirdiği için, WSL'deki 3.0 ile uyumlu
olsun diye bloke etmeyen `pop(true)` + `sleep 0.2` deseni kullanıldı.)

### Düzeltmenin doğrulaması

8 SSE bağlantısı açıp bırakıp (sekme kapatma taklidi) sayfaları ölçtük:

```
== Başlangıç
  /            200   47.1 ms
  /alerts      200   30.4 ms

== 8 SSE açıkken
  /            200   30.7 ms
  /alerts      200   30.7 ms
  /integrity   200   31.7 ms
  /health      200   31.6 ms
SONUÇ: TÜM SAYFALAR YANIT VERDİ
```

Tarayıcıda da teyit edildi: düzeltmeden sonra tek bir zaman aşımı yaşanmadı.

---

## 7. Test edilemeyen uç nokta: `/stream`

İlk denemede `/stream`'e `Rack::MockRequest` ile istek attım ve **test paketi
10 dakika takıldı**, elle öldürmek gerekti. Sebep: o rota bağlantıyı bilinçli
olarak açık tutuyor, MockRequest ise gövdenin bitmesini bekliyor — gövde hiç
bitmiyor.

> **Ders:** "asla bitmeyen" bir uç noktayı, biten bir istek gibi test edemezsin.

Çözüm: biçimlendirme mantığı `App.sse_frame` olarak dışarı alındı ve o test
edildi. İki test var: çerçeve `data: ` ile başlayıp `\n\n` ile bitiyor mu, ve
mesaj içindeki satır sonu SSE biçimini bozuyor mu (bozarsa mesaj ortadan ikiye
ayrılır — `JSON.generate` bunu `\n` olarak kaçışlıyor). Akışın kendisi canlı
sunucuyla doğrulandı.

---

## 8. Canlı test ortamı

`tools/demo_env.rb` gerçekçi bir veri kümesi kuruyor:

- **24 saate yayılmış** log üretiyor (gece 25, iş saatleri 140 istek/saat — gerçek
  bir sitenin günlük deseni). `tools/log_generator.rb` sadece son 1 saati
  üretiyordu, dashboard grafiğinde tek çubuk çıkıyordu.
- Saldırıları belirli saatlere yerleştiriyor: 3 brute force dalgası, 4 tarama,
  3 flood
- Boru hattını bir kez çalıştırıp veritabanını dolduruyor
- 3 mühürlü arşiv oluşturuyor (Bütünlük sayfası için)

```
2766 satır → 2766 olay, 10 uyarı, 3 arşiv (zincir SAĞLAM)
```

Canlı akışı beslemek için `config/demo.yml` (soğutma 120 → 8 saniye) +
`live_writer` + daemon. Soğutmayı config'den değiştirebilmek, Adım 4'te
"eşikler her zaman kodun dışındadır" derken kastettiğimiz şeyin pratik faydası.

---

## 9. Tarayıcıda doğrulanan sonuçlar

| Sayfa | Doğrulanan |
|---|---|
| Dashboard | 24 saatlik SVG grafik, 4 kart, top IP tablosu, SSE **"● bağlı"** |
| Canlı akış | Sayfa yenilenmeden 8 saniyede bir yeni alarm; en yeni satır vurgulanıyor |
| Uyarılar | 28 kayıt, filtre (`?rule=path_scan` → 4 kayıt), sayfalama |
| `/alerts/:id` | "60 saniye içinde 771 olay ölçüldü; eşik 10" + **5 satır ham kanıt** + bağlam tablosu |
| Bütünlük | "✓ BÜTÜNLÜK SAĞLAM", 3 arşiv, zincir başı, %92.8 tasarruf |
| Bütünlük (kurcalanmış) | **"✗ BÜTÜNLÜK BOZULMUŞ"**, satır 2: `DOSYA DEGISTIRILMIS (ozet uyusmuyor)`, HTTP 500 |

Son satır videonun en çarpıcı kısmı: kayıt sırasında bir arşiv dosyasının
içeriğini bozup sayfayı yeniledim, panel anında kırmızıya döndü ve hangi
dosyanın değiştirildiğini gösterdi. (Test sonrası dosya yedeğinden geri
yüklendi, zincir yine SAĞLAM.)

**Video:** `docs/logsentry-web-demo.gif` (11 kare, 1522×784, 2.2 MB)

---

## 10. Bulunan hatalar

| Bulgu | Tür | Nasıl bulundu |
|---|---|---|
| SSE bağlantıları Puma thread'lerini tutuyor, sunucu yanıt veremez hale geliyordu | **gerçek kusur** | canlı tarayıcı testi (tekrarlayan 30 sn zaman aşımları) |
| `/stream` testi MockRequest ile sonsuza kadar bekliyordu | test kusuru | test paketi 10 dk takıldı |
| `HEARTBEAT_INTERVAL` blok içinde tanımlanmıştı — her istekte "already initialized constant" uyarısı | kod kokusu | `ruby -w` |
| `demo_env.rb`, `supervisor.run`'dan sonra kapalı veritabanına sorgu atıyordu | gerçek kusur | çalıştırma (`prepare called on a closed database`) |

Birincisi bu adımın en değerli bulgusu — ve **yalnızca canlı testte** ortaya
çıkabilirdi. 33 birim testinin hiçbiri onu yakalayamazdı, çünkü sorun tek bir
isteğin doğruluğunda değil, **isteklerin birikimli etkisinde**.

---

## 11. Gerçek dünya karşılığı

Sinatra/Rack ile hizmet yazma, ERB ve XSS savunması, SSE ile canlı akış, thread
havuzu ve kaynak sızıntısı, salt okunur panel tasarımı, hata mesajlarında bilgi
sızdırmama, kullanıcı girdisine sınır koyma.

Bir de dürüst bir not: üretimde bu arayüzü yazmazsın — `alerts.jsonl`'ı
Loki/Elasticsearch'e gönderip Grafana kullanırsın. Bu adımın değeri **üretim
değeri değil, kaputun altını görmek**.

---

## 12. Çalıştırma

Test ortamını kur:

```bash
ruby tools/demo_env.rb
```

Web arayüzünü başlat:

```bash
ruby bin/logsentry-web
```

Sonra tarayıcıda `http://127.0.0.1:4567` adresini aç.

Canlı akışı beslemek için iki ayrı terminal:

```bash
ruby tools/live_writer.rb --attack brute --rps 14
```

```bash
ruby bin/logsentry --config config/demo.yml --quiet
```

Testler:

```bash
ruby test/web_test.rb
```
