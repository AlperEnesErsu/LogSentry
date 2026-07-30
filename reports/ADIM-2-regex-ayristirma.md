# ADIM 2 RAPORU — Regex ile Veri Ayıklama

**Durum:** ✅ Tamamlandı
**Test:** 21 test, 64 doğrulama — Windows ✅ / WSL ✅
**Üretilen dosyalar:** `lib/log_sentry/entry.rb`, `lib/log_sentry/parser.rb`,
`step2_parser.rb`, `test/parser_test.rb`

---

## 1. Amaç

Log satırını **metin dünyasından veri dünyasına** geçirmek. `"401"` bir metindir;
üzerinde `> 400` karşılaştırması yapılamaz. `401` bir sayıdır; yapılabilir.
Ayrıştırıcının tüm işi bu sınırı geçmektir.

## 2. Sözleşme

> Sana bir metin satırı veririm; bana ya bir `Entry` ya da `nil` döndürürsün.
> **Asla çökmezsin.** Anlamadığın satırda `nil` dön, ama programı durdurma.

Son cümle hayat kurtarıcı: bu kod bir daemon içinde günlerce, milyonlarca
satırla çalışacak. Tek bir bozuk satır yüzünden tüm güvenlik izlemesinin
durması kabul edilemez. Buna özel bir **sözleşme testi** yazıldı.

## 3. `Entry` — veri modeli

```ruby
Entry = Struct.new(:ip, :time, :http_method, :path, :protocol,
                   :status, :bytes, :referer, :user_agent, :raw,
                   keyword_init: true)
```

Kararlar ve gerekçeleri:

- **`keyword_init: true`** — 10 alanlı bir yapıda iki alanın yerini karıştırmak
  çok kolaydır ve bu hatayı test bile yakalamayabilir. İsimle yazmak
  okunabilirlik değil, doğruluk meselesidir.
- **`http_method`, `method` değil** — Ruby'de her nesnenin doğuştan gelen bir
  `method` metodu vardır. Struct alanı olarak `:method` vermek onu **ezer**;
  kod çalışır gibi görünür, sonra alakasız bir yerde tuhaf hata alırsın.
  Aynı sebeple `class`, `hash`, `send`, `freeze` de alan adı olmamalı.
- **`raw`** — satırın dokunulmamış hali. Adım 4'teki **kanıt zincirinin**
  temeli.
- **Sorgu metodları** (`?` ile bitenler): `success?`, `client_error?`,
  `server_error?`, `failed_auth?`, `malformed_request?`. Kodu cümle gibi
  okutur: `if entry.failed_auth?`.

## 4. Regex

```ruby
COMBINED = %r{\A
  (?<ip>\S+)          \s+
  (?<ident>\S+)       \s+
  (?<user>\S+)        \s+
  \[(?<time>[^\]]+)\] \s+
  "(?<request>[^"]*)" \s+        # istek satırı TEK PARÇA
  (?<status>\d{3})    \s+
  (?<bytes>\d+|-)
  (?:\s+"(?<referer>[^"]*)")?
  (?:\s+"(?<agent>[^"]*)")?
  \s*
\z}x
```

`/x` (extended) kipi boşlukları ve `#` yorumlarını yok sayar — kalıbı alt alta,
yorumlu yazmayı sağlar. `\A`/`\z` kullanımı bilinçli: `^`/`$` satır *içindeki*
satır başlarıyla da eşleşir, biz satırın **tamamının** uymasını istiyoruz.

Apache **common** formatı için ikinci bir kalıp da eklendi — mimari sözümüzü
somutlaştırmak için: *"yarın başka log formatı gelirse sadece parser değişir."*

## 5. İki aşamalı ayrıştırma — ayrıştırıcının en önemli ilkesi

İstek satırı tek parça alınıp **ikinci bir regex**'le bölünüyor. Sebebi: istek
satırının içinde boşluk olabilir.

```
"GET /search?q=hello world HTTP/1.1"   ← kodlanmamış boşluk
"\x16\x03\x01"                         ← HTTPS isteğini HTTP portuna atan tarama
```

Tek hamlede "boşluklara göre ayır" dersen bu satırlarda yanlış veri üretirsin.
İki aşamada yaparsan iç kısım bozuksa **sadece iç kısmı** işaretlersin.

> **Bozuk bir parça, sağlam parçaları götürmesin.**

Ölçülen sonuç — TLS çöpü gönderen satırda:

```
ip     : 193.34.76.101   ← SAĞLAM
status : 400             ← SAĞLAM
time   : 14:39:25        ← SAĞLAM
path   : "\x16\x03\x01"  ← ham hali kanıt olarak duruyor
malformed_request? → true
```

## 6. Adım 1'deki hilenin ölçülmüş başarısızlığı

| Durum | Hile `[8]` | Parser | |
|---|---|---|---|
| Normal satır | 200 | 200 | ✓ |
| Yolda kodlanmamış boşluk | `HTTP/1.1"` | 200 | ✗ **hile yanıldı** |
| Bozuk istek (TLS → HTTP portu) | `"-"` | 400 | ✗ **hile yanıldı** |
| Boyut alanı `-` | 304 | 304 | ✓ |
| Alakasız satır | (yok) | `nil` | ✓ doğru red |

Kritik nokta: hile **çökmüyor**, sessizce yanlış veri üretiyor. Güvenlik
araçlarında sessiz yanlış, çökmekten tehlikelidir — araç çalışıyor görünür ama
hiçbir şey görmez.

## 7. Üç tasarım kararı

1. **Bozuk isteği atmıyoruz, işaretliyoruz.** Sunucuya anlamsız bayt yığını
   göndermek başlı başına şüpheli davranıştır; atarsak yakalamak istediğimiz
   tarama davranışına kör kalırız.
2. **Tip sabitliği.** Bozuk istekte `http_method` için `nil` değil `"-"`.
   Alanlar bazen String bazen `nil` olursa her kuralda `nil` kontrolü yapmak
   gerekir. Alan tipini sabit tutmak çağıran tarafın hayatını kurtarır.
3. **Zamanı ayrıştırılamayan kaydı reddediyoruz.** Tüm kurallar zaman penceresi
   kullanacak; zamansız olayın "son 60 saniyede" olup olmadığını bilemeyiz.
   `%z` ile saat dilimi korunuyor — dilimi yok saymak farklı sunuculardan gelen
   olayları yanlış sıraya dizmene yol açar.

## 8. Karşılaşılan sorunlar ve düzeltmeler

### 8.1 Regex sınırlayıcı tuzağı (gerçek hata, program çalışmadan patladı)

```ruby
/\A ... \[(?<time>[^\]]+)\] \s+   # [29/Jul/2026:14:39:25 +0300]
                                        ↑ BURADAKİ / REGEX'İ BİTİRİYOR
```

Ruby önce satırı okuyup kapanış `/` işaretini arar; regex'in kendi `#`
yorumlarını o aşamada bilmez. **Yorumun içindeki masum bir eğik çizgi tüm
kalıbı bozdu.**

Çözüm: `%r{...}` sınırlayıcısı — kapanış `}` olunca `/` sıradan karakter olur.
Genel kural: içinde bol `/` geçen kalıplarda (URL, yol, tarih) `%r{}` kullan.

### 8.2 Bellek sınırı (Adım 1'in dersinin tekrarı)

```ruby
return if @failed_samples.size >= 10
```

Bu sınır olmasa milyonlarca bozuk satır bu diziyi büyütür ve RAM'i yerdi.
**Bir daemon içinde sınırsız büyüyen hiçbir yapıya yer yoktur.**

### 8.3 Geçersiz UTF-8 baytları (gerçek bir zafiyet)

```ruby
line = line.scrub('?') unless line.valid_encoding?
```

Saldırgan sunucuya ham bayt yığını gönderir, Nginx bunu logladığı gibi yazar.
Böyle bir satırda regex çalıştırmak `ArgumentError` fırlatır ve **tüm daemon'u
durdurur** — yani saldırgan tek istekle izlemeyi kapatabilir. `valid_encoding?`
kontrolü satırların %99,99'unda gereksiz kopyalamayı önlüyor.

## 9. Gözlemlenebilirlik

`success_rate` eklendi. Bir ayrıştırıcının kendi hata oranını bilmesi şarttır:
gerçek sistemlerde log formatı **sessizce** değişir (sunucu güncellenir, yeni
alan eklenir). Bu oranı izlemiyorsan elinde "sorunsuz çalışıyor gibi görünen
ama hiçbir şey görmeyen" bir araç kalır.

## 10. Ölçümler

```
3000 satır  ·  ~70.000 satır/saniye  ·  başarı oranı %100
```

İlk gerçek istihbarat (artık kod sorabiliyor):

```
5.188.206.14      2250  75.0%   ← tek IP tüm trafiğin dörtte üçü
45.155.205.233     168          ← başarısız giriş
sqlmap/1.8         156          ← şüpheli user-agent
/.git/config, /config.php.bak, /.env, /wp-login.php ...
```

## 11. Gerçek dünya karşılığı

Logstash/Fluentd **grok** kalıpları, log şeması tasarımı, veri normalizasyonu.
Bir SIEM'e log kaynağı eklerken yapılan ilk iş tam olarak budur.

## 12. Çalıştırma

```bash
ruby step2_parser.rb
```

```bash
ruby test/parser_test.rb
```
