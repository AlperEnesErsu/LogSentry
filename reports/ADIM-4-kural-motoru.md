# ADIM 4 RAPORU — Mini Kural Motoru (SIEM Mantığı)

**Durum:** ✅ Tamamlandı
**Test:** 36 test, 211 doğrulama — Windows ✅ / WSL ✅
**Üretilen dosyalar:** `lib/log_sentry/alert.rb`, `lib/log_sentry/rules/base.rb`,
`rules/brute_force.rb`, `rules/flood.rb`, `rules/path_scan.rb`,
`lib/log_sentry/engine.rb`, `step4_engine.rb`, `test/engine_test.rb`

---

## 1. Entry ile Alert arasındaki fark

Bu ayrım, bir log aracını SIEM yapan şeyin ta kendisi:

```
Entry  →  gözlem   (45.155.205.233, /login, 401)
Alert  →  YARGI    (bu IP şifre deniyor, müdahale et)
```

## 2. Motorun tüm mantığı tek satır

```ruby
def process(entry)
  @rules.filter_map { |rule| rule.call(entry) }
end
```

İçinde tek bir `if rule.is_a?(BruteForce)` yok. Motor kuralların ne yaptığını
**bilmiyor**, sadece sözleşmeye güveniyor: *"sana Entry veririm, bana Alert veya
`nil` döndürürsün."* 20 kural daha eklesen bu satır aynen kalır —
**polimorfizm** budur.

## 3. Şablon metod deseni

`Base#call` işin **sırasını** tanımlıyor, alt sınıflar **içeriğini** dolduruyor:

```
1) interested?(entry)         beni ilgilendiriyor mu?      [alt sınıf]
2) now = entry.time           LOGUN zamanı
3) track(...)                 pencereye ekle, eskiyeni at
4) housekeeping(now)          bellek sınırlarını koru
5) measure(key) > threshold   eşik aşıldı mı?              [ezilebilir]
6) silenced?(key, now)        susuyor muyuz?
7) build_alert(...)           kanıtla birlikte üret
```

Yeni kural yazmak için üç küçük metod yeterli: `interested?`, `message_for`,
gerekirse `measure`. Pencere yönetimi, soğutma, bellek sınırları, kanıt toplama
bedavaya gelir. `flood.rb` bu yüzden ~20 satır.

## 4. Kayan pencere

```ruby
cutoff = now - @window
list.shift while list.any? && list.first[0] < cutoff
```

Liste zaman sıralı olduğu için en eski en başta — baştan atmak tüm listeyi
taramaktan çok daha ucuz. `Array#shift` Ruby'de işaretçi kaydırmasıdır, diziyi
kopyalamaz.

**Ölçülen:** 3000 kayıt işlendi, en büyük pencere 187 olay, takip edilen anahtar
1. Dosya 3 milyar satır olsa da bu sayılar aynı mertebede kalır.

### Pencere ≠ saklama süresi

| | Tespit penceresi | Saklama süresi |
|---|---|---|
| Nerede | RAM | disk |
| Ne kadar | 1–300 saniye | **yıllar** (Adım 6) |
| Amaç | "şu an saldırı var mı?" | adli inceleme, yasal yükümlülük |

Pencerenin "eskiyi atması" **hiçbir logu silmez** — attığı şey bellekteki bir
sayaç kaydıdır. `access.log`'a sadece okuma amaçlı dokunuyoruz.

## 5. `entry.time`, `Time.now` değil

```ruby
now = entry.time   # LOGUN zamanı, bizim saatimiz değil
```

Sistem yavaşsa, log gecikmeliyse ya da geçmiş bir dosyayı işliyorsan
(`start: :begin`) bu ikisi **saatlerce** farklı olabilir. `Time.now` kullanan
bir kod geçmiş logu işlediğinde tüm olayları "çok eski" sayıp **hiçbir alarm
üretmez** — ve bunu sessizce yapar.

Buna özel test: 2020 tarihli olaylarla alarm üretiliyor mu?

Yan fayda: zamanı biz uydurduğumuz için testlerde `sleep 61` yazmak gerekmiyor.
**36 test 12 milisaniyede** koşuyor.

## 6. Üç kural

| Kural | Neyi ölçüyor | Pencere | Eşik | Önem |
|---|---|---|---|---|
| `brute_force` | `401`/`403` sayısı | 60 sn | 10 | high |
| `flood` | tüm istek sayısı | 1 sn | 100 | high |
| `path_scan` | **farklı** hassas dizin sayısı | 300 sn | 3 | medium |

### 6.1 BruteForce — 404 neden sayılmıyor

`401` = kimlik doğrulanamadı, `403` = izin yok/WAF engelledi. İkisi de "girmeye
çalıştı, giremedi" anlamına gelir. **`404` dahil edilmiyor**: "olmayan sayfa"
demektir, giriş denemesi değil. Dahil edersen kırık link tıklayan normal
kullanıcılar alarm üretir ve aracın yanlış pozitif oranı kullanılamaz hale
gelir.

`automated` alanı ile user-agent'ın otomatik araç olup olmadığı işaretleniyor.
Kesin kanıt değil (UA taklit edilebilir) ama alarma bakan insanın önceliğini
belirlemesine yardım eder: tarayıcı ise muhtemelen şifresini unutmuş kullanıcı,
araç ise saldırgan.

### 6.2 Flood — dürüst isimlendirme

Bu kural bir DDoS'u **tespit etmez**, belirtisini tespit eder. Gerçek bir DDoS
binlerce farklı IP'den gelir ve tek tek hiçbiri eşiği aşmaz. Yakaladığımız şey
tek kaynaklı aşırı trafik. "DDoS tespit ediyorum" demek, yapmadığın bir şeyi
iddia etmek olur.

### 6.3 PathScan — sayı değil **çeşitlilik**

SIEM mantığının özünü gösteren en güzel örnek:

| Desen | Çeşitlilik | Karar |
|---|---|---|
| `/admin`'e **50 istek** | 1 | alarm yok — yer imi / bozuk bot |
| 5 farklı hassas dizine **1'er istek** | 5 | **ALARM** — keşfetme davranışı |

İkinci desen insanın gezinme şekli değil, tarama aracının imzası. Toplam 5 istek
olsa bile niyet açık — **hacim bazlı bir kural bunu asla yakalamaz.**

Tek metod ezmesiyle kuralın karakteri değişiyor:

```ruby
def measure(key)
  events.map { |(_t, value)| value }.uniq.size   # count değil, distinct
end
```

İki kaçınma tekniğine karşı önlem: `downcase` (`/ADMIN` oyunu) ve sorgu dizesini
atmak (`/admin?a=1` ile `/admin?a=2` aynı hedeftir — atmasak saldırgan
çeşitliliği yapay olarak şişirebilirdi).

## 7. Soğutma (cooldown) — ölçülmüş fark

Aynı log, iki motorla:

```
Soğutma 120 sn :     24 uyarı
Soğutma   0 sn :   1097 uyarı
Fark           :   54.8 kat
```

**İkisi de teknik olarak doğru**, ama ikincisi kullanılamaz. Gerçek hayatta SIEM
projelerini bitiren şey yanlış tespit değil, **bildirim yorgunluğudur** — insan
200. bildirimden sonra hepsini görmezden gelmeye başlar ve o noktadan sonra
sistemin doğru çalışmasının hiçbir kıymeti kalmaz.

**Kritik detay:** soğutma sırasında bildirmiyoruz ama **saymaya devam
ediyoruz**. Saymayı bırakırsak soğutma bitince sayaç sıfırdan başlar ve
saldırgan **sadece bekleyerek** tespitten kurtulur.

## 8. İki bellek tavanı ve DDoS ironisi

```ruby
MAX_EVENTS_PER_KEY = 2_000    # bir IP çok istek atarsa
MAX_KEYS           = 50_000   # çok fazla FARKLI IP gelirse
```

Birincisi: pencere *süreyle* sınırlı olması *sayının* sınırlı olmasını garanti
etmez. Saniyede 500.000 istek atan saldırgan 1 saniyelik pencereye 500.000 kayıt
sokar; pencere "doğru" çalışır ve bellek biter.

İkincisi daha önemli:

> **DDoS'u tespit etmek için yazdığın kod, DDoS'un kendisi tarafından RAM
> tüketilerek öldürülebilir.**

Sınır aşılınca en eski görülenler atılıyor. Bu bir **kayıp** — ama alternatifi
process'in ölmesi, yani tüm izlemenin durması. Mühendislik böyle: kötü iki
seçenek arasından daha az kötüsünü bilerek seçmek. Önemli olan bunu **sessizce
yapmamak** — `dropped_keys` sayılıyor ve `warn` basılıyor.

## 9. Kanıt zinciri

Her `Alert`, kendisini doğuran ham log satırlarını taşıyor (en fazla 5).

```
kural   : brute_force
ölçülen : 11  (eşik: 10, pencere: 60 sn)
detay   : automated: true, user_agent: "python-requests/2.31.0"
KANIT   : 45.155.205.233 - - [...] "POST /login HTTP/1.1" 401 178 ...
```

Bir ayrıntı önemliydi:

```ruby
evidence: (@evidence[key] || []).dup   # dup ŞART
```

Kopyalamazsak alarm **canlı değişen** diziye referans tutar ve 10 dakika sonra
baktığında içinde bambaşka satırlar bulursun. Kanıt, üretildiği andaki halini
korumak zorunda.

## 10. Yapılandırma — yazım hatası başlangıçta patlıyor

```ruby
unless klass
  raise ArgumentError, "bilinmeyen kural: #{name.inspect}"
end
```

En olası senaryo config'de yazım hatası (`brute_fore`). Sessizce yok sayarsak
servis sorunsuz başlar ama o kural **hiç çalışmaz** ve bunu aylarca fark
etmezsin. Gece 3'te alarm üretmesi gereken bir servis, eksik yapılandırmayla
sessizce başlamamalıdır.

Testlerden biri gerçek `config/logsentry.yml` dosyasını yüklüyor — elle
bozulduğunda haber veriyor.

## 11. Sonuçlar

3000 kayıt, **~84.000 kayıt/saniye**, 24 uyarı:

```
[HIGH]   45.155.205.233   60 sn'de 41 başarısız giriş        brute_force
[HIGH]   5.188.206.14     1 sn'de 101 istek                  flood
[MEDIUM] 193.34.76.101    300 sn'de 8 farklı hassas dizin     path_scan
```

Üç saldırgan IP'nin üçü de yakalandı; **normal IP'lerin hiçbiri alarm
üretmedi** (bu veri setinde sıfır yanlış pozitif). `193.34.76.101` iki kuraldan
da alarm aldı — hem taradı hem `403` topladı, doğru davranış.

## 12. Bulunan hatalar

| Bulgu | Tür | Düzeltme |
|---|---|---|
| `Class.new(Base)` ile isimsiz sınıfta `rule_name` çöküyordu (`name` nil) | gerçek kusur | `:anonymous` dönecek şekilde nil-güvenli hale getirildi |
| Testlerde eşik semantiği yanlış yazılmıştı | test hatası | Eşik "aşarsa" olduğu için (`measured > threshold`) `threshold: 2` ile alarm **3.** olayda düşer; ısınma sayıları düzeltildi ve koda not düşüldü |

## 13. Gerçek dünya karşılığı

Prometheus alert rule'ları, rate limiting, eşik ayarı, yanlış pozitif/negatif
takası. Durum (state) + zaman penceresi tutan her tespit sisteminin çekirdeği.

## 14. Çalıştırma

```bash
ruby step4_engine.rb
```

```bash
ruby test/engine_test.rb
```

Canlı alarm (iki terminal):

```bash
ruby tools/watch.rb --quiet
```

```bash
ruby tools/live_writer.rb --attack brute --rps 12
```
