# LogSentry — Sistem Mimarisi

> Bu doküman, hiç Ruby bilmeyen birinin okuyup anlayabilmesi için yazıldı.
> Her teknik terim ilk geçtiği yerde açıklanıyor.

---

## 1. Bu sistem ne yapıyor?

Bir web sunucusu (Nginx, Apache) kendisine gelen **her isteği** bir dosyaya yazar.
Bu dosyaya `access.log` denir. Tek bir satır şuna benzer:

```
45.155.205.233 - - [29/Jul/2026:14:39:25 +0300] "POST /login HTTP/1.1" 401 178 "-" "python-requests/2.31.0"
```

Bu satır şunu söylüyor: *"45.155.205.233 numaralı bilgisayar, saat 14:39:25'te
/login sayfasına giriş yapmaya çalıştı ve başarısız oldu (401)."*

Tek başına bu satır masum. Ama **aynı IP'den 1 dakika içinde 50 tane** böyle satır
gelirse, o artık masum değil — biri şifre deniyor demektir. İşte kurumsal SIEM
sistemlerinin (Splunk, TR7, Wazuh) yaptığı iş tam olarak budur:

> **Tek tek anlamsız olan olayları toplayıp, aralarındaki örüntüyü yakalamak.**

LogSentry bunun küçük ama gerçek bir örneği olacak. Log dosyasını canlı canlı
izleyecek, her satırı çözümleyecek, kurallardan geçirecek ve şüpheli bir durum
görürse telefonuna bildirim gönderecek.

---

## 2. Temel tasarım fikri: Boru hattı (pipeline)

Sistemi tek bir dev dosya olarak yazmak mümkün — ama yanlış. Bunun yerine
veriyi bir **boru hattından** geçireceğiz. Her istasyon tek bir iş yapar,
işini bitirince sonucu bir sonrakine devreder:

```
  ┌──────────────────────────────────────────────────────────────────────┐
  │                          logs/access.log                             │
  │                    (sunucunun sürekli yazdığı dosya)                 │
  └───────────────────────────────┬──────────────────────────────────────┘
                                  │  ham metin satırı (String)
                                  ▼
  ┌──────────────────────────────────────────────────────────────────────┐
  │  1) TAILER        "dosyayı canlı izle"                    [ADIM 3]   │
  │     Dosyanın sonuna yapışır, yeni satır yazıldıkça haber verir.      │
  │     Linux'taki `tail -f` komutunun Ruby'deki karşılığı.              │
  └───────────────────────────────┬──────────────────────────────────────┘
                                  │  "45.155.205.233 - - [29/Jul..." 
                                  ▼
  ┌──────────────────────────────────────────────────────────────────────┐
  │  2) PARSER        "metni anlamlı veriye çevir"            [ADIM 2]   │
  │     Regex ile satırı parçalar: IP, zaman, metod, yol, durum kodu.    │
  │     Anlaşılamayan satırları çöpe atar (bozuk log her zaman olur).    │
  └───────────────────────────────┬──────────────────────────────────────┘
                                  │  Entry(ip: "45.155...", status: 401, ...)
                                  ▼
  ┌──────────────────────────────────────────────────────────────────────┐
  │  3) ENGINE        "kuralları sırayla uygula"              [ADIM 4]   │
  │     Gelen her kaydı elindeki TÜM kurallara tek tek sorar:            │
  │     "sence bu şüpheli mi?"                                           │
  │                                                                      │
  │      ├── BruteForceRule   : aynı IP'den 1 dk'da 10+ tane 401         │
  │      ├── FloodRule        : aynı IP'den saniyede 100+ istek          │
  │      └── PathScanRule     : /admin, /wp-login.php, /.env taraması    │
  └───────────────────────────────┬──────────────────────────────────────┘
                                  │  Alert(rule: "brute_force", ip: ..., ...)
                                  │  (şüphe yoksa buradan hiçbir şey çıkmaz)
                                  ▼
  ┌──────────────────────────────────────────────────────────────────────┐
  │  4) NOTIFIERS     "haber ver"                             [ADIM 5]   │
  │     Üretilen uyarıyı birden fazla kanala aynı anda gönderir.         │
  │                                                                      │
  │      ├── ConsoleNotifier  : ekrana renkli yazar                      │
  │      ├── FileNotifier     : alerts.jsonl dosyasına kaydeder          │
  │      ├── StoreNotifier    : veritabanına yazar (aşağıya bak)         │
  │      └── WebhookNotifier  : Telegram / Slack'e bildirim atar         │
  └───────────────────────────────┬──────────────────────────────────────┘
                                  │
                                  ▼
  ┌──────────────────────────────────────────────────────────────────────┐
  │  5) STORE         "sakla ve sorgulanabilir yap"           [ADIM 6]   │
  │     SQLite veritabanı. İki tablo: `events` (tüm istekler) ve         │
  │     `alerts` (üretilen uyarılar).                                    │
  │     Neden veritabanı? Çünkü web arayüzünde "dün saat 14-15 arası     │
  │     bu IP ne yaptı?" sorusunu sormak isteyeceğiz. Düz metin          │
  │     dosyasında bu soruyu sormanın makul bir yolu yok.                │
  │                                                                      │
  │     Yanında ARCHIVER: eski logları sıkıştırıp mühürler, yasal        │
  │     saklama süresini yönetir. (Bölüm 7'ye bak)                       │
  └───────────────────────────────┬──────────────────────────────────────┘
                                  │
                                  ▼
  ┌──────────────────────────────────────────────────────────────────────┐
  │  6) WEB           "insanın bakabileceği yüz"              [ADIM 7]   │
  │     Sinatra ile küçük bir web sunucusu. Tarayıcıdan izlenir.         │
  │                                                                      │
  │      ├── Dashboard   : canlı akış + özet grafikler                   │
  │      ├── Alerts      : uyarı listesi, filtreleme                     │
  │      ├── Explorer    : geçmiş log arama (IP / tarih / durum kodu)    │
  │      └── SSE akışı   : sayfa yenilemeden canlı güncelleme            │
  └──────────────────────────────────────────────────────────────────────┘
```

**Bu ayrımın pratik faydası ne?** Yarın Nginx yerine Apache logu okumak
istersen sadece PARSER'ı değiştirirsin, geri kalan hiçbir şeye dokunmazsın.
Yeni bir saldırı türü tespit etmek istersen ENGINE'e yeni bir kural eklersin,
okuma ve bildirim tarafı aynı kalır. Buna **"tek sorumluluk" ilkesi** denir ve
bir sistemi büyütülebilir kılan şeyin ta kendisidir.

---

## 3. Klasör yapısı

```
DevOps/
├── bin/
│   ├── logsentry                  # İzleyici servis (daemon)
│   ├── logsentry-web              # Web arayüzü sunucusu                [ADIM 7]
│   └── logsentry-archive          # Arşivleme/temizlik görevi (cron)    [ADIM 6]
│
├── lib/                           # Asıl kütüphane kodu
│   ├── log_sentry.rb              # Her şeyi birbirine bağlayan orkestratör
│   └── log_sentry/
│       ├── entry.rb               # Tek bir log satırının veri modeli   [ADIM 2]
│       ├── parser.rb              # Regex ile ayrıştırma                [ADIM 2]
│       ├── tailer.rb              # Canlı dosya izleme                  [ADIM 3]
│       ├── alert.rb               # Tek bir uyarının veri modeli        [ADIM 4]
│       ├── engine.rb              # Kural motoru                        [ADIM 4]
│       ├── rules/
│       │   ├── base.rb            # Tüm kuralların ortak atası
│       │   ├── brute_force.rb     # Şifre deneme saldırısı
│       │   ├── flood.rb           # DDoS belirtisi
│       │   └── path_scan.rb       # Hassas dizin taraması
│       ├── notifiers/
│       │   ├── console.rb
│       │   ├── file.rb
│       │   ├── store.rb           # Veritabanına yazan notifier         [ADIM 6]
│       │   └── webhook.rb         # Telegram / Slack                    [ADIM 5]
│       ├── daemon.rb              # Arka plan servisi                   [ADIM 5]
│       ├── store.rb               # SQLite katmanı (yazma + sorgu)      [ADIM 6]
│       ├── archiver.rb            # Sıkıştırma + mühürleme + süre       [ADIM 6]
│       └── web/                                                       # [ADIM 7]
│           ├── app.rb             # Sinatra uygulaması (rotalar)
│           ├── views/             # HTML şablonları (.erb)
│           │   ├── layout.erb
│           │   ├── dashboard.erb
│           │   ├── alerts.erb
│           │   └── explorer.erb
│           └── public/            # CSS / JS (dışa bağımlılık yok)
│               ├── app.css
│               └── app.js
│
├── config/
│   └── logsentry.yml              # Eşikler, saklama süresi, web ayarı
│
├── db/
│   └── logsentry.db               # SQLite veritabanı                   [ADIM 6]
│
├── logs/
│   ├── access.log                 # İzlenen sahte sunucu logu
│   └── alerts.jsonl               # Üretilen uyarılar (satır başı JSON)
│
├── archive/                       # Yasal saklama alanı                 [ADIM 6]
│   ├── access-2026-07-29.log.gz   # Sıkıştırılmış ham log
│   └── manifest.jsonl             # Her arşivin SHA-256 mührü
│
├── tools/
│   └── log_generator.rb           # Sahte log üreteci                   [ADIM 1] ✅
│
└── step1_reader.rb                # Adım 1 öğrenme dosyası              [ADIM 1] ✅
```

### Kaç tane program çalışacak?

Bu kafa karıştırıcı olabilir: tek bir program değil, **üç ayrı process** olacak
ve bunlar birbirinden bağımsız çalışacak:

```
   ┌─────────────────────┐         ┌─────────────────────┐
   │  bin/logsentry      │         │  bin/logsentry-web  │
   │  (daemon)           │         │  (Sinatra)          │
   │                     │         │                     │
   │  access.log'u izler │         │  tarayıcıya hizmet  │
   │  kural işletir      │         │  eder, :4567        │
   │  uyarı üretir       │         │                     │
   └──────┬──────────────┘         └───────┬─────────────┘
          │ YAZAR                          │ OKUR
          ▼                                ▼
   ┌────────────────────────────────────────────────────┐
   │        db/logsentry.db   +   logs/alerts.jsonl     │
   └────────────────────────────────────────────────────┘
                          ▲
                          │ TEMİZLER / ARŞİVLER (günde 1, cron)
                 ┌────────┴──────────────┐
                 │ bin/logsentry-archive │
                 └───────────────────────┘
```

**Neden tek programda birleştirmiyoruz?** Çünkü web arayüzü çökerse (birisi
hatalı bir sorgu atar, bellek şişer) **izleme durmamalı**. Güvenlik izlemesi
sistemin en kritik parçası; onu bir web sunucusunun kaderine bağlamak kötü
mühendisliktir. Process'leri ayırmak, birinin diğerini yıkmasını engeller.
Buna **hata izolasyonu** denir ve gerçek sistemlerde bu ayrımı her yerde
görürsün (Prometheus veri toplar, Grafana gösterir — ayrı process'lerdir).

İki process birbiriyle **dosya ve veritabanı üzerinden** konuşuyor. Aralarında
doğrudan bağlantı yok. Bu en basit ve en sağlam haberleşme yöntemi.

Bu, Ruby dünyasının **standart** proje düzenidir. `lib/` içine kütüphane kodu,
`bin/` içine çalıştırılabilir dosya konur. Bu düzene uyarsan ileride projeyi
bir **gem** (Ruby'nin paket formatı, npm'deki paket gibi) haline getirmen
neredeyse bedava olur.

---

## 4. Ruby'yi hiç bilmeyenler için: kavram sözlüğü

Aşağıdakiler projede kullanacağımız her yapının ne olduğunu anlatıyor.
Sağ sütun, o kavramı bu projede nerede göreceğini söylüyor.

### 4.1 Sınıf (class) — "kalıp"

Bir sınıf, aynı işi yapan nesneler için hazırlanmış bir **kalıptır**.
Kurabiye kalıbı gibi düşün: kalıbın kendisi kurabiye değildir, ama ondan
istediğin kadar kurabiye çıkarabilirsin.

```ruby
class Parser              # kalıbı tanımla
  def initialize(format)  # kalıptan bir nesne üretilirken çalışan metod
    @format = format      # @ ile başlayan değişken = o nesneye ait hafıza
  end

  def parse(line)         # nesnenin yapabildiği bir iş
    # ...
  end
end

parser = Parser.new("nginx")     # kalıptan gerçek bir nesne üret
sonuc  = parser.parse(satir)     # o nesneye iş yaptır
```

| Ruby'de | Türkçesi | Anlamı |
|---|---|---|
| `class Foo` | sınıf | Kalıbın tanımı |
| `Foo.new` | örnekleme | Kalıptan gerçek bir nesne üretmek |
| `def initialize` | kurucu | Nesne doğarken bir kez çalışan metod |
| `@degisken` | örnek değişkeni | Nesnenin kendi içinde sakladığı veri |
| `def metod` | metod | Nesnenin yapabildiği bir iş |

### 4.2 Struct — "sadece veri taşıyan kutu"

Bazen bir şeyin davranışa değil, sadece **veri taşımaya** ihtiyacı vardır.
Bir log satırını çözümlediğimizde elimizde IP, zaman, durum kodu kalır —
bunları bir arada tutacak bir kutu lazım. Ruby'de bunun kısa yolu `Struct`:

```ruby
Entry = Struct.new(:ip, :time, :method, :path, :status, keyword_init: true)

e = Entry.new(ip: "45.155.205.233", status: 401, path: "/login")
e.ip       # => "45.155.205.233"
e.status   # => 401
```

Neden düz bir Hash (sözlük) kullanmıyoruz? Çünkü Hash'te `e[:statuss]` yazsan
Ruby sana `nil` (boş) döner ve hata **sessizce** yayılır. Struct'ta `e.statuss`
yazarsan program **anında** hata verip seni uyarır. Üretimde çalışan bir
güvenlik aracında sessiz hata, en tehlikeli hata türüdür.

### 4.3 Hash — "sözlük"

Anahtar–değer eşleşmesi tutan yapı. Bizim için kritik bir kullanımı var:

```ruby
sayac = Hash.new(0)        # varsayılan değeri 0 olan sözlük
sayac["45.155.205.233"] += 1
sayac["45.155.205.233"] += 1
sayac["45.155.205.233"]    # => 2
```

`Hash.new(0)` demezsen ilk `+= 1` işleminde "nil'e 1 eklenemez" hatası alırsın.
IP başına istek saymak için bunu sürekli kullanacağız.

### 4.4 Sembol (`:isim`) — "değişmeyen etiket"

`:ip` ile `"ip"` neredeyse aynı şeydir, ama sembol bellekte **tek bir kez**
oluşturulur ve asla değişmez. Anahtar/etiket olarak kullanılacak şeyler için
sembol tercih edilir — hem daha hızlı hem de niyeti belli eder.

### 4.5 Blok (`do ... end`) — "işi başkasına yaptırmak"

Ruby'nin en karakteristik özelliği. Bir metoda **kod parçası** verirsin,
metod onu istediği zaman ve istediği kadar çalıştırır:

```ruby
File.foreach("access.log") do |satir|   # <- işte bu bir blok
  puts satir                            #    her satır için bir kez çalışır
end
```

Buradaki `|satir|` ifadesi "her turda bana bir satır ver, adı `satir` olsun"
demektir. Adım 1'de bunu zaten kullandık.

### 4.6 Modül (`module`) — "isim alanı"

Kod büyüdükçe isimler çakışmaya başlar. Senin `Parser` sınıfın ile
kullandığın bir kütüphanenin `Parser` sınıfı çakışırsa program bozulur.
`module` bunu çözer — bir soyadı gibi düşün:

```ruby
module LogSentry
  class Parser
    # ...
  end
end

LogSentry::Parser.new    # tam adı bu; artık kimseyle çakışmaz
```

Projedeki her sınıf `LogSentry` modülünün içinde yaşayacak.

### 4.7 `require` — "başka dosyayı yükle"

Ruby dosyaları birbirini otomatik görmez. Kullanacağın dosyayı açıkça
yüklemen gerekir:

```ruby
require_relative 'log_sentry/parser'   # kendi dosyalarımız için
require 'json'                         # Ruby'nin hazır kütüphaneleri için
```

### 4.8 `nil` — "yokluk"

Ruby'de "değer yok" demenin yolu `nil`'dir. Bu proje için kritik, çünkü
mimarimizde **`nil` bir cevaptır**: bir kural `nil` döndürüyorsa
*"bu satırda şüpheli bir şey görmedim"* demektir. Uyarı varsa bir `Alert`
nesnesi döner. Motor da bu ikisini birbirinden ayırarak çalışır.

---

## 5. Bileşenler nasıl konuşacak? (sözleşmeler)

Bir sistemin sağlam olmasının sırrı, parçaların **birbirine ne söz verdiğinin**
net olmasıdır. Bizim üç sözleşmemiz var:

**Sözleşme 1 — Parser:**
> Sana bir metin satırı veririm; bana ya bir `Entry` nesnesi ya da `nil` dönersin.
> Asla çökmezsin. Anlamadığın satır olursa `nil` dön, ama programı durdurma.

**Sözleşme 2 — Kural (Rule):**
> Sana bir `Entry` veririm; bana ya bir `Alert` ya da `nil` dönersin.
> Kendi hafızanı (kimin kaç kez ne yaptığını) kendin tutarsın.

**Sözleşme 3 — Notifier:**
> Sana bir `Alert` veririm; onu kendi kanalına iletirsin.
> Gönderemezsen (internet yoksa vs.) hata fırlatıp tüm sistemi durdurmazsın.

Bu üç cümle sayesinde her parçayı **tek başına** test edebiliriz — sunucuya,
internete, hatta diğer parçalara ihtiyaç duymadan.

Ve asıl kazanç şurada: bütün kurallar aynı sözleşmeye uyduğu için, motor
kuralların ne yaptığını bilmek zorunda değildir. Motorun tüm kodu pratikte
şu kadardır:

```ruby
def process(entry)
  @rules.filter_map { |rule| rule.call(entry) }   # nil dönenleri ele, kalanı topla
end
```

Yarın 20 kural daha eklesen bu satır aynı kalır. Buna **polimorfizm** denir.

---

## 6. En kritik tasarım kararı: kayan pencere (sliding window)

"1 dakika içinde 10'dan fazla 401" cümlesi kulağa basit geliyor ama altında
gerçek bir mühendislik problemi var: **1 dakikayı nasıl takip edeceğiz?**

Naif çözüm: her IP'nin tüm isteklerini bir listede tut. Sorun: sunucu haftalarca
çalışacak, o liste sonsuza kadar büyür ve bir noktada RAM biter. Adım 1'de
`File.read` için söylediğimiz sorunun aynısı, farklı kılıkta.

Doğru çözüm **kayan pencere**: her IP için sadece **son 60 saniyenin** zaman
damgalarını tut, eskiyeni baştan at.

```
Şimdi: 14:39:25 — pencere: [14:38:25 ... 14:39:25]

  IP 45.155.205.233 için tutulan liste:
  [14:38:10]  [14:38:50] [14:39:01] [14:39:05] [14:39:22] [14:39:25]
   ▲ 60 sn'den eski
   └── ATILIR              └────────── bunlar sayılır: 5 tane ────────┘

  Sayı 10'u geçerse  →  ALARM
```

Böylece bellek kullanımı **sabit** kalır: bir IP en fazla 60 saniyelik veri tutar.
Bu yapıyı Adım 4'te `Rules::Base` içine yazacağız ve üç kural da onu paylaşacak —
çünkü "brute force", "flood" ve "tarama" aslında aynı sorunun farklı eşiklerle
sorulmuş halleridir:

| Kural | Neyi sayıyor | Pencere | Eşik |
|---|---|---|---|
| BruteForce | aynı IP'den `401` yanıtları | 60 sn | 10 |
| Flood | aynı IP'den **tüm** istekler | 1 sn | 100 |
| PathScan | aynı IP'den hassas dizin istekleri | 300 sn | 3 |

### ÇOK ÖNEMLİ: pencere ≠ saklama süresi

Bu iki şey sürekli birbirine karıştırılıyor, net ayıralım:

| | **Tespit penceresi** | **Saklama süresi** |
|---|---|---|
| Nerede yaşar | RAM (bellek) | Disk |
| Ne kadar | 1–300 saniye | **Yıllar** (bölüm 7) |
| Amacı | "şu an saldırı var mı?" | adli inceleme, yasal yükümlülük |
| Kim yönetir | `Rules::Base` | `Archiver` + `Store` |
| Sınırı ne belirler | RAM kapasitesi | mevzuat + disk |

Kayan pencerenin "eskiyi atması" **hiçbir logu silmek anlamına gelmez.**
Attığı şey bellekteki bir sayaç kaydıdır. `access.log` dosyasına sadece
*okuma* amaçlı dokunuyoruz — tek satırını bile değiştirmiyoruz.

Analoji: bir güvenlik görevlisi kapıda durup "son 1 dakikada kaç kişi geçti?"
diye sayar. Bu sayacı sürekli sıfırlar. Ama bu, **kamera kayıtlarının
silindiği anlamına gelmez** — kayıtlar arşivde 2 yıl durur. Sayaç anlık karar
için, kayıt geçmişe dönük inceleme için.

---

## 7. Saklama, arşivleme ve yasal bütünlük

### Neden bu bir mimari mesele?

Türkiye'de 5651 sayılı Kanun ve ilgili yönetmelikler kapsamındaysan (erişim
sağlayıcı, yer sağlayıcı, ticari amaçla internet toplu kullanım sağlayıcı)
trafik kayıtlarını belirli bir süre saklamak **zorundasın**. Yaygın olarak
anılan süre 2 yıldır, ancak kategoriye göre değişir.

> **Not:** Bu bir hukuki görüş değildir. Kendi kategorin ve kesin süre için
> mevzuatı ve hukuk danışmanını teyit et. Buradaki tasarım, "böyle bir
> yükümlülük varsa mimari nasıl olmalı" sorusunun cevabıdır.

Ve mevzuatın çoğu kişinin kaçırdığı ikinci şartı var: sadece saklamak yetmez,
kayıtların **doğruluğunu, bütünlüğünü ve gizliliğini** de sağlamak gerekir.
Yani "sonradan değiştirilmedi" iddiasını kanıtlayabilmen lazım.

### İki yönlü kısıt: taban ve tavan

Burası kritik. Saklama süresinin hem alt hem üst sınırı var:

```
        │◀── ihlal ──▶│◀────── uygun aralık ──────▶│◀── ihlal ──▶│
────────┼─────────────┼────────────────────────────┼─────────────▶
        0          yasal alt sınır            amaç sonu        süresiz
                   (5651: sakla)              (KVKK: sil)

  "3 ay tutup sildim"                    "garanti olsun diye
   → 5651 ihlali                          sonsuza kadar tutuyorum"
                                          → KVKK ihlali
```

**IP adresi KVKK'ya göre kişisel veridir.** Dolayısıyla "her ihtimale karşı
süresiz tutalım" yaklaşımı da hatalıdır — veri, amacı için gerekli süre
sonunda silinmek zorundadır. Doğru tasarım, saklama süresini **açık ve
denetlenebilir bir politika** olarak tanımlamaktır. Bizde bu politika
`config/logsentry.yml` içinde tek bir yerde durur.

### `Archiver` ne yapacak?

Günde bir kez (cron ile) çalışan ayrı bir görev:

```
  1) DÖNDÜR    access.log → archive/access-2026-07-29.log
               (logrotate zaten yapıyorsa bu adımı ona bırakırız)

  2) SIKIŞTIR  gzip ile ~%90 küçültme.
               2 yıllık log, sıkıştırılmadan disk bitirir.

  3) MÜHÜRLE   SHA-256 özetini hesapla, manifest.jsonl'a yaz:
               {"file":"access-2026-07-29.log.gz",
                "sha256":"9f2b...",
                "lines":412883,
                "sealed_at":"2026-07-30T03:00:00+03:00",
                "prev_sha256":"7c1a..."}   ◀── zincir

  4) DOĞRULA   Eski arşivlerin özetlerini yeniden hesapla,
               manifest ile karşılaştır. Uyuşmuyorsa ALARM ÜRET.
               (Loglarını değiştiren biri varsa bunu bilmen gerekir.)

  5) TEMİZLE   Saklama süresi geçmiş arşivleri sil,
               sildiğini de kayda geç (silme işlemi de bir olaydır).
```

3. adımdaki `prev_sha256` alanı işin en zarif kısmı: her mühür, kendinden
öncekinin özetini de içeriyor. Böylece bir **zincir** oluşuyor. Ortadaki tek
bir dosyayı değiştirmek isteyen birinin, ondan sonraki **tüm** mühürleri de
yeniden hesaplaması gerekir. Bu fikrin adı **hash zinciri**; blok zincirinin
de temelinde yatan mekanizma budur. Kurumsal log çözümlerinin "değiştirilemez
kayıt" (WORM / tamper-evident) iddiası bunun üzerine kuruludur.

Gerçek bir 5651 uyumluluğunda buna ek olarak **yetkili bir zaman damgası
sağlayıcısından** (TSA) imza alınır — yani mührü senin değil, güvenilen bir
üçüncü tarafın attığını kanıtlarsın. Bizim `manifest.jsonl`'ımız bunun
öğretici versiyonu: mekanizma aynı, imzalayan taraf farklı.

### İki katmanlı depolama

```
  ┌───────────────────────────────────────────────────────────────┐
  │  SICAK KATMAN   —   db/logsentry.db (SQLite)                  │
  │  Süre: son 30-90 gün    Amaç: web arayüzünde hızlı sorgu      │
  │  "Dün 14:00-15:00 arası bu IP ne yaptı?" → milisaniyeler       │
  └───────────────────────────────────────────────────────────────┘
  ┌───────────────────────────────────────────────────────────────┐
  │  SOĞUK KATMAN   —   archive/*.log.gz + manifest.jsonl         │
  │  Süre: yasal süre (örn. 2 yıl)   Amaç: kanıt, adli inceleme   │
  │  Sorgulanabilir değil, ama bozulamaz ve ham haliyle korunur.   │
  └───────────────────────────────────────────────────────────────┘
```

Neden ikisi birden? Çünkü amaçları farklı. Veritabanı **hızlı sorgu** için,
arşiv **kanıt** için. Ham logu asla veritabanına ezdirmeyiz — mahkemede
"biz bunu ayrıştırdık, işledik, şemamıza soktuk" demek istemezsin. Ham
kaydın kendisi, dokunulmamış haliyle durmalıdır.

---

## 8. Web arayüzü

### Teknoloji seçimi ve nedeni

| Katman | Seçim | Neden |
|---|---|---|
| Web çatısı | **Sinatra** | Rails aşırı büyük. Sinatra ~10 satırda çalışan sunucu verir, rotaları İngilizce cümle gibi okunur. Öğrenmek için ideal. |
| Veritabanı | **SQLite** | Sunucu kurulumu gerektirmez, tek dosya. Tek makinede log izleme için fazlasıyla yeterli. |
| Canlı akış | **SSE** | WebSocket bu iş için gereğinden karmaşık. Veri tek yönlü akıyor (sunucu → tarayıcı), SSE tam bu iş için var. |
| Grafik | **elle SVG** | Dış kütüphane yok. Bir çubuk grafiğin nasıl çizildiğini görmek, hazır kütüphane çağırmaktan öğretici. |

### Rotalar (sayfalar ve veri uçları)

```
GET  /                    Dashboard
                          - son 24 saatin istek/uyarı grafiği
                          - aktif alarm sayısı, en çok alarm üreten IP'ler
                          - canlı akan uyarı listesi (SSE ile)

GET  /alerts              Uyarı listesi
                          - filtre: kural türü, önem, IP, tarih aralığı
                          - sayfalama

GET  /alerts/:id          Tek uyarının detayı
                          - alarmı TETİKLEYEN ham log satırları
                          - "neden alarm verdim" açıklaması

GET  /explorer            Geçmiş log arama
                          - IP / yol / durum kodu / tarih aralığı
                          - sonuçları CSV indir

GET  /ips/:ip             Tek bir IP'nin profili
                          - zaman çizelgesi, dokunduğu yollar, alarm geçmişi

GET  /integrity           Arşiv bütünlük raporu
                          - manifest zinciri doğrulaması: yeşil / kırmızı

GET  /stream              SSE veri ucu (sayfa değil)
                          - yeni uyarı düştükçe tarayıcıya anında iter
```

`/alerts/:id` rotası aslında en değerlisi. Bir uyarı gördüğünde ilk soracağın
şey "gerçekten saldırı mı, yanlış alarm mı?" olacak. Bu soruyu ancak alarmı
tetikleyen **ham satırları** görerek cevaplayabilirsin. Bu yüzden `Alert`
nesnesi kendisini doğuran log kayıtlarına referans tutacak. Buna
**kanıt zinciri (evidence)** denir ve bir uyarıyı "eyleme geçirilebilir"
yapan şeyin ta kendisidir. Kanıt göstermeyen alarm, gürültüdür.

### Canlı akış nasıl çalışacak? (SSE)

Klasik web'de tarayıcı sorar, sunucu cevap verir, bağlantı kapanır. Canlı
izlemede bunu tersine çevirmemiz lazım: **bağlantı açık kalacak** ve sunucu
haber oldukça yazacak.

```
  Tarayıcı                          Sinatra (:4567)         alerts.jsonl
     │                                    │                       │
     │──── GET /stream ──────────────────▶│                       │
     │                                    │──── Tailer ile izle ─▶│
     │◀─── (bağlantı açık kalıyor) ───────│                       │
     │                                    │                       │
     │                                    │◀═══ yeni uyarı ═══════│
     │◀─── data: {"rule":"brute_force"..} │                       │
     │     (JS listeye ekler, sayfa       │                       │
     │      yenilenmez)                   │                       │
     │                                    │◀═══ yeni uyarı ═══════│
     │◀─── data: {"rule":"flood"...}      │                       │
```

Dikkat et: web sunucusu canlı akış için **Adım 3'te yazacağımız `Tailer`
sınıfını yeniden kullanıyor** — sadece bu kez `access.log` yerine
`alerts.jsonl` dosyasını izliyor. Doğru mimarinin ödülü budur: bileşeni bir
kez yaz, umulmayan yerlerde bedavaya kullan.

`alerts.jsonl` formatı da bunun için seçildi. **JSONL** = her satırda bir
JSON nesnesi. Hem `tail -f` ile insan okuyabilir, hem satır satır makine
ayrıştırabilir. Düz JSON dizisi olsaydı (`[{...},{...}]`) dosyanın sonuna
yeni kayıt eklemek için her seferinde tüm dosyayı yeniden yazmak gerekirdi.

### Güvenlik: kendi izleme aracın hedef olur

Bu arayüz saldırganın en çok görmek isteyeceği ekran — hangi IP'sinin
yakalandığını, hangi kuralın ne eşikle çalıştığını gösteriyor. Dolayısıyla:

- **Sadece localhost'a bağlan** (`127.0.0.1:4567`). Dışarıya açmak
  gerekiyorsa Nginx arkasından, TLS ve kimlik doğrulama ile.
- **Salt okunur.** Arayüzden kural değiştirilemez, alarm silinemez.
  Yazma yetkisi olmayan bir panel, ele geçirilse bile hasar veremez.
- **Girdi doğrulama.** Explorer'daki arama alanları doğrudan SQL'e
  girmeyecek — SQLite'ın **parametreli sorgu** mekanizmasını kullanacağız.
  (SQL enjeksiyonu ile ilgili aracın kendisi SQL enjeksiyonuna açık olursa
  bu, işin ironisi olur.)

---

## 9. Yol haritası — hangi adımda ne inşa edilecek

| Adım | Ne inşa edilecek | Yeni öğrenilecek Ruby kavramı | Durum |
|---|---|---|---|
| **1** | Sahte log üreteci + satır satır okuma | `File.foreach`, blok, `Hash.new(0)` | ✅ Bitti |
| **2** | `Entry` + `Parser` | Regex, adlandırılmış yakalama grupları, `Struct` | Sırada |
| **3** | `Tailer` | `IO#seek`, sonsuz döngü, `sleep`, dosya rotasyonu | — |
| **4** | `Engine` + 3 kural | sınıf mirası, polimorfizm, kayan pencere | — |
| **5** | `Daemon` + `Notifier`'lar | `Process.daemon`, sinyaller, HTTP POST, YAML | — |
| **6** | `Store` + `Archiver` | SQLite, parametreli sorgu, indeks, SHA-256, gzip | — |
| **7** | Web arayüzü | Sinatra, rota, ERB şablon, SSE, SVG grafik | — |

Her adımın sonunda çalışan ve test edilmiş bir sistem olacak — sonuncuya kadar
bekleyip her şeyi bir anda birleştirmeyeceğiz.

Adım 6 ve 7 için dışarıdan iki paket (**gem**) kuracağız: `sqlite3` ve
`sinatra`. Adım 1–5 arası **sıfır bağımlılıkla**, sadece Ruby'nin kendi
kütüphaneleriyle yazılacak — çekirdek mantığın hiçbir dış pakete ihtiyaç
duymaması, aracın taşınabilirliği açısından kıymetli bir özellik.

---

## 10. Kapsam dışı bıraktıklarımız (bilinçli olarak)

Gerçek bir SIEM'de olan ama burada olmayacak şeyler — bunları bilmek, yaptığın
şeyin sınırlarını bilmek demektir:

- **Yetkili zaman damgası (TSA):** Arşivleri kendi SHA-256 zincirimizle
  mühürleyeceğiz. Hukuken tam geçerlilik için yetkili bir sağlayıcıdan imza
  almak gerekir; mekanizma aynı, imzalayan taraf farklı.
- **Kimlik doğrulama:** Web arayüzü sadece localhost'ta çalışacak, kullanıcı
  girişi olmayacak. Dışa açılacaksa bu ilk eklenmesi gereken şeydir.
- **Dağıtık toplama:** Tek makinedeki tek dosyayı izliyoruz, 500 sunucuyu değil.
- **Korelasyon:** Farklı kaynakları (firewall + web + DNS) birleştirip
  ilişkilendirmiyoruz. Kurumsal SIEM'in asıl gücü buradadır.
- **Otomatik müdahale:** Saldırganın IP'sini firewall'a otomatik eklemiyoruz.
  (Bu, eklenmesi en kolay ve en tehlikeli özelliktir — yanlış pozitif bir
  alarmda kendi kullanıcılarını engellersin.)
