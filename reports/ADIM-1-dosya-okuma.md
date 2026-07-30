# ADIM 1 RAPORU — Log Ortamı ve Dosya Okuma (File I/O)

**Durum:** ✅ Tamamlandı
**Üretilen dosyalar:** `tools/log_generator.rb`, `logs/access.log`, `step1_reader.rb`

---

## 1. Amaç

Gerçek bir sunucuya bağlanmadan üzerinde çalışabileceğimiz gerçekçi bir log
ortamı kurmak ve **büyük bir dosyanın belleği şişirmeden nasıl okunacağını**
öğrenmek.

## 2. Ortam kurulumu

Ruby hiçbir yerde kurulu değildi. İki ortama kurduk:

| Ortam | Sürüm | Kurulum yöntemi |
|---|---|---|
| Windows | Ruby 3.4.10 (+DevKit) | `winget install RubyInstallerTeam.RubyWithDevKit.3.4` |
| WSL Ubuntu-22.04 | Ruby 3.0.2 | `apt-get install ruby-full` |

İki ortam bilinçli bir tercih: Adım 1–4 her ikisinde de çalışır, ama Adım 5'teki
`Process.daemon` Windows'ta **yoktur** — o adım için Linux zorunlu.

## 3. Sahte log üreteci

`tools/log_generator.rb`, Nginx/Apache **combined** formatında log üretir:

```
IP - kullanıcı [zaman] "METOD /yol PROTOKOL" durum boyut "referer" "user-agent"
```

Normal trafiğin içine bilinçli olarak **üç saldırgan** serpiştirildi. Bunlar
sonraki adımlarda yazacağımız kuralların yakalayacağı hedeflerdir:

| IP | Davranış | Hangi kural yakalayacak |
|---|---|---|
| `45.155.205.233` | `/login`'e saniyeler içinde 12'lik `401` patlamaları | brute force (Adım 4) |
| `193.34.76.101` | `/admin`, `/wp-login.php`, `/.env`, `/.git/config` taraması; UA: `sqlmap` | dizin taraması (Adım 4) |
| `5.188.206.14` | Tek saniyede 150 istek | flood (Adım 4) |

Kullanım:

```bash
ruby tools/log_generator.rb 3000
```

## 4. Asıl ders: `File.read` vs `File.foreach`

400.000 satırlık (39 MB) bir dosyayla ölçüm:

| Yöntem | Süre | RAM'de tutulan |
|---|---|---|
| `File.read` | 33 ms | **39.592 KB** (tek bir dev String) |
| `File.foreach` | 428 ms | **187 bayt** (sadece o anki satır) |

`File.read` dosyanın tamamını tek bir String olarak belleğe çıkarır. 39 MB'da
sorun yok, ama gerçek bir sunucuda `access.log` rahatlıkla 3 GB olur — ve o
satır 3 GB RAM ister. Yetmezse process OOM-killer tarafından öldürülür.

`File.foreach` dosyayı bir **akış** gibi ele alır: RAM'de her an tek satır
bulunur, blok bitince GC onu toplar. **Dosya ne kadar büyürse büyüsün bellek
tüketimi sabit kalır.**

`File.foreach` bloklu çağrıldığında dosyayı otomatik kapatır — `ensure`/`close`
ile uğraşmaya gerek kalmaz.

## 5. İlk analiz çıktısı

3000 satırda HTTP durum kodu dağılımı:

```
200   2721   90.7%   OK
401    191    6.4%   Unauthorized   ← brute force adayı
404     37    1.2%   Not Found      ← tarama adayı
304     26    0.9%
403     24    0.8%
500      1    0.0%
```

%6,4'lük `401` oranı gözle görülür bir anomali — normal bir sitede bu oran
binde birkaçtır.

## 6. Bilinçli olarak bırakılan kusur

Durum kodunu şöyle çektik:

```ruby
status = line.split(' ')[8]      # "9. kelime durum kodudur" varsayımı
```

Bu **kırılgan**: user-agent'ta boşluk var, referer'da boşluk var, istek yolunda
boşluk olabilir. Sabit bir indekse güvenmek gerçek log verisinde er ya da geç
patlar. Adım 2 tam olarak bunu çözdü ve hilenin nerede yanıldığını ölçtü.

## 7. Karşılaşılan sorunlar

| Sorun | Çözüm |
|---|---|
| Ruby kurulu değildi | winget + apt ile iki ortama kuruldu |
| `ruby` komutu PATH'te görünmüyordu | Kurulum PATH'i ayarladı; açık terminaller eski PATH'i taşıyor, yeni terminal gerekiyor |
| 39 MB'lık test dosyası OneDrive'ı senkronize ediyordu | Test sonrası silindi; gerektiğinde yeniden üretiliyor |

## 8. Gerçek dünya karşılığı

Akış halinde (streaming) sabit bellekli okuma; büyük veri işleyen her
pipeline'ın temel şartı. Filebeat, Fluentd, Logstash — hepsinin log okuma
katmanı bu prensiple çalışır.

## 9. Çalıştırma

```bash
ruby tools/log_generator.rb 3000
```

```bash
ruby step1_reader.rb
```
