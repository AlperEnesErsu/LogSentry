# ADIM 5 RAPORU — Daemon ve Uyarı Mekanizması

**Durum:** ✅ Tamamlandı
**Test:** 29 test, 86 doğrulama — Windows ✅ / WSL ✅ · **canlı daemon testi WSL'de** ✅
**Üretilen dosyalar:** `lib/log_sentry/notifiers/{base,console,file,webhook}.rb`,
`lib/log_sentry/daemon.rb`, `lib/log_sentry.rb`, `bin/logsentry`,
`deploy/logsentry.service`, `test/daemon_test.rb`

---

## 1. Bu adımda ne değişti

Boru hattı tamamlandı ve araç bir **sistem servisine** dönüştü:

```
dosya → TAILER → PARSER → ENGINE → NOTIFIERS → ekran / dosya / telefon
       (adım 3) (adım 2)  (adım 4)   (adım 5)
```

## 2. Daemonization — `Process.daemon` gerçekte ne yapıyor

`ruby bin/logsentry` yazdığında program terminali işgal eder. Terminali
kapatınca, SSH bağlantın kopunca program da ölür. Çünkü program terminale bağlı
(controlling TTY), senin oturumunun parçası ve oturum kapanınca çekirdek o
oturumdaki process'lere `SIGHUP` gönderir.

Klasik Unix çözümü üç adımdır ve Ruby üçünü tek çağrıda yapar:

| Adım | Ne yapar | Neden gerekli |
|---|---|---|
| `fork()` | çocuk yarat, **ebeveyni öldür** | Process artık terminalin çocuğu değil; kabuk onu beklemez, hemen prompt döner |
| `setsid()` | **yeni oturum** aç, lideri ol | Controlling TTY bağını kesin olarak koparır; terminal kapanınca `SIGHUP` almaz |
| stdio yönlendirme | stdin/stdout/stderr'i yeniden bağla | Terminal yoksa bu üç akışın işaret ettiği yer de yok; ilk `puts`'ta `EIO` alırsın |

```ruby
Process.daemon(true, true)   # nochdir, noclose
```

- **`nochdir = true`** — çalışma dizinini değiştirme. Varsayılan `/` dizinine
  geçmektir (daemon dizini meşgul tutarsa o disk bölümü `unmount` edilemez), ama
  bizim yapılandırmadaki yollar göreli. Üretimde doğru yaklaşım: tüm yolları
  mutlak hale getir, sonra `/`'ye geç.
- **`noclose = true`** — stdio'yu sen kapatma. Varsayılan üçünü `/dev/null`'a
  bağlar, yani tüm çıktı çöpe gider. Biz engelleyip kendi log dosyamıza
  yönlendiriyoruz.

`$stdout.sync = true` kritik: Ruby dosyaya yazarken 8 KB birikene kadar bekler.
Bu olmadan daemon logları dakikalarca görünmez — ve process çökerse tamponda
bekleyen satırlar tamamen kaybolur. Yani *"çökmeden hemen önce ne oldu?"*
bilgisini tam ihtiyaç duyduğun anda kaybedersin.

### Kopmanın kanıtı (WSL ölçümü)

```
== Başlatan kabuk ==      == Daemon process ==
kabuk PID : 447            PID  PPID  SID  TT  STAT
kabuk SID : 447            457   442  456   ?   Sl
```

- `TT = ?` → **controlling terminal yok**
- `SID 456 ≠ 447` → **kendi oturumu var**
- `STAT = Sl` → S: uyuyor, l: çok thread'li (bizim iki thread'imiz)

Not: `PPID 442` çıktı, PID 1 değil — WSL'de bir "Relay" process alt-toplayıcı
(subreaper) olarak devraldı. Gerçek bir sunucuda systemd altında PPID 1 olur.
Kopmanın asıl kanıtı TTY ve SID'dir, PPID değil.

## 3. PID dosyası ve bayat PID tuzağı

Process arka planda; elinde Ctrl-C basacağın terminal yok. Tek yol PID'i bilip
**sinyal göndermek**. Daemon doğar doğmaz PID'ini `logs/logsentry.pid`'e yazıyor.

**Bayat (stale) PID dosyası** bilinmediğinde saatler kaybettiren klasik tuzak:
sunucu aniden kapanır (elektrik, OOM killer, `kill -9`), daemon dosyayı silemez.
Sunucu açılır, servis "zaten çalışıyor" der — ama çalışmıyor. Üstüne, o PID
bambaşka bir process'e ait olabilir.

Çözüm:

```ruby
Process.kill(0, pid)
```

`0` numaralı "sinyal" aslında sinyal değildir — hiçbir şey göndermez, sadece
*"bu PID'e sinyal gönderebilir miydim?"* diye sorar:

| Sonuç | Anlamı |
|---|---|
| `Errno::ESRCH` | böyle process yok → **bayat dosya** |
| `Errno::EPERM` | process var ama başkasının → yaşıyor |
| hata yok | process var ve bizim |

`release` sadece **bize ait** kaydı siliyor — başka bir örnek dosyayı
devraldıysa onun kaydını silmek o örneği yönetilemez hale getirir.

## 4. Sinyaller

| Sinyal | Anlamı | Nereden gelir |
|---|---|---|
| `SIGTERM` | nazikçe kapan | `kill`, `systemctl stop`, `docker stop` |
| `SIGINT` | Ctrl-C | terminal |
| `SIGHUP` | yapılandırmayı yeniden oku | `systemctl reload` (gelenek) |
| `SIGUSR1` | durumunu raporla | uygulamaya özel |

`SIGKILL` (kill -9) **trap edilemez**. Çekirdek process'i sormadan öldürür; bu
yüzden nazik kapanmaya güvenen hiçbir şey (tampon boşaltma, PID dosyası silme)
`-9` sonrası garanti değildir.

### Sinyal işleyici içinde ne yapılabilir? Neredeyse hiçbir şey.

İşleyici, programın herhangi bir noktasında, bir I/O işleminin **tam ortasında**
çalışabilir. İçinde `puts` yazmak, kilit almak ya da bellek ayırmak kilitlenmeye
(deadlock) yol açabilir.

Doğru desen: **sadece bir bayrak indir**, işi ana döngüye bırak. Bizim
işleyicilerin hepsi tek satır.

`SIGHUP`/`SIGUSR1` Windows'ta yok — `Signal.list.key?` ile kontrol edilmeden
trap edilirse `ArgumentError` fırlatır.

## 5. Neden iki thread?

`Tailer#each_line` bloke eden bir sonsuz döngü. İçinde otururken sinyal
bayraklarını kontrol edecek yer yok: dosyaya yeni satır yazılmazsa döngü hiçbir
şey yapmaz.

Çözüm: okuma işini ayrı thread'e al, **ana thread'i sinyaller için serbest
bırak**. Bu tesadüfi değil — **Ruby'de sinyal işleyicileri ana thread'de
çalışır**, yani ana thread'i boş tutmak zaten doğru tasarımdır. Gerçek
servislerin çoğu bu şekilde kurulur.

Okuma thread'i açıkça sarıldı: thread içindeki bir hata sessizce yutulur ve
thread ölür — program çalışmaya devam eder ama artık **hiçbir şey okumaz**. Bir
izleme aracında bundan daha sinsi arıza zor bulunur.

## 6. Bildirim kanalları

### Sözleşme

> Sana bir `Alert` veririm; kendi kanalına iletirsin. Gönderemezsen **tüm
> sistemi durdurmazsın.**

Telegram 30 saniye cevap vermezse ve bu hata yukarı yayılırsa daemon çöker.
Yani *"bildirim gönderememek"* yüzünden *"izlemeyi tamamen kaybetmek"* gibi
absürt bir sonuç olur. Doğru davranış: loga yaz, devam et.

**İzleme kritik; bildirim önemli ama kritik değil.** Bir sistemin hangi
parçasının vazgeçilebilir olduğunu bilmek, sağlam tasarımın temelidir.

### `rescue StandardError` — bilinçli olarak geniş

Ruby'nin istisna hiyerarşisi bu ayrımı tasarım olarak yapar:

```
Exception
  ├── ScriptError   → NotImplementedError, SyntaxError, LoadError
  ├── NoMemoryError, SignalException, Interrupt
  └── StandardError → IOError, ArgumentError, Errno::*, ...
```

`Interrupt` (Ctrl-C) `StandardError` altında **değil** — yakalamak istemiyoruz,
Ctrl-C'yi yutan bir program kapatılamaz hale gelir.

`NotImplementedError` de `StandardError` altında **değil**. Yani `deliver`
metodunu yazmayı unutan bir alt sınıf yazılırsa hata yutulmaz ve program çöker.
Bu **istediğimiz** davranış: "internet yok" geçici bir çalışma zamanı
durumudur, yutulur; "metodu yazmayı unutmuşum" ise **programcı hatasıdır** ve
gürültüyle patlaması gerekir. (Bunu test yazarken keşfettim — testi yanlış
kurmuştum, hiyerarşi beni düzeltti.)

### Üç kanal

| Kanal | Ne yapar | Kritik ayrıntı |
|---|---|---|
| `Console` | ekrana renkli yazar | `io.tty?` kontrolü — çıktı dosyaya gidiyorsa ANSI kodları yazılmaz, yoksa loglar `\e[1;31mHIGH\e[0m` gibi okunamaz hale gelir |
| `File` | `alerts.jsonl` | `sync = true`: bu bir **kanıt** dosyası, tamponda bekleyen alarm çökmede kaybolur |
| `Webhook` | Telegram / Slack / genel | aşağıda |

### Neden JSONL?

Her satırda tam bir JSON nesnesi. Düz bir JSON dizisi (`[{...},{...}]`) olsaydı
sona kayıt eklemek için **her alarmda tüm dosyayı yeniden yazmak** gerekirdi.
JSONL ile ekleme "sona bir satır yaz". Üstelik `tail -f` ile insan izleyebilir,
satır satır makine ayrıştırabilir (Adım 7'de web arayüzü bu dosyayı **bizim
Tailer'ımızla** izleyecek) ve dosyanın ortası bozulsa geri kalan satırlar hâlâ
okunabilir.

## 7. Webhook — asıl mesele HTTP değil

HTTP isteği 5 satırda yazılabilirdi. Asıl mesele şu dördü:

### 7.1 Sır yönetimi

`config/logsentry.yml`'da adresin **kendisi** değil, onu tutan **ortam
değişkeninin adı** yazılı:

```yaml
url_env: LOGSENTRY_WEBHOOK_URL
```

Neden kritik? Yapılandırma dosyaları git'e girer. **Git geçmişi silinmez** — bir
kez commit ettiğin token, sonradan dosyadan çıkarsan bile geçmişte durmaya devam
eder. Sızan sırların en yaygın sebebi budur.

Ayrıca token loglara da yazılmaz:

```ruby
def safe_url
  "#{@uri.scheme}://#{@uri.host}/***"
end
```

**Burada test beni yakaladı.** İlk denemede "sadece uzun görünen son parçayı
maskele" gibi zeki bir kalıp yazmıştım. Ama Telegram adresinde token son parça
değil, **ortada**:

```
/bot123456:GİZLİ_TOKEN/sendMessage
```

Kalıp `sendMessage`'ı maskeleyip token'ı açığa çıkardı. **Ders:** sır
maskelemede "neyi gizleyeceğimi tahmin edeyim" yaklaşımı yanlıştır. Doğrusu
"neyi göstermek **güvenli**, onun dışındakini gizle" (allow-list).

### 7.2 Zaman aşımı

```ruby
http.open_timeout = @timeout
http.read_timeout = @timeout
```

Varsayılan değerler çok uzundur (~60 sn). Bir bildirim yüzünden 60 saniye
beklemek, o 60 saniyede gelen logların işlenmemesi demek. Bunlar olmadan kod
üretime çıkmaz.

### 7.3 Durum kodu kontrolü

```ruby
raise "HTTP #{response.code}" unless response.is_a?(Net::HTTPSuccess)
```

`Net::HTTP` isteği "başarılı" saysa bile sunucu "seni engelledim" demiş olabilir.
Durum kodunu kontrol etmeden gönderdim varsaymak klasik bir hatadır.

### 7.4 Hız sınırı

Dakikada en fazla 20 bildirim. Soğutma (Adım 4) alarm sayısını zaten kısıyor,
ama bu ikinci emniyet kemeri: çok sayıda **farklı** IP'den alarm gelirse soğutma
devreye girmez (her IP kendi anahtarına sahip). Telegram'ın kendi hız sınırı da
vardır; aşarsan geçici engellenirsin — yani **aşırı gönderme, hiç gönderememeye
dönüşür**.

### Önem derecesine göre sessiz bildirim

```ruby
disable_notification: alert.severity_rank < 2
```

Gece 3'te telefonun her orta seviye uyarıda çalması, aracın kapatılmasıyla
sonuçlanır.

## 8. Bulunan gerçek kusur: sıcak yenileme durumu siliyordu

Canlı daemon testinde şunu gördük: `SIGHUP` yenilemesinden **4 saniye sonra**,
120 saniyelik soğutmaya rağmen aynı alarm ikinci kez düştü.

**Sebep:** yenileme motoru baştan kuruyordu. Yeni kural nesnelerinin kayan
pencereleri boş, soğutma kayıtları yoktu. Sonuç: devam eden bir saldırıda ya
sayaçlar sıfırlanır (saldırgan görünmez olur) ya soğutma sıfırlanır (aynı alarm
tekrar düşer).

**Çözüm:** kurallara **yapılandırma imzası** eklendi. Yenilemede sadece ayarı
değişen kural yeniden kuruluyor; ayarı aynen duran kuralın **nesnesi — yani
hafızası — korunuyor**.

```ruby
existing = reuse&.rules&.find { |r| r.signature == fresh.signature }
existing || fresh
```

Düzeltme sonrası aynı test:

```
[12:32:41] yenilendi: brute_force(10/60s) flood(100/1s) path_scan(3/300s)
[12:32:41]   3 kural hafizasiyla korundu, 0 kural yeniden kuruldu
[12:32:43] toplam 1 uyari uretildi, 99 satir okundu
```

İki alarm yerine bir — soğutma yenileme boyunca korundu. Bu davranışa üç test
yazıldı.

Yenileme sırasında **Tailer'a dokunulmuyor** — dosya konumu korunuyor, tek satır
kaybedilmiyor. Yapılandırma bozuksa eskiye dönülüyor: yanlış bir YAML yüzünden
çalışan bir izleme sistemini kaybetmek kabul edilemez.

## 9. Diğer bilinçli kararlar

**Webhook sırrı eksikse servis durmuyor.** *"Bildirim gönderemiyorum"* ile
*"izleme yapamıyorum"* aynı şiddette sorunlar değil. Sırrı olmayan bir sunucuda
bile izleme çalışmalı ve uyarılar dosyaya yazılmalı. Ama sessiz de kalmıyoruz —
eksiği açıkça söylüyoruz.

**Daemon moduna geçmeden önce her şey kuruluyor.** Arka plana çektikten sonra
terminal yok: hata mesajını kimse görmez. Yapılandırma hatası, eksik dosya, izin
problemi — hepsi henüz terminal varken ortaya çıkmalı. *"Önce doğrula, sonra
kopar"* — daemon yazarken en önemli sıra bu.

**PID dosyası daemonlaşmadan SONRA yazılıyor**, çünkü `Process.daemon` fork
yapar ve **PID değişir**. Önce yazsaydık dosyada ölü bir PID kalırdı.

**`--stop` SIGTERM gönderiyor, SIGKILL değil** — ve gerçekten kapandığını
doğruluyor. "Sinyal gönderdim" ile "kapandı" aynı şey değildir.

## 10. CLI

```bash
bin/logsentry                      # ön planda (Ctrl-C ile dur)
bin/logsentry --daemon             # arka plana çekil
bin/logsentry --stop               # SIGTERM + kapandığını doğrula
bin/logsentry --reload             # SIGHUP
bin/logsentry --status             # çalışıyor mu, PID kaç
bin/logsentry --check              # yapılandırmayı doğrula ve çık
bin/logsentry --from-begin --once  # geçmişi bir kez tara ve çık
```

`--check` küçük ama üretimde altın değerinde: yapılandırmayı **değiştirdikten
sonra**, servisi yeniden başlatmadan **önce** doğrularsın. Aksi halde bozuk bir
YAML ile servisi durdurup bir daha başlatamazsın.

## 11. Canlı daemon testi (WSL) — uçtan uca doğrulama

| Adım | Sonuç |
|---|---|
| Daemon başlatıldı | terminal **anında** geri döndü |
| `--status` | `ÇALIŞIYOR`, PID 395 |
| `ps` kontrolü | TTY `?`, kendi SID'i → terminalden koptu ✅ |
| Saldırı trafiği | brute force alarmı **kanıtla birlikte** log dosyasına düştü |
| `--reload` | 3 kural hafızasıyla korundu, 0 yeniden kuruldu |
| `kill -USR1` | canlı istatistik JSON olarak loga basıldı |
| `--stop` | nazikçe kapandı, tamponlar boşaltıldı |
| PID dosyası | **silinmiş** ✅ |
| `alerts.jsonl` | 1 geçerli JSONL kaydı ✅ |

`SIGUSR1` çıktısı (kısaltılmış):

```json
{"version":"0.5.0","pid":370,"uptime":6,
 "tailer":{"lines_read":78,"position":10449,"rotations":0},
 "parser":{"parsed":78,"failed":0,"success_rate":100.0},
 "engine":{"processed":15,"alerts":1,"rules":[...]},
 "notifiers":[{"notifier":"console","sent":1,"failed":0}, ...]}
```

## 12. `Process.daemon` mu, systemd mi? — modern cevap

`deploy/logsentry.service` eklendi. Önemli kavram: **ikisi alternatiftir**,
birbirini tamamlamaz.

`Process.daemon`'u öğrenmek **doğru** (fork, setsid, TTY, PID, sinyaller —
Unix'in temel kavramları ve her servis yöneticisi bunları kullanır), ama
2020'lerde üretimde **kendi kendine daemonlaşmıyorsun**. Program ön planda
çalışır, systemd/Docker onu arka planda tutar. Neden:

- **Çökerse kim yeniden başlatacak?** Kendi kendine daemonlaşan process çökerse
  kimse haberdar olmaz. `Restart=always` bunu bedavaya çözer.
- `Type=forking` ile servis yöneticisinin kafası karışır — gereksiz karmaşıklık.
- Log yönetimi: kendi log dosyanı döndürmek/sıkıştırmak zorunda kalırsın.
  systemd stdout'u journald'a yazar; `journalctl -u logsentry -f`.
- Kaynak ve güvenlik sınırları ancak servis yöneticisi seviyesinde uygulanır.

Birim dosyasındaki önemli satırlar:

```ini
Type=simple                  # --daemon KULLANMIYORUZ
User=logsentry               # ASLA root değil (en az yetki ilkesi)
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
ProtectSystem=strict         # çekirdek seviyesinde kısıtlar
MemoryMax=256M               # Adım 4'teki sınırların arkasındaki emniyet kemeri
EnvironmentFile=-/etc/logsentry/secrets.env   # token .service'e YAZILMAZ
```

`MemoryMax` özellikle anlamlı: Adım 4'te `MAX_KEYS`/`MAX_EVENTS_PER_KEY`
sınırları koyduk. Bu satır onların **arkasındaki** emniyet kemeri — kodda gözden
kaçan bir sızıntı olsa bile makineyi götürmez.

## 13. Test yaklaşımı

29 testte **gerçek HTTP isteği atılmıyor** ve **gerçek daemon başlatılmıyor**.
Sebep: bir testin geçmesi internete, harici servise ya da işletim sistemi
durumuna bağlı olmamalı. Öyle testler **kırılgan** (flaky) olur: bazen geçer
bazen geçmez, ve bir süre sonra kimse onlara güvenmez.

Onun yerine **sınırlar** test edildi: gövde doğru kuruldu mu, hata yutuldu mu,
sır sızdı mı, bayat PID temizlendi mi. Gerçek uçtan uca doğrulama canlı daemon
testiyle ayrıca yapıldı (bölüm 11).

## 14. Toplam test durumu

| Paket | Test | Doğrulama | Windows | WSL |
|---|---|---|---|---|
| `parser_test.rb` | 21 | 64 | ✅ | ✅ |
| `tailer_test.rb` | 15 | 24 / 32 | ✅ (3 atlama) | ✅ |
| `engine_test.rb` | 36 | 211 | ✅ | ✅ |
| `daemon_test.rb` | 29 | 86 | ✅ | ✅ |
| **Toplam** | **101** | **385 / 393** | **0 hata** | **0 hata** |

## 15. Gerçek dünya karşılığı

systemd servisi yazmak, graceful shutdown, sinyal tabanlı yönetim, sır yönetimi,
Alertmanager/on-call zinciri, bildirim yorgunluğu yönetimi. "Kodum çalışıyor" ile
"servisim ayakta" arasındaki farkın tamamı.

## 16. Çalıştırma

```bash
ruby test/daemon_test.rb
```

Ön planda (Windows'ta da çalışır):

```bash
ruby bin/logsentry --from-begin --once
```

Arka planda (WSL şart — `Process.daemon` Windows'ta yok):

```bash
wsl -d Ubuntu-22.04 ruby bin/logsentry --daemon
```

```bash
wsl -d Ubuntu-22.04 ruby bin/logsentry --status
```

```bash
wsl -d Ubuntu-22.04 ruby bin/logsentry --stop
```
