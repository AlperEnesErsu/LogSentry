# LogSentry — Adım Raporları

Her adımın sonunda ne inşa edildiği, hangi kararların neden alındığı, hangi
hataların bulunup düzeltildiği ve ölçülen sonuçlar.

| # | Rapor | Konu | Durum |
|---|---|---|---|
| 1 | [ADIM-1-dosya-okuma.md](ADIM-1-dosya-okuma.md) | Sahte log ortamı, `File.foreach` ile sabit bellekli okuma | ✅ |
| 2 | [ADIM-2-regex-ayristirma.md](ADIM-2-regex-ayristirma.md) | Regex ile ayrıştırma, `Entry` veri modeli | ✅ |
| 3 | [ADIM-3-canli-izleme.md](ADIM-3-canli-izleme.md) | `tail -f` mantığı, rotasyon, checkpoint | ✅ |
| 4 | [ADIM-4-kural-motoru.md](ADIM-4-kural-motoru.md) | Kayan pencere, üç kural, soğutma, kanıt zinciri | ✅ |
| 5 | [ADIM-5-daemon-bildirim.md](ADIM-5-daemon-bildirim.md) | `Process.daemon`, sinyaller, webhook, systemd | ✅ |
| 6 | [ADIM-6-depolama-arsivleme.md](ADIM-6-depolama-arsivleme.md) | SQLite depolama + arşivleme (hash zinciri, yasal saklama) | ✅ |
| 7 | [ADIM-7-web-arayuzu.md](ADIM-7-web-arayuzu.md) | Sinatra web arayüzü + SSE canlı akış | ✅ |

Mimarinin tamamı: [../ARCHITECTURE.md](../ARCHITECTURE.md)

---

## Genel durum

**Tamamlanan boru hattı:**

```
access.log → TAILER → PARSER → ENGINE → NOTIFIERS → ekran / JSONL / Telegram
            (adım 3) (adım 2)  (adım 4)   (adım 5)        ↓
                                                   STORE + ARCHIVER (adım 6)
                                                   SQLite + gzip/hash zinciri
                                                          ↓
                                                    WEB (adım 7)
                                                 Sinatra + SSE, :4567
```

**Test durumu** — 181 test, 0 hata (Windows + WSL Ubuntu-22.04):

| Paket | Test | Doğrulama |
|---|---|---|
| `parser_test.rb` | 21 | 64 |
| `tailer_test.rb` | 15 | 24 (Win, 3 atlama) / 32 (WSL) |
| `engine_test.rb` | 36 | 211 |
| `daemon_test.rb` | 29 | 86 |
| `store_test.rb` | 47 | 136 |
| `web_test.rb` | 33 | 106 |

Adım 1–5 arası **sıfır dış bağımlılık** — yalnızca Ruby'nin kendi
kütüphaneleri. Adım 6 `sqlite3` gem'ini ekledi (ama yoksa servis çalışmaya
devam ediyor, depolama sessizce devre dışı kalıyor).

**Ölçümler:**

| Ölçüm | Sonuç |
|---|---|
| Ayrıştırma hızı | ~70.000 satır/saniye |
| Uçtan uca (parser + motor) | ~84.000 kayıt/saniye |
| `File.foreach` bellek (39 MB dosya) | 187 bayt |
| Soğutmanın etkisi | 1097 → 24 uyarı (54,8 kat azalma) |
| Yanlış pozitif (test verisi) | 0 |
| SQLite toplu yazma kazancı | 17.000 → 201.000 kayıt/sn (11,6 kat) |
| gzip arşiv tasarrufu | %96,1 |
| Dashboard sorguları | 0,02 – 0,73 ms |

---

## Adım adım bulunan gerçek hatalar

Raporların en değerli kısmı bu tablo — hepsi kod yazılırken değil, **test
edilirken** ortaya çıktı.

| Adım | Bulgu | Nasıl bulundu |
|---|---|---|
| 2 | `%r{}` yerine `/.../x` kullanınca yorumdaki `/` regex'i bitiriyordu | program çalışmadan patladı |
| 2 | Geçersiz UTF-8 baytları `ArgumentError` fırlatıp **tüm daemon'u durduruyordu** — saldırgan tek istekle izlemeyi kapatabilirdi | test |
| 3 | Kesilme kontrolü saniyede bir çalışıyordu; aradaki satırlar kaybediliyordu | test |
| 3 | Rotasyon anında eski dosyadaki son satırlar kaybediliyordu | test |
| 4 | İsimsiz sınıfta (`Class.new(Base)`) `rule_name` çöküyordu | test |
| 5 | `safe_url` maskeleme kalıbı Telegram token'ını **açığa çıkarıyordu** | test |
| 5 | `SIGHUP` yenilemesi kayan pencereleri ve soğutmayı **siliyordu** — aynı alarm 4 saniye içinde iki kez düşüyordu | canlı daemon testi |
| 6 | `':memory:'` yolu `File.expand_path`'ten geçince bozuluyor, SQLite açamıyordu | test (27 hata birden) |
| 6 | Dosya boyutu ölçümü WAL dosyasını saymıyordu — 3000 kayıttan sonra **0.00 MB** görünüyordu | demo çıktısı |
| 6 | `--once` modu **sonsuza kadar bekliyordu**: Tailer dosya sonunda ölmüyor, `--once` onun ölmesini bekliyordu | canlı deneme (5 dk timeout) |
| 7 | SSE bağlantıları Puma thread'lerini tutuyor, birkaç gezinti sonrası **sunucu yanıt veremez hale geliyordu** | canlı tarayıcı testi + video kaydı |
| 7 | `/stream` testi `MockRequest` ile **sonsuza kadar bekledi** — bitmeyen bir uç nokta, biten bir istek gibi test edilemez | test paketi 10 dk takıldı |

---

## Tekrar eden dört ilke

Projenin her adımında farklı kılıkta karşımıza çıkan dersler:

1. **Bir daemon içinde sınırsız büyüyen hiçbir yapıya yer yoktur.**
   `File.read` (adım 1) → `failed_samples` (adım 2) → `@partial` tamponu
   (adım 3) → `MAX_KEYS` / `MAX_EVENTS_PER_KEY` / `MAX_EVIDENCE` (adım 4) →
   webhook hız sınırı (adım 5).

2. **Sessiz yanlış, çökmekten tehlikelidir.** Araç çalışıyor görünür ama hiçbir
   şey görmez. Bu yüzden: ayrıştırma başarı oranı, `dropped_keys` sayacı,
   `warn` mesajları, `SIGUSR1` durum raporu.

3. **Yapılandırma hatası başlangıçta patlamalı.** Gece 3'te alarm üretmesi
   gereken bir servis, eksik ayarla sessizce başlamamalı.

4. **Kanıt göstermeyen alarm gürültüdür.** Her `Alert`, kendisini doğuran ham
   log satırlarını taşır. Adım 7'deki `/alerts/:id` sayfası bu kanıtı görünür
   kılar.

5. **Verinin çoğunu saldırgan yazıyor.** Log satırı saldırgan-kontrollü bir
   girdidir. Bu yüzden: Parser çökmüyor (adım 2), geçersiz UTF-8 temizleniyor
   (adım 2), panel her alanı escape ediyor (adım 7), SQL parametreli (adım 6).

---

## Canlı doğrulama

Bazı kusurlar yalnızca **çalıştırarak** ortaya çıktı — birim testleri
yakalayamazdı, çünkü sorun tek bir isteğin doğruluğunda değil, isteklerin
birikimli etkisindeydi:

| Adım | Yalnızca canlı testte bulunan |
|---|---|
| 5 | `SIGHUP` yenilemesi kayan pencereleri siliyordu |
| 6 | `--once` sonsuza kadar bekliyordu; boyut ölçümü WAL'i saymıyordu |
| 7 | SSE bağlantıları thread havuzunu tüketiyordu |

Adım 7'nin uçtan uca tarayıcı testi video olarak kaydedildi:
`docs/logsentry-web-demo.gif`
