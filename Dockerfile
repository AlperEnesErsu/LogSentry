# ============================================================================
#  LogSentry -- konteyner imaji
# ============================================================================

FROM ruby:3.4-alpine

# --- Sistem bagimliliklari --------------------------------------------------
#  build-base  : sqlite3 gem'inin C uzantisini derlemek icin
#  sqlite-dev  : sqlite basliklari
#  tzdata      : saat dilimi verisi -- BU OLMADAN konteyner UTC'de calisir ve
#                loglardaki +03:00 damgalari yanlis yorumlanir. Bir log izleme
#                aracinda saat dilimi hatasi, olaylari yanlis siraya dizmek
#                demektir (Adim 2'de %z ayristirmasinda ayni konu).
#
#  NOT: `--no-mkdir` diye bir apk secenegi yoktur; dogrusu `--no-cache`
#  (indirilen paket listesini imajda birakmaz, imaj kucuk kalir).
RUN apk add --no-cache build-base sqlite-dev tzdata

ENV TZ=Europe/Istanbul \
    BUNDLE_WITHOUT=development

WORKDIR /app

# --- Bagimliliklar ----------------------------------------------------------
#  Once sadece Gemfile'i kopyalayip katman onbellegi kazanmak cazip; ama
#  bizim Gemfile'imiz `gemspec` satiri iceriyor ve gemspec, surumu okumak
#  icin lib/log_sentry.rb'yi yukluyor. Yani bundle install'in calisabilmesi
#  icin KAYNAK KODUN ZATEN ORADA olmasi gerekiyor.
#
#  Onceki surumde bu yuzden `bundle install || true` yazilmisti -- ama bu,
#  kurulum hatasini GIZLER: imaj sorunsuz build olur, sonra calisma aninda
#  "cannot load such file -- sinatra" ile patlar. Hatanin build sirasinda
#  gorunmesi her zaman daha iyidir.
COPY . .

RUN bundle install

# --- Kok olmayan kullanici --------------------------------------------------
#  Bu process yalnizca log dosyalarini OKUYOR; root yetkisine ihtiyaci yok.
#  Kodda bir zafiyet bulunursa saldirganin eline gececek yetki bu kadar olur.
#  (deploy/logsentry.service icindeki User= ayarinin konteyner karsiligi.)
RUN adduser -D -H -u 10001 logsentry \
 && mkdir -p logs db archive \
 && chown -R logsentry:logsentry /app

USER logsentry

EXPOSE 4567

# --- Saglik kontrolu NEDEN BURADA DEGIL? ------------------------------------
#  Ilk denemede buraya bir HEALTHCHECK yazmistim: /health ucuna istek atip
#  web servisinin gercekten cevap verdigini dogruluyordu.
#
#  Sorun: HEALTHCHECK IMAJA GOMULUR ve bu imajdan turetilen HER konteyner
#  onu devralir. Ama uc servisimizden yalnizca biri HTTP konusuyor --
#  izleyici ve trafik ureteci hicbir port dinlemiyor. Sonuc: iki konteyner
#  sonsuza kadar "health: starting", sonra "unhealthy" gorunuyordu.
#
#  Ders: saglik kontrolu, SERVISIN ne yaptigina bagli bir seydir; imaja
#  degil, servis tanimina aittir. Dogru yeri docker-compose.yml.
#
# Varsayilan komut: izleyici servis. compose her servis icin bunu eziyor.
CMD ["bin/logsentry"]
