// ==========================================================================
//  LogSentry -- canli akis (SSE) istemcisi
// --------------------------------------------------------------------------
//  Tum dosya bu kadar. WebSocket kutuphanesi, yeniden baglanma mantigi,
//  kalp atisi yonetimi -- hicbiri yok, cunku SSE bunlari tarayicinin
//  kendisine yaptiriyor.
//
//  EventSource, baglanti koptugunda OTOMATIK yeniden baglanir. WebSocket'te
//  bu mantigi elle yazmak zorundasin (ve genelde yanlis yazilir).
//  Veri tek yonlu aktigi icin (sunucu -> tarayici) SSE burada dogru secim.
// ==========================================================================

(function () {
  'use strict';

  var feed   = document.getElementById('live-feed');
  var status = document.getElementById('sse-status');
  if (!feed || !window.EventSource) { return; }

  var MAX_ITEMS = 40;   // Listeyi sinirla: bir daemon icinde sinirsiz buyuyen
                        // hicbir yapiya yer yoktur -- ayni ilke tarayicida da
                        // gecerli. Sinirsiz DOM, sekmeyi yavas yavas oldurur.

  var source = new EventSource('/stream');

  source.addEventListener('hello', function () {
    setStatus('● bağlı', 'live-on');
  });

  source.onopen = function () {
    setStatus('● bağlı', 'live-on');
  };

  source.onerror = function () {
    // EventSource kendi kendine yeniden baglanmayi dener; sadece durumu
    // gosteriyoruz.
    setStatus('● kopuk', 'live-off');
  };

  source.onmessage = function (event) {
    var alert;
    try {
      alert = JSON.parse(event.data);
    } catch (e) {
      return;
    }
    prepend(alert);
  };

  function setStatus(text, cls) {
    if (!status) { return; }
    status.textContent = text;
    status.className = cls;
  }

  function prepend(alert) {
    // Ilk yuklemedeki "bekleniyor..." satirini kaldir
    var placeholder = feed.querySelector('.muted');
    if (placeholder) { placeholder.remove(); }

    var li = document.createElement('li');
    li.className = 'fresh';

    var time = document.createElement('time');
    time.textContent = formatTime(alert.time);

    var sev = document.createElement('span');
    sev.className = 'sev sev-' + sanitizeClass(alert.severity);
    // textContent kullaniyoruz, innerHTML DEGIL.
    //
    // BU SATIR ONEMLI: alert.ip, alert.message ve alert.rule degerleri
    // dolayli olarak SALDIRGAN tarafindan etkilenebilir (log satirindaki
    // yol, message icine giriyor). innerHTML kullansak saldirgan bu panelde
    // kod calistirabilirdi -- sunucu tarafinda h() ile kacisladigimiz
    // seyin tarayici tarafindaki karsiligi budur.
    //
    // textContent, verilen metni HER ZAMAN metin olarak yazar; icindeki
    // <script> etiketi kod olarak yorumlanmaz.
    sev.textContent = alert.severity || '?';

    var rule = document.createElement('code');
    rule.textContent = alert.rule || '?';

    var ip = document.createElement('code');
    ip.textContent = alert.ip || '?';

    var msg = document.createElement('span');
    msg.textContent = alert.message || '';

    li.appendChild(time);
    li.appendChild(sev);
    li.appendChild(rule);
    li.appendChild(ip);
    li.appendChild(msg);

    feed.insertBefore(li, feed.firstChild);

    while (feed.children.length > MAX_ITEMS) {
      feed.removeChild(feed.lastChild);
    }
  }

  // CSS sinif adina sadece bildigimiz degerleri gecir (allow-list).
  // Adim 5'te token maskelemede ogrendigimiz ilkenin aynisi: "neyi
  // engelleyeyim" degil, "neyi kabul etmek guvenli".
  function sanitizeClass(severity) {
    var allowed = ['critical', 'high', 'medium', 'low'];
    return allowed.indexOf(severity) >= 0 ? severity : 'low';
  }

  function formatTime(iso) {
    if (!iso) { return ''; }
    var d = new Date(iso);
    if (isNaN(d.getTime())) { return ''; }
    return d.toTimeString().slice(0, 8);
  }
}());
