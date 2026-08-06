# frozen_string_literal: true

require_relative 'lib/log_sentry'

Gem::Specification.new do |spec|
  spec.name          = 'logsentry'
  spec.version       = LogSentry::VERSION
  spec.authors       = ['LogSentry Contributors']
  spec.summary       = 'Lightweight Ruby SIEM and Log Monitoring Tool'
  spec.description   = 'Real-time HTTP log monitoring, threat detection, sqlite storage, and web dashboard.'
  spec.homepage      = 'https://github.com/AlperEnesErsu/LogSentry'
  spec.license       = 'MIT'

  # Sablon dosyalari (.erb) ve statik varliklar (.css/.js) olmadan web
  # arayuzu calismaz -- sadece *.rb almak yetmiyor.
  spec.files = Dir[
    'lib/**/*.rb',
    'lib/**/*.erb',
    'lib/**/*.css',
    'lib/**/*.js',
    'bin/*',
    'config/*.yml',
    # systemd birimleri: saklama suresi temizligi ve tehdit istihbarati
    # beslemesi ancak periyodik calistirilirsa ise yarar. Bunlari pakete
    # koymazsak kullanici "nasil zamanlayacagim?" sorusuyla yalniz kalir.
    'deploy/*',
    'ARCHITECTURE.md',
    'LICENSE',
    'README.md'
  ]

  # ONEMLI: bin/ altina yeni bir komut eklerken BURAYA DA ekle.
  # Aksi halde dosya pakete girer ama `gem install` sonrasi PATH'e
  # baglanmaz -- yani komut kullanicida "yok" gorunur. logsentry-threat-intel
  # tam olarak bu sekilde gozden kacmisti; test/regression3_test.rb artik
  # bin/ ile bu listenin ayrisamamasini garanti ediyor.
  spec.executables = %w[
    logsentry
    logsentry-web
    logsentry-archive
    logsentry-doctor
    logsentry-threat-intel
  ]
  spec.require_paths = ['lib']

  # Adim 1-5 arasi cekirdek sifir bagimlilikla calisir; asagidakiler
  # depolama (adim 6) ve web arayuzu (adim 7) icin gerekli.
  spec.required_ruby_version = '>= 3.0'

  # csv: Ruby 3.4'te varsayilan gem OLMAKTAN CIKTI (bundled gem'e donustu).
  # Bundler altinda, burada bildirilmemis bir bundled gem yuklenemez ve
  # /explorer?format=csv istegi 500 doner. Bu eksik, CI'da uzun sure gorunmez
  # kaldi: is akisi `gem install ...` ile ikinci bir bagimlilik dunyasi
  # kuruyor ve testleri `bundle exec` OLMADAN kosuyordu -- yani gemspec'in
  # eksik olmasinin bir onemi yoktu. `bundle exec`e gecince aninda ortaya cikti.
  spec.add_dependency 'csv',     '>= 3.0'
  spec.add_dependency 'puma',    '>= 6.0'
  # rackup: Rack 3 ile birlikte sunucuyu baslatan kod ayri bir gem'e tasindi.
  # Sinatra'nin `run!` cagrisi bunu arar; yoksa
  #   "Sinatra could not start, the required gems weren't found"
  # der ve sunucu HIC ACILMAZ.
  #
  # Bu eksigi yerelde fark etmemistik cunku rackup'i elle kurmustuk; CI de
  # yakalayamazdi cunku web testleri Rack::MockRequest kullaniyor ve gercek
  # sunucu baslatmiyor. Ancak temiz bir konteynerde ortaya cikti.
  spec.add_dependency 'rackup',  '>= 2.0'
  spec.add_dependency 'sinatra', '~> 4.0'
  spec.add_dependency 'sqlite3', '>= 2.0'

  spec.metadata = {
    'homepage_uri'    => spec.homepage,
    'source_code_uri' => spec.homepage,
    'bug_tracker_uri' => "#{spec.homepage}/issues",
    'rubygems_mfa_required' => 'true'
  }
end
