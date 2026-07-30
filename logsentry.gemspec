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
    'ARCHITECTURE.md',
    'LICENSE',
    'README.md'
  ]
  spec.executables   = ['logsentry', 'logsentry-web', 'logsentry-archive']
  spec.require_paths = ['lib']

  # Adim 1-5 arasi cekirdek sifir bagimlilikla calisir; asagidakiler
  # depolama (adim 6) ve web arayuzu (adim 7) icin gerekli.
  spec.required_ruby_version = '>= 3.0'

  spec.add_dependency 'puma',    '>= 6.0'
  spec.add_dependency 'sinatra', '~> 4.0'
  spec.add_dependency 'sqlite3', '>= 2.0'

  spec.metadata = {
    'homepage_uri'    => spec.homepage,
    'source_code_uri' => spec.homepage,
    'bug_tracker_uri' => "#{spec.homepage}/issues",
    'rubygems_mfa_required' => 'true'
  }
end
