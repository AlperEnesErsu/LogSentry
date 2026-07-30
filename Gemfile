# frozen_string_literal: true

# ============================================================================
#  Gemfile
# ----------------------------------------------------------------------------
#  Bu dosya olmadan CI'daki `bundler-cache: true` ayari calismaz --
#  ruby/setup-ruby bir Gemfile arar ve bulamazsa hata verir.
#
#  `gemspec` satiri, logsentry.gemspec icindeki bagimliliklari buraya
#  aktarir. Boylece bagimliliklar TEK BIR YERDE tanimli kalir; gemspec ile
#  Gemfile'in birbirinden sapmasi mumkun olmaz.
# ============================================================================

source 'https://rubygems.org'

gemspec

# --- Yalnizca gelistirme/test icin ------------------------------------------
group :development, :test do
  gem 'minitest', '~> 5.0'   # Ruby ile birlikte gelir; surumu sabitliyoruz
  gem 'rake',     '~> 13.0'
end
