# frozen_string_literal: true

require 'minitest/autorun'
lib_path = File.expand_path('../lib', __dir__)
lib_path = File.expand_path('./lib') unless File.exist?(File.join(lib_path, 'log_sentry.rb'))
$LOAD_PATH.unshift(lib_path) unless $LOAD_PATH.include?(lib_path)

require 'log_sentry/masker'
require 'log_sentry/parser'
require 'log_sentry/entry'

class MaskerTest < Minitest::Test
  def test_mask_emails
    assert_equal 'Bize ulaşın: [EMAIL_MASKED]', LogSentry::Masker.mask('Bize ulaşın: alper@domain.com')
  end

  def test_mask_credit_cards
    assert_equal 'Ödeme: [CARD_MASKED]', LogSentry::Masker.mask('Ödeme: 4321-1234-5678-9012')
  end

  def test_mask_query_params
    assert_equal 'POST /login?user=admin&password=[MASKED]&token=[MASKED] HTTP/1.1',
                 LogSentry::Masker.mask('POST /login?user=admin&password=supersecret&token=abc123xyz HTTP/1.1')
  end

  def test_mask_tckn_valid_and_invalid
    # Valid TCKN (computed check digits)
    # TCKN verification:
    # 10th digit: ( (1+3+5+7+9)*7 - (2+4+6+8) ) % 10 -> ( (1+3+5+7+9)*7 - (2+4+6+8) ) % 10
    # Let's use a known valid TCKN: 10000000146
    # Digits: 1 0 0 0 0 0 0 0 1 4 6
    # Odd sum: 1 + 0 + 0 + 0 + 1 = 2
    # Even sum: 0 + 0 + 0 + 0 = 0
    # (2 * 7 - 0) % 10 = 4 (matches 10th digit)
    # Sum of first 10 digits: 1 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 1 + 4 = 6 % 10 = 6 (matches 11th digit)
    # So 10000000146 is a valid TCKN!
    valid_tckn = '10000000146'
    assert_equal '[TCKN_MASKED]', LogSentry::Masker.mask(valid_tckn)

    # Invalid TCKN (simply random 11 digits)
    invalid_tckn = '12345678901'
    assert_equal invalid_tckn, LogSentry::Masker.mask(invalid_tckn)
  end

  def test_parser_masks_output
    parser = LogSentry::Parser.new(format: :combined)
    line = '1.2.3.4 - - [29/Jul/2026:14:39:25 +0300] "POST /login?password=secret123&email=test@example.com HTTP/1.1" 200 45 "-" "Mozilla/5.0"'
    entry = parser.parse(line)

    refute_nil entry
    assert_equal 'POST /login?password=[MASKED]&email=[EMAIL_MASKED] HTTP/1.1', entry.raw.match(/"([^"]+)"/)[1]
    assert_equal '/login?password=[MASKED]&email=[EMAIL_MASKED]', entry.path
  end
end
