# frozen_string_literal: true

module LogSentry
  module Masker
    EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/
    CARD_REGEX  = /\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b/
    TCKN_REGEX  = /\b[1-9]\d{10}\b/
    PARAM_REGEX = /(password|token|secret|passwd|key|pin|cvv)=([^&\s"]+)/i

    def self.mask(text)
      return text if text.nil? || text.empty?

      masked = text.dup

      # 1) Hassas Parametreler (örn. password=gizli -> password=[MASKED])
      masked.gsub!(PARAM_REGEX) { "#{$1}=[MASKED]" }

      # 2) Kredi Kartları
      masked.gsub!(CARD_REGEX, '[CARD_MASKED]')

      # 3) E-postalar
      masked.gsub!(EMAIL_REGEX, '[EMAIL_MASKED]')

      # 4) TCKN (Türkiye Cumhuriyeti Kimlik Numarası)
      masked.gsub!(TCKN_REGEX) do |match|
        is_tckn?(match) ? '[TCKN_MASKED]' : match
      end

      masked
    end

    def self.is_tckn?(str)
      return false unless str.size == 11

      digits = str.chars.map(&:to_i)
      return false if digits[0] == 0

      sum_odd = digits[0] + digits[2] + digits[4] + digits[6] + digits[8]
      sum_even = digits[1] + digits[3] + digits[5] + digits[7]

      digit10 = ((sum_odd * 7) - sum_even) % 10
      return false unless digit10 == digits[9]

      digit11 = digits[0..9].sum % 10
      digit11 == digits[10]
    end
  end
end
