# frozen_string_literal: true

require 'net/http'
require 'json'
require 'uri'
require 'time'
require_relative '../entry'

module LogSentry
  module Fetchers
    class GitHub
      API_BASE = 'https://api.github.com'

      def self.fetch_events(repo: nil, token: nil)
        token ||= ENV['LOGSENTRY_GITHUB_TOKEN']
        return [] if repo.nil? || repo.empty?

        uri = URI("#{API_BASE}/repos/#{repo}/events")
        req = Net::HTTP::Get.new(uri)
        req['Accept'] = 'application/vnd.github+json'
        req['User-Agent'] = 'LogSentry-Fetcher'
        req['Authorization'] = "Bearer #{token}" if token && !token.empty?

        res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true, open_timeout: 5, read_timeout: 5) do |http|
          http.request(req)
        end

        return [] unless res.is_a?(Net::HTTPSuccess)

        payload = JSON.parse(res.body)
        return [] unless payload.is_a?(Array)

        payload.map do |event|
          actor = event.dig('actor', 'login') || 'github-user'
          event_type = event['type'] || 'Event'
          created_at = Time.iso8601(event['created_at']) rescue Time.now

          Entry.new(
            ip: '140.82.112.1',
            time: created_at,
            http_method: 'POST',
            path: "/github/#{event_type.downcase}",
            protocol: 'HTTP/1.1',
            status: 200,
            bytes: 1024,
            referer: "https://github.com/#{repo}",
            user_agent: "GitHub-Event-Fetcher (#{actor})"
          )
        end
      rescue StandardError => e
        warn "[GitHubFetcher] hata: #{e.message}"
        []
      end
    end
  end
end
