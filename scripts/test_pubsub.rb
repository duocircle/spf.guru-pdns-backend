#!/usr/bin/env ruby
# frozen_string_literal: true

# Test script for Redis Pub/Sub integration with SPF Guru
# Usage:
#   ruby test_pubsub.rb list                    # Send full domain list
#   ruby test_pubsub.rb add example.com         # Add single domain
#   ruby test_pubsub.rb remove example.com      # Remove single domain
#   ruby test_pubsub.rb interactive             # Interactive mode

require 'redis'
require 'json'

# Configuration
REDIS_HOST = ENV.fetch('REDIS_HOST', 'localhost')
REDIS_PORT = ENV.fetch('REDIS_PORT', 6379).to_i

# Channel names (must match Python backend)
CHANNEL_DOMAINS_LIST = 'spf:domains:list'
CHANNEL_DOMAINS_ADD = 'spf:domains:add'
CHANNEL_DOMAINS_REMOVE = 'spf:domains:remove'

class PubSubTester
  def initialize
    @redis = Redis.new(host: REDIS_HOST, port: REDIS_PORT)
    puts "Connected to Redis at #{REDIS_HOST}:#{REDIS_PORT}"
  end

  # Send full domain list sync
  def send_domain_list(domains)
    payload = { domains: domains }.to_json
    @redis.publish(CHANNEL_DOMAINS_LIST, payload)
    puts "Published to #{CHANNEL_DOMAINS_LIST}: #{payload}"
  end

  # Send single domain add event
  def send_domain_add(domain)
    payload = { domain: domain.downcase.strip }.to_json
    @redis.publish(CHANNEL_DOMAINS_ADD, payload)
    puts "Published to #{CHANNEL_DOMAINS_ADD}: #{payload}"
  end

  # Send single domain remove event
  def send_domain_remove(domain)
    payload = { domain: domain.downcase.strip }.to_json
    @redis.publish(CHANNEL_DOMAINS_REMOVE, payload)
    puts "Published to #{CHANNEL_DOMAINS_REMOVE}: #{payload}"
  end

  # Check current whitelist state in Redis
  def show_current_state
    domains = @redis.smembers('spf:whitelist')
    puts "\n=== Current Whitelist State ==="
    puts "Total domains: #{domains.size}"

    domains.each do |domain|
      info = @redis.hgetall("spf:domain:#{domain}")
      status = info['status'] || 'unknown'
      puts "  - #{domain} (status: #{status})"
    end
    puts "================================\n"
  end

  # Interactive mode
  def interactive
    puts "\n=== SPF Guru Pub/Sub Tester ==="
    puts "Commands:"
    puts "  list domain1.com domain2.com ...  - Send full domain list"
    puts "  add domain.com                    - Add single domain"
    puts "  remove domain.com                 - Remove single domain"
    puts "  show                              - Show current whitelist state"
    puts "  quit                              - Exit"
    puts "================================\n"

    loop do
      print "> "
      $stdout.flush
      input = $stdin.gets&.strip
      break if input.nil? || input.empty?

      parts = input.split(/\s+/)
      command = parts.shift&.downcase

      case command
      when 'list'
        if parts.empty?
          puts "Usage: list domain1.com domain2.com ..."
        else
          send_domain_list(parts)
        end
      when 'add'
        if parts.empty?
          puts "Usage: add domain.com"
        else
          send_domain_add(parts.first)
        end
      when 'remove'
        if parts.empty?
          puts "Usage: remove domain.com"
        else
          send_domain_remove(parts.first)
        end
      when 'show'
        show_current_state
      when 'quit', 'exit', 'q'
        puts "Bye!"
        break
      else
        puts "Unknown command: #{command}"
      end
    end
  end

  def close
    @redis.close
  end
end

# Main
if __FILE__ == $PROGRAM_NAME
  tester = PubSubTester.new

  case ARGV[0]&.downcase
  when 'list'
    domains = ARGV[1..] || []
    if domains.empty?
      # Default test domains
      domains = %w[google.com microsoft.com amazon.com]
    end
    tester.send_domain_list(domains)
  when 'add'
    domain = ARGV[1]
    if domain
      tester.send_domain_add(domain)
    else
      puts "Usage: #{$PROGRAM_NAME} add domain.com"
      exit 1
    end
  when 'remove'
    domain = ARGV[1]
    if domain
      tester.send_domain_remove(domain)
    else
      puts "Usage: #{$PROGRAM_NAME} remove domain.com"
      exit 1
    end
  when 'show'
    tester.show_current_state
  when 'interactive', 'i'
    tester.interactive
  else
    puts "SPF Guru Pub/Sub Tester"
    puts ""
    puts "Usage:"
    puts "  #{$PROGRAM_NAME} list [domain1 domain2 ...]  - Send full domain list"
    puts "  #{$PROGRAM_NAME} add <domain>                - Add single domain"
    puts "  #{$PROGRAM_NAME} remove <domain>             - Remove single domain"
    puts "  #{$PROGRAM_NAME} show                        - Show current state"
    puts "  #{$PROGRAM_NAME} interactive                 - Interactive mode"
    puts ""
    puts "Environment variables:"
    puts "  REDIS_HOST  - Redis host (default: localhost)"
    puts "  REDIS_PORT  - Redis port (default: 6379)"
  end

  tester.close
end
