#!/usr/bin/env ruby
# frozen_string_literal: true

# Test script for Redis Pub/Sub integration with SPF Guru
#
# This script simulates dmarcreport by:
# - Maintaining a local domain store in Redis (separate key)
# - Publishing domain events to SPF Guru
# - Listening for sync requests and responding automatically
#
# Usage:
#   ruby test_pubsub.rb                    # Interactive mode (default)
#   ruby test_pubsub.rb listen             # Listen for sync requests
#   ruby test_pubsub.rb add example.com    # Add domain to local store + publish
#   ruby test_pubsub.rb remove example.com # Remove domain + publish
#   ruby test_pubsub.rb sync               # Force full sync publish
#   ruby test_pubsub.rb show               # Show local domain store

require 'redis'
require 'json'

# Configuration
REDIS_HOST = ENV.fetch('REDIS_HOST', 'localhost')
REDIS_PORT = ENV.fetch('REDIS_PORT', 6379).to_i
REDIS_DB = ENV.fetch('REDIS_DB', 0).to_i

# Channel names (must match Python backend)
CHANNEL_DOMAINS_LIST = 'spf:domains:list'
CHANNEL_DOMAINS_ADD = 'spf:domains:add'
CHANNEL_DOMAINS_REMOVE = 'spf:domains:remove'
CHANNEL_SYNC_REQUEST = 'spf:domains:sync_request'

# Local domain store key (simulates dmarcreport's database)
LOCAL_STORE_KEY = 'test:dmarcreport:domains'

class DmarcReportSimulator
  def initialize
    @redis = Redis.new(host: REDIS_HOST, port: REDIS_PORT, db: REDIS_DB)
    puts "Connected to Redis at #{REDIS_HOST}:#{REDIS_PORT}/#{REDIS_DB}"
    puts "Local domain store: #{LOCAL_STORE_KEY}"
  end

  # === Local Domain Store (simulates dmarcreport database) ===

  def store_add(domain)
    domain = domain.downcase.strip
    added = @redis.sadd(LOCAL_STORE_KEY, domain)
    puts added ? "Added '#{domain}' to local store" : "'#{domain}' already in store"
    added
  end

  def store_remove(domain)
    domain = domain.downcase.strip
    removed = @redis.srem(LOCAL_STORE_KEY, domain)
    puts removed ? "Removed '#{domain}' from local store" : "'#{domain}' not in store"
    removed
  end

  def store_list
    @redis.smembers(LOCAL_STORE_KEY).sort
  end

  def store_clear
    count = @redis.scard(LOCAL_STORE_KEY)
    @redis.del(LOCAL_STORE_KEY)
    puts "Cleared #{count} domains from local store"
    count
  end

  def store_seed(domains)
    domains.each { |d| @redis.sadd(LOCAL_STORE_KEY, d.downcase.strip) }
    puts "Seeded #{domains.size} domains to local store"
  end

  # === Pub/Sub Publishing ===

  def publish_domain_list
    domains = store_list
    payload = { domains: domains }.to_json
    subs = @redis.publish(CHANNEL_DOMAINS_LIST, payload)
    puts "Published full list (#{domains.size} domains) to #{subs} subscribers"
    subs
  end

  def publish_domain_add(domain)
    payload = { domain: domain.downcase.strip }.to_json
    subs = @redis.publish(CHANNEL_DOMAINS_ADD, payload)
    puts "Published add '#{domain}' to #{subs} subscribers"
    subs
  end

  def publish_domain_remove(domain)
    payload = { domain: domain.downcase.strip }.to_json
    subs = @redis.publish(CHANNEL_DOMAINS_REMOVE, payload)
    puts "Published remove '#{domain}' to #{subs} subscribers"
    subs
  end

  # === Combined Operations (store + publish) ===

  def add_domain(domain)
    if store_add(domain)
      publish_domain_add(domain)
    end
  end

  def remove_domain(domain)
    if store_remove(domain)
      publish_domain_remove(domain)
    end
  end

  # === Sync Request Listener ===

  def listen_for_sync_requests
    puts "\n=== Listening for sync requests on #{CHANNEL_SYNC_REQUEST} ==="
    puts "Press Ctrl+C to stop\n\n"

    # Use a separate connection for subscribing (blocking operation)
    sub_redis = Redis.new(host: REDIS_HOST, port: REDIS_PORT, db: REDIS_DB)

    sub_redis.subscribe(CHANNEL_SYNC_REQUEST) do |on|
      on.subscribe do |channel, subscriptions|
        puts "Subscribed to #{channel} (#{subscriptions} subscriptions)"
      end

      on.message do |channel, message|
        handle_sync_request(message)
      end

      on.unsubscribe do |channel, subscriptions|
        puts "Unsubscribed from #{channel}"
      end
    end
  rescue Interrupt
    puts "\nStopping listener..."
  ensure
    sub_redis&.close
  end

  def handle_sync_request(message)
    begin
      data = JSON.parse(message)
      timestamp = data['timestamp'] || 'unknown'
      current_count = data['current_count'] || '?'
      puts "[#{Time.now.strftime('%H:%M:%S')}] Sync request received (SPF Guru has #{current_count} domains)"

      # Respond with full domain list
      publish_domain_list
    rescue JSON::ParserError => e
      puts "Invalid sync request JSON: #{e.message}"
    end
  end

  # === Display ===

  def show_state
    local_domains = store_list
    spf_domains = @redis.smembers('spf:whitelist').sort

    puts "\n" + "=" * 50
    puts "LOCAL STORE (simulated dmarcreport DB)"
    puts "=" * 50
    if local_domains.empty?
      puts "  (empty)"
    else
      local_domains.each { |d| puts "  - #{d}" }
    end
    puts "Total: #{local_domains.size}"

    puts "\n" + "=" * 50
    puts "SPF GURU WHITELIST"
    puts "=" * 50
    if spf_domains.empty?
      puts "  (empty)"
    else
      spf_domains.each do |d|
        info = @redis.hgetall("spf:domain:#{d}")
        status = info['status'] || '?'
        puts "  - #{d} (#{status})"
      end
    end
    puts "Total: #{spf_domains.size}"

    puts "\n" + "=" * 50
    puts "COMPARISON"
    puts "=" * 50
    only_local = local_domains - spf_domains
    only_spf = spf_domains - local_domains

    if only_local.any?
      puts "In local store only: #{only_local.join(', ')}"
    end
    if only_spf.any?
      puts "In SPF Guru only: #{only_spf.join(', ')}"
    end
    if only_local.empty? && only_spf.empty?
      puts "Both are in sync!"
    end
    puts ""
  end

  # === Interactive Mode ===

  def interactive
    puts "\n" + "=" * 50
    puts "DMARCREPORT SIMULATOR - Interactive Mode"
    puts "=" * 50
    puts "Commands:"
    puts "  add <domain>     - Add domain to local store + publish event"
    puts "  remove <domain>  - Remove domain + publish event"
    puts "  sync             - Publish full domain list"
    puts "  show             - Show local store vs SPF Guru state"
    puts "  seed <d1 d2 ...> - Seed domains to local store (no publish)"
    puts "  clear            - Clear local store (no publish)"
    puts "  listen           - Listen for sync requests (blocking)"
    puts "  help             - Show this help"
    puts "  quit             - Exit"
    puts "=" * 50 + "\n"

    loop do
      print "dmarcreport> "
      $stdout.flush
      input = $stdin.gets&.strip
      break if input.nil?
      next if input.empty?

      parts = input.split(/\s+/)
      command = parts.shift&.downcase

      case command
      when 'add'
        if parts.empty?
          puts "Usage: add domain.com"
        else
          parts.each { |d| add_domain(d) }
        end

      when 'remove', 'rm', 'del'
        if parts.empty?
          puts "Usage: remove domain.com"
        else
          parts.each { |d| remove_domain(d) }
        end

      when 'sync'
        publish_domain_list

      when 'show', 'status', 'ls'
        show_state

      when 'seed'
        if parts.empty?
          # Default seed domains
          parts = %w[example.com google.com microsoft.com]
        end
        store_seed(parts)

      when 'clear'
        store_clear

      when 'listen'
        listen_for_sync_requests
        puts "Returned to interactive mode"

      when 'help', '?'
        puts "Commands: add, remove, sync, show, seed, clear, listen, quit"

      when 'quit', 'exit', 'q'
        puts "Bye!"
        break

      else
        puts "Unknown command: #{command}. Type 'help' for commands."
      end
    end
  end

  def close
    @redis.close
  end
end

# === Main ===

if __FILE__ == $PROGRAM_NAME
  simulator = DmarcReportSimulator.new

  case ARGV[0]&.downcase
  when 'add'
    if ARGV[1]
      ARGV[1..].each { |d| simulator.add_domain(d) }
    else
      puts "Usage: #{$PROGRAM_NAME} add domain1.com [domain2.com ...]"
      exit 1
    end

  when 'remove', 'rm', 'del'
    if ARGV[1]
      ARGV[1..].each { |d| simulator.remove_domain(d) }
    else
      puts "Usage: #{$PROGRAM_NAME} remove domain.com"
      exit 1
    end

  when 'sync'
    simulator.publish_domain_list

  when 'show', 'status'
    simulator.show_state

  when 'seed'
    domains = ARGV[1..] || []
    domains = %w[example.com google.com microsoft.com] if domains.empty?
    simulator.store_seed(domains)

  when 'clear'
    simulator.store_clear

  when 'listen'
    simulator.listen_for_sync_requests

  when 'interactive', 'i', nil
    simulator.interactive

  when 'help', '-h', '--help'
    puts <<~HELP
      DMARCREPORT SIMULATOR - Test SPF Guru Pub/Sub Integration

      This script simulates dmarcreport by maintaining a local domain store
      and responding to SPF Guru's sync requests.

      Usage:
        #{$PROGRAM_NAME}                         Interactive mode (default)
        #{$PROGRAM_NAME} add <domain> [...]      Add domain(s) to store + publish
        #{$PROGRAM_NAME} remove <domain> [...]   Remove domain(s) + publish
        #{$PROGRAM_NAME} sync                    Publish full domain list
        #{$PROGRAM_NAME} show                    Show local store vs SPF Guru state
        #{$PROGRAM_NAME} seed [domain ...]       Seed domains to store (no publish)
        #{$PROGRAM_NAME} clear                   Clear local store
        #{$PROGRAM_NAME} listen                  Listen for sync requests (blocking)

      Environment:
        REDIS_HOST  - Redis host (default: localhost)
        REDIS_PORT  - Redis port (default: 6379)
        REDIS_DB    - Redis database (default: 0)

      Workflow:
        1. Run 'seed' to add test domains to local store
        2. Run 'listen' in one terminal to respond to sync requests
        3. Start SPF Guru - it will request sync on startup
        4. Use 'add'/'remove' to test real-time updates
        5. Use 'show' to compare local store vs SPF Guru state
    HELP

  else
    puts "Unknown command: #{ARGV[0]}. Use --help for usage."
    exit 1
  end

  simulator.close
end
