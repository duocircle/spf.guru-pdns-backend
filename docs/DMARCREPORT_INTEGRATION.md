# SPF Guru Integration Guide for dmarcreport

This document describes how to integrate the SPF Guru backend with dmarcreport using Redis Pub/Sub for real-time domain whitelist synchronization.

## Overview

SPF Guru uses Redis Pub/Sub to receive domain whitelist updates from dmarcreport. The flow is:

1. **dmarcreport (Ruby on Rails)** → publishes domain events to Redis
2. **SPF Guru (Python)** → subscribes to Redis channels and updates its whitelist

```
┌─────────────────┐       Redis Pub/Sub        ┌─────────────────┐
│   dmarcreport   │ ──────────────────────────▶│    SPF Guru     │
│  (Ruby on Rails)│    spf:domains:*           │    (Python)     │
└─────────────────┘                            └─────────────────┘
        │                                              │
        │ PUBLISH                              SUBSCRIBE│
        ▼                                              ▼
   ┌─────────┐                                 ┌─────────────┐
   │  Redis  │◀────────────────────────────────│  Whitelist  │
   └─────────┘         Persistence             │   + Cache   │
                       spf:whitelist           └─────────────┘
                       spf:domain:*
```

## Redis Configuration

### Connection Settings

Both services must connect to the same Redis instance:

| Setting | Environment Variable | Default |
|---------|---------------------|---------|
| Host | `REDIS_HOST` (Rails) / `REDIS_IP` (SPF Guru) | `localhost` |
| Port | `REDIS_PORT` | `6379` |
| Database | `REDIS_DB` | `0` |

### Redis URL Format

```
redis://<host>:<port>/<db>
```

Example: `redis://localhost:6379/0`

## Pub/Sub Channels

SPF Guru subscribes to three channels:

| Channel | Purpose | When to Use |
|---------|---------|-------------|
| `spf:domains:list` | Full domain list sync | Initial sync, periodic full sync |
| `spf:domains:add` | Single domain added | When user adds a domain |
| `spf:domains:remove` | Single domain removed | When user removes a domain |

## Message Formats

All messages must be valid JSON strings.

### 1. Full Domain List Sync

**Channel:** `spf:domains:list`

Use this to sync the entire domain list. SPF Guru will:
- Add domains not in its current list
- Remove domains no longer in the list
- Invalidate cache for removed domains

**Payload:**
```json
{
  "domains": ["example.com", "example.org", "mycompany.com"]
}
```

**Ruby Example:**
```ruby
class SpfGuruPublisher
  CHANNEL_DOMAINS_LIST = 'spf:domains:list'

  def initialize(redis = Redis.new)
    @redis = redis
  end

  def sync_all_domains(domains)
    payload = { domains: domains.map(&:downcase) }.to_json
    @redis.publish(CHANNEL_DOMAINS_LIST, payload)
  end
end

# Usage
publisher = SpfGuruPublisher.new
domains = User.find(user_id).domains.pluck(:name)
publisher.sync_all_domains(domains)
```

### 2. Add Single Domain

**Channel:** `spf:domains:add`

Use this when a user adds a new domain. SPF Guru will:
- Add the domain to its whitelist
- Pre-fetch and cache the domain's SPF records (warmup)

**Payload:**
```json
{
  "domain": "newdomain.com"
}
```

**Ruby Example:**
```ruby
class SpfGuruPublisher
  CHANNEL_DOMAINS_ADD = 'spf:domains:add'

  def add_domain(domain)
    payload = { domain: domain.downcase.strip }.to_json
    @redis.publish(CHANNEL_DOMAINS_ADD, payload)
  end
end

# Usage in Rails controller or model callback
publisher = SpfGuruPublisher.new
publisher.add_domain("newdomain.com")
```

### 3. Remove Single Domain

**Channel:** `spf:domains:remove`

Use this when a user removes a domain. SPF Guru will:
- Remove the domain from its whitelist
- Invalidate the cached SPF records for that domain

**Payload:**
```json
{
  "domain": "olddomain.com"
}
```

**Ruby Example:**
```ruby
class SpfGuruPublisher
  CHANNEL_DOMAINS_REMOVE = 'spf:domains:remove'

  def remove_domain(domain)
    payload = { domain: domain.downcase.strip }.to_json
    @redis.publish(CHANNEL_DOMAINS_REMOVE, payload)
  end
end

# Usage
publisher = SpfGuruPublisher.new
publisher.remove_domain("olddomain.com")
```

## Complete Ruby Implementation

### Publisher Service Class

```ruby
# app/services/spf_guru_publisher.rb
class SpfGuruPublisher
  CHANNEL_DOMAINS_LIST = 'spf:domains:list'.freeze
  CHANNEL_DOMAINS_ADD = 'spf:domains:add'.freeze
  CHANNEL_DOMAINS_REMOVE = 'spf:domains:remove'.freeze

  def initialize(redis: nil)
    @redis = redis || Redis.new(
      host: ENV.fetch('REDIS_HOST', 'localhost'),
      port: ENV.fetch('REDIS_PORT', 6379).to_i,
      db: ENV.fetch('REDIS_DB', 0).to_i
    )
  end

  # Sync entire domain list (use for initial sync or periodic full sync)
  def sync_all_domains(domains)
    normalized = domains.map { |d| d.to_s.downcase.strip }.uniq
    publish(CHANNEL_DOMAINS_LIST, { domains: normalized })
  end

  # Add a single domain
  def add_domain(domain)
    publish(CHANNEL_DOMAINS_ADD, { domain: normalize(domain) })
  end

  # Remove a single domain
  def remove_domain(domain)
    publish(CHANNEL_DOMAINS_REMOVE, { domain: normalize(domain) })
  end

  # Sync domains for a specific user
  def sync_user_domains(user)
    domains = user.domains.active.pluck(:name)
    sync_all_domains(domains)
  end

  private

  def publish(channel, payload)
    json = payload.to_json
    subscribers = @redis.publish(channel, json)

    Rails.logger.info("[SpfGuruPublisher] Published to #{channel}: #{json} (#{subscribers} subscribers)")
    subscribers
  end

  def normalize(domain)
    domain.to_s.downcase.strip
  end
end
```

### Model Callbacks

```ruby
# app/models/domain.rb
class Domain < ApplicationRecord
  belongs_to :user

  after_create :notify_spf_guru_add
  after_destroy :notify_spf_guru_remove

  scope :active, -> { where(active: true) }

  private

  def notify_spf_guru_add
    SpfGuruPublisher.new.add_domain(name)
  rescue Redis::BaseError => e
    Rails.logger.error("[SpfGuruPublisher] Failed to publish add: #{e.message}")
    # Don't fail the transaction - SPF Guru will sync eventually
  end

  def notify_spf_guru_remove
    SpfGuruPublisher.new.remove_domain(name)
  rescue Redis::BaseError => e
    Rails.logger.error("[SpfGuruPublisher] Failed to publish remove: #{e.message}")
  end
end
```

### Background Job for Full Sync

```ruby
# app/jobs/spf_guru_sync_job.rb
class SpfGuruSyncJob < ApplicationJob
  queue_as :default

  def perform(user_id = nil)
    publisher = SpfGuruPublisher.new

    if user_id
      # Sync single user's domains
      user = User.find(user_id)
      publisher.sync_user_domains(user)
    else
      # Sync all domains (global sync)
      all_domains = Domain.active.pluck(:name)
      publisher.sync_all_domains(all_domains)
    end
  end
end

# Schedule periodic sync (e.g., in config/schedule.rb with whenever gem)
# every 5.minutes do
#   runner "SpfGuruSyncJob.perform_later"
# end
```

### Controller Example

```ruby
# app/controllers/api/domains_controller.rb
class Api::DomainsController < ApplicationController
  before_action :authenticate_user!

  def create
    @domain = current_user.domains.build(domain_params)

    if @domain.save
      # Callback handles SpfGuruPublisher.add_domain
      render json: @domain, status: :created
    else
      render json: { errors: @domain.errors }, status: :unprocessable_entity
    end
  end

  def destroy
    @domain = current_user.domains.find(params[:id])
    @domain.destroy
    # Callback handles SpfGuruPublisher.remove_domain
    head :no_content
  end

  # Manual sync endpoint
  def sync
    SpfGuruSyncJob.perform_later(current_user.id)
    render json: { message: 'Sync initiated' }
  end

  private

  def domain_params
    params.require(:domain).permit(:name)
  end
end
```

### Initializer

```ruby
# config/initializers/spf_guru.rb
Rails.application.config.after_initialize do
  # Verify Redis connection on startup
  begin
    redis = Redis.new(
      host: ENV.fetch('REDIS_HOST', 'localhost'),
      port: ENV.fetch('REDIS_PORT', 6379).to_i
    )
    redis.ping
    Rails.logger.info("[SpfGuru] Redis connection verified")
  rescue Redis::BaseError => e
    Rails.logger.warn("[SpfGuru] Redis not available: #{e.message}")
  end
end
```

## Redis Data Persistence

SPF Guru also stores whitelist data directly in Redis for persistence across restarts:

| Key | Type | Description |
|-----|------|-------------|
| `spf:whitelist` | Set | Set of all whitelisted domain names |
| `spf:domain:<domain>` | Hash | Metadata for each domain |

### Domain Metadata Hash Fields

```
spf:domain:example.com
  - domain: "example.com"
  - added_at: "2025-01-15T10:30:00+00:00"
  - last_refresh: "2025-01-15T12:00:00+00:00"
  - spf_ttl: "3600"
  - ip_count: "15"
  - status: "active"  # active, error, pending
```

**Note:** You don't need to write to these keys directly. SPF Guru manages them automatically when it receives Pub/Sub events.

## Testing the Integration

### 1. Using the Test Script

SPF Guru includes a Ruby test script:

```bash
# Start the test container
docker compose --profile testing up -d

# Interactive mode
docker compose exec -it pubsub-tester ruby test_pubsub.rb interactive

# One-off commands
docker compose exec pubsub-tester ruby test_pubsub.rb list example.com example.org
docker compose exec pubsub-tester ruby test_pubsub.rb add newdomain.com
docker compose exec pubsub-tester ruby test_pubsub.rb remove olddomain.com
docker compose exec pubsub-tester ruby test_pubsub.rb show
```

### 2. Using redis-cli

```bash
# Publish a domain list
redis-cli PUBLISH spf:domains:list '{"domains":["example.com","test.org"]}'

# Add a domain
redis-cli PUBLISH spf:domains:add '{"domain":"newdomain.com"}'

# Remove a domain
redis-cli PUBLISH spf:domains:remove '{"domain":"olddomain.com"}'

# Check current whitelist
redis-cli SMEMBERS spf:whitelist

# Check domain metadata
redis-cli HGETALL spf:domain:example.com
```

### 3. Using Rails Console

```ruby
# In Rails console
publisher = SpfGuruPublisher.new

# Test add
publisher.add_domain("test.example.com")

# Test remove
publisher.remove_domain("test.example.com")

# Test full sync
publisher.sync_all_domains(["domain1.com", "domain2.com", "domain3.com"])
```

### 4. Verify in SPF Guru Logs

Watch the SPF Guru backend logs for confirmation:

```bash
docker logs -f spf-guru-backend
```

Expected log output:
```
2025-01-15 10:30:00 - spf_guru.core.whitelist - INFO - Domain added via Pub/Sub: example.com
2025-01-15 10:30:01 - spf_guru.core.whitelist - INFO - spf:example.com added to cache
2025-01-15 10:35:00 - spf_guru.core.whitelist - INFO - Domain removed via Pub/Sub: example.com
2025-01-15 10:35:00 - spf_guru.core.cache - INFO - spf:example.com removed from cache
```

## Health Check Endpoint

SPF Guru provides a health check endpoint to verify Pub/Sub status:

```bash
curl http://localhost:8000/admin/health
```

Response:
```json
{
  "status": "ok",
  "initialized": true,
  "domain_count": 42,
  "redis_connected": true,
  "pubsub_active": true
}
```

## Error Handling Best Practices

### 1. Don't Block on Publish Failures

```ruby
def add_domain(domain)
  publish(CHANNEL_DOMAINS_ADD, { domain: normalize(domain) })
rescue Redis::BaseError => e
  Rails.logger.error("[SpfGuruPublisher] Publish failed: #{e.message}")
  # Queue for retry or rely on periodic sync
  SpfGuruSyncJob.perform_later
end
```

### 2. Implement Periodic Full Sync

Even with real-time events, run a periodic full sync as a safety net:

```ruby
# Every 5 minutes, sync all domains
SpfGuruSyncJob.perform_later
```

### 3. Handle Redis Reconnection

```ruby
class SpfGuruPublisher
  def initialize(redis: nil)
    @redis = redis || create_redis_connection
  end

  private

  def create_redis_connection
    Redis.new(
      host: ENV.fetch('REDIS_HOST', 'localhost'),
      port: ENV.fetch('REDIS_PORT', 6379).to_i,
      db: ENV.fetch('REDIS_DB', 0).to_i,
      reconnect_attempts: 3,
      reconnect_delay: 1.0,
      reconnect_delay_max: 5.0
    )
  end
end
```

## Environment Variables Summary

### dmarcreport (Ruby on Rails)

```bash
REDIS_HOST=localhost      # or 'redis' in Docker
REDIS_PORT=6379
REDIS_DB=0
```

### SPF Guru (Python)

```bash
REDIS_IP=localhost        # or 'redis' in Docker
REDIS_PORT=6379
REDIS_DB=0
```

## Docker Compose Network

If running both services in Docker, ensure they're on the same network:

```yaml
# docker-compose.yml
services:
  redis:
    image: redis:7-alpine
    networks:
      - shared-network

  dmarcreport:
    # your Rails app
    environment:
      - REDIS_HOST=redis
    networks:
      - shared-network

  spf-guru:
    # SPF Guru backend
    environment:
      - REDIS_IP=redis
    networks:
      - shared-network

networks:
  shared-network:
    driver: bridge
```

## Troubleshooting

### No Events Being Received

1. Check Redis connectivity from both services
2. Verify both services use the same Redis database
3. Check SPF Guru logs for "Subscribed to Redis channels" message
4. Verify Pub/Sub is active: `curl http://localhost:8000/admin/health`

### Events Published but Not Processed

1. Check JSON format is valid
2. Ensure domain names are lowercase
3. Look for errors in SPF Guru logs

### Domains Not Persisting After Restart

1. Verify Redis persistence is enabled (RDB or AOF)
2. Check `spf:whitelist` set exists: `redis-cli SMEMBERS spf:whitelist`
3. Ensure SPF Guru has write access to Redis

## Support

For issues or questions:
- GitHub Issues: https://github.com/smck83/spf.guru-pdns-backend/issues
