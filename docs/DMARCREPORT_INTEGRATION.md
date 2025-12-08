# SPF Guru Integration Guide for dmarcreport

This guide explains how to integrate SPF Guru with dmarcreport to provide dynamic SPF flattening for your users.

## Table of Contents

1. [What is SPF Guru?](#what-is-spf-guru)
2. [User Journey](#user-journey)
3. [SPF Record Instructions for Users](#spf-record-instructions-for-users)
4. [When to Trigger Events](#when-to-trigger-events)
5. [Redis Pub/Sub Integration](#redis-pubsub-integration)
6. [Complete Ruby Implementation](#complete-ruby-implementation)
7. [Health Check Endpoint](#health-check-endpoint)
8. [Testing](#testing)
9. [Troubleshooting](#troubleshooting)

---

## What is SPF Guru?

SPF Guru is a dynamic SPF flattening service that solves the "10 DNS lookup limit" problem in SPF records. Instead of listing all IP addresses statically, users add a single SPF macro to their DNS record, and SPF Guru dynamically resolves and returns the flattened IP addresses.

**How it works:**
1. User adds SPF Guru macro to their domain's SPF record
2. When an email is sent, the receiving mail server queries SPF Guru
3. SPF Guru looks up the sender IP and domain, checks if the IP is authorized
4. Returns a PASS or FAIL response with the appropriate SPF record

---

## User Journey

### Step 1: User Signs Up for SPF Guru

When a user decides to use SPF Guru for their domain:

1. User registers their domain in dmarcreport
2. **dmarcreport publishes `spf:domains:add` event** → SPF Guru adds domain to whitelist
3. User is shown instructions to update their SPF record

### Step 2: User Configures Their DNS

User updates their domain's SPF TXT record to include the SPF Guru macro.

### Step 3: SPF Guru Handles Queries

When emails are sent from the user's domain, receiving mail servers query SPF Guru which returns dynamic responses.

### Step 4: User Removes Domain (Optional)

If user stops using SPF Guru:

1. User removes domain from dmarcreport
2. **dmarcreport publishes `spf:domains:remove` event** → SPF Guru removes from whitelist
3. User should update their SPF record to remove the macro

---

## SPF Record Instructions for Users

When a user enables SPF Guru for their domain, show them these instructions:

### How SPF Guru Works

SPF Guru optimizes SPF lookups by **pre-flattening** your existing includes. Here's how it works:

1. **User keeps their existing includes** (Google, Office 365, SendGrid, etc.) in the SPF record
2. **SPF Guru reads and parses those includes** - it recursively extracts all IPs from them
3. **SPF Guru caches the flattened IPs** for fast lookups
4. **When email is sent**, SPF Guru's macros are evaluated first (left-to-right):
   - `include:i.%{ir}._d.%{d}...` → SPF Guru checks if sender IP is in the cached/flattened list → returns PASS
   - `-include:z.%{ir}._d.%{d}...` → If not found, handles the fail case
5. **Result: 2 lookups** instead of 10+ (one for pass, one for fail)

**Important:** The existing includes (`include:_spf.google.com`, etc.) are **required** - SPF Guru uses them as the source of truth for which IPs are authorized. Don't remove them!

### What to Tell Users

> **Update Your SPF Record**
>
> Add SPF Guru macros at the **beginning** of your existing SPF record (after `v=spf1`):
>
> ```
> include:i.%{ir}._d.%{d}.my.spf.guru -include:z.%{ir}._d.%{d}.my.spf.guru
> ```
>
> **Example:**
>
> **Before** (4 lookups):
> ```
> v=spf1 include:spf.improvmx.com include:_spf.google.com -all
> ```
>
> **After** (2 lookups):
> ```
> v=spf1 include:i.%{ir}._d.%{d}.my.spf.guru -include:z.%{ir}._d.%{d}.my.spf.guru include:spf.improvmx.com include:_spf.google.com -all
> ```
>
> **Important:** Keep your existing includes! SPF Guru reads them to know which IPs are authorized for your domain. Removing them will break SPF validation.

### SPF Macro Format Explained

| Macro | Purpose | Description |
|-------|---------|-------------|
| `include:i.%{ir}._d.%{d}.my.spf.guru` | Pass check | Returns PASS if IP is authorized for domain |
| `-include:z.%{ir}._d.%{d}.my.spf.guru` | Fail check | Handles unauthorized IPs, falls through to existing includes |

**Macro variables:**

| Part | Meaning | Example |
|------|---------|---------|
| `i.` / `z.` | Check type prefix (pass/fail) | - |
| `%{ir}` | Sender IP address (reversed) | `1.2.168.192` for `192.168.2.1` |
| `._d.` | Domain separator | - |
| `%{d}` | Sender domain | `example.com` |
| `.my.spf.guru` | SPF Guru zone | - |

### UI Component Example

```html
<div class="spf-instructions">
  <h3>Configure Your SPF Record</h3>

  <p>Add these macros at the <strong>beginning</strong> of your SPF record (after v=spf1):</p>

  <div class="code-block">
    <code>include:i.%{ir}._d.%{d}.my.spf.guru -include:z.%{ir}._d.%{d}.my.spf.guru</code>
    <button onclick="copyToClipboard('include:i.%{ir}._d.%{d}.my.spf.guru -include:z.%{ir}._d.%{d}.my.spf.guru')">Copy</button>
  </div>

  <h4>Your SPF Guru Record:</h4>
  <div class="generated-record">
    <span class="badge">2 lookups</span>
    <pre>v=spf1 include:i.%{ir}._d.%{d}.my.spf.guru -include:z.%{ir}._d.%{d}.my.spf.guru <%= user_existing_spf_includes %> -all</pre>
    <button onclick="copyFullRecord()">Copy Full Record</button>
  </div>

  <details>
    <summary>How does this work?</summary>
    <p>
      SPF Guru reads your existing includes (Google, Office 365, etc.) and extracts all
      their IPs into a flattened cache. When email is sent, SPF records are evaluated
      left-to-right—SPF Guru's macros are checked first, returning PASS/FAIL in just
      2 queries instead of 10+. Your existing includes must remain in the record because
      SPF Guru uses them as the source of authorized IPs.
    </p>
  </details>
</div>
```

### Rails View Helper

```ruby
# app/helpers/spf_helper.rb
module SpfHelper
  SPF_GURU_ZONE = 'my.spf.guru'.freeze

  # Pass check macro - place first in SPF record
  def spf_guru_pass_include
    "include:i.%{ir}._d.%{d}.#{SPF_GURU_ZONE}"
  end

  # Fail check macro - place second in SPF record
  def spf_guru_fail_include
    "-include:z.%{ir}._d.%{d}.#{SPF_GURU_ZONE}"
  end

  # Combined macros to prepend to existing SPF record
  def spf_guru_macros
    "#{spf_guru_pass_include} #{spf_guru_fail_include}"
  end

  # Generate full SPF record with user's existing includes
  def generate_spf_guru_record(existing_includes, terminator = '-all')
    "v=spf1 #{spf_guru_macros} #{existing_includes} #{terminator}"
  end

  # Example: generate_spf_guru_record("include:_spf.google.com include:spf.improvmx.com")
  # => "v=spf1 include:i.%{ir}._d.%{d}.my.spf.guru -include:z.%{ir}._d.%{d}.my.spf.guru include:_spf.google.com include:spf.improvmx.com -all"
end
```

### Generating the SPF Guru Record

When displaying the recommended SPF record to users, parse their existing record and prepend the SPF Guru macros:

```ruby
# app/services/spf_record_generator.rb
class SpfRecordGenerator
  include SpfHelper

  def initialize(domain)
    @domain = domain
  end

  def generate
    existing = fetch_existing_spf_record
    return default_record if existing.blank?

    # Parse existing record
    parts = existing.split
    terminator = extract_terminator(parts)  # -all, ~all, ?all
    includes = extract_includes(parts)       # existing include: statements

    generate_spf_guru_record(includes.join(' '), terminator)
  end

  private

  def fetch_existing_spf_record
    # Fetch current SPF TXT record for domain
    Resolv::DNS.open do |dns|
      records = dns.getresources(@domain, Resolv::DNS::Resource::IN::TXT)
      records.find { |r| r.strings.join.start_with?('v=spf1') }&.strings&.join
    end
  rescue StandardError
    nil
  end

  def extract_terminator(parts)
    parts.find { |p| p.match?(/^[-~?+]all$/) } || '-all'
  end

  def extract_includes(parts)
    parts.select { |p| p.start_with?('include:', 'a:', 'mx:', 'ip4:', 'ip6:') }
  end

  def default_record
    "v=spf1 #{spf_guru_macros} -all"
  end
end

# Usage in controller/view:
# @spf_guru_record = SpfRecordGenerator.new(@domain.name).generate
```

---

## When to Trigger Events

### Event: `spf:domains:add`

**Trigger when:**
- User registers a new domain for SPF Guru
- User enables SPF Guru for an existing domain
- User's subscription becomes active
- Domain verification succeeds

```ruby
# In your Domain model or controller
after_create :notify_spf_guru_add
after_update :notify_spf_guru_add, if: :spf_guru_enabled_changed?

def notify_spf_guru_add
  return unless spf_guru_enabled?
  SpfGuruPublisher.new.add_domain(name)
end
```

### Event: `spf:domains:remove`

**Trigger when:**
- User removes domain from their account
- User disables SPF Guru for a domain
- User's subscription expires or is cancelled
- Domain verification fails or expires

```ruby
# In your Domain model or controller
after_destroy :notify_spf_guru_remove
after_update :notify_spf_guru_remove, if: :spf_guru_disabled?

def notify_spf_guru_remove
  SpfGuruPublisher.new.remove_domain(name)
end

def spf_guru_disabled?
  saved_change_to_spf_guru_enabled? && !spf_guru_enabled?
end
```

### Event: `spf:domains:list`

**Trigger when:**
- Application starts up (initial sync)
- Periodic sync (every 5-15 minutes recommended)
- After recovering from Redis connection failure
- Admin triggers manual sync

```ruby
# Background job for periodic sync
class SpfGuruSyncJob < ApplicationJob
  queue_as :low

  def perform
    domains = Domain.where(spf_guru_enabled: true).pluck(:name)
    SpfGuruPublisher.new.sync_all_domains(domains)
  end
end

# In config/initializers/spf_guru.rb
Rails.application.config.after_initialize do
  SpfGuruSyncJob.perform_later if Rails.env.production?
end

# In config/schedule.rb (using whenever gem)
every 10.minutes do
  runner "SpfGuruSyncJob.perform_later"
end
```

---

## Redis Pub/Sub Integration

### Architecture

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
```

### Channels

**dmarcreport → SPF Guru** (SPF Guru subscribes):

| Channel | Message Format | Description |
|---------|---------------|-------------|
| `spf:domains:list` | `{"domains": ["a.com", "b.com"]}` | Full sync - replace entire whitelist |
| `spf:domains:add` | `{"domain": "example.com"}` | Add single domain to whitelist |
| `spf:domains:remove` | `{"domain": "example.com"}` | Remove domain and invalidate cache |

**SPF Guru → dmarcreport** (dmarcreport should subscribe):

| Channel | Message Format | Description |
|---------|---------------|-------------|
| `spf:domains:sync_request` | `{"timestamp": "...", "current_count": 42}` | SPF Guru requests full domain list |

**Optional:** SPF Guru can publish sync requests (when `SYNC_ENABLED=true`):
- On startup (after 5 second delay)
- Periodically (configurable via `SYNC_INTERVAL`, default 5 minutes)

You have two options for keeping domains in sync:

1. **Push from dmarcreport** (recommended) - Run a periodic job on your side that publishes to `spf:domains:list`
2. **Pull from SPF Guru** - Enable `SYNC_ENABLED=true` on SPF Guru and set up a listener on `spf:domains:sync_request`

No matter how it is handled, if you get a change that is larger than a few lines do not apply this change, wait for confirmation. We dont want to break things because of a bad sync. 

Option 1 is simpler as it doesn't require an additional listener process.

### Redis Connection

Both services must connect to the same Redis instance:

| Service | Host Variable | Port Variable | DB Variable |
|---------|--------------|---------------|-------------|
| dmarcreport | `REDIS_HOST` | `REDIS_PORT` | `REDIS_DB` |
| SPF Guru | `REDIS_IP` | `REDIS_PORT` | `REDIS_DB` |

---

## Complete Ruby Implementation

### Publisher Service

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
      db: ENV.fetch('REDIS_DB', 0).to_i,
      reconnect_attempts: 3
    )
  end

  # Full sync - replaces entire whitelist
  def sync_all_domains(domains)
    normalized = domains.map { |d| d.to_s.downcase.strip }.uniq.reject(&:blank?)
    publish(CHANNEL_DOMAINS_LIST, { domains: normalized })
  end

  # Add single domain
  def add_domain(domain)
    publish(CHANNEL_DOMAINS_ADD, { domain: normalize(domain) })
  end

  # Remove single domain (also invalidates SPF cache)
  def remove_domain(domain)
    publish(CHANNEL_DOMAINS_REMOVE, { domain: normalize(domain) })
  end

  private

  def publish(channel, payload)
    json = payload.to_json
    subscribers = @redis.publish(channel, json)
    Rails.logger.info("[SpfGuru] Published to #{channel}: #{json} (#{subscribers} subscribers)")
    subscribers
  rescue Redis::BaseError => e
    Rails.logger.error("[SpfGuru] Publish failed: #{e.message}")
    raise
  end

  def normalize(domain)
    domain.to_s.downcase.strip
  end
end
```

### Domain Model with Callbacks

```ruby
# app/models/domain.rb
class Domain < ApplicationRecord
  belongs_to :user

  # Add callback hooks for SPF Guru integration
  after_commit :notify_spf_guru_add, on: [:create], if: :spf_guru_enabled?
  after_commit :notify_spf_guru_update, on: [:update], if: :spf_guru_status_changed?
  after_commit :notify_spf_guru_remove, on: [:destroy]

  scope :spf_guru_active, -> { where(spf_guru_enabled: true) }

  private

  def notify_spf_guru_add
    SpfGuruPublisher.new.add_domain(name)
  rescue Redis::BaseError => e
    Rails.logger.error("[SpfGuru] Failed to add domain: #{e.message}")
    # Don't fail the transaction - will sync on next periodic job
  end

  def notify_spf_guru_update
    if spf_guru_enabled?
      SpfGuruPublisher.new.add_domain(name)
    else
      SpfGuruPublisher.new.remove_domain(name)
    end
  rescue Redis::BaseError => e
    Rails.logger.error("[SpfGuru] Failed to update domain: #{e.message}")
  end

  def notify_spf_guru_remove
    SpfGuruPublisher.new.remove_domain(name)
  rescue Redis::BaseError => e
    Rails.logger.error("[SpfGuru] Failed to remove domain: #{e.message}")
  end

  def spf_guru_status_changed?
    saved_change_to_spf_guru_enabled?
  end
end
```

### Periodic Sync Job

```ruby
# app/jobs/spf_guru_sync_job.rb
class SpfGuruSyncJob < ApplicationJob
  queue_as :low

  # Retry on Redis failures
  retry_on Redis::BaseError, wait: 30.seconds, attempts: 3

  def perform(user_id: nil)
    publisher = SpfGuruPublisher.new

    domains = if user_id
      User.find(user_id).domains.spf_guru_active.pluck(:name)
    else
      Domain.spf_guru_active.pluck(:name)
    end

    publisher.sync_all_domains(domains)
    Rails.logger.info("[SpfGuru] Synced #{domains.count} domains")
  end
end
```

### Sync Request Listener (Optional)

If SPF Guru has `SYNC_ENABLED=true`, it will periodically request a full domain sync. Set up a listener to respond:

```ruby
# app/services/spf_guru_sync_listener.rb
class SpfGuruSyncListener
  CHANNEL_SYNC_REQUEST = 'spf:domains:sync_request'.freeze

  def initialize(redis: nil)
    @redis = redis || Redis.new(
      host: ENV.fetch('REDIS_HOST', 'localhost'),
      port: ENV.fetch('REDIS_PORT', 6379).to_i,
      db: ENV.fetch('REDIS_DB', 0).to_i
    )
  end

  def start
    Rails.logger.info("[SpfGuru] Starting sync request listener on #{CHANNEL_SYNC_REQUEST}")

    @redis.subscribe(CHANNEL_SYNC_REQUEST) do |on|
      on.message do |channel, message|
        handle_sync_request(message)
      end
    end
  end

  private

  def handle_sync_request(message)
    data = JSON.parse(message)
    Rails.logger.info("[SpfGuru] Sync requested (current_count: #{data['current_count']})")

    # Publish full domain list in response
    SpfGuruSyncJob.perform_later
  rescue JSON::ParserError => e
    Rails.logger.error("[SpfGuru] Invalid sync request: #{e.message}")
  end
end
```

Run the listener as a background process:

```ruby
# lib/tasks/spf_guru.rake
namespace :spf_guru do
  desc 'Start SPF Guru sync request listener'
  task listen: :environment do
    SpfGuruSyncListener.new.start
  end
end
```

```bash
# Run with:
bundle exec rake spf_guru:listen

# Or in Procfile:
spf_listener: bundle exec rake spf_guru:listen
```

**Alternative: Using Sidekiq or Action Cable**

If you prefer not to run a separate process, you can use Sidekiq's scheduled jobs to poll for sync requests, or integrate with Action Cable for WebSocket-based pub/sub.

### Controller Example

```ruby
# app/controllers/domains_controller.rb
class DomainsController < ApplicationController
  before_action :authenticate_user!

  def create
    @domain = current_user.domains.build(domain_params)

    if @domain.save
      # after_commit callback handles SpfGuruPublisher.add_domain
      redirect_to @domain, notice: 'Domain added. Follow the SPF setup instructions below.'
    else
      render :new
    end
  end

  def enable_spf_guru
    @domain = current_user.domains.find(params[:id])
    @domain.update!(spf_guru_enabled: true)
    # after_commit callback handles SpfGuruPublisher.add_domain

    redirect_to @domain, notice: 'SPF Guru enabled. Update your DNS record.'
  end

  def disable_spf_guru
    @domain = current_user.domains.find(params[:id])
    @domain.update!(spf_guru_enabled: false)
    # after_commit callback handles SpfGuruPublisher.remove_domain

    redirect_to @domain, notice: 'SPF Guru disabled. Remember to update your DNS record.'
  end
end
```

---

## Health Check Endpoint

SPF Guru provides a health check endpoint to verify integration status:

**Endpoint:** `GET /healthcheck`

**Request:**
```bash
curl http://spf-guru-host:8000/healthcheck
```

**Response:**
```json
{
  "status": "ok",
  "initialized": true,
  "domain_count": 42,
  "redis_connected": true,
  "pubsub_active": true
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | `"ok"` if healthy |
| `initialized` | boolean | Whitelist manager is ready |
| `domain_count` | integer | Number of domains in whitelist |
| `redis_connected` | boolean | Redis connection is active |
| `pubsub_active` | boolean | Pub/Sub listener is running |

### Monitoring Integration

```ruby
# app/services/spf_guru_health_check.rb
class SpfGuruHealthCheck
  def self.healthy?
    response = HTTParty.get(
      "#{ENV['SPF_GURU_URL']}/healthcheck",
      timeout: 5
    )

    data = JSON.parse(response.body)
    data['status'] == 'ok' && data['pubsub_active'] == true
  rescue StandardError => e
    Rails.logger.error("[SpfGuru] Health check failed: #{e.message}")
    false
  end
end

# Use in your monitoring/alerting
unless SpfGuruHealthCheck.healthy?
  AdminMailer.spf_guru_alert.deliver_later
end
```

---

## Testing

### Using the Test Script

SPF Guru includes a Ruby test script for integration testing:

```bash
# Start Redis and test container
docker compose --profile testing up -d

# Interactive mode - menu-driven testing
docker compose exec pubsub-tester ruby test_pubsub.rb

# Command-line mode
docker compose exec pubsub-tester ruby test_pubsub.rb add example.com
docker compose exec pubsub-tester ruby test_pubsub.rb remove example.com
docker compose exec pubsub-tester ruby test_pubsub.rb list domain1.com domain2.com
docker compose exec pubsub-tester ruby test_pubsub.rb show
```

### Using redis-cli

```bash
# Add a domain
redis-cli PUBLISH spf:domains:add '{"domain":"test.com"}'

# Remove a domain
redis-cli PUBLISH spf:domains:remove '{"domain":"test.com"}'

# Full sync
redis-cli PUBLISH spf:domains:list '{"domains":["a.com","b.com"]}'

# Check current whitelist
redis-cli SMEMBERS spf:whitelist
```

### Rails Console

```ruby
publisher = SpfGuruPublisher.new

# Test add
publisher.add_domain("test.example.com")

# Test remove
publisher.remove_domain("test.example.com")

# Test full sync
publisher.sync_all_domains(["domain1.com", "domain2.com"])

# Check health
response = HTTParty.get("http://localhost:8000/healthcheck")
puts response.body
```

### Verify in SPF Guru Logs

```bash
docker logs -f spf-guru-backend
```

Expected output:
```
2025-01-15 10:30:00 - spf_guru.core.whitelist - INFO - Domain added via Pub/Sub: example.com
2025-01-15 10:35:00 - spf_guru.core.whitelist - INFO - Domain removed via Pub/Sub: example.com
2025-01-15 10:35:00 - spf_guru.core.cache - INFO - spf:example.com removed from cache
```

---

## Troubleshooting

### Events Not Being Received

1. **Check Redis connectivity**
   ```bash
   redis-cli ping  # Should return PONG
   ```

2. **Verify same Redis database**
   - Both services must use same `REDIS_DB` value

3. **Check SPF Guru health**
   ```bash
   curl http://localhost:8000/healthcheck
   ```
   - `pubsub_active` should be `true`

4. **Check SPF Guru logs** for "Subscribed to Redis channels" message

### Domain Added But SPF Queries Fail

1. **Verify domain is in whitelist**
   ```bash
   redis-cli SISMEMBER spf:whitelist example.com
   ```

2. **Check DNS record format**
   - Must use exact macro format: `include:i.%{ir}._d.%{d}.my.spf.guru`

3. **Test DNS resolution**
   ```bash
   # Replace with actual IP (reversed) and domain
   dig TXT i.1.0.0.127._d.example.com.my.spf.guru
   ```

### Cache Not Invalidating

After removing a domain, cached SPF results may still return for the TTL period (default 4 hours). The `spf:domains:remove` event triggers immediate cache invalidation.

### Redis Connection Issues

```ruby
# Add reconnection handling
Redis.new(
  host: ENV['REDIS_HOST'],
  reconnect_attempts: 3,
  reconnect_delay: 1.0,
  reconnect_delay_max: 5.0
)
```

---

## Docker Compose Network

Ensure both services share a network:

```yaml
services:
  redis:
    image: redis:7-alpine
    networks:
      - spf-network

  dmarcreport:
    environment:
      - REDIS_HOST=redis
    networks:
      - spf-network

  spf-guru:
    environment:
      - REDIS_IP=redis
    networks:
      - spf-network

networks:
  spf-network:
    driver: bridge
```

---

## Support

- GitHub Issues: https://github.com/smck83/spf.guru-pdns-backend/issues
