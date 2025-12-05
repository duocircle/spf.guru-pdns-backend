# spf.guru-pdns-backend

PowerDNS remote backend for SPF validation.

## Quick Start

```bash
docker run -it --name checkspf \
  -e NS_RECORDS="my-primary-ns.example.org my-other-ns.example.com" \
  -e ZONE="my.example.com" \
  -p 8000:8000 \
  ghcr.io/smck83/spf.guru-pdns-backend:latest
```

## Configuration

All configuration is done via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `ZONE` | DNS zone to serve | `my.spf.guru` |
| `NS_RECORDS` | Space-separated list of NS records | `ns-{ZONE}` |
| `SOA_SERIAL` | SOA serial number | `2025120400` |
| `SOA_HOSTMASTER` | SOA hostmaster email | `hostmaster@duocircle.com` |
| `MY_DOMAINS` | Space-separated domain whitelist (fallback) | (none) |
| `SOURCE_PREFIX` | Prefix for SPF lookups | (none) |
| `SPF_RECORD_MODE` | Pattern matching mode (0=standard, 1=rbldnsd) | `0` |
| `SPF_MACRO_RECORD` | Custom SPF macro template | (auto-generated) |
| `SPF_PREFIX` | SPF record prefix | `v=spf1` |
| `SPF_SUFFIX` | SPF record suffix | ` ~all` |
| `REDIS_IP` | Redis server IP (enables caching + Pub/Sub) | (none) |
| `REDIS_PORT` | Redis server port | `6379` |
| `REDIS_DB` | Redis database number | `0` |
| `SYNC_ENABLED` | Enable periodic sync requests to dmarcreport | `false` |
| `SYNC_INTERVAL` | Interval (seconds) for sync requests (if enabled) | `300` |
| `BUNNY_DB_URL` | Database logging URL | (none) |
| `BUNNY_DB_TOKEN` | Database logging token | (none) |
| `SENTRY_DSN` | Sentry DSN for error tracking | (none) |
| `SENTRY_ENVIRONMENT` | Sentry environment name | `production` |
| `SENTRY_TRACES_SAMPLE_RATE` | Sentry traces sample rate | `1.0` |

## Redis Integration

When `REDIS_IP` is configured, the backend uses Redis for:

1. **SPF Result Caching** - Caches SPF lookup results for improved performance
2. **Domain Whitelist Persistence** - Stores allowed domains in Redis SET `spf:allowed_domains`
3. **Pub/Sub Events** - Listens for domain whitelist updates via Redis Pub/Sub

### Pub/Sub Channels

**Incoming** (SPF Guru subscribes):

| Channel | Message Format | Description |
|---------|---------------|-------------|
| `spf:domains:list` | `{"domains": [...]}` | Replace entire whitelist |
| `spf:domains:add` | `{"domain": "..."}` | Add single domain |
| `spf:domains:remove` | `{"domain": "..."}` | Remove domain and invalidate cache |

**Outgoing** (SPF Guru publishes, when `SYNC_ENABLED=true`):

| Channel | Message Format | Description |
|---------|---------------|-------------|
| `spf:domains:sync_request` | `{"timestamp": "...", "current_count": N}` | Request full sync from dmarcreport |

When enabled, SPF Guru requests sync on startup and every `SYNC_INTERVAL` seconds.

See [docs/DMARCREPORT_INTEGRATION.md](docs/DMARCREPORT_INTEGRATION.md) for integration details.

### Testing Pub/Sub

Two testing services are available (under `testing` profile):

**1. dmarcreport-sim** - Auto-listener that seeds domains and responds to sync requests:
```bash
# Start backend + dmarcreport simulator
docker compose --profile testing up -d backend dmarcreport-sim

# View logs
docker logs -f spf-guru-dmarcreport-sim
```

**2. pubsub-tester** - Interactive mode for manual testing:
```bash
# Start interactive tester
docker compose --profile testing run --rm pubsub-tester

# Commands in interactive mode:
#   add example.com    - Add domain + publish
#   remove example.com - Remove domain + publish
#   show               - Compare local store vs SPF Guru
#   sync               - Force full sync
#   listen             - Start listening for sync requests
```

The simulator maintains a local domain store (`test:dmarcreport:domains`) and responds to SPF Guru's sync requests automatically.

### Health Check

The `/healthcheck` endpoint returns the current status:

```json
{
  "status": "ok",
  "initialized": true,
  "domain_count": 42,
  "redis_connected": true,
  "pubsub_active": true
}
```

## Development

### Requirements Management

This project uses `pip-compile` from `pip-tools` for reproducible dependency management.

#### Installing Dependencies

For production:
```bash
pip install pip-tools
pip-compile requirements.in
pip install -r requirements.txt
```

For development:
```bash
pip install pip-tools
pip-compile requirements-dev.in -o requirements-dev.txt
pip install -r requirements-dev.txt
```

#### Updating Dependencies

To update all dependencies to latest versions:
```bash
pip-compile --upgrade requirements.in
pip-compile --upgrade requirements-dev.in -o requirements-dev.txt
```

To update a specific package:
```bash
pip-compile --upgrade-package fastapi requirements.in
```

### Running Tests

```bash
pytest
```

With coverage:
```bash
pytest --cov=spf_guru --cov-report=term-missing
```

### Running Locally

```bash
# Set Python path
export PYTHONPATH=src

# Run the application
python -m spf_guru
```

Or with uvicorn directly:
```bash
uvicorn spf_guru.app:app --host 0.0.0.0 --port 8000 --reload
```

### Project Structure

```
spf.guru-pdns-backend/
├── src/
│   └── spf_guru/
│       ├── __init__.py
│       ├── __main__.py         # Entry point
│       ├── app.py              # FastAPI application
│       ├── api/
│       │   ├── __init__.py
│       │   ├── healthcheck.py  # Health check endpoint
│       │   ├── models.py       # Pydantic schemas
│       │   └── routes.py       # API endpoints
│       ├── core/
│       │   ├── __init__.py
│       │   ├── cache.py        # Redis/memory cache
│       │   ├── config.py       # Settings management
│       │   ├── database.py     # Database logging
│       │   ├── extractor.py    # SPF extraction
│       │   └── whitelist.py    # Domain whitelist with Pub/Sub
│       ├── dns/
│       │   ├── __init__.py
│       │   ├── patterns.py     # DNS pattern matching
│       │   └── resolver.py     # DNS resolution
│       └── utils/
│           ├── __init__.py
│           ├── banners.py      # Fortune banners
│           ├── decorators.py   # Sentry integration
│           └── exceptions.py   # Custom exceptions
├── docs/
│   └── DMARCREPORT_INTEGRATION.md  # Integration guide
├── scripts/
│   └── test_pubsub.rb          # Pub/Sub testing utility
├── requirements.in             # Production dependencies
├── requirements-dev.in         # Development dependencies
├── docker-compose.yaml
├── Dockerfile
└── README.md
```

## PowerDNS Configuration

Example `pdns.conf`:
```
launch=remote
remote-connection-string=http:url=http://checkspf:8000,timeout=4000
webserver=yes
webserver-address=0.0.0.0:8081
log-dns-queries=yes
loglevel=6
```

## License

See [LICENSE](LICENSE) file.
