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
| `SOA_SERIAL` | SOA serial number | `2025080300` |
| `SOA_HOSTMASTER` | SOA hostmaster email | `hostmaster@example.com` |
| `MY_DOMAINS` | Space-separated domain whitelist | (none) |
| `SOURCE_PREFIX` | Prefix for SPF lookups | (none) |
| `SPF_RECORD_MODE` | Pattern matching mode (0=standard, 1=rbldnsd) | `0` |
| `SPF_MACRO_RECORD` | Custom SPF macro template | (auto-generated) |
| `REDIS_IP` | Redis server IP (enables caching) | (none) |
| `REDIS_PORT` | Redis server port | `6379` |
| `BUNNY_DB_URL` | Database logging URL | (none) |
| `BUNNY_DB_TOKEN` | Database logging token | (none) |
| `SENTRY_DSN` | Sentry DSN for error tracking | (none) |
| `SENTRY_ENVIRONMENT` | Sentry environment name | `production` |
| `SENTRY_TRACES_SAMPLE_RATE` | Sentry traces sample rate | `1.0` |

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
│       │   ├── models.py       # Pydantic schemas
│       │   └── routes.py       # API endpoints
│       ├── core/
│       │   ├── __init__.py
│       │   ├── cache.py        # Redis/memory cache
│       │   ├── config.py       # Settings management
│       │   ├── database.py     # Database logging
│       │   └── extractor.py    # SPF extraction
│       ├── dns/
│       │   ├── __init__.py
│       │   ├── patterns.py     # DNS pattern matching
│       │   └── resolver.py     # DNS resolution
│       └── utils/
│           ├── __init__.py
│           ├── banners.py      # Fortune banners
│           └── decorators.py   # Sentry integration
├── requirements.in             # Production dependencies
├── requirements-dev.in         # Development dependencies
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
