"""FastAPI application entry point."""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from spf_guru.api.routes import router
from spf_guru.core.cache import init_cache
from spf_guru.core.config import get_settings
from spf_guru.utils.decorators import init_sentry


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Application lifespan handler."""
    # Startup
    init_sentry()
    settings = get_settings()
    init_cache(settings.use_redis, settings.redis_url)
    print("SPF Guru starting...")
    print(f"Zone: {settings.zone_dotted}")
    print(f"Redis: {'enabled' if settings.use_redis else 'disabled'}")
    print(f"Sentry: {'enabled' if settings.sentry_dsn else 'disabled'}")
    yield
    # Shutdown (if needed)
    print("SPF Guru shutting down...")


app = FastAPI(
    title="SPF Guru",
    description="PowerDNS backend for SPF validation",
    version="1.0.0",
    lifespan=lifespan,
)

# Include API routes
app.include_router(router)
