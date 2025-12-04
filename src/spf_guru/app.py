"""FastAPI application entry point."""

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI

from spf_guru.api.routes import router
from spf_guru.api.healthcheck import router as healthcheck_router
from spf_guru.core.cache import init_cache
from spf_guru.core.config import get_settings
from spf_guru.core.extractor import get_extractor
from spf_guru.core.whitelist import get_whitelist_manager
from spf_guru.utils.decorators import init_sentry

# Configure logging for the application
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

# Set spf_guru loggers to INFO level
logging.getLogger("spf_guru").setLevel(logging.INFO)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Application lifespan handler."""
    # Startup
    init_sentry()
    settings = get_settings()
    init_cache(settings.use_redis, settings.redis_url)

    # Initialize whitelist manager with cache warmup callback
    whitelist = get_whitelist_manager()
    extractor = get_extractor()

    # Set warmup callback to pre-fetch SPF records for new domains
    whitelist.set_warmup_callback(extractor.get_or_compute_spf)

    # Initialize whitelist (loads from Redis or env var, starts Pub/Sub listener)
    await whitelist.initialize()

    logger.info("SPF Guru starting...")
    logger.info(f"Zone: {settings.zone_dotted}")
    logger.info(f"Redis: {'enabled' if settings.use_redis else 'disabled'}")
    logger.info(f"Sentry: {'enabled' if settings.sentry_dsn else 'disabled'}")
    logger.info(f"Whitelist: {len(whitelist.domains)} domains")
    logger.info(f"Pub/Sub: {'active' if whitelist.is_pubsub_active else 'inactive'}")

    yield

    # Shutdown
    logger.info("SPF Guru shutting down...")
    await whitelist.close()


app = FastAPI(
    title="SPF Guru",
    description="PowerDNS backend for SPF validation",
    version="1.0.0",
    lifespan=lifespan,
)

# Include API routes
app.include_router(router)
app.include_router(healthcheck_router)
