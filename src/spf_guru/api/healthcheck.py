"""Health check API endpoint."""

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from spf_guru.core.whitelist import WhitelistManager, get_whitelist_manager

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    """Response model for health check."""

    status: str
    initialized: bool
    domain_count: int
    redis_connected: bool
    pubsub_active: bool


@router.get("/healthcheck", response_model=HealthResponse)
async def health_check(
    whitelist: WhitelistManager = Depends(get_whitelist_manager),
) -> HealthResponse:
    """
    Health check endpoint (no auth required).

    Returns status of whitelist manager and Redis Pub/Sub connection.
    """
    return HealthResponse(
        status="ok",
        initialized=whitelist.is_initialized,
        domain_count=len(whitelist.domains),
        redis_connected=whitelist.uses_redis,
        pubsub_active=whitelist.is_pubsub_active,
    )
