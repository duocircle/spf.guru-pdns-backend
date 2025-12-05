"""Dynamic whitelist management for SPF Guru with Redis Pub/Sub support."""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, Optional, Set

import redis.asyncio as aioredis

from spf_guru.core.cache import cache_delete
from spf_guru.core.config import Settings, get_settings


logger = logging.getLogger(__name__)

# Redis keys for persistence
REDIS_WHITELIST_SET = "spf:whitelist"
REDIS_DOMAIN_INFO_PREFIX = "spf:domain:"

# Redis Pub/Sub channels (events from dmarcreport)
CHANNEL_DOMAINS_LIST = "spf:domains:list"  # Full domain list sync
CHANNEL_DOMAINS_ADD = "spf:domains:add"  # Single domain added
CHANNEL_DOMAINS_REMOVE = "spf:domains:remove"  # Single domain removed

# Redis Pub/Sub channel (request TO dmarcreport)
CHANNEL_DOMAINS_SYNC_REQUEST = "spf:domains:sync_request"  # Request full sync


@dataclass
class DomainInfo:
    """Metadata for a whitelisted domain."""

    domain: str
    added_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_refresh: Optional[datetime] = None
    spf_ttl: int = 3600  # Default TTL, updated after SPF extraction
    ip_count: int = 0
    status: str = "active"  # active, error, pending

    def to_dict(self) -> dict:
        """Convert to dictionary for Redis storage."""
        return {
            "domain": self.domain,
            "added_at": self.added_at.isoformat(),
            "last_refresh": self.last_refresh.isoformat() if self.last_refresh else "",
            "spf_ttl": str(self.spf_ttl),
            "ip_count": str(self.ip_count),
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DomainInfo":
        """Create from dictionary (Redis storage)."""
        last_refresh = None

        if data.get("last_refresh"):
            last_refresh = datetime.fromisoformat(data["last_refresh"])

        return cls(
            domain=data["domain"],
            added_at=datetime.fromisoformat(data["added_at"]),
            last_refresh=last_refresh,
            spf_ttl=int(data.get("spf_ttl", 3600)),
            ip_count=int(data.get("ip_count", 0)),
            status=data.get("status", "active"),
        )


class WhitelistManager:
    """
    Manages the dynamic whitelist of allowed domains.

    Supports:
    - Redis-backed whitelist with metadata persistence
    - Redis Pub/Sub for real-time updates from dmarcreport
    - In-memory cache for fast lookups
    - Fallback to MY_DOMAINS env var if Redis unavailable
    """

    def __init__(
        self,
        settings: Optional[Settings] = None,
        redis_client: Optional[aioredis.Redis] = None,
    ):
        self._settings = settings or get_settings()
        self._redis: Optional[aioredis.Redis] = redis_client
        self._pubsub: Optional[aioredis.client.PubSub] = None

        # In-memory whitelist: domain -> DomainInfo (cache)
        self._domains: Dict[str, DomainInfo] = {}

        # Lock for thread-safe operations
        self._lock = asyncio.Lock()

        # Background task for Pub/Sub listener
        self._pubsub_task: Optional[asyncio.Task] = None

        # Callback for cache warmup (set by app during init)
        self._warmup_callback: Optional[Callable[[str], asyncio.Future]] = None

        # Flag to track if initial sync completed
        self._initialized = False

        # Background task for periodic sync requests
        self._sync_task: Optional[asyncio.Task] = None

        # Sync interval from settings
        self._sync_interval: int = self._settings.sync_interval

    @property
    def domains(self) -> Set[str]:
        """Return current whitelisted domains as a set."""
        return set(self._domains.keys())

    @property
    def is_initialized(self) -> bool:
        """Check if whitelist has been initialized."""
        return self._initialized

    @property
    def uses_redis(self) -> bool:
        """Check if Redis is being used for persistence."""
        return self._redis is not None

    @property
    def is_pubsub_active(self) -> bool:
        """Check if Pub/Sub listener is running."""
        return self._pubsub_task is not None and not self._pubsub_task.done()

    def set_warmup_callback(self, callback: Callable[[str], asyncio.Future]) -> None:
        """Set the callback function for cache warmup."""
        self._warmup_callback = callback

    async def _init_redis(self) -> bool:
        """Initialize Redis connection if configured."""
        if self._redis is not None:
            return True

        settings = self._settings

        if not settings.use_redis:
            return False

        try:
            self._redis = aioredis.from_url(
                settings.redis_url,
                encoding="utf-8",
                decode_responses=True,
            )
            # Test connection
            await self._redis.ping()
            logger.info("Whitelist Redis connection established")

            return True
        except Exception as e:
            logger.error(f"Failed to connect to Redis for whitelist: {e}")
            self._redis = None

            return False

    async def close(self) -> None:
        """Cleanup resources."""
        # Stop periodic sync task
        if self._sync_task and not self._sync_task.done():
            self._sync_task.cancel()

            try:
                await self._sync_task
            except asyncio.CancelledError:
                pass

        # Stop Pub/Sub listener
        if self._pubsub_task and not self._pubsub_task.done():
            self._pubsub_task.cancel()
            try:
                await self._pubsub_task
            except asyncio.CancelledError:
                pass

        # Close Pub/Sub connection
        if self._pubsub:
            await self._pubsub.unsubscribe()
            await self._pubsub.aclose()
            self._pubsub = None

        if self._redis:
            await self._redis.aclose()
            self._redis = None

    async def _load_from_redis(self) -> bool:
        """Load whitelist from Redis into memory cache."""
        if not self._redis:
            return False

        try:
            # Get all domains from the set
            domains = await self._redis.smembers(REDIS_WHITELIST_SET)

            async with self._lock:
                self._domains.clear()

                for domain in domains:
                    # Try to get domain info from hash
                    info_key = f"{REDIS_DOMAIN_INFO_PREFIX}{domain}"
                    info_data = await self._redis.hgetall(info_key)

                    if info_data:
                        self._domains[domain] = DomainInfo.from_dict(info_data)
                    else:
                        # Domain in set but no info - create default
                        self._domains[domain] = DomainInfo(
                            domain=domain,
                            status="active",
                        )

            logger.info(f"Loaded {len(domains)} domains from Redis")

            return True

        except Exception as e:
            logger.error(f"Failed to load whitelist from Redis: {e}")
            return False

    async def _save_domain_to_redis(self, info: DomainInfo) -> bool:
        """Save a domain to Redis."""
        if not self._redis:
            return False

        try:
            domain = info.domain
            # Add to set
            await self._redis.sadd(REDIS_WHITELIST_SET, domain)
            # Save info hash
            info_key = f"{REDIS_DOMAIN_INFO_PREFIX}{domain}"
            await self._redis.hset(info_key, mapping=info.to_dict())

            return True
        except Exception as e:
            logger.error(f"Failed to save domain to Redis: {e}")
            return False

    async def _remove_domain_from_redis(self, domain: str) -> bool:
        """Remove a domain from Redis."""
        if not self._redis:
            return False

        try:
            # Remove from set
            await self._redis.srem(REDIS_WHITELIST_SET, domain)
            # Remove info hash
            info_key = f"{REDIS_DOMAIN_INFO_PREFIX}{domain}"
            await self._redis.delete(info_key)

            return True
        except Exception as e:
            logger.error(f"Failed to remove domain from Redis: {e}")
            return False

    async def initialize(self) -> bool:
        """
        Initialize whitelist from Redis persistence or fallback to env var.

        Priority:
        1. Load from Redis (if configured and has data)
        2. Fallback to MY_DOMAINS env var

        After initialization, starts Pub/Sub listener for real-time updates
        from dmarcreport.

        Returns True if initialization was successful.
        """
        settings = self._settings

        # Try to connect to Redis
        redis_available = await self._init_redis()

        # Try to load from Redis first
        if redis_available:
            loaded = await self._load_from_redis()

            if loaded and self._domains:
                logger.info(
                    f"Initialized whitelist from Redis: {len(self._domains)} domains"
                )
                self._initialized = True
                # Start Pub/Sub listener
                await self._start_pubsub_listener()

                return True

        # Load from env var as baseline
        env_domains = settings.my_domains_set

        if env_domains:
            async with self._lock:
                for domain in env_domains:
                    info = DomainInfo(domain=domain.lower(), status="active")
                    self._domains[domain.lower()] = info
                    # Save to Redis if available
                    await self._save_domain_to_redis(info)

            logger.info(f"Loaded {len(env_domains)} domains from MY_DOMAINS env var")

        # Start Pub/Sub listener if Redis available
        if redis_available:
            await self._start_pubsub_listener()

        self._initialized = True
        return True

    async def _start_pubsub_listener(self) -> None:
        """Start the Redis Pub/Sub listener for domain events."""
        if not self._redis:
            logger.warning("Cannot start Pub/Sub listener: Redis not available")
            return

        try:
            self._pubsub = self._redis.pubsub()

            await self._pubsub.subscribe(
                CHANNEL_DOMAINS_LIST,
                CHANNEL_DOMAINS_ADD,
                CHANNEL_DOMAINS_REMOVE,
            )
            logger.info(
                f"Subscribed to Redis channels: {CHANNEL_DOMAINS_LIST}, "
                f"{CHANNEL_DOMAINS_ADD}, {CHANNEL_DOMAINS_REMOVE}"
            )

            # Start listener task
            self._pubsub_task = asyncio.create_task(self._pubsub_listener_loop())

            # Start periodic sync request task (if enabled)
            if self._settings.sync_enabled:
                self._sync_task = asyncio.create_task(self._periodic_sync_loop())
            else:
                logger.info("Periodic sync disabled (set SYNC_ENABLED=true to enable)")
        except Exception as e:
            logger.error(f"Failed to start Pub/Sub listener: {e}")

    async def request_sync(self) -> bool:
        """
        Request a full domain list sync from dmarcreport.

        Publishes to spf:domains:sync_request channel. dmarcreport should
        listen on this channel and respond by publishing to spf:domains:list.

        Returns True if request was published, False otherwise.
        """
        if not self._redis:
            logger.warning("Cannot request sync: Redis not available")
            return False

        try:
            payload = json.dumps(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "current_count": len(self._domains),
                }
            )
            subscribers = await self._redis.publish(
                CHANNEL_DOMAINS_SYNC_REQUEST, payload
            )
            logger.info(f"Sync request published ({subscribers} subscribers)")

            return subscribers > 0
        except Exception as e:
            logger.error(f"Failed to publish sync request: {e}")
            return False

    async def _periodic_sync_loop(self) -> None:
        """Background task that periodically requests domain list sync."""
        logger.info(f"Periodic sync started (interval: {self._sync_interval}s)")

        # Request sync on startup
        await asyncio.sleep(5)  # Brief delay to let dmarcreport connect
        await self.request_sync()

        try:
            while True:
                await asyncio.sleep(self._sync_interval)
                await self.request_sync()
        except asyncio.CancelledError:
            logger.info("Periodic sync stopped")
            raise

    async def _pubsub_listener_loop(self) -> None:
        """Background task that listens for Pub/Sub messages."""
        logger.info("Pub/Sub listener started")

        try:
            while True:
                try:
                    message = await self._pubsub.get_message(
                        ignore_subscribe_messages=True, timeout=1.0
                    )
                    if message is not None:
                        await self._handle_pubsub_message(message)
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    logger.error(f"Error processing Pub/Sub message: {e}")
                    await asyncio.sleep(1)  # Brief pause before retrying
        except asyncio.CancelledError:
            logger.info("Pub/Sub listener stopped")
            raise

    async def _handle_pubsub_message(self, message: dict) -> None:
        """Handle incoming Pub/Sub message from dmarcreport."""
        channel = message.get("channel")
        data = message.get("data")

        if not channel or not data:
            return

        logger.debug(f"Received Pub/Sub message on {channel}: {data[:100]}...")

        try:
            if channel == CHANNEL_DOMAINS_LIST:
                await self._handle_domains_list(data)
            elif channel == CHANNEL_DOMAINS_ADD:
                await self._handle_domain_add(data)
            elif channel == CHANNEL_DOMAINS_REMOVE:
                await self._handle_domain_remove(data)
        except Exception as e:
            logger.error(f"Error handling message on {channel}: {e}")

    async def _handle_domains_list(self, data: str) -> None:
        """Handle full domain list sync from dmarcreport."""
        try:
            payload = json.loads(data)
            domains = payload.get("domains", [])

            if not isinstance(domains, list):
                logger.error("Invalid domains list format")
                return

            async with self._lock:
                current_domains = set(self._domains.keys())
                new_domains = set(d.lower() for d in domains)

                # Remove domains no longer in list
                removed = current_domains - new_domains

                for domain in removed:
                    del self._domains[domain]
                    await self._remove_domain_from_redis(domain)

                # Add new domains
                added = new_domains - current_domains

                for domain in added:
                    info = DomainInfo(domain=domain, status="pending")
                    self._domains[domain] = info
                    await self._save_domain_to_redis(info)

            # Invalidate SPF cache for removed domains
            for domain in removed:
                await cache_delete(f"spf:{domain}")

            # Warmup cache for new domains (outside lock)
            if self._warmup_callback and added:
                await self._warmup_domains(added)

            logger.info(
                f"Domain list sync: added {len(added)}, removed {len(removed)}, "
                f"total {len(self._domains)}"
            )

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in domains list: {e}")

    async def _handle_domain_add(self, data: str) -> None:
        """Handle single domain add event from dmarcreport."""
        try:
            payload = json.loads(data)
            domain = payload.get("domain", "").lower().strip()

            if not domain:
                logger.error("Missing domain in add event")
                return

            async with self._lock:
                if domain in self._domains:
                    logger.debug(f"Domain {domain} already in whitelist")
                    return

                info = DomainInfo(domain=domain, status="pending")
                self._domains[domain] = info
                await self._save_domain_to_redis(info)

            logger.info(f"Domain added via Pub/Sub: {domain}")

            # Warmup cache
            if self._warmup_callback:
                await self._warmup_domains({domain})

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in domain add event: {e}")

    async def _handle_domain_remove(self, data: str) -> None:
        """Handle single domain remove event from dmarcreport."""
        try:
            payload = json.loads(data)
            domain = payload.get("domain", "").lower().strip()

            if not domain:
                logger.error("Missing domain in remove event")
                return

            async with self._lock:
                if domain not in self._domains:
                    logger.debug(f"Domain {domain} not in whitelist")
                    return

                del self._domains[domain]
                await self._remove_domain_from_redis(domain)

            # Invalidate SPF cache for this domain
            await cache_delete(f"spf:{domain}")

            logger.info(f"Domain removed via Pub/Sub: {domain}")

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in domain remove event: {e}")

    async def _warmup_domains(self, domains: Set[str]) -> None:
        """Warmup cache for a set of domains."""
        if not self._warmup_callback:
            return

        warmup_tasks = [self._warmup_callback(domain) for domain in domains]
        results = await asyncio.gather(*warmup_tasks, return_exceptions=True)

        for domain, result in zip(domains, results):
            if isinstance(result, Exception):
                logger.warning(f"Warmup failed for {domain}: {result}")
                await self.update_domain_info(domain, status="error")
            else:
                ip_count = len(result.get("ips", [])) if isinstance(result, dict) else 0
                await self.update_domain_info(
                    domain, status="active", ip_count=ip_count
                )

    async def add_domain(self, domain: str, warmup: bool = True) -> DomainInfo:
        """
        Add a domain to the whitelist.

        Args:
            domain: Domain name to add
            warmup: Whether to pre-fetch SPF records

        Returns:
            DomainInfo for the added domain
        """
        domain = domain.lower().strip()

        async with self._lock:
            if domain in self._domains:
                return self._domains[domain]

            info = DomainInfo(domain=domain, status="pending")
            self._domains[domain] = info
            await self._save_domain_to_redis(info)

        logger.info(f"Domain added to whitelist: {domain}")

        # Warmup cache
        if warmup and self._warmup_callback:
            try:
                result = await self._warmup_callback(domain)
                ip_count = len(result.get("ips", [])) if isinstance(result, dict) else 0
                await self.update_domain_info(
                    domain, status="active", ip_count=ip_count
                )
            except Exception as e:
                logger.warning(f"Warmup failed for {domain}: {e}")
                await self.update_domain_info(domain, status="error")

        return self._domains.get(domain, info)

    async def remove_domain(self, domain: str) -> bool:
        """
        Remove a domain from the whitelist.

        Returns True if domain was removed, False if it wasn't in the list.
        """
        domain = domain.lower().strip()

        async with self._lock:
            if domain not in self._domains:
                return False

            del self._domains[domain]
            await self._remove_domain_from_redis(domain)

        # Invalidate SPF cache for this domain
        await cache_delete(f"spf:{domain}")

        logger.info(f"Domain removed from whitelist: {domain}")
        return True

    def is_allowed(self, domain: str) -> bool:
        """
        Check if a domain is in the whitelist.

        If whitelist is empty, returns True (allow all).
        """
        # If no domains configured, allow all (backwards compatible)
        if not self._domains:
            return True

        return domain.lower().strip() in self._domains

    async def get_domain_info(self, domain: str) -> Optional[DomainInfo]:
        """Get metadata for a whitelisted domain."""
        return self._domains.get(domain.lower().strip())

    async def list_domains(self) -> list[dict]:
        """Return list of all whitelisted domains with metadata."""
        return [
            {
                "domain": info.domain,
                "added_at": info.added_at.isoformat(),
                "last_refresh": (
                    info.last_refresh.isoformat() if info.last_refresh else None
                ),
                "spf_ttl": info.spf_ttl,
                "ip_count": info.ip_count,
                "status": info.status,
            }
            for info in self._domains.values()
        ]

    async def update_domain_info(
        self,
        domain: str,
        spf_ttl: Optional[int] = None,
        ip_count: Optional[int] = None,
        status: Optional[str] = None,
    ) -> None:
        """Update metadata for a domain after SPF extraction."""
        domain = domain.lower().strip()

        async with self._lock:
            if domain not in self._domains:
                return

            info = self._domains[domain]
            info.last_refresh = datetime.now(timezone.utc)

            if spf_ttl is not None:
                info.spf_ttl = spf_ttl
            if ip_count is not None:
                info.ip_count = ip_count
            if status is not None:
                info.status = status

            # Persist to Redis
            await self._save_domain_to_redis(info)


# Global whitelist manager instance
_whitelist_manager: Optional[WhitelistManager] = None


def get_whitelist_manager() -> WhitelistManager:
    """Get or create the default whitelist manager."""
    global _whitelist_manager

    if _whitelist_manager is None:
        _whitelist_manager = WhitelistManager()

    return _whitelist_manager


def set_whitelist_manager(manager: WhitelistManager) -> None:
    """Set a custom whitelist manager (useful for testing)."""
    global _whitelist_manager

    _whitelist_manager = manager


def reset_whitelist_manager() -> None:
    """Reset the whitelist manager (useful for testing)."""
    global _whitelist_manager

    _whitelist_manager = None


async def init_whitelist() -> bool:
    """Initialize the whitelist manager. Call at app startup."""
    manager = get_whitelist_manager()

    return await manager.initialize()
