"""Custom exceptions and error handling utilities."""

import logging
from typing import Optional

import dns.exception
import dns.resolver
import sentry_sdk

from spf_guru.core.config import get_settings

logger = logging.getLogger(__name__)


class SPFGuruError(Exception):
    """Base exception for SPF Guru errors."""


class DNSResolutionError(SPFGuruError):
    """DNS resolution failed unexpectedly."""


class SPFExtractionError(SPFGuruError):
    """SPF record extraction failed."""


class PatternMatchError(SPFGuruError):
    """DNS pattern matching failed."""


class CacheError(SPFGuruError):
    """Cache operation failed."""


class DatabaseError(SPFGuruError):
    """Database operation failed."""


def capture_exception(
    exception: Exception,
    context: Optional[dict] = None,
    level: str = "error",
) -> None:
    """
    Capture exception to Sentry if configured, otherwise log it.

    Args:
        exception: The exception to capture
        context: Additional context to include
        level: Log level ('error', 'warning', 'info')
    """
    settings = get_settings()

    # Log locally
    log_func = getattr(logger, level, logger.error)
    log_func("%s: %s", type(exception).__name__, exception, exc_info=True)

    # Send to Sentry if configured
    if settings.sentry_dsn:
        if context:
            with sentry_sdk.push_scope() as scope:
                for key, value in context.items():
                    scope.set_extra(key, value)
                sentry_sdk.capture_exception(exception)
        else:
            sentry_sdk.capture_exception(exception)


def is_expected_dns_error(exception: Exception) -> bool:
    """Check if exception is an expected DNS error (NXDOMAIN, NoAnswer, Timeout)."""
    return isinstance(
        exception,
        (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout),
    )
