"""Decorators for error handling and monitoring."""

import asyncio
import functools
from typing import Callable, TypeVar

import sentry_sdk

from spf_guru.core.config import get_settings

F = TypeVar("F", bound=Callable)


def sentry_exception_catcher(func: F) -> F:
    """
    Decorator to catch exceptions and report to Sentry.

    Works with both sync and async functions.
    Only reports if Sentry is configured (SENTRY_DSN is set).
    """

    @functools.wraps(func)
    async def async_wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            settings = get_settings()

            if settings.sentry_dsn:
                sentry_sdk.capture_exception(e)
            raise

    @functools.wraps(func)
    def sync_wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            settings = get_settings()
            if settings.sentry_dsn:
                sentry_sdk.capture_exception(e)
            raise

    if asyncio.iscoroutinefunction(func):
        return async_wrapper  # type: ignore
    return sync_wrapper  # type: ignore


def init_sentry() -> None:
    """Initialize Sentry SDK if configured."""
    settings = get_settings()

    if not settings.sentry_dsn:
        return

    sentry_sdk.init(
        dsn=settings.sentry_dsn,
        environment=settings.sentry_environment,
        traces_sample_rate=settings.sentry_traces_sample_rate,
        send_default_pii=False,
    )
