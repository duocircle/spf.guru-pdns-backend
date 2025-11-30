"""Database logging functionality."""

import json

import aiohttp

from spf_guru.core.config import get_settings
from spf_guru.utils.decorators import sentry_exception_catcher


@sentry_exception_catcher
async def log_spf_result(domain: str, ip: str, result: str, ipversion: int) -> bool:
    """
    Log SPF check result to database.

    Args:
        domain: The domain that was checked
        ip: The IP address that was checked
        result: The SPF result ('pass' or 'fail')
        ipversion: IP version (4 or 6)

    Returns:
        True if successful, raises RuntimeError otherwise
    """
    settings = get_settings()

    if not settings.bunny_db_url or not settings.bunny_db_token:
        return False

    query = """
        INSERT INTO spf_results (domain, ip, result, ipversion)
        VALUES (?1, ?2, ?3, ?4);
    """

    data = {"statements": [{"q": query, "params": [domain, ip, result, ipversion]}]}

    headers = {
        "Authorization": f"Bearer {settings.bunny_db_token}",
        "Content-Type": "application/json",
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(
            settings.bunny_db_url, headers=headers, data=json.dumps(data)
        ) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise RuntimeError(f"DB insert failed: {resp.status} | {text}")
            return True
