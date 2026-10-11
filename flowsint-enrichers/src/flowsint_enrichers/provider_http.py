"""Bounded passive lookups with credential-scoped coordination and provenance."""

import hashlib
import json
import math
import os
import random
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import redis
import requests

MAX_BYTES = 4 * 1024 * 1024
CACHE_TTL = {"VirusTotal": 3600, "Shodan": 900}
REFRESH_SCHEMA = {
    "name": "refresh",
    "type": "boolean",
    "default": "false",
    "required": False,
    "description": "Refresh provider evidence instead of using a fresh cached response. Shared cooldowns still apply.",
}


def _redis() -> Any:
    url = os.getenv("REDIS_URL")
    return (
        redis.from_url(url, socket_timeout=2, socket_connect_timeout=2) if url else None
    )


def retry_after(value: str | None, default: int = 60) -> int:
    try:
        seconds = float(value or "")
    except ValueError:
        try:
            seconds = (
                parsedate_to_datetime(value or "") - datetime.now(timezone.utc)
            ).total_seconds()
        except (ValueError, TypeError, OverflowError):
            return default
    return max(1, math.ceil(seconds)) if math.isfinite(seconds) else default


def request_identity(
    provider: str, url: str, key: str, params: dict | None
) -> tuple[str, str]:
    parsed = urlsplit(url)
    expected = {"VirusTotal": "www.virustotal.com", "Shodan": "api.shodan.io"}[provider]
    if (
        parsed.scheme != "https"
        or parsed.hostname != expected
        or parsed.username
        or parsed.password
        or parsed.port not in (None, 443)
    ):
        raise ValueError("Invalid provider URL")
    query = parse_qsl(parsed.query, keep_blank_values=True) + [
        (str(k), str(v)) for k, v in (params or {}).items()
    ]
    if any(k.lower() in ("key", "apikey", "x-apikey") for k, _ in query):
        raise ValueError("Credentials must be supplied separately")
    canonical = urlunsplit(
        ("https", expected, parsed.path, urlencode(sorted(query)), "")
    )
    account = hashlib.sha256((provider + "\0" + key).encode()).hexdigest()
    request_id = hashlib.sha256(canonical.encode()).hexdigest()
    return f"flowsint:provider:{account}", request_id


def _record(
    enricher: Any, provider: str, request_id: str, record: dict, reused: bool
) -> dict:
    evidence = getattr(enricher, "provider_evidence", None)
    if evidence is None:
        evidence = enricher.provider_evidence = []
    enricher.last_provider_evidence = {
        "provider": provider,
        "request_id": request_id,
        "fetched_at": record["fetched_at"],
        "source_scan_id": record["source_scan_id"],
        "cache_hit": reused,
    }
    if len(evidence) < 1000:
        evidence.append(enricher.last_provider_evidence)
    return dict(record["payload"])


def request_json(
    enricher: Any, provider: str, url: str, key: str, params: dict | None = None
) -> dict | None:
    """Failures never become cached empty evidence; configured Redis fails closed."""
    lock = None
    enricher.last_provider_evidence = None
    if getattr(enricher, "_provider_stop", False):
        return None
    try:
        account, request_id = request_identity(provider, url, key, params)
        client = _redis()
        cache_key = f"{account}:response:{request_id}"
        cooldown_key = f"{account}:cooldown"
        started_at = datetime.now(timezone.utc).isoformat()
        refresh = str(enricher.params.get("refresh", "false")).lower() == "true"
        if client:
            cached = client.get(cache_key)
            if cached and not refresh:
                return _record(enricher, provider, request_id, json.loads(cached), True)
            # A credential-level lease also prevents other inputs racing a quota response.
            lock = client.lock(
                f"{account}:request-lock", timeout=180, blocking_timeout=5
            )
            if not lock.acquire():
                enricher.report_issue(
                    "partial",
                    f"{provider} has a lookup in progress; retry after it completes.",
                )
                return None
            cached = client.get(cache_key)
            if cached:
                record = json.loads(cached)
                if not refresh or record["fetched_at"] >= started_at:
                    return _record(enricher, provider, request_id, record, True)
            cooldown = client.get(cooldown_key)
            if cooldown:
                status = int(cooldown)
                enricher._provider_stop = True
                enricher.report_issue(
                    "quota_exceeded" if status == 429 else "failed",
                    f"{provider} credential is cooling down after HTTP {status}.",
                )
                return None
        for attempt in range(2):
            count = getattr(enricher, "provider_request_count", 0)
            limit = getattr(enricher, "provider_request_limit", None)
            if limit is not None and count >= limit:
                enricher._provider_stop = True
                enricher.report_issue(
                    "partial", f"{provider} request budget exhausted."
                )
                return None
            enricher.provider_request_count = count + 1
            response = None
            try:
                deadline = time.monotonic() + 40
                response = requests.get(
                    url,
                    params={
                        **(params or {}),
                        **({"key": key} if provider == "Shodan" else {}),
                    },
                    headers={"x-apikey": key} if provider == "VirusTotal" else {},
                    timeout=(5, 30),
                    allow_redirects=False,
                    stream=True,
                )
                status = response.status_code
                if status in (401, 403, 429):
                    enricher._provider_stop = True
                    if client:
                        client.set(
                            cooldown_key,
                            status,
                            ex=retry_after(
                                response.headers.get("Retry-After"),
                                300 if status != 429 else 60,
                            ),
                        )
                    enricher.report_issue(
                        "quota_exceeded" if status == 429 else "failed",
                        f"{provider} returned HTTP {status}; remaining inputs stopped.",
                    )
                    return None
                if status == 404:
                    return None
                if status in (500, 502, 503, 504) and attempt == 0:
                    delay = retry_after(response.headers.get("Retry-After"), 1)
                    if delay <= 2:
                        response.close()
                        time.sleep(delay + random.uniform(0, 0.25))
                        continue
                    enricher._provider_stop = True
                    if client:
                        client.set(cooldown_key, status, ex=delay)
                if status != 200:
                    enricher.report_issue(
                        "failed", f"{provider} returned HTTP {status}."
                    )
                    return None
                body = bytearray()
                for chunk in response.iter_content(chunk_size=65536):
                    if time.monotonic() > deadline:
                        raise ValueError("Provider response exceeded time limit")
                    if len(body) + len(chunk) > MAX_BYTES:
                        raise ValueError("Provider response exceeds size limit")
                    body.extend(chunk)
                payload = json.loads(body)
                if not isinstance(payload, dict):
                    raise ValueError("Invalid provider response")
                record = {
                    "payload": payload,
                    "fetched_at": datetime.now(timezone.utc).isoformat(),
                    "source_scan_id": str(enricher.scan_id),
                }
                if client:
                    client.set(cache_key, json.dumps(record), ex=CACHE_TTL[provider])
                return _record(enricher, provider, request_id, record, False)
            except (requests.Timeout, requests.ConnectionError):
                if attempt:
                    raise
                time.sleep(1 + random.uniform(0, 0.25))
            finally:
                if response is not None:
                    response.close()
    except (
        redis.RedisError,
        requests.RequestException,
        ValueError,
        TypeError,
        OverflowError,
    ) as exc:
        # URLs and exception strings can contain provider credentials.
        enricher.report_issue(
            "failed", f"{provider} lookup failed ({type(exc).__name__})."
        )
    finally:
        if lock is not None:
            try:
                if lock.owned():
                    lock.release()
            except redis.RedisError:
                pass  # Lease expires even if Redis became unavailable.
    return None
