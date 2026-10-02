"""Shared passive VirusTotal requests; never submit or rescan targets."""

import datetime
import os
from typing import Any
from urllib.parse import urlsplit

import requests

from flowsint_core.core.enricher_base import Enricher

KEY_SCHEMA = {
    "name": "VT_API_KEY",
    "type": "vaultSecret",
    "description": "The VirusTotal API key.",
    "required": True,
}
PAGE_SCHEMA = {
    "name": "max_pages",
    "type": "number",
    "required": False,
    "default": 5,
    "description": "Maximum passive DNS pages per input (40 records/page, 1–25). Remaining pages are reported as truncated.",
}


def api_key(enricher: Enricher) -> str | None:
    enricher._vt_stop = False
    key = enricher.get_secret("VT_API_KEY", os.getenv("VT_API_KEY"))
    if not key:
        enricher.report_issue("missing_credentials", "VT_API_KEY is not configured.")
    return str(key) if key else None


def timestamp(value: Any) -> str | None:
    if not value:
        return None
    return datetime.datetime.fromtimestamp(
        int(value), datetime.timezone.utc
    ).isoformat()


def request_json(
    enricher: Enricher, url: str, key: str, params: dict | None = None
) -> dict | None:
    try:
        response = requests.get(
            url,
            params=params,
            headers={"x-apikey": key},
            timeout=30,
            allow_redirects=False,
        )
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            outcome = "quota_exceeded" if response.status_code == 429 else "failed"
            enricher.report_issue(
                outcome, f"VirusTotal returned HTTP {response.status_code}."
            )
            if response.status_code in (401, 403, 429):
                enricher._vt_stop = True
            return None
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("Invalid provider response")
        return payload
    except (requests.RequestException, ValueError) as exc:
        # Exception strings can contain request URLs and secrets; retain only the type.
        enricher.report_issue(
            "failed", f"VirusTotal request failed ({type(exc).__name__})."
        )
        return None


def resolutions(enricher: Enricher, url: str, key: str) -> list[dict]:
    try:
        raw = enricher.params.get("max_pages", 5)
        max_pages = int(raw)
        if isinstance(raw, bool) or float(raw) != max_pages or not 1 <= max_pages <= 25:
            raise ValueError("max_pages must be an integer between 1 and 25")
    except (TypeError, ValueError):
        enricher.report_issue(
            "failed", "max_pages must be an integer between 1 and 25."
        )
        return []
    rows: list[dict] = []
    visited: set[str] = set()
    next_url = url
    expected = urlsplit(url)
    for page in range(max_pages):
        parsed = urlsplit(next_url)
        if (parsed.scheme, parsed.netloc, parsed.path) != (
            expected.scheme,
            expected.netloc,
            expected.path,
        ):
            enricher.report_issue(
                "partial",
                "VirusTotal returned an invalid continuation URL; pagination stopped.",
            )
            break
        if next_url in visited:
            enricher.report_issue(
                "partial", "VirusTotal repeated a continuation URL; pagination stopped."
            )
            break
        visited.add(next_url)
        payload = request_json(
            enricher, next_url, key, {"limit": 40} if page == 0 else None
        )
        if payload is None:
            break
        data = payload.get("data") or []
        if not isinstance(data, list) or any(not isinstance(row, dict) for row in data):
            enricher.report_issue(
                "partial", "VirusTotal returned malformed resolution records."
            )
            break
        rows.extend(data)
        continuation = (payload.get("links") or {}).get("next")
        if not continuation:
            break
        if not isinstance(continuation, str):
            enricher.report_issue(
                "partial", "VirusTotal returned an invalid continuation URL."
            )
            break
        next_url = continuation
        if page == max_pages - 1:
            enricher.report_issue(
                "partial",
                f"VirusTotal passive DNS truncated after {max_pages} pages; increase max_pages to retrieve more.",
            )
    return rows


async def reputation(enricher: Enricher, data: list, kind: str, field: str) -> list:
    from flowsint_types.reputation_score import ReputationScore

    enricher._pairs = []
    results: list[ReputationScore] = []
    key = api_key(enricher)
    if not key:
        return results
    for item in data:
        value = getattr(item, field)
        url = f"https://www.virustotal.com/api/v3/{kind}/{value}"
        payload = request_json(enricher, url, key)
        if payload is not None:
            try:
                attrs = (payload.get("data") or {}).get("attributes") or {}
                stats = attrs.get("last_analysis_stats") or {}
                observed = timestamp(attrs.get("last_analysis_date"))
                rep = ReputationScore(
                    entity_id=f"VirusTotal {value}",
                    entity_type=type(item).__name__,
                    score=attrs.get("reputation"),
                    score_type="community_reputation",
                    provider="VirusTotal",
                    source=url,
                    last_updated=observed,
                    factors=[
                        f"{name}: {count}" for name, count in sorted(stats.items())
                    ],
                    description="Community vote score; negative suggests maliciousness, positive suggests harmlessness. Engine verdict counts are independent observations, not a certainty.",
                    analysis_stats=stats,
                    total_votes=attrs.get("total_votes") or {},
                    categories=attrs.get("categories") or {},
                    tags=attrs.get("tags") or [],
                )
            except (ValueError, TypeError, AttributeError, OverflowError, OSError):
                enricher.report_issue(
                    "failed", "VirusTotal returned invalid reputation metadata."
                )
                continue
            results.append(rep)
            enricher._pairs.append((item, rep))
        if enricher._vt_stop:
            break
    return results


def reputation_graph(enricher: Enricher, results: list) -> list:
    if enricher._graph_service:
        for item, rep in enricher._pairs:
            enricher.create_node(item)
            enricher.create_node(rep)
            enricher.create_relationship(
                item,
                rep,
                "HAS_REPUTATION",
                observed_at=rep.last_updated,
                source_ref=rep.source,
                provider="VirusTotal",
            )
    return results
