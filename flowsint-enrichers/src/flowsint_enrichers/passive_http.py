"""Bound public indexed responses before JSON decoding."""

import json
from typing import Any

import requests

from flowsint_core.core.enricher_base import Enricher


def indexed_json(enricher: Enricher, url: str, params: dict) -> Any:
    try:
        with requests.get(
            url, params=params, timeout=(10, 30), stream=True, allow_redirects=False
        ) as response:
            if response.status_code != 200:
                enricher.report_issue(
                    "quota_exceeded" if response.status_code == 429 else "failed",
                    f"Indexed source returned HTTP {response.status_code}.",
                )
                return None
            body = bytearray()
            for chunk in response.iter_content(65536):
                if len(body) + len(chunk) > 4 * 1024 * 1024:
                    enricher.report_issue(
                        "partial",
                        "Indexed response exceeds 4 MiB; narrow the query. No records imported.",
                    )
                    return None
                body.extend(chunk)
            return json.loads(body)
    except (requests.RequestException, ValueError) as exc:
        enricher.report_issue(
            "failed", f"Indexed request failed ({type(exc).__name__})."
        )
        return None
