"""Read-only worker build and connector inventory."""

import os
from typing import Any

from flowsint_core.core.celery import celery


@celery.task(name="worker_diagnostics")
def worker_diagnostics() -> dict[str, Any]:
    from flowsint_enrichers import ENRICHER_REGISTRY

    return {
        "revision": os.getenv("FLOWSINT_BUILD_REVISION", "development"),
        "connectors": sorted(item["name"] for item in ENRICHER_REGISTRY.list()),
    }
