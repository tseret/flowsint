"""Authenticated diagnostics; never return connection strings or credentials."""

import os
from pathlib import Path
from typing import Any

import redis
from alembic.config import Config
from alembic.script import ScriptDirectory
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from flowsint_core.core.celery import celery
from flowsint_core.core.graph.connection import neo4j_connection
from flowsint_core.core.models import Profile
from flowsint_core.core.postgre_db import get_db
from flowsint_enrichers import ENRICHER_REGISTRY

router = APIRouter()


@router.get("")
def diagnostics(
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "revision": os.getenv("FLOWSINT_BUILD_REVISION", "development"),
        "connectors": sorted(item["name"] for item in ENRICHER_REGISTRY.list()),
    }
    config = Config()
    config.set_main_option(
        "script_location", str(Path(__file__).resolve().parents[3] / "alembic")
    )
    report["expected_migrations"] = list(
        ScriptDirectory.from_config(config).get_heads()
    )
    try:
        report["database_migrations"] = list(
            db.execute(text("SELECT version_num FROM alembic_version")).scalars()
        )
        report["postgres"] = "ok"
    except Exception:
        db.rollback()
        report["database_migrations"] = []
        report["postgres"] = "unavailable or migration table missing"
    report["migrations_current"] = set(report["database_migrations"]) == set(
        report["expected_migrations"]
    )
    try:
        cache = redis.Redis.from_url(
            os.environ["REDIS_URL"], socket_timeout=2, socket_connect_timeout=2
        )
        try:
            cache.ping()
            report["redis"] = "ok"
        finally:
            cache.close()
    except Exception:
        report["redis"] = "unavailable"
    try:
        if neo4j_connection is None:
            raise RuntimeError("Not configured")
        neo4j_connection.query("RETURN 1")
        report["neo4j"] = "ok"
    except Exception:
        report["neo4j"] = "unavailable"
    try:
        task = celery.send_task("worker_diagnostics")
        worker = task.get(timeout=3)
        report["worker"] = worker
        report["worker_matches_api"] = (
            worker["revision"] == report["revision"]
            and worker["connectors"] == report["connectors"]
        )
    except Exception:
        report["worker"] = None
        report["worker_matches_api"] = False
    return report
