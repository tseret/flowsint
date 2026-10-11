import asyncio
import uuid
from contextlib import ExitStack
from datetime import datetime, timezone
from time import monotonic
from typing import Any, Dict, List, Optional

from celery import Task, states
from sqlalchemy.orm import Session

from flowsint_core.utils import to_json_serializable
from flowsint_enrichers import ENRICHER_REGISTRY, load_all_enrichers

from ..core.celery import celery
from ..core.enums import EventLevel
from ..core.graph.repository import Neo4jGraphRepository
from ..core.logger import Logger
from ..core.models import Scan
from ..core.postgre_db import SessionLocal, get_db
from ..core.services import create_enricher_template_service, create_vault_service
from ..core.task_lease import task_lease
from ..core.template_enricher import TemplateEnricher
from ..templates.types import Template

# Auto-discover and register all enrichers
load_all_enrichers()

db: Session = next(get_db())


def _recover_scan(session: Session, scan: Scan) -> Dict[str, Any]:
    if scan.completed_at is None:
        # Cross-database commits cannot prove whether the last graph batch committed.
        # Preserve checkpoints and stop; retrying the provider could spend twice.
        summary = dict(scan.summary or {})
        message = "Worker interrupted; saved graph batches retained. Provider calls were not repeated."
        summary.update(
            outcome="partial",
            interrupted=True,
            graph_commit_uncertain=True,
            output_count=None,
            errors=[{"outcome": "partial", "message": message}],
        )
        scan.summary = summary
        scan.status = EventLevel.FAILED
        scan.error = message
        scan.completed_at = datetime.now(timezone.utc)
        session.commit()
    return {"result": scan.details or [], "summary": scan.summary}


def _checkpoint_enricher(
    enricher: Any, scan: Scan, session: Session, policy: dict | None = None
) -> None:
    policy = policy or {}
    enricher.provider_request_limit = policy.get("max_provider_requests")
    if enricher.provider_request_limit is not None and (
        type(enricher.provider_request_limit) is not int
        or enricher.provider_request_limit < 0
    ):
        raise ValueError("max_provider_requests must be a nonnegative integer")
    enricher.provider_request_count = 0
    repository = getattr(getattr(enricher, "_graph_service", None), "repository", None)
    if not isinstance(repository, Neo4jGraphRepository):
        return
    limit = policy.get("max_new_entities")
    if limit is not None and (type(limit) is not int or limit < 0):
        raise ValueError("max_new_entities must be a nonnegative integer")
    repository.max_new_entities = limit

    def checkpoint(count: int) -> None:
        scan.summary = {
            **(scan.summary or {}),
            "committed_graph_operations": count,
            "new_entity_count": repository.new_entity_count,
            "provider_request_count": getattr(enricher, "provider_request_count", 0),
            "provider_evidence": getattr(enricher, "provider_evidence", []),
        }
        session.commit()

    repository.on_commit = checkpoint


@celery.task(name="run_enricher", bind=True)
def run_enricher(
    self: Task,
    enricher_name: str,
    serialized_objects: List[dict],
    sketch_id: str | None,
    owner_id: Optional[str] = None,
    params: Optional[dict] = None,
    execution_policy: Optional[dict] = None,
) -> Dict[str, Any]:
    started = monotonic()
    session = SessionLocal()
    lease = ExitStack()
    enricher = None

    try:
        scan_id = uuid.UUID(self.request.id)
        if not lease.enter_context(task_lease(session, str(scan_id))):
            return {
                "in_progress": True,
                "result": [],
                "summary": {"outcome": "running", "scan_id": str(scan_id)},
            }
        existing = session.get(Scan, scan_id)
        if existing is not None:
            return _recover_scan(session, existing)

        scan = Scan(
            id=scan_id,
            status=EventLevel.RUNNING,
            sketch_id=uuid.UUID(sketch_id) if sketch_id else None,
            summary={
                "provider": enricher_name,
                "enricher": enricher_name,
                "scan_id": str(scan_id),
                "outcome": "running",
                "input_count": len(serialized_objects),
                "committed_graph_operations": 0,
            },
        )
        session.add(scan)
        session.commit()

        # Create vault instance if owner_id is provided
        vault = None
        if owner_id:
            try:
                vault = create_vault_service(session).for_user(uuid.UUID(owner_id))
            except Exception as e:
                # Logger.error's signature omits None even though the column
                # it writes is nullable and a sketch-less scan is legal here.
                Logger.error(
                    sketch_id,  # type: ignore[arg-type]
                    {"message": f"Failed to create vault: {str(e)}"},
                )
                raise RuntimeError("Could not open credential vault") from e

        if not ENRICHER_REGISTRY.enricher_exists(enricher_name):
            raise ValueError(f"Enricher '{enricher_name}' not found in registry")

        enricher = ENRICHER_REGISTRY.get_enricher(
            name=enricher_name,
            sketch_id=sketch_id,
            scan_id=scan_id,
            vault=vault,
            params=params or {},
        )

        # Deserialize objects back into Pydantic models
        # The preprocess method in Enricher will handle these already-parsed objects
        enricher.defer_status_until_commit = True
        _checkpoint_enricher(enricher, scan, session, execution_policy)
        results = asyncio.run(enricher.execute(values=serialized_objects))

        summary = getattr(enricher, "execution_summary", None) or {
            "outcome": "results" if results else "no_matches",
            "input_count": len(serialized_objects),
            "output_count": len(results),
        }
        summary = {
            "provider": enricher_name,
            "enricher": enricher_name,
            "scan_id": str(scan_id),
            "duration_ms": round((monotonic() - started) * 1000),
            "errors": [],
            **summary,
        }
        scan.status = (
            EventLevel.FAILED
            if summary["outcome"] in {"failed", "missing_credentials", "quota_exceeded"}
            else EventLevel.COMPLETED
        )
        scan.details = to_json_serializable(results)
        scan.summary = to_json_serializable(summary)
        scan.completed_at = datetime.now(timezone.utc)
        scan.error = (
            "; ".join(issue["message"] for issue in summary.get("errors", [])) or None
        )
        session.commit()
        if sketch_id:
            Logger.status(
                sketch_id,
                EventLevel.WARNING if summary["outcome"] == "partial" else scan.status,
                {"message": "Enrichment finished", "summary": scan.summary},
            )

        return {"result": scan.details, "summary": scan.summary}

    except Exception as ex:
        session.rollback()
        error_logs = f"An error occurred: {str(ex)}"
        print(f"Error in task: {error_logs}")

        failed_scan = (
            session.query(Scan).filter(Scan.id == uuid.UUID(self.request.id)).first()
        )
        if failed_scan and failed_scan.completed_at is None:
            failed_scan.status = EventLevel.FAILED
            failed_scan.completed_at = datetime.now(timezone.utc)
            checkpoint = dict(failed_scan.summary or {})
            checkpoint.update(getattr(enricher, "execution_summary", {}) or {})
            failed_scan.summary = {
                **checkpoint,
                "provider": enricher_name,
                "enricher": enricher_name,
                "scan_id": str(failed_scan.id),
                "duration_ms": round((monotonic() - started) * 1000),
                "outcome": "partial"
                if checkpoint.get("committed_graph_operations")
                else "failed",
                "errors": [{"outcome": "failed", "message": error_logs}],
                "input_count": len(serialized_objects),
                "output_count": 0,
            }
            failed_scan.error = error_logs
            session.commit()
            if sketch_id:
                Logger.status(
                    sketch_id,
                    EventLevel.FAILED,
                    {"message": "Enrichment failed", "summary": failed_scan.summary},
                )

        self.update_state(state=states.FAILURE)
        raise ex

    finally:
        lease.close()
        session.close()


@celery.task(name="run_template_enricher", bind=True)
def run_template_enricher(
    self: Task,
    template_name: str,
    serialized_objects: List[dict],
    sketch_id: str | None,
    owner_id: str,
    params: Optional[dict] = None,
) -> Dict[str, Any]:
    """Run an enricher defined by a YAML template stored in the database."""
    started = monotonic()
    session = SessionLocal()
    lease = ExitStack()
    enricher = None

    try:
        scan_id = uuid.UUID(self.request.id)
        if not lease.enter_context(task_lease(session, str(scan_id))):
            return {
                "in_progress": True,
                "result": [],
                "summary": {"outcome": "running", "scan_id": str(scan_id)},
            }
        existing = session.get(Scan, scan_id)
        if existing is not None:
            return _recover_scan(session, existing)

        scan = Scan(
            id=scan_id,
            status=EventLevel.RUNNING,
            sketch_id=uuid.UUID(sketch_id) if sketch_id else None,
            summary={
                "provider": template_name,
                "enricher": template_name,
                "scan_id": str(scan_id),
                "outcome": "running",
                "input_count": len(serialized_objects),
                "committed_graph_operations": 0,
            },
        )
        session.add(scan)
        session.commit()

        # Resolve vault for secrets
        vault = None
        try:
            vault = create_vault_service(session).for_user(uuid.UUID(owner_id))
        except Exception as e:
            Logger.error(
                sketch_id,  # type: ignore[arg-type]
                {"message": f"Failed to create vault: {str(e)}"},
            )
            raise RuntimeError("Could not open credential vault") from e

        # Load template from database
        template_service = create_enricher_template_service(session)
        db_template = template_service.find_by_name(template_name, uuid.UUID(owner_id))
        if not db_template:
            raise ValueError(
                f"Template '{template_name}' not found for user {owner_id}"
            )

        template = Template(**db_template.content)

        enricher = TemplateEnricher(
            template=template,
            sketch_id=sketch_id,
            scan_id=str(scan_id),
            vault=vault,
            params=params or {},
        )

        enricher.defer_status_until_commit = True
        _checkpoint_enricher(enricher, scan, session)
        results = asyncio.run(enricher.execute(values=serialized_objects))

        summary = getattr(enricher, "execution_summary", None) or {
            "outcome": "results" if results else "no_matches",
            "input_count": len(serialized_objects),
            "output_count": len(results),
        }
        summary = {
            "provider": template_name,
            "enricher": template_name,
            "scan_id": str(scan_id),
            "duration_ms": round((monotonic() - started) * 1000),
            "errors": [],
            **summary,
        }
        scan.status = (
            EventLevel.FAILED
            if summary["outcome"] in {"failed", "missing_credentials", "quota_exceeded"}
            else EventLevel.COMPLETED
        )
        scan.details = to_json_serializable(results)
        scan.summary = to_json_serializable(summary)
        scan.completed_at = datetime.now(timezone.utc)
        scan.error = (
            "; ".join(issue["message"] for issue in summary.get("errors", [])) or None
        )
        session.commit()
        if sketch_id:
            Logger.status(
                sketch_id,
                EventLevel.WARNING if summary["outcome"] == "partial" else scan.status,
                {"message": "Enrichment finished", "summary": scan.summary},
            )

        return {"result": scan.details, "summary": scan.summary}

    except Exception as ex:
        session.rollback()
        error_logs = f"An error occurred: {str(ex)}"
        print(f"Error in template task: {error_logs}")

        failed_scan = (
            session.query(Scan).filter(Scan.id == uuid.UUID(self.request.id)).first()
        )
        if failed_scan and failed_scan.completed_at is None:
            failed_scan.status = EventLevel.FAILED
            failed_scan.completed_at = datetime.now(timezone.utc)
            checkpoint = dict(failed_scan.summary or {})
            checkpoint.update(getattr(enricher, "execution_summary", {}) or {})
            failed_scan.summary = {
                **checkpoint,
                "provider": template_name,
                "enricher": template_name,
                "scan_id": str(failed_scan.id),
                "duration_ms": round((monotonic() - started) * 1000),
                "outcome": "partial"
                if checkpoint.get("committed_graph_operations")
                else "failed",
                "errors": [{"outcome": "failed", "message": error_logs}],
                "input_count": len(serialized_objects),
                "output_count": 0,
            }
            failed_scan.error = error_logs
            session.commit()
            if sketch_id:
                Logger.status(
                    sketch_id,
                    EventLevel.FAILED,
                    {"message": "Enrichment failed", "summary": failed_scan.summary},
                )

        self.update_state(state=states.FAILURE)
        raise ex

    finally:
        lease.close()
        session.close()
