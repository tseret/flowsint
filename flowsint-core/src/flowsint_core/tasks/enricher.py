import asyncio
import uuid
from datetime import datetime, timezone
from time import monotonic
from typing import Any, Dict, List, Optional

from celery import Task, states
from sqlalchemy.orm import Session

from flowsint_core.utils import to_json_serializable
from flowsint_enrichers import ENRICHER_REGISTRY, load_all_enrichers

from ..core.celery import celery
from ..core.enums import EventLevel
from ..core.logger import Logger
from ..core.models import Scan
from ..core.postgre_db import SessionLocal, get_db
from ..core.services import create_enricher_template_service, create_vault_service
from ..core.template_enricher import TemplateEnricher
from ..templates.types import Template

# Auto-discover and register all enrichers
load_all_enrichers()

db: Session = next(get_db())


@celery.task(name="run_enricher", bind=True)
def run_enricher(
    self: Task,
    enricher_name: str,
    serialized_objects: List[dict],
    sketch_id: str | None,
    owner_id: Optional[str] = None,
    params: Optional[dict] = None,
) -> Dict[str, Any]:
    started = monotonic()
    session = SessionLocal()

    try:
        scan_id = uuid.UUID(self.request.id)

        scan = Scan(
            id=scan_id,
            status=EventLevel.PENDING,
            sketch_id=uuid.UUID(sketch_id) if sketch_id else None,
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
        if failed_scan:
            failed_scan.status = EventLevel.FAILED
            failed_scan.completed_at = datetime.now(timezone.utc)
            failed_scan.summary = {
                "provider": enricher_name,
                "enricher": enricher_name,
                "scan_id": str(failed_scan.id),
                "duration_ms": round((monotonic() - started) * 1000),
                "outcome": "failed",
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

    try:
        scan_id = uuid.UUID(self.request.id)

        scan = Scan(
            id=scan_id,
            status=EventLevel.PENDING,
            sketch_id=uuid.UUID(sketch_id) if sketch_id else None,
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
        if failed_scan:
            failed_scan.status = EventLevel.FAILED
            failed_scan.completed_at = datetime.now(timezone.utc)
            failed_scan.summary = {
                "provider": template_name,
                "enricher": template_name,
                "scan_id": str(failed_scan.id),
                "duration_ms": round((monotonic() - started) * 1000),
                "outcome": "failed",
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
        session.close()
