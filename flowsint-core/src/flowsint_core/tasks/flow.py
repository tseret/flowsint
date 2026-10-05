import uuid
from typing import Any, Dict, List, Optional

from celery import Task, states
from sqlalchemy.orm import Session

from flowsint_core.utils import to_json_serializable

from ..core.celery import celery
from ..core.enums import EventLevel
from ..core.logger import Logger
from ..core.models import Scan
from ..core.orchestrator import FlowOrchestrator
from ..core.postgre_db import SessionLocal, get_db
from ..core.services import create_vault_service
from ..core.types import FlowBranch

db: Session = next(get_db())


@celery.task(name="run_flow", bind=True)
def run_flow(
    self: Task,
    enricher_branches: List[dict],
    serialized_objects: List[dict],
    sketch_id: str | None,
    owner_id: Optional[str] = None,
) -> Dict[str, Any]:
    session = SessionLocal()

    try:
        if not enricher_branches:
            raise ValueError("enricher_branches not provided in the input enricher")

        scan_id = uuid.UUID(self.request.id)

        scan = Scan(
            id=scan_id,
            status=EventLevel.PENDING,
            sketch_id=uuid.UUID(sketch_id) if sketch_id else None,
            enricher="flow",
        )
        session.add(scan)
        session.commit()

        # Create vault instance if owner_id is provided
        vault = None
        if owner_id:
            try:
                vault = create_vault_service(session).for_user(uuid.UUID(owner_id))
            except Exception as e:
                # Same nullable sketch_id as in tasks/enricher.py.
                Logger.error(
                    sketch_id,  # type: ignore[arg-type]
                    {"message": f"Failed to create vault: {str(e)}"},
                )

        branches = [FlowBranch(**branch) for branch in enricher_branches]
        enricher = FlowOrchestrator(
            sketch_id=sketch_id,  # type: ignore[arg-type]  # the flows route always sends one
            scan_id=str(scan_id),
            enricher_branches=branches,
            vault=vault,
        )

        # Use the synchronous scan method which internally handles the async operations
        # Pass serialized objects instead of strings - the preprocess will handle them
        results = enricher.scan(values=serialized_objects)  # type: ignore[arg-type]

        scan.status = EventLevel.COMPLETED
        scan.details = to_json_serializable(results)
        session.commit()

        return {"result": scan.details}

    except Exception as ex:
        session.rollback()
        error_logs = f"An error occurred: {str(ex)}"
        print(f"Error in task: {error_logs}")

        failed_scan = (
            session.query(Scan).filter(Scan.id == uuid.UUID(self.request.id)).first()
        )
        if failed_scan:
            failed_scan.status = EventLevel.FAILED
            # Scan.error is a legacy Column(), not Mapped[] (see tasks/enricher.py).
            failed_scan.error = error_logs  # type: ignore[assignment]
            session.commit()

        self.update_state(state=states.FAILURE)
        raise ex

    finally:
        session.close()
