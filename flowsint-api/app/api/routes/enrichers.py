from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from flowsint_core.core.celery import celery
from flowsint_core.core.graph import create_graph_service
from flowsint_core.core.models import (
    Investigation,
    InvestigationUserRole,
    Key,
    Profile,
    Scan,
    Sketch,
)
from flowsint_core.core.postgre_db import get_db
from flowsint_core.core.services import (
    NotFoundError,
    PermissionDeniedError,
    create_enricher_service,
    create_enricher_template_service,
)
from flowsint_core.core.services.type_registry_service import (
    create_type_registry_service,
)
from flowsint_enrichers import ENRICHER_REGISTRY, load_all_enrichers

load_all_enrichers()


class launchEnricherPayload(BaseModel):
    node_ids: List[str]
    sketch_id: str
    # Left loose on purpose: the enricher's own ParamsModel (built from its
    # params_schema) is what actually validates these, and it differs per
    # enricher, so constraining the shape here would only reject values the
    # enricher would have accepted.
    params: Optional[Dict[str, Any]] = None


router = APIRouter()


# response_model=None is load-bearing: this endpoint mixes registry dicts with
# EnricherTemplate ORM rows, and a return annotation alone would make FastAPI
# adopt it as a response model, which pydantic cannot serialize the rows
# through. The annotation exists for mypy, not for the wire format.
@router.get("", response_model=None)
def get_enrichers(
    category: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> list:
    """Get all enrichers, optionally filtered by category."""
    enricher_service = create_enricher_service(db)
    enrichers: list = enricher_service.get_all_enrichers(
        category, current_user.id, ENRICHER_REGISTRY
    )
    return enrichers


@router.get("/readiness")
def get_readiness(
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> dict[str, Any]:
    """Credential presence and recent accessible runs; secret values stay in Vault."""
    available_keys = set(
        db.execute(select(Key.name).where(Key.owner_id == current_user.id)).scalars()
    )
    memberships = select(InvestigationUserRole.investigation_id).where(
        InvestigationUserRole.user_id == current_user.id
    )
    # ponytail: bounded recent history, indexed per-provider history if cases exceed 500 runs.
    recent = (
        db.query(Scan)
        .join(Sketch, Sketch.id == Scan.sketch_id)
        .join(Investigation, Investigation.id == Sketch.investigation_id)
        .filter(
            or_(
                Investigation.owner_id == current_user.id,
                Investigation.id.in_(memberships),
            )
        )
        .order_by(Scan.started_at.desc())
        .limit(500)
        .all()
    )
    readiness: dict[str, Any] = {}
    for enricher in get_enrichers(None, db, current_user):
        name = enricher["name"] if isinstance(enricher, dict) else enricher.name
        schema = (
            enricher.get("params_schema", [])
            if isinstance(enricher, dict)
            else enricher.params_schema
        )
        missing = [
            param["name"]
            for param in schema
            if param.get("type") == "vaultSecret"
            and param.get("required")
            and param["name"] not in available_keys
        ]
        readiness[name] = {
            "credentials_configured": not missing,
            "missing_required_keys": missing,
            "last_run": None,
            "last_run_at": None,
            "last_success_at": None,
        }
    for run in recent:
        summary = getattr(run, "summary", None) or {}
        entry = readiness.get(str(summary.get("enricher", "")))
        if entry is None:
            continue
        timestamp = run.started_at.isoformat() if run.started_at else None
        if entry["last_run"] is None:
            entry["last_run"] = summary
            entry["last_run_at"] = timestamp
        if entry["last_success_at"] is None and summary.get("outcome") in (
            "results",
            "no_matches",
        ):
            entry["last_success_at"] = timestamp
    return readiness


@router.post("/{enricher_name}/launch")
async def launch_enricher(
    enricher_name: str,
    payload: launchEnricherPayload,
    current_user: Profile = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, str]:
    enricher_service = create_enricher_service(db)
    try:
        # Before anything reads the graph: an enricher writes its findings into
        # this sketch, so the caller needs update rights on its investigation.
        enricher_service.get_sketch_for_launch(payload.sketch_id, current_user.id)

        # Retrieve nodes from Neo4J by their element IDs
        type_registry = create_type_registry_service(db)
        resolver = type_registry.build_type_resolver(current_user.id)
        graph_service = create_graph_service(
            sketch_id=payload.sketch_id, type_resolver=resolver
        )
        entities = graph_service.get_nodes_by_ids_for_task(payload.node_ids)

        # Send deserialized nodes
        entities = [
            entity.model_dump(mode="json", serialize_as_any=True) for entity in entities
        ]
        if not entities:
            raise HTTPException(
                status_code=404, detail="No entities found with provided IDs"
            )

        is_template = False
        enricher_in_registry = ENRICHER_REGISTRY.enricher_exists(enricher_name)
        if not enricher_in_registry:
            template_service = create_enricher_template_service(db)
            template = template_service.find_by_name(enricher_name, current_user.id)
            if not template:
                raise HTTPException(
                    status_code=404,
                    detail=f"Enricher '{enricher_name}' not found",
                )
            is_template = True

        task_name = "run_template_enricher" if is_template else "run_enricher"
        task = celery.send_task(
            task_name,
            args=[
                enricher_name,
                entities,
                payload.sketch_id,
                str(current_user.id),
            ],
            # Keyword rather than a 5th positional arg so the positional
            # signature stays byte-identical to what older API instances queue:
            # a message already in flight still binds cleanly against the new
            # task. (Workers still have to roll out before the API either way —
            # a worker predating `params` rejects the keyword.)
            kwargs={"params": payload.params or {}},
        )
        return {"id": task.id}

    except HTTPException:
        raise
    except NotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionDeniedError:
        raise HTTPException(status_code=403, detail="Forbidden")
    except Exception as e:
        print(e)
        raise HTTPException(
            status_code=500, detail=f"Error launching enricher: {str(e)}"
        )
