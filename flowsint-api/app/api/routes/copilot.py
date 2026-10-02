"""Reviewed passive enrichment plans, using existing providers and workers."""

import asyncio
import json
import re
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from openai import APIConnectionError, APIStatusError
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from flowsint_core.core.celery import celery
from flowsint_core.core.graph import GraphNode, create_graph_service
from flowsint_core.core.graph.serializer import GraphSerializer
from flowsint_core.core.llm.protocol import LLMProvider
from flowsint_core.core.models import Key, Profile, Scan
from flowsint_core.core.postgre_db import get_db
from flowsint_core.core.services import (
    NotFoundError,
    PermissionDeniedError,
    create_chat_service,
    create_enricher_service,
    create_flow_service,
    create_sketch_service,
)
from flowsint_core.core.services.copilot_service import (
    PASSIVE_ENRICHERS,
    CopilotPlan,
    CopilotRequest,
    eligible_catalog,
    planning_messages,
    summary_messages,
    validate_plan,
)
from flowsint_core.core.services.type_registry_service import (
    create_type_registry_service,
)
from flowsint_core.utils import extract_input_schema_flow
from flowsint_enrichers import ENRICHER_REGISTRY
from flowsint_types import Domain, Ip

router = APIRouter()


def _model_failure(error: Exception, fallback: str) -> HTTPException:
    # Return fixed messages; provider bodies can contain sensitive request data.
    if isinstance(error, APIStatusError):
        if error.code in {"credit_balance_exhausted", "insufficient_quota"}:
            return HTTPException(
                502,
                "The OpenAI project has exhausted its API credits or quota. "
                "Check that project's billing and limits, or update OPENAI_API_KEY "
                "in Vault with a key from a funded project.",
            )
        if error.status_code == 401:
            return HTTPException(
                502, "OpenAI rejected the API key. Update OPENAI_API_KEY in Vault."
            )
        if error.status_code in {403, 404}:
            return HTTPException(
                502,
                "The configured OpenAI model is unavailable to this project. Check model access and API key permissions.",
            )
        if error.status_code == 429:
            return HTTPException(
                503, "OpenAI is rate limiting requests. Wait before trying again."
            )
    if isinstance(error, (TimeoutError, APIConnectionError)):
        return HTTPException(
            504, "The model connection failed or timed out. Try again later."
        )
    return HTTPException(502, fallback)


class SavePlan(CopilotPlan):
    name: str = Field(min_length=1, max_length=120)


class SummaryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sketch_id: UUID
    run_ids: list[UUID] = Field(min_length=1, max_length=3)
    question: str = Field(min_length=1, max_length=2000)


def _check_sketch(db: Session, user: Profile, sketch_id: UUID, write: bool) -> None:
    try:
        if write:
            create_enricher_service(db).get_sketch_for_launch(str(sketch_id), user.id)
        else:
            create_sketch_service(db).get_by_id(sketch_id, user.id)
    except NotFoundError:
        raise HTTPException(404, "Sketch not found")
    except PermissionDeniedError:
        raise HTTPException(403, "Forbidden")


def _selection(
    request: CopilotRequest, db: Session, user: Profile
) -> tuple[Any, list[GraphNode], list[dict[str, Any]]]:
    resolver = create_type_registry_service(db).build_type_resolver(user.id)
    graph = create_graph_service(
        sketch_id=str(request.sketch_id), type_resolver=resolver
    )
    nodes = graph.get_nodes_by_ids(request.node_ids)
    if {node.id for node in nodes} != set(request.node_ids):
        raise HTTPException(404, "One or more selected entities are unavailable")
    keys = set(db.execute(select(Key.name).where(Key.owner_id == user.id)).scalars())
    candidates = eligible_catalog(
        ENRICHER_REGISTRY.list(),
        [node.model_dump(mode="json") for node in nodes],
        keys,
    )
    return graph, nodes, candidates


def _provider(db: Session, user: Profile) -> LLMProvider | None:
    try:
        return create_chat_service(db).get_llm_provider(user.id)
    except ValueError:
        # No configured model: offer transparent deterministic suggestions instead.
        return None


def _reviewed_plan(
    payload: CopilotPlan, db: Session, user: Profile, require_fresh: bool = True
) -> tuple[CopilotPlan, list[GraphNode]]:
    _check_sketch(db, user, payload.sketch_id, write=True)
    _, nodes, candidates = _selection(payload, db, user)
    versions = {str(node.id): node.version for node in nodes}
    if require_fresh and payload.node_versions != versions:
        raise HTTPException(409, "Selected entities changed. Generate a new plan.")
    try:
        plan = validate_plan(
            {
                "analysis": payload.analysis,
                "steps": [s.model_dump() for s in payload.steps],
            },
            CopilotRequest(
                **payload.model_dump(include={"sketch_id", "node_ids", "question"})
            ),
            candidates,
            payload.context_truncated,
        )
    except ValueError:
        raise HTTPException(
            422, "The plan includes an unavailable or incompatible lookup"
        )
    if not plan.steps:
        raise HTTPException(422, "Select at least one enrichment step")
    plan.node_versions = versions
    return plan, nodes


@router.post("/plan", response_model=CopilotPlan)
async def plan_investigation(
    payload: CopilotRequest,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> CopilotPlan:
    _check_sketch(db, current_user, payload.sketch_id, write=False)
    graph, nodes, candidates = _selection(payload, db, current_user)
    # Read-only, sketch-scoped one-hop context; the model never supplies Cypher.
    relationships = graph.query(
        """MATCH (n)-[r]-(other)
        WHERE elementId(n) IN $node_ids AND n.sketch_id = $sketch_id
          AND other.sketch_id = $sketch_id AND n.deleted_at IS NULL
          AND other.deleted_at IS NULL AND r.deleted_at IS NULL
        RETURN elementId(r) AS id, type(r) AS relationship,
          elementId(startNode(r)) AS source, elementId(endNode(r)) AS target,
          other.nodeLabel AS neighbor_label, r.observations AS observations
        ORDER BY id LIMIT 51""",
        {"node_ids": payload.node_ids, "sketch_id": str(payload.sketch_id)},
    )
    recent = (
        db.query(Scan)
        .filter(Scan.sketch_id == payload.sketch_id)
        .order_by(Scan.started_at.desc())
        .limit(6)
        .all()
    )
    messages, truncated = planning_messages(
        payload,
        [node.model_dump(mode="json") for node in nodes],
        candidates,
        {
            "relationships": relationships[:50],
            "recent_runs": [
                {"run_id": str(run.id), "status": run.status, "summary": run.summary}
                for run in recent[:5]
            ],
            "relationships_truncated": len(relationships) > 50,
            "recent_runs_truncated": len(recent) > 5,
        },
    )
    truncated |= len(relationships) > 50 or len(recent) > 5
    provider = _provider(db, current_user) if candidates else None
    if provider:
        try:
            response = await asyncio.wait_for(provider.complete(messages), timeout=60)
            if len(response) > 20000:
                raise ValueError("Oversized model response")
            proposed = json.loads(response)
            if not isinstance(proposed, dict):
                raise ValueError("Expected a plan object")
            plan = validate_plan(proposed, payload, candidates, truncated)
        except (ValueError, TypeError):
            raise HTTPException(502, "The model returned an invalid plan. Try again.")
        except Exception as error:
            raise _model_failure(
                error, "The model could not generate a plan. Try again."
            ) from None
    else:
        plan = validate_plan(
            {
                "analysis": (
                    "Suggested compatible passive lookups. No LLM was used; these suggestions "
                    "are based on entity types, not an interpretation of your question. "
                    "Configure your LLM key in Profile for question-specific planning."
                    if candidates
                    else "No supported passive lookups are available for the selected entity types."
                ),
                "steps": [
                    {
                        "enricher": item["enricher"],
                        "node_ids": item["node_ids"],
                        "reason": item["description"]
                        or "Compatible passive enrichment.",
                    }
                    for item in candidates[:3]
                ],
            },
            payload,
            candidates,
            truncated,
        )
    plan.node_versions = {str(node.id): node.version for node in nodes}
    return plan


@router.post("/run")
def run_plan(
    payload: CopilotPlan,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> dict[str, Any]:
    plan, nodes = _reviewed_plan(payload, db, current_user)
    if any(step.missing_keys for step in plan.steps):
        raise HTTPException(
            422, "Configure the required provider keys before running this plan"
        )
    # Validate and serialize every step before the first task is queued.
    by_id = {str(node.id): node for node in nodes}
    try:
        inputs = [
            [
                GraphSerializer.graph_node_to_flowsint_type(by_id[node_id]).model_dump(
                    mode="json", serialize_as_any=True
                )
                for node_id in step.node_ids
            ]
            for step in plan.steps
        ]
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(
            422, "Selected entity properties are invalid. Correct them before running."
        )
    runs: list[dict[str, Any]] = []
    for step, entities in zip(plan.steps, inputs):
        try:
            task = celery.send_task(
                "run_enricher",
                args=[
                    step.enricher,
                    entities,
                    str(plan.sketch_id),
                    str(current_user.id),
                ],
                kwargs={"params": {}},
            )
        except Exception:
            if not runs:
                raise HTTPException(
                    503,
                    "Could not queue enrichment. Check worker availability before retrying.",
                )
            return {
                "runs": runs,
                "error": "Only part of the plan was queued. Review these runs before starting another plan.",
            }
        runs.append(
            {"id": task.id, "enricher": step.enricher, "node_ids": step.node_ids}
        )
    return {"runs": runs}


@router.post("/save")
def save_plan(
    payload: SavePlan,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> dict[str, str]:
    # A recipe stores types and actions, not original entity IDs or values.
    # Enrichment can legitimately increment entity versions before the recipe is saved.
    plan, _ = _reviewed_plan(payload, db, current_user, require_fresh=False)
    if not payload.name.strip():
        raise HTTPException(422, "A flow name is required")
    metadata = {item["name"]: item for item in ENRICHER_REGISTRY.list()}
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    categories = []
    for index, step in enumerate(plan.steps):
        item = metadata[step.enricher]
        category = item["inputs"]["type"]
        categories.append(category)
        input_id, enricher_id = f"input-{index}", f"{step.enricher}-{index}"
        input_type = Domain if category.lower() == "domain" else Ip
        nodes.extend(
            [
                {
                    "id": input_id,
                    "type": "type",
                    "position": {"x": 0, "y": index * 160},
                    "data": extract_input_schema_flow(input_type),
                },
                {
                    "id": enricher_id,
                    "type": "enricher",
                    "position": {"x": 300, "y": index * 160},
                    "data": {**item, "type": "enricher", "params": {}},
                },
            ]
        )
        edges.append(
            {
                "id": f"edge-{index}",
                "source": input_id,
                "target": enricher_id,
                "sourceHandle": category,
                "targetHandle": category,
            }
        )
    flow = create_flow_service(db).create(
        payload.name.strip(),
        f"Reviewed passive enrichment recipe. Question: {plan.question}. "
        "Run on compatible selected entities; original case entity IDs are not stored.",
        sorted(set(categories)),
        {"nodes": nodes, "edges": edges},
        current_user.id,
    )
    return {"id": str(flow.id)}


@router.post("/summary")
async def summarize_plan(
    payload: SummaryRequest,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> dict[str, Any]:
    _check_sketch(db, current_user, payload.sketch_id, write=False)
    if len(set(payload.run_ids)) != len(payload.run_ids):
        raise HTTPException(422, "Select distinct enrichment runs")
    runs = (
        db.query(Scan)
        .filter(Scan.sketch_id == payload.sketch_id, Scan.id.in_(payload.run_ids))
        .all()
    )
    if len(runs) != len(payload.run_ids):
        raise HTTPException(404, "One or more enrichment runs are unavailable")
    if any(
        (run.summary or {}).get("enricher") not in PASSIVE_ENRICHERS for run in runs
    ):
        raise HTTPException(422, "Select supported passive enrichment runs")
    if any(run.status not in {"COMPLETED", "FAILED"} for run in runs):
        raise HTTPException(409, "Wait for all enrichment runs to finish")
    by_id = {run.id: run for run in runs}
    evidence = [
        {
            "run_id": str(run_id),
            "status": by_id[run_id].status,
            "summary": by_id[run_id].summary,
            "details": by_id[run_id].details,
        }
        for run_id in payload.run_ids
    ]
    messages, truncated = summary_messages(payload.question, evidence)
    provider = _provider(db, current_user)
    if provider:
        try:
            summary = await asyncio.wait_for(provider.complete(messages), timeout=60)
            if not summary.strip() or len(summary) > 12000:
                raise ValueError("Invalid summary")
            # Unknown citation IDs must not look like evidence links in the UI.
            citations = re.findall(r"\[run:([^\]]+)\]", summary)
            if not citations or set(citations) - {
                str(run_id) for run_id in payload.run_ids
            }:
                raise ValueError("Invalid evidence citations")
        except Exception as error:
            raise _model_failure(
                error,
                "The model could not produce a valid evidence-linked summary. Try again.",
            ) from None
    else:
        lines = ["Recorded enrichment outcomes (no LLM used):"]
        for run in runs:
            result = run.summary or {}
            lines.append(
                f"- {result.get('enricher')}: {result.get('outcome', 'unknown')}; "
                f"{result.get('input_count', 'unknown')} inputs, "
                f"{result.get('output_count', 'unknown')} outputs. [run:{run.id}]"
            )
        lines.append(
            "Empty results do not prove absence. Failed or partial runs are inconclusive; review the evidence before accepting a finding."
        )
        summary = "\n".join(lines)
    return {"summary": summary, "evidence": evidence, "context_truncated": truncated}
