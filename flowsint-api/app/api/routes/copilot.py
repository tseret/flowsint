"""Reviewed passive enrichment plans, using existing providers and workers."""

import asyncio
import json
import re
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any, cast
from uuid import UUID

import requests
from fastapi import APIRouter, Depends, HTTPException
from openai import APIConnectionError, APIStatusError
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.api.deps import get_current_user
from flowsint_core.core.celery import celery
from flowsint_core.core.graph import GraphNode, create_graph_service
from flowsint_core.core.graph.serializer import GraphSerializer
from flowsint_core.core.llm.protocol import LLMProvider, SubscriptionError
from flowsint_core.core.models import CaseItem, Key, Profile, Scan, Sketch
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
    PASSIVE_PARAMS,
    CopilotPlan,
    CopilotRequest,
    candidate_review_evidence,
    eligible_catalog,
    planning_messages,
    service_fingerprint_evidence,
    summary_messages,
    validate_plan,
)
from flowsint_core.core.services.type_registry_service import (
    create_type_registry_service,
)
from flowsint_core.core.vault import Vault
from flowsint_core.utils import extract_input_schema_flow
from flowsint_enrichers import ENRICHER_REGISTRY
from flowsint_enrichers.ip.to_ports_modat import (
    FIELDS,
    lookup_recorded_fingerprint,
    recorded_fingerprint_query,
)
from flowsint_types import Domain, Ip, Port

router = APIRouter()


def _model_failure(error: Exception, fallback: str) -> HTTPException:
    if isinstance(error, SubscriptionError):
        return HTTPException(502, str(error))
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


class ServiceContextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sketch_id: UUID
    service_id: str = Field(min_length=1, max_length=200)


class FingerprintRequest(ServiceContextRequest):
    service_version: int = Field(ge=0)
    fingerprint: str = Field(min_length=1, max_length=100)


class FingerprintImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sketch_id: UUID
    finding_id: UUID
    finding_version: int = Field(ge=1)


class SavePlan(CopilotPlan):
    name: str = Field(min_length=1, max_length=120)


class SummaryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sketch_id: UUID
    run_ids: list[UUID] = Field(min_length=1, max_length=7)
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
    except SubscriptionError as error:
        raise HTTPException(502, str(error)) from None


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
          other.nodeLabel AS neighbor_label, r.observations AS observations,
          CASE WHEN other.nodeType = 'port' THEN properties(other) ELSE {} END AS neighbor_properties
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
    provider = (
        await run_in_threadpool(_provider, db, current_user) if candidates else None
    )
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
                    for item in candidates[:7]
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
                kwargs={"params": PASSIVE_PARAMS.get(step.enricher, {})},
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


@router.post("/collect")
def collect_ip_intelligence(
    payload: CopilotRequest,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> dict[str, Any]:
    """Collect indexed records for the exact selected IPs, then summarize runs."""
    _check_sketch(db, current_user, payload.sketch_id, write=True)
    _, nodes, candidates = _selection(payload, db, current_user)
    if any(node.nodeType.lower() != "ip" for node in nodes):
        raise HTTPException(
            422, "Select only IP entities for IP intelligence collection"
        )
    plan = validate_plan(
        {
            "analysis": "Collect existing provider records for the selected IPs. "
            "The final report will distinguish observations, hypotheses and gaps. "
            "Related entities require review before any further lookups.",
            "steps": [
                {
                    "enricher": item["enricher"],
                    "node_ids": item["node_ids"],
                    "reason": item["description"]
                    or "Read existing provider intelligence",
                }
                for item in candidates
            ],
        },
        payload,
        candidates,
    )
    skipped = [step for step in plan.steps if step.missing_keys]
    plan.steps = [step for step in plan.steps if not step.missing_keys]
    if not plan.steps:
        missing = sorted({key for step in skipped for key in step.missing_keys})
        raise HTTPException(
            422,
            "No IP intelligence providers are ready. Configure provider keys in Vault: "
            + ", ".join(missing),
        )
    # Fail an unavailable subscription before incurring intelligence-provider usage.
    _provider(db, current_user)
    plan.node_versions = {str(node.id): node.version for node in nodes}
    result = run_plan(plan, db, current_user)
    return {"plan": plan, "skipped": skipped, **result}


@router.post("/candidates")
def review_existing_ip_evidence(
    payload: CopilotRequest,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> dict[str, Any]:
    """Review existing/imported associations without calling discovery providers."""
    _check_sketch(db, current_user, payload.sketch_id, write=False)
    graph, nodes, _ = _selection(payload, db, current_user)
    if any(node.nodeType.lower() != "ip" for node in nodes):
        raise HTTPException(422, "Select only IP entities to review related evidence")
    rows = graph.query(
        """MATCH (source)-[a]-(evidence)-[b]-(candidate)
        WHERE elementId(source) IN $node_ids AND NOT elementId(candidate) IN $node_ids
          AND source.sketch_id = $sketch_id AND evidence.sketch_id = $sketch_id
          AND candidate.sketch_id = $sketch_id AND candidate.nodeType = 'ip'
          AND source.deleted_at IS NULL AND evidence.deleted_at IS NULL
          AND candidate.deleted_at IS NULL AND a.deleted_at IS NULL AND b.deleted_at IS NULL
          AND ((evidence.nodeType = 'phrase' AND
            ((type(a) = 'HAS_MODAT_PIVOT' AND type(b) = 'MATCHES_MODAT_PIVOT') OR
             (type(a) = 'MATCHES_MODAT_PIVOT' AND type(b) = 'HAS_MODAT_PIVOT'))) OR
            (evidence.nodeType = 'domain' AND type(a) IN ['PASSIVE_DNS_RESOLVED_TO', 'REVERSE_RESOLVES_TO']
            AND type(b) IN ['PASSIVE_DNS_RESOLVED_TO', 'REVERSE_RESOLVES_TO']))
        RETURN elementId(source) AS source_id, source.nodeLabel AS source_label,
          elementId(candidate) AS node_id, candidate.nodeLabel AS label,
          candidate.nodeType AS candidate_type, evidence.nodeType AS evidence_type,
          elementId(evidence) AS evidence_id, evidence.nodeLabel AS evidence_label,
          [type(a), type(b)] AS relationships,
          coalesce(a.observations, []) + coalesce(b.observations, []) AS observations
        ORDER BY node_id, source_id, evidence_id LIMIT 201""",
        {"node_ids": payload.node_ids, "sketch_id": str(payload.sketch_id)},
    )
    result = cast(
        dict[str, Any], candidate_review_evidence(rows, set(payload.node_ids))
    )
    services = graph.query(
        """MATCH (source)-[r:HAS_PORT]-(port)
        WHERE elementId(source) IN $node_ids AND source.sketch_id = $sketch_id
          AND port.sketch_id = $sketch_id AND port.nodeType = 'port'
          AND source.deleted_at IS NULL AND port.deleted_at IS NULL AND r.deleted_at IS NULL
        RETURN DISTINCT elementId(source) AS source_id, source.nodeLabel AS source_label,
          source.`nodeProperties.address` AS source_address,
          elementId(port) AS service_id, properties(port) AS data
        ORDER BY source_id, service_id LIMIT 51""",
        {"node_ids": payload.node_ids, "sketch_id": str(payload.sketch_id)},
    )
    service_evidence = service_fingerprint_evidence(services, set(payload.node_ids))
    for service in service_evidence["services"]:
        _add_recorded_queries(service)
    result.update(service_evidence)
    return result


def _add_recorded_queries(service: dict[str, Any]) -> None:
    service["modat_queries"] = {
        field: query
        for field in FIELDS
        if (query := recorded_fingerprint_query(service, field))
    }


def _service_context(
    payload: ServiceContextRequest, db: Session, user: Profile
) -> dict[str, Any]:
    resolver = create_type_registry_service(db).build_type_resolver(user.id)
    graph = create_graph_service(
        sketch_id=str(payload.sketch_id), type_resolver=resolver
    )
    nodes = graph.get_nodes_by_ids([payload.service_id])
    if len(nodes) != 1 or nodes[0].id != payload.service_id:
        raise HTTPException(404, "Service entity not found")
    if nodes[0].nodeType.lower() != "port":
        raise HTTPException(422, "Select a Port entity for a service lookup")
    rows = graph.query(
        """MATCH (source)-[r:HAS_PORT]-(port)
        WHERE elementId(port) = $service_id AND port.sketch_id = $sketch_id
          AND port.nodeType = 'port'
          AND source.sketch_id = $sketch_id AND source.nodeType = 'ip'
          AND source.deleted_at IS NULL AND port.deleted_at IS NULL AND r.deleted_at IS NULL
        RETURN DISTINCT elementId(source) AS source_id, source.nodeLabel AS source_label,
          source.`nodeProperties.address` AS source_address,
          elementId(port) AS service_id, properties(port) AS data
        ORDER BY source_id LIMIT 2""",
        {"sketch_id": str(payload.sketch_id), "service_id": payload.service_id},
    )
    if len(rows) != 1:
        raise HTTPException(
            422, "Service must have exactly one owning IP in this sketch"
        )
    try:
        source_address = rows[0].get("source_address")
        if not isinstance(source_address, str):
            raise ValueError("Missing IP address")
        address = str(ip_address(source_address))
        host = rows[0].get("data", {}).get("nodeProperties.host")
        if host and (not isinstance(host, str) or str(ip_address(host)) != address):
            raise ValueError("Host mismatch")
    except (ValueError, TypeError):
        raise HTTPException(
            422, "Service ownership is missing or inconsistent"
        ) from None
    result = service_fingerprint_evidence(rows, {rows[0]["source_id"]})
    if len(result["services"]) != 1:
        raise HTTPException(422, "Stored service endpoint is incomplete")
    service = cast(dict[str, Any], result["services"][0])
    service["host"] = address
    stored_version = rows[0]["data"].get("version", 0)
    if type(stored_version) is not int or stored_version < 0:
        raise HTTPException(422, "Stored service version is invalid")
    service["service_version"] = stored_version
    _add_recorded_queries(service)
    return service


@router.post("/service-context")
def recorded_service_context(
    payload: ServiceContextRequest,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> dict[str, Any]:
    _check_sketch(db, current_user, payload.sketch_id, write=False)
    return _service_context(payload, db, current_user)


@router.post("/fingerprint")
def query_recorded_service_fingerprint(
    payload: FingerprintRequest,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> dict[str, Any]:
    # Provider usage is an explicit editor action, never a model-issued tool.
    _check_sketch(db, current_user, payload.sketch_id, write=True)
    service = _service_context(payload, db, current_user)
    if service["service_version"] != payload.service_version:
        raise HTTPException(409, "Service evidence changed. Reload before searching.")
    if payload.fingerprint not in service["modat_queries"]:
        raise HTTPException(
            422, "That fingerprint has no supported recorded Modat service query"
        )
    key = Vault(db, current_user.id).get_secret("MODAT_API_KEY")
    if not key:
        raise HTTPException(422, "Configure MODAT_API_KEY in Vault before searching.")
    try:
        return cast(
            dict[str, Any],
            lookup_recorded_fingerprint(service, payload.fingerprint, key),
        )
    except requests.HTTPError as exc:
        code = exc.response.status_code if exc.response is not None else 502
        if code == 429:
            raise HTTPException(
                503,
                "Modat's lookup allowance or rate limit was reached. No fallback was used.",
            ) from None
        if code in {401, 403}:
            raise HTTPException(
                502, "Modat rejected the configured key or its search permissions."
            ) from None
        raise HTTPException(
            502, "Modat could not complete the service query."
        ) from None
    except requests.RequestException:
        raise HTTPException(
            504, "The Modat lookup timed out or could not connect."
        ) from None
    except (ValueError, TypeError, KeyError):
        raise HTTPException(
            502, "Modat returned an unusable service response."
        ) from None


@router.post("/fingerprint/import")
def import_fingerprint_candidate(
    payload: FingerprintImportRequest,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> dict[str, str]:
    """Import one saved passive observation; never query the candidate host."""
    _check_sketch(db, current_user, payload.sketch_id, write=True)
    sketch = db.get(Sketch, payload.sketch_id)
    finding = db.execute(
        select(CaseItem).where(CaseItem.id == payload.finding_id).with_for_update()
    ).scalar_one_or_none()
    if (
        not sketch
        or not finding
        or finding.investigation_id != sketch.investigation_id
        or finding.sketch_id != payload.sketch_id
        or finding.kind != "finding"
        or finding.target_kind != "entity"
    ):
        raise HTTPException(404, "Candidate finding not found in this sketch")
    if finding.version != payload.finding_version:
        raise HTTPException(409, "Finding changed. Reload before importing.")
    if finding.decision == "rejected":
        raise HTTPException(409, "Rejected findings cannot be imported.")
    try:
        evidence = json.loads(finding.evidence)
        source = evidence["source"]
        candidate = evidence["candidate"]
        if source["service_id"] != finding.target_id:
            raise ValueError("Wrong finding target")
        service = _service_context(
            ServiceContextRequest(
                sketch_id=payload.sketch_id, service_id=source["service_id"]
            ),
            db,
            current_user,
        )
        if any(
            source[key] != service[key]
            for key in ("source_id", "host", "port", "transport", "service")
        ):
            raise ValueError("Source endpoint changed")
        address = str(ip_address(candidate["ip"]))
        if (
            address == service["host"]
            or type(candidate["port"]) is not int
            or candidate["port"] != service["port"]
            or candidate["transport"] != service["transport"].lower()
            or candidate["protocol"] != service["service"].lower()
        ):
            raise ValueError("Different endpoint")
        supported = [
            field
            for field, query in service["modat_queries"].items()
            if query == evidence["query"]
            and field in evidence["matching_fingerprints"]
            and field in candidate["matching_fingerprints"]
            and source["fingerprints"].get(field)
            == candidate["fingerprints"].get(field)
            == service["fingerprints"].get(field)
        ]
        if not supported:
            raise ValueError("Fingerprint no longer matches")
        ip = Ip(address=address)
        port = Port(
            host=address,
            number=candidate["port"],
            protocol=candidate["transport"],
            service=candidate["protocol"],
            banner=candidate.get("banner") or None,
            fingerprints={
                field: candidate["fingerprints"][field] for field in supported
            },
            provider="Modat",
            observed_at=candidate.get("observed_at") or None,
            retrieved_at=evidence["retrieved_at"],
            source_ref=candidate.get("source_ref") or None,
        )
    except (ValueError, TypeError, KeyError, AttributeError):
        raise HTTPException(
            422,
            "Finding lacks matching recorded service evidence. Review it before importing.",
        ) from None
    ip_props = GraphSerializer.flowsint_type_to_neo4j_dict(ip)
    port_props = GraphSerializer.flowsint_type_to_neo4j_dict(port)
    graph = create_graph_service(sketch_id=str(payload.sketch_id))
    # One transaction, canonical identities, create-only properties: retries do not
    # duplicate entities or overwrite newer enrichment already present in the graph.
    rows = graph.query(
        """MATCH (source:port)<-[owner:HAS_PORT]-(source_ip:ip)
        WHERE elementId(source) = $source_id AND source.sketch_id = $sketch_id
          AND source.deleted_at IS NULL AND coalesce(source.version, 0) = $source_version
          AND elementId(source_ip) = $source_ip_id AND source_ip.sketch_id = $sketch_id
          AND source_ip.deleted_at IS NULL AND owner.deleted_at IS NULL
        OPTIONAL MATCH (old_ip:ip {sketch_id: $sketch_id})
        WHERE old_ip.nodeKey = $ip_key OR
          (old_ip.nodeKey IS NULL AND old_ip.`nodeProperties.address` = $address)
        WITH source, source_ip, head(collect(old_ip)) AS old_ip
        OPTIONAL MATCH (old_port:port {sketch_id: $sketch_id})
        WHERE old_port.nodeKey = $port_key OR
          (old_port.nodeKey IS NULL AND old_port.`nodeProperties.host` = $address
          AND old_port.`nodeProperties.number` = $port
          AND coalesce(old_port.`nodeProperties.protocol`, 'tcp') = $transport)
        WITH source, source_ip, old_ip, head(collect(old_port)) AS old_port
        WHERE (old_ip IS NULL OR old_ip.deleted_at IS NULL)
          AND (old_port IS NULL OR old_port.deleted_at IS NULL)
        FOREACH (old IN CASE WHEN old_ip IS NULL THEN [] ELSE [old_ip] END | SET old.nodeKey = $ip_key)
        FOREACH (old IN CASE WHEN old_port IS NULL THEN [] ELSE [old_port] END | SET old.nodeKey = $port_key)
        MERGE (ip:ip {nodeKey: $ip_key, sketch_id: $sketch_id})
        ON CREATE SET ip += $ip_props, ip.version = 1, ip.x = 100, ip.y = 100
        MERGE (service:port {nodeKey: $port_key, sketch_id: $sketch_id})
        ON CREATE SET service += $port_props, service.version = 1, service.x = 100, service.y = 100
        MERGE (ip)-[owns:HAS_PORT {sketch_id: $sketch_id}]->(service)
        MERGE (source_ip)-[match:SHARES_FINGERPRINT {sketch_id: $sketch_id}]->(ip)
        SET match.caption = CASE WHEN match.caption IS NULL OR match.caption = $caption
          THEN $caption ELSE 'Shared service fingerprints' END
        FOREACH (r IN [owns, match] |
          SET r.deleted_at = null,
              r.observations = CASE WHEN $observation IN coalesce(r.observations, [])
                THEN coalesce(r.observations, []) ELSE coalesce(r.observations, []) + [$observation] END)
        WITH source, source_ip, ip, service, match
        OPTIONAL MATCH (source)-[legacy:SHARES_FINGERPRINT {sketch_id: $sketch_id}]->(service)
        WHERE legacy.deleted_at IS NULL
        WITH source, source_ip, ip, service, match, collect(legacy) AS legacy_links
        FOREACH (legacy IN legacy_links |
          SET match.observations = reduce(observations = coalesce(match.observations, []),
            observation IN coalesce(legacy.observations, []) |
            CASE WHEN observation IN observations THEN observations ELSE observations + [observation] END)
          SET legacy.deleted_at = $migrated_at)
        RETURN elementId(ip) AS ip_id, elementId(service) AS service_id,
          elementId(source) AS source_service_id""",
        {
            "sketch_id": str(payload.sketch_id),
            "source_id": service["service_id"],
            "source_ip_id": service["source_id"],
            "source_version": service["service_version"],
            "address": address,
            "port": port.number,
            "transport": port.protocol,
            "ip_key": ip_props["nodeKey"],
            "port_key": port_props["nodeKey"],
            "ip_props": ip_props,
            "port_props": port_props,
            "migrated_at": datetime.now(timezone.utc).isoformat(),
            "caption": f"Shared {service['service'].upper()} {supported[0].split('.')[-1].upper()} · port {port.number}",
            "observation": json.dumps(
                {
                    "provider": "Modat",
                    "finding_id": str(finding.id),
                    "imported_by": str(current_user.id),
                    "association": "unverified fingerprint similarity",
                    "evidence": evidence,
                },
                sort_keys=True,
            ),
        },
    )
    if len(rows) != 1:
        raise HTTPException(
            409, "Graph entities changed or were deleted. Reload before importing."
        )
    return cast(dict[str, str], rows[0])


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
                    "data": {
                        **item,
                        "type": "enricher",
                        "params": PASSIVE_PARAMS.get(step.enricher, {}),
                    },
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
    # Dated DNS/hostname observations live on relationships rather than output
    # entities. Include only observations attributed to these authorized runs.
    graph = create_graph_service(sketch_id=str(payload.sketch_id))
    rows = graph.query(
        """MATCH (source)-[r]->(target)
        WHERE source.sketch_id = $sketch_id AND target.sketch_id = $sketch_id
          AND source.deleted_at IS NULL AND target.deleted_at IS NULL
          AND r.deleted_at IS NULL
          AND any(obs IN coalesce(r.observations, []) WHERE
            any(run_id IN $run_ids WHERE obs CONTAINS run_id))
        RETURN source.nodeLabel AS source, target.nodeLabel AS target,
          type(r) AS relationship, r.observations AS observations
        ORDER BY elementId(r) LIMIT 201""",
        {
            "sketch_id": str(payload.sketch_id),
            "run_ids": [str(id) for id in payload.run_ids],
        },
    )
    for item in evidence:
        relationships = []
        for row in rows[:200]:
            observations = []
            for raw in row.get("observations") or []:
                try:
                    observation = json.loads(raw) if isinstance(raw, str) else raw
                except (ValueError, TypeError):
                    continue
                if (
                    isinstance(observation, dict)
                    and observation.get("scan_id") == item["run_id"]
                ):
                    observations.append(observation)
            if observations:
                relationships.append({**row, "observations": observations})
        item["relationships"] = relationships
        item["relationships_truncated"] = len(rows) > 200
    messages, truncated = summary_messages(payload.question, evidence)
    provider = await run_in_threadpool(_provider, db, current_user)
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
