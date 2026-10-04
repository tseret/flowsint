"""Autonomous passive investigation agent and recorded-evidence review routes."""

import json
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from typing import Any, cast
from uuid import UUID

import requests
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from flowsint_core.core.celery import celery
from flowsint_core.core.enums import EventLevel
from flowsint_core.core.graph import GraphNode, create_graph_service
from flowsint_core.core.graph.serializer import GraphSerializer
from flowsint_core.core.llm.protocol import SubscriptionError
from flowsint_core.core.models import (
    AgentRun,
    CaseItem,
    Key,
    Profile,
    Scan,
    Sketch,
)
from flowsint_core.core.postgre_db import get_db
from flowsint_core.core.services import (
    NotFoundError,
    PermissionDeniedError,
    create_chat_service,
    create_enricher_service,
    create_sketch_service,
)
from flowsint_core.core.services.collaboration_service import CollaborationService
from flowsint_core.core.services.copilot_service import (
    CopilotRequest,
    candidate_review_evidence,
    eligible_catalog,
    service_fingerprint_evidence,
)
from flowsint_core.core.services.type_registry_service import (
    create_type_registry_service,
)
from flowsint_core.core.vault import Vault
from flowsint_core.tasks.agent import AGENT_DEADLINE_S
from flowsint_enrichers import ENRICHER_REGISTRY
from flowsint_enrichers.ip.to_ports_modat import (
    FIELDS,
    lookup_recorded_fingerprint,
    recorded_fingerprint_query,
)
from flowsint_types import Ip, Port

router = APIRouter()


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


class AgentStartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sketch_id: UUID
    node_ids: list[str] = Field(min_length=1, max_length=10)
    objective: str = Field(min_length=1, max_length=2000)
    max_steps: int = Field(default=20, ge=1, le=50)


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


def _run_view(run: AgentRun) -> dict[str, Any]:
    return {
        "id": str(run.id),
        "sketch_id": str(run.sketch_id),
        "objective": run.objective,
        "seed_ids": run.seed_ids,
        "status": run.status,
        "max_steps": run.max_steps,
        "steps": run.steps,
        "report": run.report,
        "finding_ids": run.finding_ids,
        "error": run.error,
        "created_at": run.created_at.isoformat() if run.created_at else None,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
    }


# The task bounds every model and scan wait by AGENT_DEADLINE_S; only the final
# publish writes run after it, so a run still active past this lost its worker.
LOST_AFTER = timedelta(seconds=AGENT_DEADLINE_S, minutes=10)


def _fail_if_lost(db: Session, run: AgentRun) -> AgentRun:
    """Fail a run whose worker died. Queued runs (no started_at) are left alone:
    they start once a worker is available."""
    now = datetime.now(timezone.utc)
    db.execute(
        update(AgentRun)
        .where(
            AgentRun.id == run.id,
            AgentRun.status.in_(("running", "publishing")),
            AgentRun.started_at < now - LOST_AFTER,
        )
        .values(
            status="failed",
            error="The agent worker stopped before finishing. Start a new run.",
            finished_at=now,
        )
        .execution_options(synchronize_session=False)
    )
    db.commit()
    db.refresh(run)
    return run


def _agent_run(db: Session, user: Profile, run_id: UUID) -> AgentRun:
    run = db.get(AgentRun, run_id)
    if run is None:
        raise HTTPException(404, "Agent run not found")
    _check_sketch(db, user, run.sketch_id, write=False)
    return _fail_if_lost(db, run)


@router.post("/agent", status_code=201)
def start_agent(
    payload: AgentStartRequest,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> dict[str, Any]:
    _check_sketch(db, current_user, payload.sketch_id, write=True)
    resolver = create_type_registry_service(db).build_type_resolver(current_user.id)
    graph = create_graph_service(
        sketch_id=str(payload.sketch_id), type_resolver=resolver
    )
    seeds = list(dict.fromkeys(payload.node_ids))
    if {node.id for node in graph.get_nodes_by_ids(seeds)} != set(seeds):
        raise HTTPException(404, "One or more selected entities are unavailable")
    # Fail an unavailable subscription now, before any provider usage is queued.
    try:
        create_chat_service(db).get_subscription_provider(current_user.id)
    except (SubscriptionError, ValueError) as error:
        raise HTTPException(502, str(error)) from None
    run = AgentRun(
        sketch_id=payload.sketch_id,
        owner_id=current_user.id,
        objective=payload.objective,
        seed_ids=seeds,
        status="running",
        max_steps=payload.max_steps,
        steps=[],
        finding_ids=[],
    )
    db.add(run)
    db.commit()
    try:
        celery.send_task("run_investigation_agent", args=[str(run.id)])
    except Exception:
        db.delete(run)
        db.commit()
        raise HTTPException(
            503,
            "Could not queue enrichment. Check worker availability before retrying.",
        ) from None
    db.refresh(run)
    return _run_view(run)


@router.get("/agent")
def latest_agent_run(
    sketch_id: UUID,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> dict[str, Any] | None:
    _check_sketch(db, current_user, sketch_id, write=False)
    run = db.scalars(
        select(AgentRun)
        .where(AgentRun.sketch_id == sketch_id)
        .order_by(AgentRun.created_at.desc())
        .limit(1)
    ).first()
    return _run_view(_fail_if_lost(db, run)) if run else None


@router.get("/agent/{run_id}")
def get_agent_run(
    run_id: UUID,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> dict[str, Any]:
    return _run_view(_agent_run(db, current_user, run_id))


@router.post("/agent/{run_id}/cancel")
def cancel_agent_run(
    run_id: UUID,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> dict[str, Any]:
    run = _agent_run(db, current_user, run_id)
    _check_sketch(db, current_user, run.sketch_id, write=True)
    # Atomic: only a running run is cancelled; publishing/finished runs keep their state.
    db.execute(
        update(AgentRun)
        .where(AgentRun.id == run.id, AgentRun.status == "running")
        .values(status="cancelled", finished_at=datetime.now(timezone.utc))
    )
    db.commit()
    db.refresh(run)
    return _run_view(run)


@router.post("/agent/{run_id}/undo")
def undo_agent_run(
    run_id: UUID,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> dict[str, Any]:
    """Soft-delete what a finished run added: entities and relationships its scans
    created, and draft findings nobody has edited or reviewed. Idempotent."""
    run = _agent_run(db, current_user, run_id)
    _check_sketch(db, current_user, run.sketch_id, write=True)
    if run.status not in ("completed", "failed", "cancelled", "undone"):
        raise HTTPException(409, "Cancel the agent or let it finish before undoing it.")
    scan_ids = [step["scan_id"] for step in run.steps if step.get("scan_id")]
    # A cancelled step's scan keeps writing until it ends. Scans older than
    # Celery's hard time limit lost their worker and never finish.
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(
        seconds=celery.conf.task_time_limit
    )
    if scan_ids and db.scalar(
        select(Scan.id)
        .where(
            Scan.id.in_([UUID(scan_id) for scan_id in scan_ids]),
            Scan.status.not_in((EventLevel.COMPLETED, EventLevel.FAILED)),
            Scan.started_at > cutoff,
        )
        .limit(1)
    ):
        raise HTTPException(
            409, "An enrichment from this run is still running. Undo it once it ends."
        )
    # A relationship's first observation names the scan that created it
    # (observations are JSON with sorted keys).
    [removed] = create_graph_service(sketch_id=str(run.sketch_id)).query(
        """OPTIONAL MATCH (n)
        WHERE n.sketch_id = $sketch_id AND n.deleted_at IS NULL
          AND n.`nodeMetadata.created_by_scan` IN $scan_ids
        SET n.deleted_at = $now
        WITH count(n) AS nodes
        OPTIONAL MATCH (a)-[r]->(b)
        WHERE r.sketch_id = $sketch_id AND r.deleted_at IS NULL
          AND (a.deleted_at = $now OR b.deleted_at = $now
               OR any(needle IN $needles WHERE r.observations[0] CONTAINS needle))
        SET r.deleted_at = $now
        RETURN nodes, count(r) AS relationships""",
        {
            "sketch_id": str(run.sketch_id),
            "scan_ids": scan_ids,
            "needles": [json.dumps({"scan_id": scan_id})[1:-1] for scan_id in scan_ids],
            "now": datetime.now(timezone.utc).isoformat(),
        },
    )
    # Version 1 means untouched since the agent wrote it; edited or reviewed
    # findings carry human work and stay.
    findings = db.scalars(
        select(CaseItem)
        .where(
            CaseItem.id.in_([UUID(item_id) for item_id in run.finding_ids]),
            CaseItem.sketch_id == run.sketch_id,
            CaseItem.version == 1,
        )
        .with_for_update()
    ).all()
    collaboration = CollaborationService(db)
    for finding in findings:
        collaboration.record(
            finding.investigation_id,
            current_user.id,
            "deleted",
            finding.id,
            {"kind": finding.kind, "body": finding.body, "reason": "Agent run undone"},
        )
        db.delete(finding)
    run.status = "undone"
    db.commit()
    db.refresh(run)
    return {
        **_run_view(run),
        "removed": {**removed, "findings": len(findings)},
    }
