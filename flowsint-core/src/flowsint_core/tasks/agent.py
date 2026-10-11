"""Autonomous passive investigation: LLM decision -> allowlisted enricher -> repeat."""

import asyncio
import json
import uuid
from datetime import datetime, timezone
from time import monotonic
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from flowsint_enrichers import ENRICHER_REGISTRY, load_all_enrichers

from ..core.celery import celery
from ..core.enums import EventLevel
from ..core.graph import create_graph_service
from ..core.graph.serializer import GraphSerializer
from ..core.llm.protocol import LLMProvider, SubscriptionError
from ..core.logger import Logger
from ..core.models import AgentRun, Key, Scan, Sketch
from ..core.postgre_db import SessionLocal
from ..core.services import create_chat_service, create_type_registry_service
from ..core.services.collaboration_service import CollaborationService
from ..core.services.copilot_service import (
    PASSIVE_PARAMS,
    AgentDecision,
    AgentReport,
    decision_messages,
    eligible_catalog,
    graph_observation,
    parse_model_json,
    provider_block_reason,
    report_messages,
    validate_decision,
    validate_report,
)

load_all_enrichers()

# Everything finishes before Celery's 3600 s hard limit; the loop stops early
# enough to leave both report attempts their full model timeout.
AGENT_DEADLINE_S = 3500.0
MODEL_TIMEOUT_S = 180.0
REPORT_RESERVE_S = 2 * MODEL_TIMEOUT_S
STEP_TIMEOUT_S = 300.0
POLL_S = 2.0
MAX_REJECTED = 3
TERMINAL_SCAN = {"COMPLETED", "FAILED"}
# Collection runs separately from report synthesis; retrying a report never collects.
# Cancel only applies while running; already dispatched scans may finish.
ACTIVE = ("running", "reporting", "publishing")


@celery.task(name="run_investigation_agent")
def run_investigation_agent(run_id: str, report_only: bool = False) -> None:
    session = SessionLocal()
    try:
        run = session.get(AgentRun, uuid.UUID(run_id))
        if run is None or run.status != ("reporting" if report_only else "running"):
            return
        # The API fails a run whose start is older than Celery's hard time limit.
        run.started_at = datetime.now(timezone.utc)
        session.commit()
        sketch_id = str(run.sketch_id)
        Logger.status(
            sketch_id, EventLevel.RUNNING, {"message": "Investigation agent started"}
        )
        try:
            asyncio.run(_investigate(session, run, report_only=report_only))
        except Exception as error:
            session.rollback()
            if isinstance(error, (SubscriptionError, ValueError)):
                message = str(error)
            else:
                message = "The agent stopped unexpectedly. Check the worker logs."
            _transition(
                session,
                run,
                ACTIVE,
                "report_pending" if run.report and not run.finding_ids else "failed",
                error=message[:2000],
            )
            Logger.error(sketch_id, {"message": f"Agent run failed: {error}"})
        session.refresh(run)
        Logger.status(
            sketch_id,
            EventLevel.COMPLETED if run.status == "completed" else EventLevel.FAILED,
            {"message": f"Investigation agent {run.status}"},
        )
    finally:
        session.close()


def _transition(
    session: Session,
    run: AgentRun,
    sources: tuple[str, ...],
    status: str,
    **values: Any,
) -> bool:
    """Atomic status change; False when another writer (cancel) got there first."""
    if status in ("completed", "failed", "report_pending"):
        values["finished_at"] = datetime.now(timezone.utc)
    result = session.execute(
        update(AgentRun)
        .where(AgentRun.id == run.id, AgentRun.status.in_(sources))
        .values(status=status, **values)
    )
    session.commit()
    return bool(getattr(result, "rowcount", 0))


def _cancelled(session: Session, run: AgentRun) -> bool:
    session.refresh(run, ["status"])
    return run.status != "running"


def _save_steps(session: Session, run: AgentRun, steps: list[dict[str, Any]]) -> None:
    run.steps = [dict(step) for step in steps]
    session.commit()


async def _complete(provider: LLMProvider, messages: list, until: float) -> str:
    timeout = min(MODEL_TIMEOUT_S, until - monotonic())
    if timeout <= 0:
        raise asyncio.TimeoutError
    return await asyncio.wait_for(provider.complete(messages), timeout=timeout)


def _scan_result(scan: Scan) -> dict[str, Any]:
    summary = scan.summary or {}
    return {
        "outcome": str(summary.get("outcome") or scan.status.lower()),
        "output_count": summary.get("output_count"),
        "errors": summary.get("errors") or [],
    }


async def _await_scan(
    session: Session, run: AgentRun, scan_id: str, until: float
) -> dict[str, Any]:
    while True:
        scan = session.get(Scan, uuid.UUID(scan_id), populate_existing=True)
        if scan is not None and scan.status in TERMINAL_SCAN:
            return _scan_result(scan)
        if _cancelled(session, run):
            return {"outcome": "cancelled"}
        if monotonic() >= until:
            return {"outcome": "timeout"}
        await asyncio.sleep(POLL_S)


async def _investigate(
    session: Session, run: AgentRun, report_only: bool = False
) -> None:
    deadline = monotonic() + AGENT_DEADLINE_S
    loop_until = deadline - REPORT_RESERVE_S
    owner_id = run.owner_id
    if owner_id is None:
        raise ValueError("The run owner no longer exists")
    provider = create_chat_service(session).get_subscription_provider(owner_id)
    resolver = create_type_registry_service(session).build_type_resolver(owner_id)
    graph_service = create_graph_service(
        sketch_id=str(run.sketch_id), type_resolver=resolver
    )
    keys = set(
        session.execute(select(Key.name).where(Key.owner_id == owner_id)).scalars()
    )
    seeds = set(run.seed_ids)
    steps: list[dict[str, Any]] = list(run.steps or [])
    done = {(step["enricher"], node) for step in steps for node in step["node_ids"]}
    feedback: str | None = None
    rejected = 0

    while not report_only and len(steps) < run.max_steps and rejected < MAX_REJECTED:
        if _cancelled(session, run):
            return
        centers = list(
            dict.fromkeys(
                [
                    *run.seed_ids,
                    *(node for step in steps[-9:] for node in step["node_ids"]),
                ]
            )
        )[:100]
        graph = graph_service.get_graph_slice(center_ids=centers, limit=150)
        nodes = {str(node.id): node for node in graph.nodes if node.id}
        blocked = {
            provider_id
            for step in steps
            if step.get("provider_block_reason")
            for provider_id in step.get("provider_ids", [step["enricher"]])
        }
        catalog = [
            item
            for item in eligible_catalog(
                ENRICHER_REGISTRY.list(),
                [node.model_dump(mode="json") for node in nodes.values()],
                keys,
            )
            if not item["missing_keys"]
            and not blocked.intersection(item["provider_ids"])
        ]
        if not catalog:
            break
        observation = graph_observation(
            graph,
            seeds,
            {
                str(node.id)
                for node in graph.nodes
                if node.nodeMetadata.created_by_scan
                in {step["scan_id"] for step in steps}
            },
        )
        history = [
            {
                key: step.get(key)
                for key in (
                    "enricher",
                    "node_ids",
                    "reason",
                    "outcome",
                    "output_count",
                    "scan_id",
                )
            }
            for step in steps
        ]
        messages = decision_messages(
            run.objective,
            observation,
            catalog,
            history,
            run.max_steps - len(steps),
            feedback,
        )
        try:
            text = await _complete(provider, messages, loop_until)
        except asyncio.TimeoutError:
            break  # Out of loop time: report on the evidence gathered so far.
        try:
            decision = AgentDecision.model_validate(parse_model_json(text))
            if decision.action == "finish":
                break
            step = validate_decision(
                decision, run.sketch_id, run.objective, catalog, done
            )
        except ValueError as error:  # pydantic ValidationError is a ValueError
            rejected += 1
            feedback = str(error)
            continue
        rejected, feedback = 0, None
        objects = [
            GraphSerializer.graph_node_to_flowsint_type(nodes[node_id]).model_dump(
                mode="json", serialize_as_any=True
            )
            for node_id in step.node_ids
        ]
        if _cancelled(session, run):
            return
        task = celery.send_task(
            "run_enricher",
            args=[step.enricher, objects, str(run.sketch_id), str(owner_id)],
            kwargs={"params": PASSIVE_PARAMS.get(step.enricher, {})},
        )
        record: dict[str, Any] = {
            "step": len(steps) + 1,
            "enricher": step.enricher,
            "node_ids": step.node_ids,
            "reason": step.reason,
            "thought": decision.thought,
            "scan_id": str(task.id),
            "outcome": "running",
            "provider_ids": next(
                item["provider_ids"]
                for item in catalog
                if item["enricher"] == step.enricher
            ),
        }
        steps.append(record)
        done |= {(step.enricher, node) for node in step.node_ids}
        _save_steps(session, run, steps)
        record.update(
            await _await_scan(
                session,
                run,
                record["scan_id"],
                min(loop_until, monotonic() + STEP_TIMEOUT_S),
            )
        )
        record["provider_block_reason"] = provider_block_reason(record)
        _save_steps(session, run, steps)
        if record["outcome"] == "cancelled":
            return

    if not report_only and _cancelled(session, run):
        return
    scan_ids = {step["scan_id"] for step in steps}
    scans = {
        str(scan.id): scan
        for scan in session.query(Scan).filter(
            Scan.id.in_([uuid.UUID(scan_id) for scan_id in scan_ids])
        )
    }
    # A scan that timed out during collection can have finished before report retry.
    for saved_step in steps:
        scan = scans.get(saved_step["scan_id"])
        if scan is not None and scan.status in TERMINAL_SCAN:
            saved_step.update(_scan_result(scan))
            saved_step["provider_block_reason"] = provider_block_reason(saved_step)
    _save_steps(session, run, steps)
    evidence = [
        {
            "scan_id": step["scan_id"],
            "enricher": step["enricher"],
            "node_ids": step["node_ids"],
            "outcome": step["outcome"],
            "summary": getattr(scans.get(step["scan_id"]), "summary", None),
            "details": getattr(scans.get(step["scan_id"]), "details", None),
        }
        for step in steps
    ]
    centers = list(
        dict.fromkeys(
            [*run.seed_ids, *(node for step in steps[-9:] for node in step["node_ids"])]
        )
    )[:100]
    graph = graph_service.get_graph_slice(center_ids=centers, limit=150)
    node_ids = {str(node.id) for node in graph.nodes if node.id}
    observation = graph_observation(
        graph,
        seeds,
        {
            str(node.id)
            for node in graph.nodes
            if node.nodeMetadata.created_by_scan in scan_ids
        },
    )
    partial = "Partial evidence summary — synthesis pending.\n\n" + "\n".join(
        f"- {step['enricher']}: {step['outcome']}; "
        f"{step.get('output_count', 'unknown')} results [scan:{step['scan_id']}]."
        for step in steps
    )
    if not _transition(
        session, run, ("running", "reporting"), "reporting", report=partial
    ):
        return
    report: AgentReport | None = None
    feedback = None
    for _ in range(2):
        try:
            text = await _complete(
                provider,
                report_messages(run.objective, evidence, observation, feedback),
                deadline,
            )
        except asyncio.TimeoutError:
            feedback = "The model did not return the report in time"
            continue
        try:
            report = validate_report(
                AgentReport.model_validate(parse_model_json(text)), scan_ids, node_ids
            )
            break
        except ValueError as error:
            feedback = str(error)
    if report is None:
        raise ValueError(
            f"The model could not produce a valid evidence-linked report: {feedback}"
        )
    # Claim publication atomically; a cancel that landed first wins.
    if not _transition(session, run, ("reporting",), "publishing"):
        return
    finding_ids, publish_error = _publish_findings(session, run, report, owner_id)
    _transition(
        session,
        run,
        ("publishing",),
        "completed",
        report=report.report,
        finding_ids=finding_ids,
        error=publish_error,
    )


def _publish_findings(
    session: Session, run: AgentRun, report: AgentReport, owner_id: uuid.UUID
) -> tuple[list[str], str | None]:
    sketch = session.get(Sketch, run.sketch_id)
    if not report.findings or sketch is None or sketch.investigation_id is None:
        return [], None
    collaboration = CollaborationService(session)
    finding_ids: list[str] = []
    try:
        for finding in report.findings:
            item = collaboration.create(
                sketch.investigation_id,
                owner_id,
                {
                    "sketch_id": run.sketch_id,
                    "target_kind": "entity" if finding.target_node_id else None,
                    "target_id": finding.target_node_id,
                    "kind": "finding",
                    "body": finding.body,
                    "evidence": json.dumps(
                        {"agent_run_id": str(run.id), "scan_ids": finding.scan_ids}
                    ),
                },
            )
            finding_ids.append(str(item.id))
    except Exception as error:
        session.rollback()
        return (
            finding_ids,
            f"Report saved, but draft findings could not be created: {error}",
        )
    return finding_ids, None
