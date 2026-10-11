"""Offline replay of boundary and evidence failures; no provider/model requests."""

from uuid import uuid4

import pytest

from flowsint_core.core.services.copilot_policy import (
    InvestigationScope,
    entity_in_scope,
    validate_scope_step,
)
from flowsint_core.core.services.copilot_service import (
    AgentDecision,
    AgentReport,
    eligible_catalog,
    validate_decision,
    validate_report,
)


def node(value, kind="domain"):
    return {"id": value, "nodeLabel": value, "nodeType": kind}


@pytest.mark.parametrize(
    "value,kind,allowed",
    [
        ("api.example.org", "domain", True),
        ("example.org.evil.test", "domain", False),
        ("blocked.example.org", "domain", False),
        ("sub.blocked.example.org", "domain", False),
        ("192.0.2.42", "ip", True),
        ("192.0.3.1", "ip", False),
        ("192.0.2.128/25", "cidr", False),
        ("192.0.2.0/26", "cidr", True),
        ("AS123", "asn", False),
    ],
)
def test_scope_replay(value, kind, allowed):
    scope = InvestigationScope(
        permitted_domains=["EXAMPLE.org."],
        permitted_cidrs=["192.0.2.0/24"],
        excluded_entities=["blocked.example.org", "192.0.2.200"],
    )
    assert entity_in_scope(scope, node(value, kind)) is allowed


@pytest.mark.parametrize(
    "changes,message",
    [
        ({"node_depths": {}}, "pivot depth"),
        ({"node_depths": {"example.org": 3}}, "pivot depth"),
        ({"provider_requests": 20}, "request budget"),
        ({"estimated_requests": -1}, "nonnegative"),
        ({"graph_growth": 500}, "growth budget"),
        ({"graph_growth": 499, "estimated_growth": 2}, "growth budget"),
    ],
)
def test_budget_replay(changes, message):
    args = dict(
        scope=InvestigationScope(),
        nodes=[node("example.org")],
        node_depths={"example.org": 0},
        provider_requests=0,
        graph_growth=0,
    )
    args.update(changes)
    with pytest.raises(ValueError, match=message):
        validate_scope_step(**args)


def test_local_action_allowed_with_zero_request_budget():
    validate_scope_step(
        InvestigationScope(max_provider_requests=0),
        [node("example.org")],
        {"example.org": 0},
        0,
        0,
        estimated_requests=0,
    )


def test_catalog_excludes_unknown_cost_and_rejects_redundant_decision():
    metadata = [
        {"name": name, "inputs": {"type": "domain"}}
        for name in ["domain_to_root_domain", "domain_to_dehashed"]
    ]
    catalog = eligible_catalog(
        metadata, [node("example.org")], set(), bounded_requests=True
    )
    assert [item["enricher"] for item in catalog] == ["domain_to_root_domain"]
    assert catalog[0]["request_cost"] == 0
    with pytest.raises(ValueError, match="already ran"):
        validate_decision(
            AgentDecision(
                action="enrich",
                enricher="domain_to_root_domain",
                node_ids=["example.org"],
            ),
            uuid4(),
            "Map infrastructure",
            catalog,
            {("domain_to_root_domain", "example.org")},
        )


OBSERVATION = {
    "observations": [{"id": "o1", "scan_id": "historical", "node_ids": ["a", "b"]}]
}


def report(**changes):
    finding = dict(
        body="Recorded association",
        kind="fact",
        observation_ids=["o1"],
        scan_ids=["historical"],
        target_node_id="a",
    )
    finding.update(changes)
    return AgentReport(
        report="Recorded association [observation:o1].", findings=[finding]
    )


def test_historical_observation_can_ground_finding():
    assert validate_report(report(), {"new-scan"}, {"a", "b"}, OBSERVATION).findings[
        0
    ].scan_ids == ["historical"]


@pytest.mark.parametrize(
    "changes",
    [
        {"observation_ids": ["invented"]},
        {"observation_ids": []},
        {"target_node_id": "unrelated"},
        {"scan_ids": ["new-scan"]},
    ],
)
def test_unsupported_reference_replay(changes):
    with pytest.raises(ValueError):
        validate_report(
            report(**changes), {"new-scan"}, {"a", "b", "unrelated"}, OBSERVATION
        )


def test_report_cannot_invent_observation():
    with pytest.raises(ValueError, match="unknown observations"):
        validate_report(
            AgentReport(report="Fact [observation:invented]"), set(), set(), OBSERVATION
        )


def test_observation_ids_are_stable_redacted_and_bound_to_relationship():
    from flowsint_core.core.graph.types import (
        GraphData,
        GraphEdge,
        GraphNode,
        NodeMetadata,
    )
    from flowsint_core.core.services.copilot_service import graph_observation

    graph = GraphData(
        nodes=[
            GraphNode(
                id=value,
                nodeLabel=value,
                nodeType="domain",
                nodeMetadata=NodeMetadata(),
                nodeProperties={},
            )
            for value in ["a", "b"]
        ],
        edges=[
            GraphEdge(
                id="ab",
                source="a",
                target="b",
                label="USES_NAMESERVER",
                observations=[
                    {"scan_id": "old", "api_key": "never-send", "provider": "index"}
                ],
            )
        ],
    )
    first = graph_observation(graph, {"a"}, set())["observations"][0]
    assert "api_key" not in first["data"]
    assert first["node_ids"] == ["a", "b"]
    assert first["scan_id"] == "old"
    assert (
        first["id"] == graph_observation(graph, set(), {"a"})["observations"][0]["id"]
    )
    graph.edges[0].id = "different"
    assert (
        first["id"] != graph_observation(graph, set(), set())["observations"][0]["id"]
    )


def test_email_exclusion_applies_before_domain_extraction():
    assert not entity_in_scope(
        InvestigationScope(excluded_entities=["analyst@example.org"]),
        node("analyst@example.org", "email"),
    )
