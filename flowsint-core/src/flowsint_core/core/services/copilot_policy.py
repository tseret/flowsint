"""Deterministic investigation boundaries, independent of model instructions."""

from ipaddress import ip_address, ip_network
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator


def normalized_domain(value: str) -> str:
    value = value.strip().rstrip(".").lower().encode("idna").decode("ascii")
    if (
        not value
        or len(value) > 253
        or any(
            not part
            or len(part) > 63
            or part.startswith("-")
            or part.endswith("-")
            or any(not (c.isalnum() or c == "-") for c in part)
            for part in value.split(".")
        )
    ):
        raise ValueError("Enter domain names without URLs or wildcards")
    return value


class InvestigationScope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    permitted_domains: list[str] = Field(default_factory=list, max_length=100)
    permitted_cidrs: list[str] = Field(default_factory=list, max_length=100)
    excluded_entities: list[str] = Field(default_factory=list, max_length=100)
    max_pivot_depth: int = Field(default=2, ge=0, le=10)
    max_provider_requests: int = Field(default=20, ge=0, le=100)
    max_graph_growth: int = Field(default=500, ge=1, le=2000)

    @field_validator("permitted_domains")
    @classmethod
    def domains(cls, values: list[str]) -> list[str]:
        return sorted({normalized_domain(value) for value in values})

    @field_validator("permitted_cidrs")
    @classmethod
    def networks(cls, values: list[str]) -> list[str]:
        return sorted(
            {str(ip_network(value.strip(), strict=False)) for value in values}
        )

    @field_validator("excluded_entities")
    @classmethod
    def exclusions(cls, values: list[str]) -> list[str]:
        if any(not value.strip() or len(value) > 300 for value in values):
            raise ValueError(
                "Excluded entities must be nonempty IDs, domains or addresses"
            )
        return sorted({value.strip().lower().rstrip(".") for value in values})


def entity_in_scope(scope: InvestigationScope, node: dict[str, Any]) -> bool:
    kind = str(node.get("nodeType", node.get("type", ""))).lower()
    props = node.get("nodeProperties", node.get("properties", {})) or {}
    if isinstance(props, BaseModel):
        props = props.model_dump(mode="json")
    if not isinstance(props, dict):
        props = {}
    value = (
        str(
            props.get(
                {"domain": "domain", "ip": "address", "cidr": "network"}.get(kind, ""),
                node.get("nodeLabel", node.get("label", "")),
            )
        )
        .strip()
        .lower()
        .rstrip(".")
    )
    excluded = set(scope.excluded_entities)
    if str(node.get("id", "")).lower() in excluded or value in excluded:
        return False
    if kind == "website":
        value = (urlsplit(value).hostname or "").lower()
        kind = "domain"
    elif kind == "email":
        value = value.rsplit("@", 1)[-1]
        kind = "domain"
    if value in excluded:
        return False
    if kind == "domain":
        try:
            value = normalized_domain(value)
        except (ValueError, UnicodeError):
            return False
        if any(value == item or value.endswith("." + item) for item in excluded):
            return False
    if kind in {"ip", "cidr"}:
        try:
            network = (
                ip_network(value, strict=False)
                if kind == "cidr"
                else ip_network(ip_address(value))
            )
        except ValueError:
            return False
        for item in excluded:
            try:
                denied = ip_network(item, strict=False)
            except ValueError:
                continue
            if network.version == denied.version and network.overlaps(denied):
                return False
        return (not scope.permitted_domains and not scope.permitted_cidrs) or any(
            network.version == allowed.version
            and int(network.network_address) >= int(allowed.network_address)
            and int(network.broadcast_address) <= int(allowed.broadcast_address)
            for allowed in map(ip_network, scope.permitted_cidrs)
        )
    if not scope.permitted_domains and not scope.permitted_cidrs:
        return True
    return kind == "domain" and any(
        value == allowed or value.endswith("." + allowed)
        for allowed in scope.permitted_domains
    )


def validate_scope_step(
    scope: InvestigationScope,
    nodes: list[dict[str, Any]],
    node_depths: dict[str, int],
    provider_requests: int,
    graph_growth: int,
    estimated_requests: int = 1,
    estimated_growth: int = 0,
) -> None:
    if min(provider_requests, graph_growth, estimated_requests, estimated_growth) < 0:
        raise ValueError("Budget counters must be nonnegative")
    if provider_requests + estimated_requests > scope.max_provider_requests:
        raise ValueError("Provider request budget exhausted")
    if (
        graph_growth >= scope.max_graph_growth
        or graph_growth + estimated_growth > scope.max_graph_growth
    ):
        raise ValueError("Graph growth budget exhausted")
    for node in nodes:
        depth = node_depths.get(str(node.get("id")))
        if depth is None or depth < 0 or depth > scope.max_pivot_depth:
            raise ValueError("Entity is outside the approved pivot depth")
        if not entity_in_scope(scope, node):
            raise ValueError("Entity is outside the approved investigation scope")
