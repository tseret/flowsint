"""Opt-in real Cypher regression against a disposable Neo4j database."""

import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from flowsint_core.core.graph import (
    GraphSerializer,
    GraphService,
    Neo4jConnection,
    Neo4jGraphRepository,
)
from flowsint_core.core.graph.types import NodeVersionConflict
from flowsint_types import Domain, Ip, Port, SSLCertificate

pytestmark = pytest.mark.skipif(
    not os.getenv("FLOWSINT_TEST_NEO4J_URI"), reason="Disposable Neo4j not configured"
)


@pytest.fixture
def live_graph():
    Neo4jConnection.reset_instance()
    connection = Neo4jConnection(
        os.environ["FLOWSINT_TEST_NEO4J_URI"], "neo4j", "unused"
    )
    sketch_id = str(uuid.uuid4())
    service = GraphService(sketch_id, Neo4jGraphRepository(connection))
    yield service, connection, sketch_id
    connection.query(
        "MATCH (n {sketch_id:$sketch_id}) DETACH DELETE n", {"sketch_id": sketch_id}
    )
    Neo4jConnection.reset_instance()


def test_identity_evidence_positions_and_stale_edit(live_graph):
    service, connection, sketch_id = live_graph
    domain, ip = Domain(domain="example.test"), Ip(address="192.0.2.1")
    node_id = service.create_node_from_flowsint_type(domain)
    service.create_node_from_flowsint_type(ip)
    for run in ("first", "second"):
        service.create_relationship(
            domain,
            ip,
            "RESOLVES_TO",
            observation={"provider": "fixture", "scan_id": run},
        )
    rows = connection.query(
        "MATCH (n) WHERE elementId(n)=$id RETURN n.version AS version", {"id": node_id}
    )
    version = rows[0]["version"]
    assert service.update_node(
        node_id, {"nodeLabel": "analyst label", "x": 321, "y": 654}, version
    )
    with pytest.raises(NodeVersionConflict):
        service.update_node(node_id, {"nodeLabel": "stale"}, version)
    service.create_node_from_flowsint_type(domain)
    rows = connection.query(
        "MATCH (n:domain {sketch_id:$sketch_id}) RETURN n.x AS x,n.y AS y",
        {"sketch_id": sketch_id},
    )
    assert rows == [{"x": 321, "y": 654}]
    edges = connection.query(
        "MATCH ()-[r:RESOLVES_TO {sketch_id:$sketch_id}]->() RETURN size(r.observations) AS count",
        {"sketch_id": sketch_id},
    )
    assert edges == [{"count": 2}]
    for host in ("192.0.2.1", "192.0.2.2"):
        service.create_node_from_flowsint_type(
            Port(number=443, protocol="tcp", host=host)
        )
    assert connection.query(
        "MATCH (n:port {sketch_id:$sketch_id}) RETURN count(n) AS count",
        {"sketch_id": sketch_id},
    ) == [{"count": 2}]


def test_concurrent_entity_edits_have_one_winner(live_graph):
    service, connection, _ = live_graph
    node_id = service.create_node_from_flowsint_type(Domain(domain="race.test"))
    version = connection.query(
        "MATCH (n) WHERE elementId(n)=$id RETURN n.version AS version", {"id": node_id}
    )[0]["version"]
    ready = Barrier(2)

    def edit(label):
        ready.wait()
        try:
            service.update_node(node_id, {"nodeLabel": label}, version)
            return "saved"
        except NodeVersionConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(edit, ["first", "second"]))
    assert sorted(outcomes) == ["conflict", "saved"]


def test_certificate_renewals_keep_separate_identity(live_graph):
    service, connection, sketch_id = live_graph
    for fingerprint in ("AA:BB", "CC:DD"):
        service.create_node_from_flowsint_type(
            SSLCertificate(subject="example.test", fingerprint_sha256=fingerprint)
        )
    assert connection.query(
        "MATCH (n:sslcertificate {sketch_id:$sketch_id}) RETURN count(n) AS count",
        {"sketch_id": sketch_id},
    ) == [{"count": 2}]
    assert GraphSerializer.canonical_key(
        SSLCertificate(subject="example.test", fingerprint_sha256="AA:BB")
    ) == GraphSerializer.canonical_key(
        SSLCertificate(subject="other label", fingerprint_sha256="aabb")
    )


def test_editing_primary_properties_updates_canonical_identity(live_graph):
    service, connection, sketch_id = live_graph
    node_id = service.create_node_from_flowsint_type(Domain(domain="before.test"))
    assert service.update_node(node_id, {"nodeProperties": {"domain": "after.test"}}, 1)
    service.create_node_from_flowsint_type(Domain(domain="after.test"))
    assert connection.query(
        "MATCH (n:domain {sketch_id:$sketch_id}) RETURN count(n) AS count",
        {"sketch_id": sketch_id},
    ) == [{"count": 1}]


def test_first_creating_scan_survives_later_scans(live_graph):
    service, connection, _ = live_graph
    domain = Domain(domain="owned.test")

    def stamp(scan_id):
        node_id = service.create_node_from_flowsint_type(
            domain, metadata={"scan_id": scan_id}
        )
        row = connection.query(
            "MATCH (n) WHERE elementId(n)=$id RETURN n.`nodeMetadata.created_by_scan`"
            " AS created, n.`nodeMetadata.scan_id` AS latest",
            {"id": node_id},
        )[0]
        return node_id, (row["created"], row["latest"])

    node_id, _ = stamp("scan-a")
    assert stamp("scan-b")[1] == ("scan-a", "scan-b")
    service.delete_nodes([node_id])
    assert stamp("scan-c")[1] == ("scan-c", "scan-c")
