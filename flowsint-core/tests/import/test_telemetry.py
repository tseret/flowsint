import json

import pytest

from flowsint_core.imports.telemetry import parse_telemetry

TIME = "2026-01-01T01:00:00+01:00"


def test_normalized_batch_and_safe_properties():
    record = {
        "source": "192.0.2.1",
        "target": "EXAMPLE.COM.",
        "timestamp": TIME,
        "authorization": "private-token",
        "headers": {"Cookie": "secret"},
    }
    [edge] = parse_telemetry(json.dumps(record), "normalized")
    assert edge == {
        "source": {
            "type": "ip",
            "label": "192.0.2.1",
            "properties": {"address": "192.0.2.1"},
        },
        "target": {
            "type": "domain",
            "label": "example.com",
            "properties": {"domain": "example.com"},
        },
        "relationship": "OBSERVED_CONTACT",
        "observed_at": "2026-01-01T00:00:00+00:00",
        "source_ref": "local:normalized:record:1",
    }


def test_proxy_url_drops_credentials_query_and_fragment():
    [edge] = parse_telemetry(
        json.dumps(
            {
                "client_ip": "2001:db8::1",
                "url": "https://user:password@example.com/download?token=secret#private",
                "time": TIME,
            }
        ),
        "proxy",
    )
    assert edge["target"]["properties"] == {"url": "https://example.com/download"}
    assert edge["relationship"] == "REQUESTED_URL"
    assert "secret" not in json.dumps(edge) and "password" not in json.dumps(edge)


def test_dns_alias_and_answer_relationships():
    edges = parse_telemetry(
        json.dumps(
            {
                "src_ip": "192.0.2.1",
                "query": "example.com",
                "answers": ["192.0.2.2", "alias.example.com"],
                "timestamp": TIME,
            }
        ),
        "dns",
    )
    assert [edge["relationship"] for edge in edges] == [
        "QUERIED_DOMAIN",
        "DNS_RESOLVED_TO",
        "ALIASES_TO",
    ]


def test_zeek_conn_and_dns_ndjson():
    records = [
        {"ts": 1767225600.0, "id.orig_h": "192.0.2.1", "id.resp_h": "192.0.2.2"},
        {
            "ts": 1767225600,
            "id.orig_h": "192.0.2.1",
            "query": "example.com",
            "qtype_name": "A",
            "answers": ["192.0.2.3"],
        },
    ]
    edges = parse_telemetry("\n".join(json.dumps(row) for row in records), "zeek")
    assert len(edges) == 3
    assert edges[0]["relationship"] == "CONNECTED_TO"
    assert edges[0]["observed_at"] == "2026-01-01T00:00:00+00:00"
    assert edges[2]["source_ref"] == "local:zeek:record:2"


def test_suricata_dns_flow_and_http():
    records = [
        {
            "event_type": "dns",
            "timestamp": TIME,
            "src_ip": "192.0.2.53",
            "dest_ip": "192.0.2.1",
            "dns": {
                "type": "answer",
                "rrname": "example.com",
                "answers": [{"rrtype": "A", "rdata": "192.0.2.2"}],
            },
        },
        {
            "event_type": "flow",
            "timestamp": TIME,
            "src_ip": "192.0.2.1",
            "dest_ip": "192.0.2.2",
        },
        {
            "event_type": "http",
            "timestamp": TIME,
            "src_ip": "192.0.2.1",
            "http": {"hostname": "example.com", "url": "/test?key=secret"},
        },
    ]
    edges = parse_telemetry(json.dumps(records), "suricata")
    assert [edge["relationship"] for edge in edges] == [
        "QUERIED_DOMAIN",
        "DNS_RESOLVED_TO",
        "CONNECTED_TO",
        "REQUESTED_URL",
    ]
    assert edges[0]["source"]["label"] == "192.0.2.1"
    assert edges[-1]["target"]["label"] == "http://example.com/test"


def test_cloudtrail_actor_ip_and_service_only():
    record = {
        "eventTime": TIME,
        "userIdentity": {
            "arn": "arn:aws:iam::123456789012:user/analyst",
            "accessKeyId": "private",
        },
        "sourceIPAddress": "192.0.2.1",
        "eventSource": "s3.amazonaws.com",
        "requestParameters": {"secret": "private"},
    }
    edges = parse_telemetry(json.dumps({"Records": [record]}), "cloudtrail")
    assert len(edges) == 2
    assert edges[0]["source"]["type"] == "phrase"
    assert edges[0]["target"]["type"] == "ip"
    assert edges[1]["target"]["label"] == "s3.amazonaws.com"
    assert "private" not in json.dumps(edges)


@pytest.mark.parametrize(
    "record",
    [
        {"source": "192.0.2.1", "target": "example.com", "timestamp": "2026-01-01"},
        {
            "source": "192.0.2.1",
            "target": "example.com",
            "timestamp": TIME,
            "relationship": "EXECUTE_QUERY",
        },
        {"source": "bad private-token", "target": "example.com", "timestamp": TIME},
        {
            "source": "192.0.2.1",
            "target": {"type": "unknown", "label": "private-token"},
            "timestamp": TIME,
        },
    ],
)
def test_malformed_batch_rejected_at_record_without_echoing_input(record):
    valid = {"source": "192.0.2.1", "target": "example.com", "timestamp": TIME}
    with pytest.raises(ValueError, match="Record 2") as error:
        parse_telemetry(json.dumps([valid, record]), "normalized")
    assert "private-token" not in str(error.value)


def test_input_record_and_edge_budgets():
    with pytest.raises(ValueError, match="2 MiB"):
        parse_telemetry(" " * (2 * 1024 * 1024 + 1), "normalized")
    record = {"source": "192.0.2.1", "target": "example.com", "timestamp": TIME}
    with pytest.raises(ValueError, match="1000 record"):
        parse_telemetry(json.dumps([record] * 1001), "normalized")
    dns = {
        "source": "192.0.2.1",
        "target": "example.com",
        "answers": ["192.0.2.2", "192.0.2.3"],
        "timestamp": TIME,
    }
    with pytest.raises(ValueError, match="2000 edge"):
        parse_telemetry(json.dumps([dns] * 667), "dns")
    assert len(parse_telemetry(json.dumps([record] * 1000), "normalized")) == 1000


def test_invalid_json_and_empty_batches():
    with pytest.raises(ValueError, match="Record 2"):
        parse_telemetry('{}\n{"incomplete":', "normalized")
    with pytest.raises(ValueError, match="at least one"):
        parse_telemetry("[]", "normalized")
    with pytest.raises(ValueError, match="Unsupported"):
        parse_telemetry("[]", "unknown")


def test_deeply_nested_json_is_a_validation_error():
    with pytest.raises(ValueError, match="Record 1"):
        parse_telemetry("[" * 2000 + "0" + "]" * 2000, "normalized")
