from unittest.mock import Mock

import pytest

from flowsint_enrichers.ip.to_ports_modat import IpToPortsModatEnricher
from flowsint_types.ip import Ip

MOD = "flowsint_enrichers.ip.to_ports_modat"


class _NoLogger:
    error = staticmethod(lambda *args, **kwargs: None)


class _Response:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self.payload = payload

    def json(self):
        return self.payload


def _enricher(monkeypatch, responses, key="test-key"):
    calls = []
    queue = iter(responses)

    def fake_get(url, headers, timeout):
        calls.append((url, headers, timeout))
        return next(queue)

    monkeypatch.setattr(f"{MOD}.Logger", _NoLogger)
    monkeypatch.setattr(f"{MOD}.requests.get", fake_get)
    vault = Mock()
    vault.get_secret.return_value = key
    enricher = IpToPortsModatEnricher(sketch_id="s", scan_id="t", vault=vault)
    return enricher, calls


@pytest.mark.asyncio
async def test_host_lookup_maps_ports_and_preserves_transport(monkeypatch):
    services = [
        {"transport": "tcp", "ports": [53, 443, 443], "protocol": "http"},
        {"transport": "udp", "ports": [53], "protocol": "dns"},
        {"transport": "tcp", "ports": [0, 65536, "22", True], "protocol": "ssh"},
    ]
    enricher, calls = _enricher(
        monkeypatch, [_Response(payload={"data": {"services": services}})]
    )

    ports = await enricher.scan([Ip(address="8.8.8.8")])
    enricher.vault.get_secret.assert_called_once_with("MODAT_API_KEY")

    assert calls == [
        (
            "https://api.magnify.modat.io/host/8.8.8.8/v1",
            {
                "Authorization": "Bearer test-key",
                "User-Agent": "Flowsint-Modat-Connector",
            },
            30,
        )
    ]
    assert [(p.number, p.protocol, p.service, p.state) for p in ports] == [
        (53, "TCP", "http", "open"),
        (443, "TCP", "http", "open"),
        (53, "UDP", "dns", "open"),
    ]
    assert ports[1].nodeLabel == "443 http (TCP)"
    assert {p.host for p in ports} == {"8.8.8.8"}


@pytest.mark.asyncio
async def test_auth_error_stops_batch_but_missing_host_does_not(monkeypatch):
    enricher, calls = _enricher(
        monkeypatch,
        [
            _Response(404),
            _Response(
                payload={
                    "data": {
                        "services": [
                            {"transport": "tcp", "ports": [22], "protocol": "unknown"}
                        ]
                    }
                }
            ),
            _Response(403),
        ],
    )

    ports = await enricher.scan([Ip(address=f"10.0.0.{i}") for i in range(1, 5)])

    assert [(p.number, p.service) for p in ports] == [(22, None)]
    assert len(calls) == 3


@pytest.mark.asyncio
async def test_missing_key_makes_no_request(monkeypatch):
    enricher, calls = _enricher(monkeypatch, [], key=None)
    monkeypatch.delenv("MODAT_API_KEY", raising=False)

    assert await enricher.scan([Ip(address="8.8.8.8")]) == []
    assert calls == []


@pytest.mark.asyncio
async def test_postprocess_links_each_port_to_source_ip(monkeypatch):
    enricher, _ = _enricher(
        monkeypatch,
        [
            _Response(
                payload={
                    "data": {
                        "services": [
                            {"transport": "udp", "ports": [53], "protocol": "dns"}
                        ]
                    }
                }
            ),
            _Response(
                payload={
                    "data": {
                        "services": [
                            {"transport": "tcp", "ports": [443], "protocol": "http"}
                        ]
                    }
                }
            ),
        ],
    )
    edges = []
    enricher._graph_service = object()
    monkeypatch.setattr(enricher, "create_node", lambda node: None)
    monkeypatch.setattr(enricher, "log_graph_message", lambda message: None)
    monkeypatch.setattr(
        enricher,
        "create_relationship",
        lambda src, dst, kind, **evidence: edges.append(
            (src.address, dst.number, dst.protocol, kind)
        ),
    )

    results = await enricher.scan([Ip(address="8.8.8.8"), Ip(address="1.1.1.1")])
    enricher.postprocess(results)

    assert edges == [
        ("8.8.8.8", 53, "UDP", "HAS_PORT"),
        ("1.1.1.1", 443, "TCP", "HAS_PORT"),
    ]


@pytest.mark.asyncio
async def test_ssh_only_service_retains_hassh_and_observation_provenance(monkeypatch):
    service = {
        "transport": "tcp",
        "ports": [22],
        "protocol": "ssh",
        "timestamp": "2026-10-02T09:00:00Z",
        "ssh": {"hassh": "AB" * 16, "password": "private"},
        "banner_sha256": "cd" * 32,
    }
    enricher, calls = _enricher(
        monkeypatch, [_Response(payload={"data": {"services": [service]}})]
    )
    results = await enricher.scan([Ip(address="192.0.2.1")])
    assert len(calls) == 1
    assert results[0].model_extra["fingerprints"] == {
        "ssh.hassh": "ab" * 16,
        "banner_sha256": "cd" * 32,
    }
    assert results[0].model_extra["observed_at"] == service["timestamp"]
    assert results[0].model_extra["provider"] == "Modat"
    assert "private" not in results[0].model_dump_json()
    enricher._graph_service = object()
    monkeypatch.setattr(enricher, "create_node", lambda node: None)
    monkeypatch.setattr(enricher, "log_graph_message", lambda message: None)
    relationship = Mock()
    monkeypatch.setattr(enricher, "create_relationship", relationship)
    enricher.postprocess(results)
    assert relationship.call_args.kwargs == {
        "provider": "Modat",
        "observed_at": service["timestamp"],
        "source_ref": "https://api.magnify.modat.io/host/192.0.2.1/v1",
    }


@pytest.mark.asyncio
async def test_invalid_hashes_are_not_recorded_and_dates_are_not_invented(monkeypatch):
    services = [
        None,
        {
            "transport": "tcp",
            "ports": [22],
            "protocol": "ssh",
            "ssh": {"hassh": "invalid"},
            "tls": {"jarm": {"nested": "value"}},
        },
    ]
    enricher, _ = _enricher(
        monkeypatch, [_Response(payload={"data": {"services": services}})]
    )
    results = await enricher.scan([Ip(address="192.0.2.1")])
    assert results[0].model_extra["fingerprints"] == {}
    assert results[0].model_extra["observed_at"] is None


@pytest.mark.asyncio
async def test_quota_failure_is_reported_as_collection_gap(monkeypatch):
    enricher, _ = _enricher(monkeypatch, [_Response(429)])
    issue = Mock()
    monkeypatch.setattr(enricher, "report_issue", issue)
    assert await enricher.scan([Ip(address="192.0.2.1")]) == []
    issue.assert_called_once_with("quota_exceeded", "Modat returned HTTP 429.")


@pytest.mark.asyncio
async def test_provider_scanned_date_and_readable_banner_are_retained(monkeypatch):
    service = {
        "transport": "tcp",
        "ports": [22],
        "protocol": "ssh",
        "scanned_at": "2026-10-02T08:00:00Z",
        "timestamp": "older",
        "banner": "SSH-2.0-OpenSSH_9.6",
        "ssh": {"hassh": "ab" * 16},
    }
    enricher, _ = _enricher(
        monkeypatch, [_Response(payload={"data": {"services": [service]}})]
    )
    port = (await enricher.scan([Ip(address="192.0.2.1")]))[0]
    assert port.banner == service["banner"]
    assert port.model_extra["observed_at"] == service["scanned_at"]
    assert port.model_extra["retrieved_at"]


def _recorded_service():
    return {
        "host": "192.0.2.1",
        "port": 22,
        "transport": "TCP",
        "service": "ssh",
        "provider": "Modat",
        "fingerprints": {"ssh.hassh": "ab" * 16},
    }


def test_single_ssh_hash_builds_same_endpoint_query_without_three_family_gate():
    from flowsint_enrichers.ip.to_ports_modat import recorded_fingerprint_query

    assert recorded_fingerprint_query(_recorded_service(), "ssh.hassh") == (
        'port=22 protocol="ssh" transport="tcp" ssh.hassh="' + "ab" * 16 + '"'
    )
    for override in (
        {"service": 'ssh" OR port=1'},
        {"port": True},
        {"transport": "icmp"},
        {"provider": "Shodan"},
        {"fingerprints": {"ssh.hassh": "bad"}},
    ):
        assert (
            recorded_fingerprint_query({**_recorded_service(), **override}, "ssh.hassh")
            is None
        )
    assert recorded_fingerprint_query(_recorded_service(), "arbitrary") is None


def test_indexed_lookup_makes_one_request_returns_exact_unverified_matches(monkeypatch):
    from flowsint_enrichers.ip.to_ports_modat import lookup_recorded_fingerprint

    response = Mock()
    rows = [
        {
            "ip": f"192.0.2.{n}",
            "service": {
                "port": 22,
                "protocol": "ssh",
                "transport": "tcp",
                "scanned_at": "2026-10-01",
                "ssh": {"hassh": "ab" * 16},
                "banner": "SSH-2.0-Test",
            },
        }
        for n in range(1, 5)
    ]
    rows += [
        {"ip": "192.0.2.2", "service": rows[1]["service"]},
        {"ip": "192.0.2.9", "service": {**rows[1]["service"], "port": 443}},
        {
            "ip": "192.0.2.8",
            "service": {**rows[1]["service"], "ssh": {"hassh": "cd" * 16}},
        },
        {"ip": "192.0.2.7", "service": {**rows[1]["service"], "transport": "udp"}},
        {"ip": "192.0.2.6", "service": {**rows[1]["service"], "protocol": "http"}},
        {"ip": "not-an-ip", "service": rows[1]["service"]},
        None,
    ]
    response.json.return_value = {
        "page": rows,
        "total_records": len(rows),
        "total_pages": 1,
    }
    post = Mock(return_value=response)
    monkeypatch.setattr(f"{MOD}.requests.post", post)
    result = lookup_recorded_fingerprint(_recorded_service(), "ssh.hassh", "test-key")
    post.assert_called_once()
    assert post.call_args.args[0] == "https://api.magnify.modat.io/service/search/v1"
    assert post.call_args.kwargs["json"] == {
        "query": result["query"],
        "page": 1,
        "page_size": 50,
    }
    assert {item["ip"] for item in result["matches"]} == {
        "192.0.2.2",
        "192.0.2.3",
        "192.0.2.4",
    }
    assert result["matches"][0]["matching_fingerprints"] == ["ssh.hassh"]
    assert result["matches"][0]["observed_at"] == "2026-10-01"
    assert result["matches"][0]["banner"] == "SSH-2.0-Test"
    assert result["truncated"]
    assert "test-key" not in str(result)


def test_provider_pagination_is_flagged_without_automatic_second_request(monkeypatch):
    from flowsint_enrichers.ip.to_ports_modat import lookup_recorded_fingerprint

    response = Mock()
    response.json.return_value = {"page": [], "total_records": 80, "total_pages": 2}
    post = Mock(return_value=response)
    monkeypatch.setattr(f"{MOD}.requests.post", post)
    assert lookup_recorded_fingerprint(_recorded_service(), "ssh.hassh", "test-key")[
        "truncated"
    ]
    post.assert_called_once()


@pytest.mark.parametrize("payload", [None, {}, {"page": None}])
def test_lookup_rejects_unusable_provider_payload(monkeypatch, payload):
    from flowsint_enrichers.ip.to_ports_modat import lookup_recorded_fingerprint

    response = Mock()
    response.json.return_value = payload
    monkeypatch.setattr(f"{MOD}.requests.post", Mock(return_value=response))
    with pytest.raises(ValueError):
        lookup_recorded_fingerprint(_recorded_service(), "ssh.hassh", "test-key")
