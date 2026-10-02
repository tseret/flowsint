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
        lambda src, dst, kind: edges.append(
            (src.address, dst.number, dst.protocol, kind)
        ),
    )

    results = await enricher.scan([Ip(address="8.8.8.8"), Ip(address="1.1.1.1")])
    enricher.postprocess(results)

    assert edges == [
        ("8.8.8.8", 53, "UDP", "HAS_PORT"),
        ("1.1.1.1", 443, "TCP", "HAS_PORT"),
    ]
