import pytest

from flowsint_enrichers.ip.to_shodan import IpToPortsShodanEnricher
from flowsint_types.ip import Ip

MOD = "flowsint_enrichers.ip.to_shodan"

PAYLOAD = {
    "hostnames": ["example.com", "_.map.fastly.net", "www.example.com", "example.com"],
    "data": [
        {
            "port": 443,
            "transport": "tcp",
            "product": "nginx",
            "version": "1.24",
            "data": "B" * 600,
            "timestamp": "2026-09-30T10:00:00",
            "hash": 123,
            "ssl": {"cert": {"fingerprint": {"sha256": "a" * 64}}},
        },
        {"port": 443, "transport": "tcp", "product": "dup"},
        {"port": 53, "transport": "udp", "data": "x"},
        {"port": 443, "transport": "udp"},
    ],
}


class _NoLogger:
    info = warn = error = staticmethod(lambda *a, **k: None)


class _Resp:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload

    def json(self):
        return self._payload


def _enricher(monkeypatch, resp, key="k"):
    monkeypatch.setattr(f"{MOD}.Logger", _NoLogger)
    monkeypatch.setattr(f"{MOD}.requests.get", lambda *a, **k: resp)
    e = IpToPortsShodanEnricher(sketch_id="s", scan_id="t")
    monkeypatch.setattr(e, "get_secret", lambda *a, **k: key)
    return e


@pytest.mark.asyncio
async def test_scan_maps_ports_and_dedupes_by_port_transport(monkeypatch):
    e = _enricher(monkeypatch, _Resp(200, PAYLOAD))

    ports = await e.scan([Ip(address="93.184.216.34")])

    assert [(p.number, p.protocol, p.state, p.service) for p in ports] == [
        (443, "tcp", "open", "nginx 1.24"),
        (53, "udp", "open", None),
        (443, "udp", "open", None),
    ]
    assert ports[0].banner == "B" * 500
    assert ports[0].model_extra["fingerprints"] == {
        "banner_hash": "123",
        "tls_sha256": "a" * 64,
    }
    assert ports[0].model_extra["observed_at"] == "2026-09-30T10:00:00"
    assert (
        ports[0].model_extra["source_ref"] == "https://www.shodan.io/host/93.184.216.34"
    )


@pytest.mark.asyncio
async def test_404_yields_nothing(monkeypatch):
    e = _enricher(monkeypatch, _Resp(404, {"error": "No information available"}))
    assert await e.scan([Ip(address="10.0.0.1")]) == []


@pytest.mark.asyncio
async def test_missing_key_makes_no_request(monkeypatch):
    e = _enricher(monkeypatch, _Resp(200, PAYLOAD), key=None)
    monkeypatch.setattr(
        f"{MOD}.requests.get", lambda *a, **k: pytest.fail("should not call API")
    )
    assert await e.scan([Ip(address="10.0.0.1")]) == []


@pytest.mark.asyncio
async def test_postprocess_creates_port_and_hostname_edges(monkeypatch):
    e = _enricher(monkeypatch, _Resp(200, PAYLOAD))
    edges = []
    e._graph_service = object()
    monkeypatch.setattr(e, "create_node", lambda n: None)
    monkeypatch.setattr(e, "log_graph_message", lambda m: None)
    monkeypatch.setattr(
        e,
        "create_relationship",
        lambda s, d, r, **kwargs: edges.append(
            (s.address, getattr(d, "domain", d.nodeLabel), r)
        ),
    )
    ips = [Ip(address="93.184.216.34")]

    e.postprocess(await e.scan(ips), ips)

    rels = [(d, r) for _, d, r in edges]
    assert rels.count(("443 nginx 1.24 (tcp)", "HAS_PORT")) == 1
    assert [x for x in rels if x[1] == "REVERSE_RESOLVES_TO"] == [
        ("example.com", "REVERSE_RESOLVES_TO"),
        ("www.example.com", "REVERSE_RESOLVES_TO"),
    ]
