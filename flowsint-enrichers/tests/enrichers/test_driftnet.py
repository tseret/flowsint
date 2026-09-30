import pytest

from flowsint_enrichers.ip.to_ports_driftnet import IpToPortsDriftnetEnricher
from flowsint_types.ip import Ip

MOD = "flowsint_enrichers.ip.to_ports_driftnet"


class _NoLogger:
    info = warn = error = staticmethod(lambda *a, **k: None)


class _Resp:
    def __init__(self, status=200, payload=None):
        self.status_code, self._payload, self.text = status, payload, "body"

    def json(self):
        return self._payload


def _enricher(monkeypatch, responses, key="k"):
    """`responses` is one _Resp per request, in order."""
    calls = []
    queue = list(responses)

    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append((params["ip"], headers))
        return queue.pop(0)

    monkeypatch.setattr(f"{MOD}.Logger", _NoLogger)
    monkeypatch.setattr(f"{MOD}.requests.get", fake_get)
    e = IpToPortsDriftnetEnricher(sketch_id="s", scan_id="t")
    monkeypatch.setattr(e, "get_secret", lambda *a, **k: key)
    return e, calls


@pytest.mark.asyncio
async def test_scan_maps_port_counts_to_open_tcp_ports(monkeypatch):
    payload = {"other": 2, "values": {"443": 10, "53": 4, "junk": 1}, "honeypot": True}
    e, calls = _enricher(monkeypatch, [_Resp(200, payload)])

    ports = await e.scan([Ip(address="8.8.8.8")])

    assert calls == [("8.8.8.8", {"Authorization": "Bearer k"})]
    assert [(p.number, p.protocol, p.state, p.nodeLabel) for p in ports] == [
        (443, "tcp", "open", "443 (tcp)"),
        (53, "tcp", "open", "53 (tcp)"),
    ]


@pytest.mark.asyncio
async def test_other_errors_skip_input_but_quota_403_stops(monkeypatch):
    e, calls = _enricher(
        monkeypatch,
        [
            _Resp(500),
            _Resp(200, {"other": 0, "values": {"22": 1}}),
            _Resp(403, {"code": 403, "message": "api usage limit hit"}),
        ],
    )
    ips = [Ip(address=f"10.0.0.{i}") for i in range(1, 5)]

    ports = await e.scan(ips)

    assert [p.number for p in ports] == [22]
    assert [ip for ip, _ in calls] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


@pytest.mark.asyncio
async def test_missing_key_makes_no_request(monkeypatch):
    e, calls = _enricher(monkeypatch, [], key=None)

    assert await e.scan([Ip(address="10.0.0.1")]) == []
    assert calls == []


@pytest.mark.asyncio
async def test_postprocess_links_ip_to_ports(monkeypatch):
    e, _ = _enricher(monkeypatch, [_Resp(200, {"other": 0, "values": {"443": 3}})])
    edges = []
    e._graph_service = object()
    monkeypatch.setattr(e, "create_node", lambda n: None)
    monkeypatch.setattr(e, "log_graph_message", lambda m: None)
    monkeypatch.setattr(
        e,
        "create_relationship",
        lambda s, d, r: edges.append((s.address, d.nodeLabel, r)),
    )
    ips = [Ip(address="8.8.8.8")]

    e.postprocess(await e.scan(ips), ips)

    assert edges == [("8.8.8.8", "443 (tcp)", "HAS_PORT")]
