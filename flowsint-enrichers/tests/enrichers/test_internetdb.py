import pytest

from flowsint_enrichers.ip.to_internetdb import IpToInternetDbEnricher
from flowsint_types.ip import Ip

PAYLOAD = {
    "cpes": ["cpe:/a:varnish-software:varnish_cache"],
    "hostnames": ["python.org", "www.python.org"],
    "ip": "151.101.128.223",
    "ports": [80, 443],
    "tags": ["cdn"],
    "vulns": ["CVE-2021-0001"],
}


class _NoLogger:
    info = warn = error = staticmethod(lambda *a, **k: None)


class _Resp:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("bad json")
        return self._body


def _enricher(monkeypatch, responses):
    monkeypatch.setattr("flowsint_enrichers.ip.to_internetdb.Logger", _NoLogger)
    monkeypatch.setattr(
        "flowsint_enrichers.ip.to_internetdb.requests.get",
        lambda url, **k: responses[url.rsplit("/", 1)[1]],
    )
    return IpToInternetDbEnricher(sketch_id="s", scan_id="t")


@pytest.mark.asyncio
async def test_scan_maps_ports_and_postprocess_links_ports_and_hostnames(monkeypatch):
    enricher = _enricher(monkeypatch, {"151.101.128.223": _Resp(200, PAYLOAD)})
    edges, logs = [], []
    enricher._graph_service = object()
    monkeypatch.setattr(enricher, "create_node", lambda node: None)
    monkeypatch.setattr(enricher, "log_graph_message", logs.append)
    monkeypatch.setattr(
        enricher,
        "create_relationship",
        lambda s, d, rel: edges.append(
            (s.address, getattr(d, "number", None) or d.domain, rel)
        ),
    )
    ips = [Ip(address="151.101.128.223")]

    ports = await enricher.scan(ips)
    enricher.postprocess(ports, ips)

    assert [(p.number, p.protocol, p.state) for p in ports] == [
        (80, "tcp", "open"),
        (443, "tcp", "open"),
    ]
    assert edges == [
        ("151.101.128.223", 80, "HAS_PORT"),
        ("151.101.128.223", 443, "HAS_PORT"),
        ("151.101.128.223", "python.org", "REVERSE_RESOLVES_TO"),
        ("151.101.128.223", "www.python.org", "REVERSE_RESOLVES_TO"),
    ]
    assert any("CVE-2021-0001" in m for m in logs)


@pytest.mark.asyncio
async def test_404_is_no_data_and_later_ips_still_processed(monkeypatch):
    enricher = _enricher(
        monkeypatch,
        {
            "10.0.0.1": _Resp(404, {"detail": "No information available"}),
            "10.0.0.2": _Resp(500),
            "10.0.0.3": _Resp(200, {"ip": "10.0.0.3", "ports": [22]}),
        },
    )

    ports = await enricher.scan([Ip(address=f"10.0.0.{i}") for i in (1, 2, 3)])

    assert [p.number for p in ports] == [22]
