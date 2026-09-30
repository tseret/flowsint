import pytest

from flowsint_enrichers.domain.to_ips_virustotal import DomainToIpsVirusTotal
from flowsint_enrichers.ip.to_domains_virustotal import IpToDomainsVirusTotal
from flowsint_types.domain import Domain
from flowsint_types.ip import Ip

MODS = {
    DomainToIpsVirusTotal: "flowsint_enrichers.domain.to_ips_virustotal",
    IpToDomainsVirusTotal: "flowsint_enrichers.ip.to_domains_virustotal",
}

# 1591813960 = 2020-06-10, 1591787179 = 2020-06-10, 1700000000 = 2023-11-14
PAYLOAD = {
    "data": [
        {
            "attributes": {
                "ip_address": "1.2.3.4",
                "host_name": "foo.com",
                "date": 1591813960,
            }
        },
        {
            "attributes": {
                "ip_address": "1.2.3.4",
                "host_name": "foo.com",
                "date": 1700000000,
            }
        },
        {
            "attributes": {
                "ip_address": "5.6.7.8",
                "host_name": "bar.foo.com",
                "date": 1591787179,
            }
        },
    ],
    "links": {"next": "https://www.virustotal.com/api/v3/next"},
}


class _NoLogger:
    info = warn = error = staticmethod(lambda *a, **k: None)


class _Resp:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.text = ""

    def json(self):
        return self._payload


def _setup(monkeypatch, cls, responder, key="k"):
    mod = MODS[cls]
    monkeypatch.setattr(f"{mod}.Logger", _NoLogger)
    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return responder(url)

    monkeypatch.setattr(f"{mod}.requests.get", fake_get)
    enricher = cls(sketch_id="s", scan_id="t")
    monkeypatch.setattr(enricher, "get_secret", lambda *a, **k: key)
    return enricher, calls


def _capture_graph(monkeypatch, enricher):
    edges, msgs = [], []
    enricher._graph_service = object()
    monkeypatch.setattr(enricher, "create_node", lambda node: None)
    monkeypatch.setattr(enricher, "log_graph_message", msgs.append)
    monkeypatch.setattr(
        enricher,
        "create_relationship",
        lambda src, dst, rel: edges.append((src.domain, dst.address, rel)),
    )
    return edges, msgs


@pytest.mark.asyncio
async def test_domain_to_ips_maps_and_dedupes(monkeypatch):
    enricher, calls = _setup(
        monkeypatch, DomainToIpsVirusTotal, lambda u: _Resp(payload=PAYLOAD)
    )

    results = await enricher.scan([Domain(domain="foo.com")])

    assert [ip.address for ip in results] == ["1.2.3.4", "5.6.7.8"]
    url, kwargs = calls[0]
    assert url.endswith("/domains/foo.com/resolutions")
    assert kwargs["headers"] == {"x-apikey": "k"}
    assert kwargs["params"] == {"limit": 40}


@pytest.mark.asyncio
async def test_ip_to_domains_maps_and_dedupes(monkeypatch):
    enricher, calls = _setup(
        monkeypatch, IpToDomainsVirusTotal, lambda u: _Resp(payload=PAYLOAD)
    )

    results = await enricher.scan([Ip(address="1.2.3.4")])

    assert [d.domain for d in results] == ["foo.com", "bar.foo.com"]
    assert calls[0][0].endswith("/ip_addresses/1.2.3.4/resolutions")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cls, item",
    [
        (DomainToIpsVirusTotal, Domain(domain="foo.com")),
        (IpToDomainsVirusTotal, Ip(address="1.2.3.4")),
    ],
)
async def test_404_yields_no_data(monkeypatch, cls, item):
    enricher, _ = _setup(monkeypatch, cls, lambda u: _Resp(status=404))

    assert await enricher.scan([item]) == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cls, item",
    [
        (DomainToIpsVirusTotal, Domain(domain="foo.com")),
        (IpToDomainsVirusTotal, Ip(address="1.2.3.4")),
    ],
)
async def test_missing_key_makes_no_request(monkeypatch, cls, item):
    enricher, calls = _setup(
        monkeypatch, cls, lambda u: _Resp(payload=PAYLOAD), key=None
    )

    assert await enricher.scan([item]) == []
    assert calls == []


@pytest.mark.asyncio
async def test_429_stops_remaining_inputs(monkeypatch):
    enricher, calls = _setup(
        monkeypatch, DomainToIpsVirusTotal, lambda u: _Resp(status=429)
    )

    results = await enricher.scan([Domain(domain="a.com"), Domain(domain="b.com")])

    assert results == []
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_domain_to_ips_edges_and_last_seen(monkeypatch):
    enricher, _ = _setup(
        monkeypatch, DomainToIpsVirusTotal, lambda u: _Resp(payload=PAYLOAD)
    )
    edges, msgs = _capture_graph(monkeypatch, enricher)

    results = await enricher.scan([Domain(domain="foo.com")])
    enricher.postprocess(results)

    assert edges == [
        ("foo.com", "1.2.3.4", "PASSIVE_DNS_RESOLVED_TO"),
        ("foo.com", "5.6.7.8", "PASSIVE_DNS_RESOLVED_TO"),
    ]
    assert "last seen 2023-11-14" in msgs[0]  # max date wins
    assert "last seen 2020-06-10" in msgs[1]


@pytest.mark.asyncio
async def test_ip_to_domains_edge_points_domain_to_ip(monkeypatch):
    enricher, _ = _setup(
        monkeypatch, IpToDomainsVirusTotal, lambda u: _Resp(payload=PAYLOAD)
    )
    edges, msgs = _capture_graph(monkeypatch, enricher)

    results = await enricher.scan([Ip(address="1.2.3.4")])
    enricher.postprocess(results)

    assert edges == [
        ("foo.com", "1.2.3.4", "PASSIVE_DNS_RESOLVED_TO"),
        ("bar.foo.com", "1.2.3.4", "PASSIVE_DNS_RESOLVED_TO"),
    ]
    assert "last seen 2023-11-14" in msgs[0]
