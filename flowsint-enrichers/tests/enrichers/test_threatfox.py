import pytest

from flowsint_enrichers.domain.to_threatfox import DomainToThreatFox
from flowsint_enrichers.ip.to_threatfox import IpToThreatFox
from flowsint_types.domain import Domain
from flowsint_types.ip import Ip


class _NoLogger:
    info = warn = error = staticmethod(lambda *a, **k: None)


class _Resp:
    def __init__(self, payload, status=200):
        self._payload, self.status_code, self.text = payload, status, "body"

    def json(self):
        return self._payload


def _ioc(ioc, ioc_type, malware="win.cobalt_strike", printable="Cobalt Strike", **kw):
    return {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "threat_type": "botnet_cc",
        "malware": malware,
        "malware_printable": printable,
        "first_seen": "2024-03-01 10:00:00 UTC",
        "last_seen": None,
        "reference": None,
        **kw,
    }


def _setup(monkeypatch, enricher_cls, payload, key="k", status=200):
    calls = []

    def fake_post(url, headers=None, json=None, timeout=None):
        calls.append((headers, json))
        return _Resp(payload, status)

    monkeypatch.setattr("flowsint_enrichers.ip.to_threatfox.requests.post", fake_post)
    monkeypatch.setattr("flowsint_enrichers.ip.to_threatfox.Logger", _NoLogger)
    monkeypatch.setattr("flowsint_enrichers.domain.to_threatfox.Logger", _NoLogger)
    enricher = enricher_cls(sketch_id="s", scan_id="t")
    monkeypatch.setattr(enricher, "get_secret", lambda *a, **k: key)
    return enricher, calls


@pytest.mark.asyncio
async def test_ip_maps_merges_and_drops_substring_hits(monkeypatch):
    payload = {
        "query_status": "ok",
        "data": [
            _ioc("1.2.3.4:443", "ip:port", reference="https://r/1"),
            _ioc(
                "1.2.3.4:8080",
                "ip:port",
                first_seen="2024-01-01 00:00:00 UTC",
                last_seen="2024-05-01 00:00:00 UTC",
            ),
            _ioc("11.2.3.4:443", "ip:port"),
            _ioc("1.2.3.44:443", "ip:port", malware="win.x", printable="Other"),
        ],
    }
    enricher, calls = _setup(monkeypatch, IpToThreatFox, payload)

    [m] = await enricher.scan([Ip(address="1.2.3.4")])

    assert calls[0][0] == {"Auth-Key": "k"}
    assert calls[0][1] == {"query": "search_ioc", "search_term": "1.2.3.4"}
    assert (m.name, m.family, m.type, m.source) == (
        "Cobalt Strike",
        "win.cobalt_strike",
        "botnet_cc",
        "ThreatFox",
    )
    assert m.indicators == ["1.2.3.4:443", "1.2.3.4:8080"]
    assert (m.first_seen, m.last_seen) == (
        "2024-01-01 00:00:00 UTC",
        "2024-05-01 00:00:00 UTC",
    )
    assert m.description == "https://r/1"


@pytest.mark.asyncio
async def test_domain_keeps_exact_and_url_host_drops_lookalikes(monkeypatch):
    payload = {
        "query_status": "ok",
        "data": [
            _ioc("example.com", "domain"),
            _ioc("http://example.com/gate.php", "url"),
            _ioc("evil-example.com", "domain"),
            _ioc("http://evil-example.com/x", "url"),
            _ioc("http://sub.example.com/x", "url"),
            _ioc("http://other.org/example.com", "url"),
        ],
    }
    enricher, _ = _setup(monkeypatch, DomainToThreatFox, payload)

    [m] = await enricher.scan([Domain(domain="example.com")])

    assert m.indicators == ["example.com", "http://example.com/gate.php"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload, status",
    [
        (
            {
                "query_status": "no_result",
                "data": "Your search did not yield any results",
            },
            200,
        ),
        ({"query_status": "illegal_search_term"}, 200),
        ({"query_status": "ok", "data": []}, 401),
    ],
)
async def test_no_data_and_failures_return_nothing(monkeypatch, payload, status):
    enricher, _ = _setup(monkeypatch, IpToThreatFox, payload, status=status)

    assert await enricher.scan([Ip(address="1.2.3.4")]) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("enricher_cls", [IpToThreatFox, DomainToThreatFox])
async def test_missing_key_makes_no_request(monkeypatch, enricher_cls):
    enricher, calls = _setup(monkeypatch, enricher_cls, {}, key=None)
    item = (
        Ip(address="1.2.3.4")
        if enricher_cls is IpToThreatFox
        else Domain(domain="a.com")
    )

    assert await enricher.scan([item]) == []
    assert calls == []


@pytest.mark.asyncio
async def test_postprocess_links_each_input_to_its_malware(monkeypatch):
    payload = {"query_status": "ok", "data": [_ioc("example.com", "domain")]}
    enricher, _ = _setup(monkeypatch, DomainToThreatFox, payload)
    edges = []
    enricher._graph_service = object()
    monkeypatch.setattr(enricher, "create_node", lambda node: None)
    monkeypatch.setattr(enricher, "log_graph_message", lambda msg: None)
    monkeypatch.setattr(
        enricher,
        "create_relationship",
        lambda src, dst, rel: edges.append((src.domain, dst.name, rel)),
    )
    items = [Domain(domain="example.com")]

    enricher.postprocess(await enricher.scan(items), items)

    assert edges == [("example.com", "Cobalt Strike", "ASSOCIATED_WITH")]
