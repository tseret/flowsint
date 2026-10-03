import pytest

from flowsint_enrichers.domain.to_sekoia import DomainToSekoia
from flowsint_enrichers.ip.to_sekoia import IpToSekoia
from flowsint_types.domain import Domain
from flowsint_types.ip import Ip


class _NoLogger:
    info = warn = error = staticmethod(lambda *a, **k: None)


class _Resp:
    def __init__(self, payload, status=200):
        self._payload, self.status_code, self.text = payload, status, "body"

    def json(self):
        return self._payload


def _indicator(iid, pattern, valid_from="2026-06-01T00:00:00Z", revoked=False):
    return {
        "type": "indicator",
        "id": iid,
        "pattern": pattern,
        "valid_from": valid_from,
        "revoked": revoked,
    }


def _indicates(src, dst):
    return {
        "type": "relationship",
        "relationship_type": "indicates",
        "source_ref": src,
        "target_ref": dst,
    }


def _malware(mid, name, types=("remote-access-trojan",)):
    return {
        "type": "malware",
        "id": mid,
        "name": name,
        "malware_types": list(types),
        "description": f"{name} desc",
    }


def _bundle(*objects):
    return {"items": [{"type": "bundle", "objects": list(objects)}]}


def _setup(monkeypatch, enricher_cls, responses, key="k"):
    """`responses` is one (payload, status) per request, in order."""
    calls = []
    queue = list(responses)

    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append(params)
        return _Resp(*queue.pop(0))

    monkeypatch.setattr("flowsint_enrichers.ip.to_sekoia.requests.get", fake_get)
    monkeypatch.setattr("flowsint_enrichers.ip.to_sekoia.Logger", _NoLogger)
    monkeypatch.setattr("flowsint_enrichers.domain.to_sekoia.Logger", _NoLogger)
    enricher = enricher_cls(sketch_id="s", scan_id="t")
    monkeypatch.setattr(enricher, "get_secret", lambda *a, **k: key)
    return enricher, calls


@pytest.mark.asyncio
async def test_links_only_malware_indicated_by_live_indicators(monkeypatch):
    payload = _bundle(
        _indicator(
            "indicator--a", "[ipv4-addr:value = '1.2.3.4']", "2026-06-01T00:00:00Z"
        ),
        _indicator(
            "indicator--b",
            "[network-traffic:dst_ref.value = '1.2.3.4']",
            "2026-05-01T00:00:00Z",
        ),
        _indicator("indicator--r", "[ipv4-addr:value = '1.2.3.4']", revoked=True),
        _malware("malware--remcos", "Remcos"),
        _malware("malware--other", "Unrelated"),  # in bundle, no indicates edge
        _malware("malware--revoked", "OnlyRevoked"),
        {"type": "infrastructure", "id": "infrastructure--x", "name": "C2 infra"},
        _indicates("indicator--a", "malware--remcos"),
        _indicates("indicator--b", "malware--remcos"),
        _indicates("indicator--r", "malware--revoked"),
        _indicates("indicator--a", "infrastructure--x"),
        {
            "type": "relationship",
            "relationship_type": "uses",
            "source_ref": "indicator--a",
            "target_ref": "malware--other",
        },
    )
    enricher, calls = _setup(monkeypatch, IpToSekoia, [(payload, 200)])

    [m] = await enricher.scan([Ip(address="1.2.3.4")])

    assert calls == [{"type": "ipv4-addr", "value": "1.2.3.4"}]
    assert (m.name, m.nodeLabel, m.family, m.source) == (
        "Remcos",
        "Remcos",
        None,
        "Sekoia",
    )
    assert m.type == "remote-access-trojan"
    assert m.first_seen == "2026-05-01T00:00:00Z"
    assert m.indicators == [
        "[ipv4-addr:value = '1.2.3.4']",
        "[network-traffic:dst_ref.value = '1.2.3.4']",
    ]


@pytest.mark.asyncio
async def test_ipv6_uses_ipv6_stix_type(monkeypatch):
    enricher, calls = _setup(monkeypatch, IpToSekoia, [({"items": []}, 200)])

    assert await enricher.scan([Ip(address="2001:db8::1")]) == []
    assert calls == [{"type": "ipv6-addr", "value": "2001:db8::1"}]


@pytest.mark.asyncio
async def test_non_200_skips_input_but_429_stops(monkeypatch):
    hit = _bundle(
        _indicator("indicator--a", "[domain-name:value = 'b.com']"),
        _malware("malware--cf", "ClearFake", types=()),
        _indicates("indicator--a", "malware--cf"),
    )
    enricher, calls = _setup(
        monkeypatch,
        DomainToSekoia,
        [({}, 403), (hit, 200), ({}, 429)],
    )
    items = [Domain(domain=d) for d in ("a.com", "b.com", "c.com", "d.com")]

    [m] = await enricher.scan(items)

    assert (m.name, m.type) == ("ClearFake", None)
    assert [c["value"] for c in calls] == ["a.com", "b.com", "c.com"]


@pytest.mark.asyncio
@pytest.mark.parametrize("enricher_cls", [IpToSekoia, DomainToSekoia])
async def test_missing_key_makes_no_request(monkeypatch, enricher_cls):
    enricher, calls = _setup(monkeypatch, enricher_cls, [], key=None)
    item = (
        Ip(address="1.2.3.4") if enricher_cls is IpToSekoia else Domain(domain="a.com")
    )

    assert await enricher.scan([item]) == []
    assert calls == []


@pytest.mark.asyncio
async def test_postprocess_links_each_input_to_its_malware(monkeypatch):
    payload = _bundle(
        _indicator("indicator--a", "[domain-name:value = 'example.com']"),
        _malware("malware--cf", "ClearFake"),
        _indicates("indicator--a", "malware--cf"),
    )
    enricher, _ = _setup(monkeypatch, DomainToSekoia, [(payload, 200)])
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

    assert edges == [("example.com", "ClearFake", "ASSOCIATED_WITH")]
