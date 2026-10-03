import pytest

from flowsint_enrichers.ip.to_abuseipdb import IpToAbuseIpdbEnricher
from flowsint_types.ip import Ip

MOD = "flowsint_enrichers.ip.to_abuseipdb"


def _payload(score, **over):
    data = {
        "ipAddress": "118.25.6.39",
        "abuseConfidenceScore": score,
        "totalReports": 7,
        "numDistinctUsers": 3,
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Tencent",
        "domain": "tencent.com",
        "countryCode": "CN",
        "isWhitelisted": False,
        "isTor": True,
        "lastReportedAt": "2024-05-01T10:00:00+00:00",
    }
    data.update(over)
    return {"data": data}


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
    e = IpToAbuseIpdbEnricher(sketch_id="s", scan_id="t")
    monkeypatch.setattr(e, "get_secret", lambda *a, **k: key)
    return e


@pytest.mark.asyncio
async def test_scan_maps_score_and_factors(monkeypatch):
    e = _enricher(monkeypatch, _Resp(200, _payload(80)))

    [rep] = await e.scan([Ip(address="118.25.6.39")])

    assert rep.entity_id == "AbuseIPDB 118.25.6.39"
    assert (rep.entity_type, rep.score, rep.score_type) == (
        "IP address",
        80,
        "abuse_confidence",
    )
    assert (rep.provider, rep.source, rep.risk_level) == (
        "AbuseIPDB",
        "AbuseIPDB",
        "high",
    )
    assert rep.last_updated == "2024-05-01T10:00:00+00:00"
    assert rep.factors == [
        "usage: Data Center/Web Hosting/Transit",
        "reports: 7",
        "tor",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "score, level",
    [(0, "low"), (24, "low"), (25, "medium"), (74, "medium"), (75, "high")],
)
async def test_risk_level_thresholds(monkeypatch, score, level):
    e = _enricher(
        monkeypatch, _Resp(200, _payload(score, isTor=False, isWhitelisted=True))
    )

    [rep] = await e.scan([Ip(address="118.25.6.39")])

    assert rep.risk_level == level
    assert rep.factors[-1] == "whitelisted"


@pytest.mark.asyncio
@pytest.mark.parametrize("resp", [_Resp(429, {}), _Resp(200, {"errors": []})])
async def test_error_or_no_data_yields_nothing(monkeypatch, resp):
    e = _enricher(monkeypatch, resp)
    assert await e.scan([Ip(address="118.25.6.39")]) == []


@pytest.mark.asyncio
async def test_missing_key_makes_no_request(monkeypatch):
    e = _enricher(monkeypatch, _Resp(200, _payload(1)), key=None)
    monkeypatch.setattr(
        f"{MOD}.requests.get", lambda *a, **k: pytest.fail("should not call API")
    )
    assert await e.scan([Ip(address="118.25.6.39")]) == []


@pytest.mark.asyncio
async def test_postprocess_links_ip_to_score(monkeypatch):
    e = _enricher(monkeypatch, _Resp(200, _payload(10)))
    edges = []
    e._graph_service = object()
    monkeypatch.setattr(e, "create_node", lambda n: None)
    monkeypatch.setattr(e, "log_graph_message", lambda m: None)
    monkeypatch.setattr(
        e,
        "create_relationship",
        lambda s, d, r: edges.append((s.address, d.entity_id, r)),
    )
    ips = [Ip(address="118.25.6.39")]

    e.postprocess(await e.scan(ips), ips)

    assert edges == [("118.25.6.39", "AbuseIPDB 118.25.6.39", "HAS_REPUTATION")]
