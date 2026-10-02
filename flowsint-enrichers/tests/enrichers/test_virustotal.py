import pytest
import requests

from flowsint_enrichers.domain.to_ips_virustotal import DomainToIpsVirusTotal
from flowsint_enrichers.domain.to_reputation_virustotal import (
    DomainToReputationVirusTotal,
)
from flowsint_enrichers.ip.to_domains_virustotal import IpToDomainsVirusTotal
from flowsint_enrichers.ip.to_reputation_virustotal import IpToReputationVirusTotal
from flowsint_types.domain import Domain
from flowsint_types.ip import Ip

DNS_CASES = [
    (DomainToIpsVirusTotal, Domain(domain="foo.com"), "domains/foo.com", "address"),
    (IpToDomainsVirusTotal, Ip(address="1.2.3.4"), "ip_addresses/1.2.3.4", "domain"),
]


def row(ip="1.2.3.4", host="foo.com", date=1700000000):
    return {
        "attributes": {"ip_address": ip, "host_name": host, "date": date},
        "links": {"self": f"https://www.virustotal.com/api/v3/resolutions/{ip}{host}"},
    }


class Response:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self.payload = payload or {}

    def json(self):
        return self.payload


def setup(monkeypatch, cls, responder, key="k", params=None):
    enricher = cls(sketch_id="s", scan_id="t", params=params or {})
    monkeypatch.setattr(enricher, "get_secret", lambda *a, **k: key)
    calls = []

    def get(url, **kwargs):
        calls.append((url, kwargs))
        return responder(url)

    monkeypatch.setattr("flowsint_enrichers.virustotal.requests.get", get)
    return enricher, calls


def graph(monkeypatch, enricher):
    edges = []
    enricher._graph_service = object()
    monkeypatch.setattr(enricher, "create_node", lambda node: None)
    monkeypatch.setattr(enricher, "log_graph_message", lambda msg: None)
    monkeypatch.setattr(
        enricher,
        "create_relationship",
        lambda src, dst, rel, **kw: edges.append((src, dst, rel, kw)),
    )
    return edges


@pytest.mark.asyncio
@pytest.mark.parametrize("cls,item,path,field", DNS_CASES)
async def test_pagination_dedupes_entities_preserves_observations(
    monkeypatch, cls, item, path, field
):
    url = f"https://www.virustotal.com/api/v3/{path}/resolutions"
    pages = {
        url: Response(
            payload={
                "data": [row(date=1591813960)],
                "links": {"next": url + "?cursor=2"},
            }
        ),
        url + "?cursor=2": Response(
            payload={"data": [row(), row("5.6.7.8", "bar.foo.com")]}
        ),
    }
    enricher, calls = setup(monkeypatch, cls, pages.__getitem__)
    edges = graph(monkeypatch, enricher)
    results = await enricher.scan([item])
    enricher.postprocess(results)
    assert len(results) == 2
    assert len(edges) == 3
    assert [(edge[0].domain, edge[1].address) for edge in edges] == [
        ("foo.com", "1.2.3.4"),
        ("foo.com", "1.2.3.4"),
        (
            "bar.foo.com" if isinstance(item, Ip) else "foo.com",
            "1.2.3.4" if isinstance(item, Ip) else "5.6.7.8",
        ),
    ]
    assert edges[0][3]["observed_at"] == "2020-06-10T18:32:40+00:00"
    assert edges[0][3]["provider"] == "VirusTotal"
    assert edges[0][3]["source_ref"].endswith("1.2.3.4foo.com")
    assert calls[0][1]["params"] == {"limit": 40}
    assert calls[1][1]["params"] is None
    assert calls[0][1]["allow_redirects"] is False
    assert enricher._issues == []


@pytest.mark.asyncio
@pytest.mark.parametrize("cls,item,path,field", DNS_CASES)
async def test_page_limit_reports_truncated(monkeypatch, cls, item, path, field):
    url = f"https://www.virustotal.com/api/v3/{path}/resolutions"
    enricher, calls = setup(
        monkeypatch,
        cls,
        lambda u: Response(
            payload={"data": [row()], "links": {"next": url + "?cursor=2"}}
        ),
        params={"max_pages": 1},
    )
    assert len(await enricher.scan([item])) == 1
    assert len(calls) == 1
    assert enricher._issues[0]["outcome"] == "partial"
    assert "truncated" in enricher._issues[0]["message"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "next_url",
    [
        "https://evil.example/resolutions",
        "http://www.virustotal.com/api/v3/domains/foo.com/resolutions",
        "https://www.virustotal.com/api/v3/other",
    ],
)
async def test_invalid_continuation_never_receives_key(monkeypatch, next_url):
    enricher, calls = setup(
        monkeypatch,
        DomainToIpsVirusTotal,
        lambda u: Response(payload={"data": [row()], "links": {"next": next_url}}),
    )
    assert len(await enricher.scan([Domain(domain="foo.com")])) == 1
    assert len(calls) == 1
    assert enricher._issues[0]["outcome"] == "partial"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,outcome",
    [(404, None), (429, "quota_exceeded"), (500, "failed"), (403, "failed")],
)
async def test_provider_outcomes(monkeypatch, status, outcome):
    enricher, calls = setup(
        monkeypatch, DomainToIpsVirusTotal, lambda u: Response(status)
    )
    assert await enricher.scan([Domain(domain="foo.com")]) == []
    assert (enricher._issues[0]["outcome"] if enricher._issues else None) == outcome


@pytest.mark.asyncio
async def test_missing_credentials_no_request(monkeypatch):
    enricher, calls = setup(
        monkeypatch, DomainToIpsVirusTotal, lambda u: Response(), key=None
    )
    assert await enricher.scan([Domain(domain="foo.com")]) == []
    assert calls == []
    assert enricher._issues[0]["outcome"] == "missing_credentials"


@pytest.mark.asyncio
async def test_quota_after_first_page_preserves_partial_and_stops_batch(monkeypatch):
    url = "https://www.virustotal.com/api/v3/domains/foo.com/resolutions"
    enricher, calls = setup(
        monkeypatch,
        DomainToIpsVirusTotal,
        lambda u: (
            Response(payload={"data": [row()], "links": {"next": url + "?cursor=2"}})
            if u == url
            else Response(429)
        ),
    )
    assert (
        len(await enricher.scan([Domain(domain="foo.com"), Domain(domain="bar.com")]))
        == 1
    )
    assert len(calls) == 2
    assert enricher._issues[0]["outcome"] == "quota_exceeded"


@pytest.mark.asyncio
@pytest.mark.parametrize("pages", [0, 26, 1.5, True, "invalid"])
async def test_page_limit_validation(monkeypatch, pages):
    enricher, calls = setup(
        monkeypatch,
        DomainToIpsVirusTotal,
        lambda u: Response(),
        params={"max_pages": pages},
    )
    assert await enricher.scan([Domain(domain="foo.com")]) == []
    assert calls == []
    assert enricher._issues[0]["outcome"] == "failed"


@pytest.mark.asyncio
async def test_invalid_name_does_not_drop_valid_resolutions(monkeypatch):
    enricher, calls = setup(
        monkeypatch,
        IpToDomainsVirusTotal,
        lambda u: Response(payload={"data": [row(host="_.map.fastly.net"), row()]}),
    )
    assert [d.domain for d in await enricher.scan([Ip(address="1.2.3.4")])] == [
        "foo.com"
    ]


@pytest.mark.asyncio
async def test_network_error_redacts_secret(monkeypatch):
    def fail(url):
        raise requests.RequestException("sensitive-key")

    enricher, calls = setup(monkeypatch, DomainToIpsVirusTotal, fail)
    assert await enricher.scan([Domain(domain="foo.com")]) == []
    assert "sensitive-key" not in str(enricher._issues)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cls,item,path",
    [
        (DomainToReputationVirusTotal, Domain(domain="foo.com"), "domains/foo.com"),
        (IpToReputationVirusTotal, Ip(address="1.2.3.4"), "ip_addresses/1.2.3.4"),
    ],
)
async def test_reputation_preserves_signed_community_score_and_verdicts(
    monkeypatch, cls, item, path
):
    payload = {
        "data": {
            "attributes": {
                "reputation": -15,
                "last_analysis_date": 1700000000,
                "last_analysis_stats": {"malicious": 2, "undetected": 8},
                "total_votes": {"malicious": 3},
                "tags": ["test"],
            }
        }
    }
    enricher, calls = setup(monkeypatch, cls, lambda u: Response(payload=payload))
    edges = graph(monkeypatch, enricher)
    results = await enricher.scan([item])
    enricher.postprocess(results)
    assert results[0].score == -15
    assert results[0].analysis_stats == {"malicious": 2, "undetected": 8}
    assert results[0].score_type == "community_reputation"
    assert results[0].risk_level is None
    assert calls[0][0].endswith(path)
    assert edges[0][3]["observed_at"] == "2023-11-14T22:13:20+00:00"


@pytest.mark.asyncio
async def test_malformed_page_retains_prior_page_and_reports_partial(monkeypatch):
    url = "https://www.virustotal.com/api/v3/domains/foo.com/resolutions"
    pages = {
        url: Response(payload={"data": [row()], "links": {"next": url + "?cursor=2"}}),
        url + "?cursor=2": Response(payload={"data": {"invalid": "shape"}}),
    }
    enricher, calls = setup(monkeypatch, DomainToIpsVirusTotal, pages.__getitem__)
    assert len(await enricher.scan([Domain(domain="foo.com")])) == 1
    assert enricher._issues[0]["outcome"] == "partial"


@pytest.mark.asyncio
async def test_invalid_reputation_metadata_does_not_drop_later_inputs(monkeypatch):
    def responder(url):
        return Response(
            payload={
                "data": {
                    "attributes": {
                        "last_analysis_date": "invalid"
                        if url.endswith("first.example")
                        else 1700000000
                    }
                }
            }
        )

    enricher, calls = setup(monkeypatch, DomainToReputationVirusTotal, responder)
    results = await enricher.scan(
        [Domain(domain="first.example"), Domain(domain="second.example")]
    )
    assert len(results) == 1
    assert results[0].entity_id == "VirusTotal second.example"
    assert enricher._issues[0]["outcome"] == "failed"
