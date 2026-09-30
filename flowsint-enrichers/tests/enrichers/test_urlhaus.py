import pytest

from flowsint_enrichers.domain.to_urlhaus import DomainToUrlhaus
from flowsint_enrichers.ip.to_urlhaus import IpToUrlhaus
from flowsint_enrichers.website.to_urlhaus import WebsiteToUrlhaus
from flowsint_types.domain import Domain
from flowsint_types.ip import Ip
from flowsint_types.website import Website

SHA = "4293c1d8574dc87c58360d6bac3daa182f64f7785c9d41da5e0741d2b1817fc7"


class _NoLogger:
    info = warn = error = staticmethod(lambda *a, **k: None)


class _Resp:
    def __init__(self, payload, status=200):
        self._payload, self.status_code, self.text = payload, status, "body"

    def json(self):
        return self._payload


def _setup(monkeypatch, enricher_cls, payload, key="k", status=200):
    calls = []

    def fake_post(url, headers=None, data=None, timeout=None):
        calls.append((url, data))
        return _Resp(payload, status)

    monkeypatch.setattr("flowsint_enrichers.domain.to_urlhaus.requests.post", fake_post)
    for mod in ("domain", "ip", "website"):
        monkeypatch.setattr(f"flowsint_enrichers.{mod}.to_urlhaus.Logger", _NoLogger)
    enricher = enricher_cls(sketch_id="s", scan_id="t")
    monkeypatch.setattr(enricher, "get_secret", lambda *a, **k: key)
    return enricher, calls


def _url(url, status="online", **kw):
    return {
        "url": url,
        "url_status": status,
        "threat": "malware_download",
        "tags": ["Mozi"],
        "date_added": "2026-09-30 10:00:00 UTC",
        **kw,
    }


HOST_PAYLOAD = {
    "query_status": "ok",
    "urls": [
        _url("http://1.2.3.4:5555/i"),
        _url("http://1.2.3.4:5555/i", status="offline"),  # duplicate listing
        _url("http://1.2.3.4/bins/x.arm", status="offline", tags=None),
        _url("not a url"),
    ],
}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "enricher_cls, item, host",
    [
        (IpToUrlhaus, Ip(address="1.2.3.4"), "1.2.3.4"),
        (DomainToUrlhaus, Domain(domain="evil.example"), "evil.example"),
    ],
)
async def test_host_lookup_maps_unique_valid_urls(
    monkeypatch, enricher_cls, item, host
):
    enricher, calls = _setup(monkeypatch, enricher_cls, HOST_PAYLOAD)
    edges = []
    enricher._graph_service = object()
    monkeypatch.setattr(enricher, "create_node", lambda node: None)
    monkeypatch.setattr(
        enricher, "create_relationship", lambda a, b, rel: edges.append((a, b, rel))
    )
    monkeypatch.setattr(enricher, "log_graph_message", lambda *a: None)

    first, second = await enricher.scan([item])
    enricher.postprocess([first, second], [item])

    assert calls == [("https://urlhaus-api.abuse.ch/v1/host/", {"host": host})]
    assert (str(first.url), first.active) == ("http://1.2.3.4:5555/i", True)
    assert first.description == (
        "URLhaus malware_download (Mozi), added 2026-09-30 10:00:00 UTC"
    )
    assert (second.active, second.description) == (
        False,
        "URLhaus malware_download, added 2026-09-30 10:00:00 UTC",
    )
    assert [(a, rel) for a, _, rel in edges] == [(item, "HAS_WEBSITE")] * 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload, status",
    [({"query_status": "no_results"}, 200), ({}, 504), ({"query_status": "x"}, 200)],
)
async def test_no_results_and_failures_return_nothing(monkeypatch, payload, status):
    enricher, _ = _setup(monkeypatch, IpToUrlhaus, payload, status=status)

    assert await enricher.scan([Ip(address="1.2.3.4")]) == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "enricher_cls, item",
    [
        (IpToUrlhaus, Ip(address="1.2.3.4")),
        (DomainToUrlhaus, Domain(domain="a.com")),
        (WebsiteToUrlhaus, Website(url="http://a.com/x")),
    ],
)
async def test_missing_key_makes_no_request(monkeypatch, enricher_cls, item):
    enricher, calls = _setup(monkeypatch, enricher_cls, {}, key=None)

    assert await enricher.scan([item]) == []
    assert calls == []


@pytest.mark.asyncio
async def test_website_payloads_become_hash_files(monkeypatch):
    payload = {
        "query_status": "ok",
        "payloads": [
            {
                "filename": "i",
                "file_type": "elf",
                "response_size": "307960",
                "response_md5": "ABC123",
                "response_sha256": SHA.upper(),
                "signature": "Mozi",
            },
            {"response_sha256": SHA},  # same payload served twice
            {"response_sha256": None},
        ],
    }
    enricher, calls = _setup(monkeypatch, WebsiteToUrlhaus, payload)
    edges = []
    enricher._graph_service = object()
    monkeypatch.setattr(enricher, "create_node", lambda node: None)
    monkeypatch.setattr(
        enricher, "create_relationship", lambda a, b, rel: edges.append((a, b, rel))
    )
    monkeypatch.setattr(enricher, "log_graph_message", lambda *a: None)
    site = Website(url="http://1.2.3.4:5555/i")

    [file] = await enricher.scan([site])
    enricher.postprocess([file], [site])

    assert calls == [
        ("https://urlhaus-api.abuse.ch/v1/url/", {"url": "http://1.2.3.4:5555/i"})
    ]
    assert (file.nodeLabel, file.hash_sha256, file.hash_md5) == (SHA, SHA, "abc123")
    assert (file.file_size, file.malware_family, file.is_malicious) == (
        307960,
        "Mozi",
        True,
    )
    assert file.description == "Served as 'i'"
    assert edges == [(site, file, "SERVES_PAYLOAD")]
