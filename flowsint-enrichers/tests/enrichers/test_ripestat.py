import pytest

from flowsint_enrichers.asn.to_cidrs_ripestat import AsnToCidrsRipestatEnricher
from flowsint_enrichers.ip.to_asn_ripestat import IpToAsnRipestatEnricher
from flowsint_types.asn import ASN
from flowsint_types.ip import Ip


class _NoLogger:
    info = warn = error = staticmethod(lambda *a, **k: None)


class _Resp:
    def __init__(self, status, data=None):
        self.status_code = status
        self._data = data

    def json(self):
        return {"data": self._data}


def _fake_get(table):
    """table: (call, resource) -> _Resp"""

    def get(url, params=None, **k):
        call = url.rstrip("/").rsplit("/", 2)[1]
        return table[(call, params["resource"])]

    return get


def _graph(enricher, monkeypatch, edges):
    enricher._graph_service = object()
    monkeypatch.setattr(enricher, "create_node", lambda node: None)
    monkeypatch.setattr(enricher, "log_graph_message", lambda msg: None)
    monkeypatch.setattr(
        enricher,
        "create_relationship",
        lambda s, d, rel: edges.append((str(d.__class__.__name__), rel)),
    )


@pytest.mark.asyncio
async def test_ip_to_asn_names_node_like_asnmap_and_links_ip(monkeypatch):
    monkeypatch.setattr("flowsint_enrichers.ip.to_asn_ripestat.Logger", _NoLogger)
    monkeypatch.setattr(
        "flowsint_enrichers.ip.to_asn_ripestat.requests.get",
        _fake_get(
            {
                ("network-info", "151.101.128.223"): _Resp(
                    200, {"asns": ["54113"], "prefix": "151.101.128.0/22"}
                ),
                ("as-overview", "AS54113"): _Resp(
                    200, {"holder": "FASTLY - Fastly, Inc."}
                ),
                ("network-info", "10.0.0.1"): _Resp(200, {"asns": [], "prefix": None}),
            }
        ),
    )
    enricher = IpToAsnRipestatEnricher(sketch_id="s", scan_id="t")
    edges: list = []
    _graph(enricher, monkeypatch, edges)
    ips = [Ip(address="10.0.0.1"), Ip(address="151.101.128.223")]

    results = await enricher.scan(ips)
    enricher.postprocess(results, ips)

    [asn] = results
    # Same nodeLabel as asnmap's ip_to_asn ("AS54113 - fastly"), so both merge.
    assert (asn.nodeLabel, asn.description) == (
        "AS54113 - fastly",
        "FASTLY - Fastly, Inc.",
    )
    assert edges == [("ASN", "BELONGS_TO")]


@pytest.mark.asyncio
async def test_ip_to_asn_http_error_yields_nothing(monkeypatch):
    monkeypatch.setattr("flowsint_enrichers.ip.to_asn_ripestat.Logger", _NoLogger)
    monkeypatch.setattr(
        "flowsint_enrichers.ip.to_asn_ripestat.requests.get",
        _fake_get({("network-info", "1.1.1.1"): _Resp(503)}),
    )
    enricher = IpToAsnRipestatEnricher(sketch_id="s", scan_id="t")

    assert await enricher.scan([Ip(address="1.1.1.1")]) == []


@pytest.mark.asyncio
async def test_asn_to_cidrs_maps_v4_and_v6_prefixes(monkeypatch):
    monkeypatch.setattr("flowsint_enrichers.asn.to_cidrs_ripestat.Logger", _NoLogger)
    monkeypatch.setattr(
        "flowsint_enrichers.asn.to_cidrs_ripestat.requests.get",
        _fake_get(
            {
                ("announced-prefixes", "AS54113"): _Resp(
                    200,
                    {
                        "prefixes": [
                            {"prefix": "151.101.128.0/22", "timelines": []},
                            {"prefix": "2a04:4e40::/32", "timelines": []},
                        ]
                    },
                ),
                ("announced-prefixes", "AS1"): _Resp(200, {"prefixes": []}),
            }
        ),
    )
    enricher = AsnToCidrsRipestatEnricher(sketch_id="s", scan_id="t")
    edges: list = []
    _graph(enricher, monkeypatch, edges)
    asns = [ASN(asn_str="AS1"), ASN(asn_str="as54113")]

    results = await enricher.scan(asns)
    enricher.postprocess(results, asns)

    assert [str(c.network) for c in results] == ["151.101.128.0/22", "2a04:4e40::/32"]
    assert edges == [("CIDR", "ANNOUNCES")] * 2
