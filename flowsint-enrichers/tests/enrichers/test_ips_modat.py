from unittest.mock import ANY, Mock, call

import pytest
import requests

from flowsint_core.core.logger import Logger
from flowsint_enrichers.ip.to_ips_modat import IpToIpsModatEnricher
from flowsint_types.ip import Ip
from flowsint_types.phrase import Phrase

BANNER = "a" * 64
HTML = "b" * 64
TLS = "c" * 64
SOURCE = Ip(address="198.51.100.1")


def response(payload=None, status=200):
    return Mock(status_code=status, json=Mock(return_value=payload))


def service(
    *,
    port=443,
    transport="tcp",
    banner: str | None = BANNER,
    html: str | None = HTML,
    tls: str | None = TLS,
):
    return {
        "port": port,
        "ports": [port],
        "transport": transport,
        "banner_sha256": banner,
        "http": {"body_sha256": html},
        "tls": {"fingerprint_sha256": tls},
    }


def enricher(**params):
    vault = Mock()
    vault.get_secret.return_value = "secret"
    return IpToIpsModatEnricher(
        graph_service=Mock(),
        vault=vault,
        params={"port": "443", "pivot_field": "banner_sha256", **params},
    )


@pytest.mark.asyncio
async def test_domain_pivot_promotes_only_independently_corroborated_peers(monkeypatch):
    log = Mock()
    monkeypatch.setattr(Logger, "info", log)
    get = Mock(return_value=response({"data": {"services": [service()]}}))
    post = Mock(
        return_value=response(
            {
                "page": [
                    {
                        "ip": "198.51.100.1",
                        "service": service(),
                        "fqdns": ["example.org"],
                    },
                    {
                        "ip": "203.0.113.1",
                        "service": service(tls=None),
                        "fqdns": ["sub.example.org"],
                    },
                    {
                        "ip": "203.0.113.2",
                        "service": service(html=None, tls=None),
                        "fqdns": ["example.org"],
                    },
                    {
                        "ip": "203.0.113.3",
                        "service": service(),
                        "fqdns": ["other-example.org"],
                    },
                    {
                        "ip": "203.0.113.4",
                        "service": service(port=8443),
                        "fqdns": ["example.org"],
                    },
                    {
                        "ip": "203.0.113.5",
                        "service": service(banner="f" * 64),
                        "fqdns": ["example.org"],
                    },
                ],
                "total_pages": 1,
            }
        )
    )
    monkeypatch.setattr(requests, "get", get)
    monkeypatch.setattr(requests, "post", post)
    pivot = enricher(target_domain="example.org")

    peers = await pivot.scan([SOURCE, SOURCE])

    assert [peer.address for peer in peers] == ["203.0.113.1"]
    get.assert_called_once_with(
        "https://api.magnify.modat.io/host/198.51.100.1/v1",
        headers={
            "Authorization": "Bearer secret",
            "User-Agent": "Flowsint-Modat-Connector",
        },
        timeout=30,
    )
    post.assert_called_once_with(
        "https://api.magnify.modat.io/service/search/v1",
        headers={
            "Authorization": "Bearer secret",
            "User-Agent": "Flowsint-Modat-Connector",
        },
        json={"query": f"banner_sha256={BANNER} port=443", "page": 1, "page_size": 100},
        timeout=30,
    )
    assert "203.0.113.2" in log.call_args.args[1]["message"]
    assert "203.0.113.3" in log.call_args.args[1]["message"]
    pivot.postprocess(peers)
    evidence = Phrase(text=f"Modat banner_sha256:{BANNER}")
    assert pivot._graph_service.create_relationship.call_args_list == [
        call(
            from_obj=SOURCE,
            to_obj=evidence,
            rel_label="HAS_MODAT_PIVOT",
            observation=ANY,
        ),
        call(
            from_obj=evidence,
            to_obj=peers[0],
            rel_label="MATCHES_MODAT_PIVOT",
            observation=ANY,
        ),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field", ["banner_sha256", "http.body_sha256", "tls.fingerprint_sha256"]
)
async def test_domainless_pivot_requires_all_three_hashes(monkeypatch, field):
    monkeypatch.setattr(Logger, "info", Mock())
    monkeypatch.setattr(
        requests,
        "get",
        Mock(return_value=response({"data": {"services": [service()]}})),
    )
    post = Mock(
        return_value=response(
            {
                "page": [
                    {"ip": "203.0.113.1", "service": service(), "fqdns": []},
                    {"ip": "203.0.113.2", "service": service(tls=None), "fqdns": []},
                ],
                "total_pages": 1,
            }
        )
    )
    monkeypatch.setattr(requests, "post", post)
    pivot = enricher(pivot_field=field)

    peers = await pivot.scan([SOURCE])

    assert [peer.address for peer in peers] == ["203.0.113.1"]
    assert (
        post.call_args.kwargs["json"]["query"]
        == f"{field}="
        + {
            "banner_sha256": BANNER,
            "http.body_sha256": HTML,
            "tls.fingerprint_sha256": TLS,
        }[field]
        + " port=443"
    )


@pytest.mark.asyncio
async def test_two_pages_can_upgrade_candidate_and_auth_error_stops_batch(monkeypatch):
    monkeypatch.setattr(Logger, "info", Mock())
    monkeypatch.setattr(Logger, "error", Mock())
    get = Mock(return_value=response({"data": {"services": [service()]}}))
    monkeypatch.setattr(requests, "get", get)
    first = [{"ip": "203.0.113.1", "service": service(tls=None), "fqdns": []}]
    first += [{"ip": "203.0.113.2", "service": service(tls=None), "fqdns": []}] * 99
    post = Mock(
        side_effect=[
            response({"page": first, "total_pages": 3}),
            response(
                {
                    "page": [{"ip": "203.0.113.1", "service": service(), "fqdns": []}],
                    "total_pages": 3,
                }
            ),
            response(status=429),
        ]
    )
    monkeypatch.setattr(requests, "post", post)
    pivot = enricher()
    peers = await pivot.scan([SOURCE, Ip(address="198.51.100.2")])
    assert [peer.address for peer in peers] == ["203.0.113.1"]
    assert [c.kwargs["json"]["page"] for c in post.call_args_list] == [1, 2, 1]
    assert get.call_count == 2


@pytest.mark.asyncio
async def test_missing_source_hash_skips_search_and_does_not_make_graph_edges(
    monkeypatch,
):
    monkeypatch.setattr(
        requests,
        "get",
        Mock(return_value=response({"data": {"services": [service(banner=None)]}})),
    )
    post = Mock()
    monkeypatch.setattr(requests, "post", post)
    pivot = enricher()
    assert await pivot.scan([SOURCE]) == []
    pivot.postprocess([])
    post.assert_not_called()
    pivot._graph_service.create_relationship.assert_not_called()


@pytest.mark.asyncio
async def test_execute_resolves_vault_key_and_writes_only_correlated_graph(monkeypatch):
    monkeypatch.setattr(Logger, "info", Mock())
    monkeypatch.setattr(Logger, "completed", Mock())
    get = Mock(return_value=response({"data": {"services": [service()]}}))
    post = Mock(
        return_value=response(
            {
                "page": [
                    {"ip": "203.0.113.1", "service": service(), "fqdns": []},
                    {
                        "ip": "203.0.113.2",
                        "service": service(tls=None),
                        "fqdns": [],
                    },
                ],
                "total_pages": 1,
            }
        )
    )
    monkeypatch.setattr(requests, "get", get)
    monkeypatch.setattr(requests, "post", post)
    graph = Mock()
    vault = Mock()
    vault.get_secret.return_value = "resolved-key"
    pivot = IpToIpsModatEnricher(
        graph_service=graph,
        vault=vault,
        params={},
    )

    peers = await pivot.execute([{"address": SOURCE.address}])

    assert [peer.address for peer in peers] == ["203.0.113.1"]
    vault.get_secret.assert_called_once_with("MODAT_API_KEY")
    assert get.call_args.kwargs["headers"]["Authorization"] == "Bearer resolved-key"
    assert post.call_args.kwargs["headers"]["Authorization"] == "Bearer resolved-key"
    assert graph.create_node_from_flowsint_type.call_count == 3
    assert graph.create_relationship.call_args_list == [
        call(
            from_obj=SOURCE,
            to_obj=Phrase(text=f"Modat banner_sha256:{BANNER}"),
            rel_label="HAS_MODAT_PIVOT",
            observation=ANY,
        ),
        call(
            from_obj=Phrase(text=f"Modat banner_sha256:{BANNER}"),
            to_obj=peers[0],
            rel_label="MATCHES_MODAT_PIVOT",
            observation=ANY,
        ),
    ]
    graph.flush.assert_called_once_with()


@pytest.mark.asyncio
async def test_no_port_discovers_tcp_and_udp_services_with_two_search_page_limit(
    monkeypatch,
):
    log = Mock()
    monkeypatch.setattr(Logger, "info", log)
    monkeypatch.setattr(Logger, "completed", Mock())
    monkeypatch.setattr(
        requests,
        "get",
        Mock(
            return_value=response(
                {
                    "data": {
                        "services": [
                            service(),
                            service(port=53, transport="udp"),
                            service(port=8443),
                        ]
                    }
                }
            )
        ),
    )
    post = Mock(
        side_effect=[
            response(
                {
                    "page": [{"ip": "203.0.113.1", "service": service(), "fqdns": []}],
                    "total_pages": 1,
                }
            ),
            response(
                {
                    "page": [
                        {
                            "ip": "203.0.113.2",
                            "service": service(port=53, transport="udp"),
                            "fqdns": [],
                        }
                    ],
                    "total_pages": 1,
                }
            ),
        ]
    )
    monkeypatch.setattr(requests, "post", post)
    pivot = enricher(port=None, pivot_field=None)

    peers = await pivot.execute([SOURCE])

    assert [peer.address for peer in peers] == ["203.0.113.1", "203.0.113.2"]
    assert [call.kwargs["json"]["query"] for call in post.call_args_list] == [
        f"banner_sha256={BANNER} port=443",
        f"banner_sha256={BANNER} port=53",
    ]
    assert any(
        "Skipped 1 source service pivot" in call.args[1]["message"]
        for call in log.call_args_list
    )
    assert pivot._graph_service.create_relationship.call_count == 4


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field, value, path",
    [
        ("banner_sha1", "d" * 40, ("banner_sha1",)),
        ("banner_mmh3", 0, ("banner_mmh3",)),
        ("http.headers_sha256", "e" * 64, ("http", "headers_sha256")),
        ("tls.ja4s", "t13d1516h2_abc", ("tls", "ja4s")),
        ("ssh.hassh", "f" * 32, ("ssh", "hassh")),
    ],
)
async def test_additional_documented_fingerprints_pivot_with_independent_evidence(
    monkeypatch, field, value, path
):
    monkeypatch.setattr(Logger, "info", Mock())
    source_service = service()
    candidate_service = service()
    for item in (source_service, candidate_service):
        if field == "ssh.hassh":
            item["tls"] = None
        nested = item
        for part in path[:-1]:
            nested = nested.setdefault(part, {})
        nested[path[-1]] = value
    monkeypatch.setattr(
        requests,
        "get",
        Mock(return_value=response({"data": {"services": [source_service]}})),
    )
    post = Mock(
        return_value=response(
            {
                "page": [
                    {"ip": "203.0.113.1", "service": candidate_service, "fqdns": []}
                ],
                "total_pages": 1,
            }
        )
    )
    monkeypatch.setattr(requests, "post", post)

    peers = await enricher(pivot_field=field).scan([SOURCE])

    assert [peer.address for peer in peers] == ["203.0.113.1"]
    assert post.call_args.kwargs["json"]["query"] == f"{field}={value} port=443"


@pytest.mark.asyncio
async def test_two_banner_hashes_are_not_two_independent_identity_families(monkeypatch):
    source_service = service()
    source_service["banner_sha1"] = "d" * 40
    candidate = service(tls=None)
    candidate["banner_sha1"] = "d" * 40
    log = Mock()
    monkeypatch.setattr(Logger, "info", log)
    monkeypatch.setattr(
        requests,
        "get",
        Mock(return_value=response({"data": {"services": [source_service]}})),
    )
    monkeypatch.setattr(
        requests,
        "post",
        Mock(
            return_value=response(
                {
                    "page": [{"ip": "203.0.113.1", "service": candidate, "fqdns": []}],
                    "total_pages": 1,
                }
            )
        ),
    )
    pivot = enricher()

    peers = await pivot.scan([SOURCE])
    pivot.postprocess(peers)

    assert peers == []
    assert "203.0.113.1" in log.call_args.args[1]["message"]
    pivot._graph_service.create_relationship.assert_not_called()
