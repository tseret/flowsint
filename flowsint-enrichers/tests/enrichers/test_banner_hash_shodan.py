from unittest.mock import ANY, Mock, call

import pytest
import requests

from flowsint_core.core.logger import Logger
from flowsint_enrichers.ip.to_banner_hash_shodan import IpToBannerHashShodanEnricher
from flowsint_types.ip import Ip
from flowsint_types.phrase import Phrase


def response(payload, status=200):
    return Mock(status_code=status, json=Mock(return_value=payload))


@pytest.fixture(autouse=True)
def capture_log(monkeypatch):
    info = Mock()
    monkeypatch.setattr(Logger, "info", info)
    return info


@pytest.mark.asyncio
async def test_banner_hash_pivot_keeps_provenance_and_distinct_peers(monkeypatch):
    calls = []

    def get(url, *, params, timeout):
        calls.append((url, params, timeout))
        if url.endswith("/host/198.51.100.1"):
            return response(
                {
                    "data": [
                        {"port": 53, "transport": "udp", "hash": 999},
                        {
                            "port": 443,
                            "transport": "tcp",
                            "hash": -42,
                            "product": "Example App",
                            "http": {"html_hash": 12345},
                        },
                    ]
                }
            )
        return response(
            {
                "matches": [
                    {"ip_str": "198.51.100.1", "hash": -42},
                    {
                        "ip_str": "203.0.113.7",
                        "hash": -42,
                        "product": "Example App",
                        "domains": ["example.org"],
                        "http": {"html_hash": 12345},
                    },
                    {"ip_str": "203.0.113.7", "hash": -42},
                    {"ip_str": "not-an-ip", "hash": -42},
                    {
                        "ip_str": "203.0.113.8",
                        "hash": -42,
                        "product": "Example App",
                        "hostnames": ["sub.example.org"],
                        "http": {"html_hash": 12345},
                    },
                    {
                        "ip_str": "203.0.113.9",
                        "hash": -42,
                        "domains": ["other-example.org"],
                        "product": "Example App",
                        "http": {"html_hash": 12345},
                    },
                    {
                        "ip_str": "203.0.113.10",
                        "hash": -42,
                        "domains": ["example.org"],
                        "product": "Other",
                        "http": {"html_hash": 12345},
                    },
                ]
            }
        )

    monkeypatch.setattr(requests, "get", get)
    graph = Mock()
    enricher = IpToBannerHashShodanEnricher(
        graph_service=graph,
        params={
            "SHODAN_API_KEY": "secret",
            "port": "443",
            "transport": "tcp",
            "target_domain": "example.org",
            "target_product": "example app",
        },
    )
    source = Ip(address="198.51.100.1")
    peers = await enricher.scan([source])
    assert [ip.address for ip in peers] == ["203.0.113.7", "203.0.113.8"]
    assert calls == [
        ("https://api.shodan.io/shodan/host/198.51.100.1", {"key": "secret"}, 30),
        (
            "https://api.shodan.io/shodan/host/search",
            {"key": "secret", "query": "hash:-42", "page": 1},
            30,
        ),
    ]

    assert enricher.postprocess(peers) == peers
    banner_hash = Phrase(text="Shodan banner hash:-42")
    assert graph.create_relationship.call_args_list == [
        call(
            from_obj=source,
            to_obj=banner_hash,
            rel_label="HAS_BANNER_HASH",
            observation=ANY,
        ),
        call(
            from_obj=banner_hash,
            to_obj=peers[0],
            rel_label="MATCHES_BANNER_HASH",
            observation=ANY,
        ),
        call(
            from_obj=banner_hash,
            to_obj=peers[1],
            rel_label="MATCHES_BANNER_HASH",
            observation=ANY,
        ),
    ]
    assert graph.create_node_from_flowsint_type.call_count == 4


@pytest.mark.asyncio
async def test_execute_resolves_vault_key_and_keeps_launch_parameters(monkeypatch):
    monkeypatch.setattr(Logger, "info", Mock())
    monkeypatch.setattr(Logger, "completed", Mock())
    monkeypatch.setattr(Logger, "error", Mock())
    vault = Mock()
    vault.get_secret.return_value = "secret"
    calls = []

    def get(url, *, params, timeout):
        calls.append((url, params))
        if url.endswith("/host/198.51.100.1"):
            return response(
                {
                    "data": [
                        {
                            "port": 53,
                            "transport": "udp",
                            "hash": -42,
                            "ssl": {"cert": {"fingerprint": {"sha256": "fingerprint"}}},
                        }
                    ]
                }
            )
        return response(
            {
                "matches": [
                    {
                        "ip_str": "203.0.113.7",
                        "hash": -42,
                        "domains": ["example.org"],
                        "ssl": {"cert": {"fingerprint": {"sha256": "fingerprint"}}},
                    }
                ]
            }
        )

    monkeypatch.setattr(requests, "get", get)
    graph = Mock()
    enricher = IpToBannerHashShodanEnricher(
        graph_service=graph,
        vault=vault,
        params={
            "SHODAN_API_KEY": "vault-key-id",
            "port": "53",
            "transport": "udp",
            "target_domain": "example.org",
        },
    )
    result = await enricher.execute([Ip(address="198.51.100.1")])
    assert [peer.address for peer in result] == ["203.0.113.7"]
    vault.get_secret.assert_called_once_with("vault-key-id")
    assert calls[1][1]["query"] == "hash:-42"
    assert graph.create_relationship.call_count == 2
    graph.flush.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "banners",
    [
        [{"port": 80, "hash": 12}],
        [{"port": 443, "transport": "tcp", "hash": 0}],
        [{"port": 443, "transport": "tcp"}],
    ],
)
async def test_no_matching_or_nonempty_banner_skips_search(monkeypatch, banners):
    get = Mock(return_value=response({"data": banners}))
    monkeypatch.setattr(requests, "get", get)
    graph = Mock()
    enricher = IpToBannerHashShodanEnricher(
        graph_service=graph,
        params={
            "SHODAN_API_KEY": "secret",
            "port": "443",
            "target_domain": "example.org",
        },
    )
    assert await enricher.scan([Ip(address="198.51.100.1")]) == []
    assert get.call_count == 1
    enricher.postprocess([])
    graph.create_relationship.assert_not_called()


@pytest.mark.asyncio
async def test_two_pages_review_uncorroborated_candidates_without_graphing(
    monkeypatch, capture_log
):
    calls = []

    def get(url, *, params, timeout):
        if url.endswith("/host/198.51.100.1"):
            return response(
                {
                    "data": [
                        {
                            "port": 53,
                            "transport": "udp",
                            "hash": 222,
                            "http": {"html_hash": 135},
                            "data": 'HTTP/1.1 200 OK\r\nETag: "same"\r\n',
                        }
                    ]
                }
            )
        calls.append(params["page"])
        if params["page"] == 1:
            return response(
                {
                    "total": 103,
                    "matches": [
                        {"ip_str": f"203.0.113.{number}", "hash": 222}
                        for number in range(1, 100)
                    ]
                    + [
                        {
                            "ip_str": "192.0.2.1",
                            "hash": 222,
                            "domains": ["example.org"],
                            "data": 'HTTP/1.1 200 OK\r\nETag: "same"\r\n',
                        }
                    ],
                }
            )
        return response(
            {
                "total": 103,
                "matches": [
                    {
                        "ip_str": "203.0.113.7",
                        "hash": 222,
                        "domains": ["example.org"],
                        "http": {"html_hash": 135},
                    },
                    {
                        "ip_str": "192.0.2.2",
                        "hash": 222,
                        "hostnames": ["api.example.org"],
                        "http": {"html_hash": 135},
                    },
                    {"ip_str": "192.0.2.1", "hash": 222},
                ],
            }
        )

    monkeypatch.setattr(requests, "get", get)
    graph = Mock()
    enricher = IpToBannerHashShodanEnricher(
        graph_service=graph,
        params={
            "SHODAN_API_KEY": "secret",
            "port": "53",
            "transport": "udp",
            "target_domain": "example.org",
        },
    )
    peers = await enricher.scan([Ip(address="198.51.100.1")])
    assert calls == [1, 2]
    assert [peer.address for peer in peers] == ["203.0.113.7", "192.0.2.2"]
    assert "192.0.2.1: target domain" in capture_log.call_args.args[1]["message"]
    assert "203.0.113.7:" not in capture_log.call_args.args[1]["message"]
    enricher.postprocess(peers)
    assert graph.create_relationship.call_count == 3


@pytest.mark.asyncio
async def test_product_hunt_selects_matching_source_banner(monkeypatch):
    calls = []

    def get(url, *, params, timeout):
        calls.append((url, params))
        if url.endswith("/host/198.51.100.1"):
            return response(
                {
                    "data": [
                        {"port": 443, "hash": 11, "product": "Other"},
                        {
                            "port": 443,
                            "hash": 99,
                            "product": "Example App",
                            "ssl": {"cert": {"fingerprint": {"sha256": "cert"}}},
                            "http": {"html_hash": 77},
                        },
                    ]
                }
            )
        return response(
            {
                "matches": [
                    {
                        "ip_str": "203.0.113.2",
                        "hash": 99,
                        "product": "Example App",
                        "ssl": {"cert": {"fingerprint": {"sha256": "cert"}}},
                        "http": {"html_hash": 77},
                    }
                ]
            }
        )

    monkeypatch.setattr(requests, "get", get)
    enricher = IpToBannerHashShodanEnricher(
        graph_service=Mock(),
        params={
            "SHODAN_API_KEY": "secret",
            "port": "443",
            "target_product": "example app",
        },
    )
    peers = await enricher.scan([Ip(address="198.51.100.1")])
    assert [peer.address for peer in peers] == ["203.0.113.2"]
    assert calls[1][1]["query"] == "hash:99"


@pytest.mark.asyncio
async def test_duplicate_sources_do_not_repeat_paid_search(monkeypatch, capture_log):
    calls = []

    def get(url, *, params, timeout):
        calls.append((url, params))
        if url.endswith("/host/198.51.100.1"):
            return response({"data": [{"port": 443, "hash": 99}]})
        if params["page"] == 1:
            return response(
                {
                    "total": 101,
                    "matches": [
                        {"ip_str": f"203.0.113.{n}", "hash": 99} for n in range(1, 101)
                    ],
                }
            )
        return response(
            {"total": 101, "matches": [{"ip_str": "198.51.100.2", "hash": 99}]}
        )

    monkeypatch.setattr(requests, "get", get)
    enricher = IpToBannerHashShodanEnricher(
        graph_service=Mock(),
        params={
            "SHODAN_API_KEY": "secret",
            "port": "443",
            "target_domain": "example.org",
        },
    )
    source = Ip(address="198.51.100.1")
    assert await enricher.scan([source, source]) == []
    assert len(calls) == 3
    assert [params["page"] for _, params in calls[1:]] == [1, 2]
    capture_log.assert_called_once()


@pytest.mark.asyncio
async def test_inferred_product_needs_both_independent_fingerprints(
    monkeypatch, capture_log
):
    def get(url, *, params, timeout):
        if url.endswith("/host/198.51.100.1"):
            return response(
                {
                    "data": [
                        {
                            "port": 443,
                            "hash": 99,
                            "product": "Example App",
                            "ssl": {"cert": {"fingerprint": {"sha256": "cert"}}},
                            "http": {"html_hash": 77},
                        }
                    ]
                }
            )
        return response(
            {
                "matches": [
                    {
                        "ip_str": "203.0.113.1",
                        "hash": 99,
                        "product": "Example App",
                        "http": {"html_hash": 77},
                        "ssl": {"cert": {"fingerprint": None}},
                    },
                    {
                        "ip_str": "203.0.113.2",
                        "hash": 99,
                        "product": "Example App",
                        "ssl": {"cert": {"fingerprint": {"sha256": "cert"}}},
                        "http": {"html_hash": 77},
                    },
                    {
                        "ip_str": "203.0.113.3",
                        "hash": 99,
                        "product": "Other",
                        "ssl": {"cert": {"fingerprint": {"sha256": "cert"}}},
                        "http": {"html_hash": 77},
                    },
                ]
            }
        )

    monkeypatch.setattr(requests, "get", get)
    enricher = IpToBannerHashShodanEnricher(
        graph_service=Mock(), params={"SHODAN_API_KEY": "secret"}
    )
    peers = await enricher.scan([Ip(address="198.51.100.1")])
    assert [peer.address for peer in peers] == ["203.0.113.2"]
    message = capture_log.call_args.args[1]["message"]
    assert "203.0.113.1: product, HTML body" in message
    assert "203.0.113.3: TLS certificate, HTML body" in message


@pytest.mark.asyncio
async def test_no_port_hunts_distinct_transports_with_two_page_total_limit(
    monkeypatch, capture_log
):
    calls = []

    def get(url, *, params, timeout):
        calls.append((url, params))
        if url.endswith("/host/198.51.100.1"):
            return response(
                {
                    "data": [
                        {"port": 80, "hash": 1, "product": "Unqualified"},
                        *[
                            {
                                "port": port,
                                "transport": transport,
                                "hash": banner_hash,
                                "product": "Example App",
                                "ssl": {
                                    "cert": {"fingerprint": {"sha256": f"cert-{port}"}}
                                },
                                "http": {"html_hash": port},
                            }
                            for port, transport, banner_hash in (
                                (443, "tcp", 11),
                                (53, "udp", 22),
                                (8443, "tcp", 33),
                            )
                        ],
                    ]
                }
            )
        banner_hash = int(params["query"].split(":")[1])
        port = {11: 443, 22: 53, 33: 8443}[banner_hash]
        return response(
            {
                "total": 101,
                "matches": [
                    {
                        "ip_str": f"203.0.113.{port % 100}",
                        "hash": banner_hash,
                        "product": "Example App",
                        "ssl": {"cert": {"fingerprint": {"sha256": f"cert-{port}"}}},
                        "http": {"html_hash": port},
                    }
                ],
            }
        )

    monkeypatch.setattr(requests, "get", get)
    graph = Mock()
    enricher = IpToBannerHashShodanEnricher(
        graph_service=graph, params={"SHODAN_API_KEY": "secret"}
    )
    peers = await enricher.scan([Ip(address="198.51.100.1")])
    assert [peer.address for peer in peers] == ["203.0.113.43", "203.0.113.53"]
    assert [(params["query"], params["page"]) for _, params in calls[1:]] == [
        ("hash:11", 1),
        ("hash:22", 1),
    ]
    assert any(
        "skipped 1 indexed service(s)" in call.args[1]["message"]
        for call in capture_log.call_args_list
    )
    enricher.postprocess(peers)
    assert graph.create_relationship.call_count == 4


@pytest.mark.asyncio
async def test_no_product_or_target_skips_paid_search(monkeypatch, capture_log):
    get = Mock(return_value=response({"data": [{"port": 443, "hash": 99}]}))
    monkeypatch.setattr(requests, "get", get)
    graph = Mock()
    enricher = IpToBannerHashShodanEnricher(
        graph_service=graph, params={"SHODAN_API_KEY": "secret"}
    )
    assert await enricher.scan([Ip(address="198.51.100.1")]) == []
    assert get.call_count == 1
    assert "no paid search was run" in capture_log.call_args.args[1]["message"]
    enricher.postprocess([])
    graph.create_relationship.assert_not_called()


@pytest.mark.asyncio
async def test_provider_failure_fails_scan_without_exposing_key(monkeypatch):
    monkeypatch.setattr(requests, "get", Mock(return_value=response({}, status=403)))
    enricher = IpToBannerHashShodanEnricher(
        graph_service=Mock(),
        params={
            "SHODAN_API_KEY": "secret",
            "port": "443",
            "target_domain": "example.org",
        },
    )
    with pytest.raises(
        RuntimeError, match="Shodan host lookup failed \\(HTTP 403\\)"
    ) as error:
        await enricher.scan([Ip(address="198.51.100.1")])
    assert "secret" not in str(error.value)


@pytest.mark.asyncio
async def test_invalid_port_rejected_before_provider_request(monkeypatch):
    get = Mock()
    monkeypatch.setattr(requests, "get", get)
    enricher = IpToBannerHashShodanEnricher(
        graph_service=Mock(),
        params={
            "SHODAN_API_KEY": "secret",
            "port": "65536",
            "target_domain": "example.org",
        },
    )
    with pytest.raises(ValueError, match="port must be between"):
        await enricher.scan([Ip(address="198.51.100.1")])
    get.assert_not_called()
