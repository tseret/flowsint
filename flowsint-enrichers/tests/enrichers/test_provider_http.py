import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import redis
import requests

from flowsint_enrichers import provider_http as http
from flowsint_enrichers.passive_http import indexed_json

URL = "https://api.shodan.io/shodan/host/192.0.2.1"


class MemoryRedis:
    def __init__(self):
        self.values = {}
        self.ttls = {}
        self.mutex = threading.Lock()

    def get(self, key):
        return self.values.get(key)

    def set(self, key, value, ex):
        self.values[key] = str(value)
        self.ttls[key] = ex

    def lock(self, key, **kwargs):
        client = self

        class Lock:
            acquired = False

            def acquire(self):
                self.acquired = client.mutex.acquire(timeout=2)
                return self.acquired

            def owned(self):
                return self.acquired

            def release(self):
                self.acquired = False
                client.mutex.release()

        return Lock()


def enricher(scan="scan-original", **params):
    return SimpleNamespace(scan_id=scan, params=params, report_issue=Mock())


def response(status=200, payload=None, headers=None):
    return Mock(
        status_code=status,
        headers=headers or {},
        iter_content=Mock(return_value=[json.dumps(payload or {"data": []}).encode()]),
    )


@pytest.fixture
def provider(monkeypatch):
    store = MemoryRedis()
    monkeypatch.setattr(http, "_redis", lambda: store)
    get = Mock(return_value=response())
    monkeypatch.setattr(http.requests, "get", get)
    monkeypatch.setattr(http.time, "sleep", lambda _: None)
    return store, get


def test_fresh_cache_reuses_provenance_and_refresh_replaces_it(provider):
    store, get = provider
    first = enricher()
    assert http.request_json(first, "Shodan", URL, "secret") == {"data": []}
    second = enricher("scan-next")
    assert http.request_json(second, "Shodan", URL, "secret") == {"data": []}
    assert get.call_count == 1
    assert second.provider_evidence[0] == {
        **first.provider_evidence[0],
        "cache_hit": True,
    }
    second.params["refresh"] = "true"
    http.request_json(second, "Shodan", URL, "secret")
    assert get.call_count == 2
    assert second.provider_evidence[-1]["source_scan_id"] == "scan-next"
    assert not second.provider_evidence[-1]["cache_hit"]
    assert list(store.ttls.values()) == [900]
    assert all("secret" not in key and "192.0.2.1" not in key for key in store.values)


def test_inflight_requests_are_deduplicated(provider):
    _, get = provider
    entered, release = threading.Event(), threading.Event()

    def fetch(*args, **kwargs):
        entered.set()
        assert release.wait(2)
        return response()

    get.side_effect = fetch
    with ThreadPoolExecutor(2) as pool:
        first = pool.submit(http.request_json, enricher(), "Shodan", URL, "secret")
        assert entered.wait(2)
        second = pool.submit(
            http.request_json, enricher("next"), "Shodan", URL, "secret"
        )
        release.set()
        assert first.result() == second.result() == {"data": []}
    assert get.call_count == 1


@pytest.mark.parametrize("status", [401, 403, 429])
def test_shared_cooldown_stops_other_inputs_and_is_credential_scoped(provider, status):
    store, get = provider
    get.return_value = response(status, headers={"Retry-After": "120"})
    first = enricher()
    assert http.request_json(first, "Shodan", URL, "secret") is None
    second = enricher("other")
    assert http.request_json(second, "Shodan", URL + "0", "secret") is None
    assert first._provider_stop and second._provider_stop
    assert get.call_count == 1
    assert list(store.ttls.values()) == [120]
    assert not any(":response:" in key for key in store.values)
    http.request_json(enricher(), "Shodan", URL, "other-credential")
    assert get.call_count == 2


def test_transient_retry_count_and_budget(provider):
    _, get = provider
    get.side_effect = [requests.Timeout("secret"), response()]
    limited = enricher()
    limited.provider_request_limit = 1
    assert http.request_json(limited, "Shodan", URL, "secret") is None
    assert limited.provider_request_count == get.call_count == 1
    assert "budget exhausted" in limited.report_issue.call_args.args[1]
    get.reset_mock(side_effect=True)
    get.side_effect = [response(503), response()]
    allowed = enricher()
    assert http.request_json(allowed, "Shodan", URL, "secret") == {"data": []}
    assert allowed.provider_request_count == get.call_count == 2


def test_long_retry_after_does_not_sleep_or_retry(provider):
    store, get = provider
    get.return_value = response(503, headers={"Retry-After": "600"})
    assert http.request_json(enricher(), "Shodan", URL, "secret") is None
    assert http.request_json(enricher(), "Shodan", URL + "0", "secret") is None
    assert get.call_count == 1
    assert list(store.ttls.values()) == [600]


@pytest.mark.parametrize("body", [b"[]", b"invalid", b"x" * (http.MAX_BYTES + 1)])
def test_invalid_or_oversized_response_is_not_cached(provider, body):
    store, get = provider
    get.return_value.iter_content.return_value = [body]
    e = enricher()
    assert http.request_json(e, "Shodan", URL, "secret") is None
    assert not store.values
    get.return_value.close.assert_called_once()
    assert "secret" not in str(e.report_issue.call_args)


def test_request_url_and_query_identity(provider):
    a = http.request_identity("Shodan", URL + "?b=2&a=1", "key", None)
    b = http.request_identity("Shodan", URL, "key", {"a": 1, "b": 2})
    assert a == b
    for url in [
        "https://evil.test/",
        "http://api.shodan.io/x",
        URL + "?key=secret",
        "https://u:p@api.shodan.io/x",
    ]:
        assert http.request_json(enricher(), "Shodan", url, "secret") is None
    provider[1].assert_not_called()


def test_unavailable_redis_fails_closed(provider, monkeypatch):
    monkeypatch.setattr(
        http, "_redis", Mock(side_effect=redis.ConnectionError("secret"))
    )
    e = enricher()
    assert http.request_json(e, "Shodan", URL, "secret") is None
    provider[1].assert_not_called()
    assert "secret" not in str(e.report_issue.call_args)


def test_retry_after_http_date_and_invalid_values():
    future = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=120))
    assert 119 <= http.retry_after(future) <= 120
    assert http.retry_after("NaN") == 60
    assert http.retry_after("garbage") == 60


def test_public_indexed_lookup_respects_budget(monkeypatch):
    get = Mock()
    monkeypatch.setattr("flowsint_enrichers.passive_http.requests.get", get)
    e = enricher()
    e.provider_request_limit = 0
    assert indexed_json(e, "https://crt.sh/", {}) is None
    get.assert_not_called()


@pytest.mark.asyncio
async def test_shodan_cached_relations_keep_each_inputs_original_evidence(
    provider, monkeypatch
):
    from flowsint_enrichers.ip.to_shodan import IpToPortsShodanEnricher
    from flowsint_types.ip import Ip

    _, get = provider
    get.return_value = response(
        payload={"data": [{"port": 443}], "hostnames": ["example.org"]}
    )
    expected = {}
    inputs = [Ip(address="192.0.2.1"), Ip(address="192.0.2.2")]
    for index, ip in enumerate(inputs):
        original = enricher(f"original-{index}")
        http.request_json(
            original,
            "Shodan",
            f"https://api.shodan.io/shodan/host/{ip.address}",
            "secret",
        )
        expected[ip.address] = original.provider_evidence[0]
    graph = Mock()
    reused = IpToPortsShodanEnricher(
        graph_service=graph, sketch_id="sketch", scan_id="current"
    )
    monkeypatch.setattr(reused, "get_secret", lambda *args: "secret")
    ports = await reused.scan(inputs)
    reused.postprocess(ports)
    assert get.call_count == 2
    assert len(graph.create_relationship.call_args_list) == 4
    for call in graph.create_relationship.call_args_list:
        original = expected[call.kwargs["from_obj"].address]
        observation = call.kwargs["observation"]
        assert observation["scan_id"] == "current"
        assert observation["source_scan_id"] == original["source_scan_id"]
        assert observation["retrieved_at"] == original["fetched_at"]
        assert observation["cache_hit"] is True


@pytest.mark.asyncio
async def test_vt_cached_pages_keep_their_own_original_evidence(provider, monkeypatch):
    from flowsint_enrichers.domain.to_ips_virustotal import DomainToIpsVirusTotal
    from flowsint_types.domain import Domain

    _, get = provider
    url = "https://www.virustotal.com/api/v3/domains/example.org/resolutions"
    pages = [url, url + "?cursor=next"]
    expected = {}
    for index, page in enumerate(pages):
        ip = f"192.0.2.{index + 1}"
        get.return_value = response(
            payload={
                "data": [{"attributes": {"ip_address": ip, "date": 1700000000}}],
                "links": {"next": pages[1]} if index == 0 else {},
            }
        )
        original = enricher(f"page-{index}")
        http.request_json(
            original,
            "VirusTotal",
            page,
            "secret",
            {"limit": 40} if index == 0 else None,
        )
        expected[ip] = original.provider_evidence[0]
    graph = Mock()
    reused = DomainToIpsVirusTotal(
        graph_service=graph, sketch_id="sketch", scan_id="current"
    )
    monkeypatch.setattr(reused, "get_secret", lambda *args: "secret")
    outputs = await reused.scan([Domain(domain="example.org")])
    reused.postprocess(outputs)
    assert get.call_count == 2
    assert len(graph.create_relationship.call_args_list) == 2
    for call in graph.create_relationship.call_args_list:
        original = expected[call.kwargs["to_obj"].address]
        observation = call.kwargs["observation"]
        assert observation["source_scan_id"] == original["source_scan_id"]
        assert observation["retrieved_at"] == original["fetched_at"]
        assert observation["cache_hit"] is True
