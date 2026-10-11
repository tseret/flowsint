import json
from unittest.mock import Mock

import pytest

from flowsint_enrichers.certificate.to_domains import CertificateToDomains
from flowsint_enrichers.cidr.to_ips import CidrToIpsEnricher
from flowsint_enrichers.cidr.to_routing_history_ripestat import (
    CidrToRoutingHistoryRipestat,
)
from flowsint_enrichers.domain.to_certificates_ct import DomainToCertificatesCT
from flowsint_enrichers.domain.to_dns_dependencies_virustotal import (
    DomainToDnsDependenciesVirusTotal,
)
from flowsint_enrichers.passive_http import indexed_json
from flowsint_enrichers.registry import ENRICHER_REGISTRY
from flowsint_types.cidr import CIDR
from flowsint_types.domain import Domain
from flowsint_types.ssl_certificate import SSLCertificate


def instance(cls, **params):
    enricher = cls(sketch_id="s", scan_id="t", params=params)
    enricher.report_issue = Mock()
    enricher.create_node = Mock()
    enricher.create_relationship = Mock()
    enricher._graph_service = Mock()
    return enricher


@pytest.mark.asyncio
async def test_cidr_budget_is_checked_before_ipv6_enumeration():
    enricher = instance(CidrToIpsEnricher)
    assert await enricher.scan([CIDR(network="2001:db8::/32")]) == []
    assert "79228162514264337593543950336" in enricher.report_issue.call_args.args[1]
    enricher = instance(CidrToIpsEnricher, max_results="4")
    assert (
        await enricher.scan(
            [CIDR(network="192.0.2.0/30"), CIDR(network="198.51.100.0/30")]
        )
        == []
    )


@pytest.mark.asyncio
async def test_cidr_preview_and_exact_budget():
    enricher = instance(CidrToIpsEnricher, max_results="4", preview_only="true")
    ranges = [CIDR(network="192.0.2.0/30")]
    assert await enricher.scan(ranges) == []
    enricher.params["preview_only"] = "false"
    results = await enricher.scan(ranges)
    assert [ip.address for ip in results] == [f"192.0.2.{i}" for i in range(4)]
    enricher.postprocess(results, ranges)
    assert enricher.create_relationship.call_count == 4


@pytest.mark.asyncio
async def test_ct_preserves_distinct_certificates_and_provenance(monkeypatch):
    rows = [
        {
            "id": i,
            "common_name": "example.com",
            "name_value": "example.com\nwww.example.com",
            "entry_timestamp": "2026-01-01T00:00:00",
            "serial_number": str(i),
        }
        for i in (1, 1, 2)
    ]
    monkeypatch.setattr(
        "flowsint_enrichers.domain.to_certificates_ct.indexed_json", lambda *a: rows
    )
    enricher = instance(DomainToCertificatesCT)
    results = await enricher.scan([Domain(domain="example.com")])
    assert len(results) == 2
    assert results[0].subject != results[1].subject
    enricher.postprocess(results)
    assert enricher.create_relationship.call_args.kwargs == {
        "observed_at": "2026-01-01T00:00:00",
        "source_ref": "https://crt.sh/?id=2",
        "provider": "crt.sh",
    }


@pytest.mark.asyncio
async def test_ct_budget_and_certificate_wildcards(monkeypatch):
    monkeypatch.setattr(
        "flowsint_enrichers.domain.to_certificates_ct.indexed_json",
        lambda *a: [
            {"id": i + 1, "common_name": "example.com", "name_value": "example.com"}
            for i in range(101)
        ],
    )
    enricher = instance(DomainToCertificatesCT)
    assert len(await enricher.scan([Domain(domain="example.com")])) == 100
    assert enricher.report_issue.called
    local = instance(CertificateToDomains)
    domains = await local.scan(
        [
            SSLCertificate(
                subject="test",
                san_domains=["*.example.com", "www.example.com", "bad value"],
            )
        ]
    )
    assert [d.domain for d in domains] == ["www.example.com"]


@pytest.mark.asyncio
async def test_indexed_dns_preserves_record_roles_and_observation(monkeypatch):
    monkeypatch.setattr(
        "flowsint_enrichers.domain.to_dns_dependencies_virustotal.api_key",
        lambda e: "test",
    )
    monkeypatch.setattr(
        "flowsint_enrichers.domain.to_dns_dependencies_virustotal.request_json",
        lambda *a: {
            "data": {
                "attributes": {
                    "last_dns_records_date": 1767225600,
                    "last_dns_records": [
                        {"type": kind, "value": f"{kind.lower()}.example.com."}
                        for kind in ("NS", "MX", "CNAME", "TXT")
                    ],
                }
            }
        },
    )
    enricher = instance(DomainToDnsDependenciesVirusTotal)
    enricher._vt_stop = False
    results = await enricher.scan([Domain(domain="example.com")])
    enricher.postprocess(results)
    assert [c.args[2] for c in enricher.create_relationship.call_args_list] == [
        "USES_NAMESERVER",
        "USES_MAILSERVER",
        "ALIASES_TO",
    ]
    assert (
        enricher.create_relationship.call_args.kwargs["observed_at"]
        == "2026-01-01T00:00:00+00:00"
    )


@pytest.mark.asyncio
async def test_routing_history_keeps_interval_and_origin(monkeypatch):
    monkeypatch.setattr(
        "flowsint_enrichers.cidr.to_routing_history_ripestat.indexed_json",
        lambda *a: {
            "data": {
                "by_origin": [
                    {
                        "origin": "64500",
                        "prefixes": [
                            {
                                "prefix": "192.0.2.0/24",
                                "timelines": [
                                    {
                                        "starttime": "2026-01-01T00:00:00",
                                        "endtime": "2026-01-02T00:00:00",
                                        "visibility": 0.8,
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        },
    )
    enricher = instance(
        CidrToRoutingHistoryRipestat, starttime="2026-01-01", endtime="2026-02-01"
    )
    results = await enricher.scan([CIDR(network="192.0.2.0/24")])
    assert results[0].origin_asn == "AS64500"
    assert results[0].end_time == "2026-01-02T00:00:00"
    enricher.postprocess(results)
    assert enricher.create_relationship.call_count == 2
    enricher.params["endtime"] = "2030-01-01"
    assert await enricher.scan([CIDR(network="192.0.2.0/24")]) == []


def test_indexed_response_is_bounded_and_quota_reported(monkeypatch):
    response = Mock()
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    response.status_code = 200
    response.iter_content.return_value = [b"x" * (4 * 1024 * 1024 + 1)]
    monkeypatch.setattr(
        "flowsint_enrichers.passive_http.requests.get", lambda *a, **k: response
    )
    enricher = instance(DomainToCertificatesCT)
    assert indexed_json(enricher, "https://crt.sh/", {}) is None
    response.iter_content.return_value = [json.dumps([{"id": 1}]).encode()]
    assert indexed_json(enricher, "https://crt.sh/", {}) == [{"id": 1}]
    response.status_code = 429
    assert indexed_json(enricher, "https://crt.sh/", {}) is None
    assert enricher.report_issue.call_args.args[0] == "quota_exceeded"


def test_catalog_metadata_and_hidden_dummy():
    for catalog in [
        ENRICHER_REGISTRY.list(),
        ENRICHER_REGISTRY.list_by_input_type("domain"),
        sum(ENRICHER_REGISTRY.list_by_categories().values(), []),
    ]:
        assert all("dummy" not in row["name"] for row in catalog)
        assert all("display_name" in row and "passive" in row for row in catalog)
    assert ENRICHER_REGISTRY.enricher_exists("domain_to_dummy")
    ct = next(
        row
        for row in ENRICHER_REGISTRY.list()
        if row["name"] == "domain_to_certificates_ct"
    )
    assert ct["passive"] is True and ct["max_results"] == 100
