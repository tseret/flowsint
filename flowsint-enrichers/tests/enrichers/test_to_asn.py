import pytest

from flowsint_enrichers.domain.to_asn import DomainToAsnEnricher
from flowsint_enrichers.ip.to_asn import IpToAsnEnricher
from flowsint_enrichers.organization.to_asn import OrgToAsnEnricher
from flowsint_types.domain import Domain
from flowsint_types.ip import Ip
from flowsint_types.organization import Organization

ASNMAP_ROW = {
    "as_number": "AS54113",
    "as_name": "fastly",
    "as_country": "US",
    "as_range": ["151.101.128.0/18"],
}


class _FakeAsnmap:
    def launch(self, item, type="domain", api_key=None):
        return ASNMAP_ROW


class _NoLogger:
    info = warn = error = staticmethod(lambda *a, **k: None)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "module, enricher_cls, item",
    [
        ("ip", IpToAsnEnricher, Ip(address="151.101.128.223")),
        ("domain", DomainToAsnEnricher, Domain(domain="python.org")),
        ("organization", OrgToAsnEnricher, Organization(name="fastly")),
    ],
)
async def test_scan_builds_asn_from_asnmap_row(monkeypatch, module, enricher_cls, item):
    monkeypatch.setattr(
        f"flowsint_enrichers.{module}.to_asn.AsnmapTool", lambda: _FakeAsnmap()
    )
    # keep the test off the logs table
    monkeypatch.setattr(f"flowsint_enrichers.{module}.to_asn.Logger", _NoLogger)
    enricher = enricher_cls(sketch_id="s", scan_id="t")
    monkeypatch.setattr(enricher, "get_secret", lambda *a, **k: "key")

    [asn] = await enricher.scan([item])

    assert (asn.asn_str, asn.number, asn.name, asn.country) == (
        "AS54113",
        54113,
        "fastly",
        "US",
    )
