import pytest

from flowsint_enrichers.ip.to_internetdb import IpToInternetDbEnricher
from flowsint_enrichers.ip.to_ports import IpToPortsEnricher
from flowsint_enrichers.ip.to_ports_driftnet import IpToPortsDriftnetEnricher
from flowsint_enrichers.ip.to_shodan import IpToPortsShodanEnricher
from flowsint_types.ip import Ip


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cls,payload",
    [
        (IpToInternetDbEnricher, {"ports": [443]}),
        (IpToPortsDriftnetEnricher, {"values": {"443": 1}}),
        (IpToPortsShodanEnricher, {"data": [{"port": 443, "transport": "tcp"}]}),
        (IpToPortsEnricher, None),
    ],
)
async def test_port_identity_retains_host_across_all_port_connectors(
    monkeypatch, cls, payload
):
    class Response:
        status_code = 200

        def json(self):
            return payload

    monkeypatch.setattr("requests.get", lambda *a, **k: Response())

    class Tool:
        def launch(self, **kwargs):
            return [{"port": 443, "protocol": "tcp"}]

    monkeypatch.setattr("flowsint_enrichers.ip.to_ports.NaabuTool", Tool)
    enricher = cls(sketch_id="s", scan_id="t")
    monkeypatch.setattr(enricher, "get_secret", lambda *a: "k")
    ports = await enricher.scan([Ip(address="1.2.3.4"), Ip(address="5.6.7.8")])
    assert [(p.host, p.number, p.protocol.lower()) for p in ports] == [
        ("1.2.3.4", 443, "tcp"),
        ("5.6.7.8", 443, "tcp"),
    ]
    assert all("host" in port.model_dump() for port in ports)
