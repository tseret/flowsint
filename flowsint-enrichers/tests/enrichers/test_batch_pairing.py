import json

import pytest

from flowsint_enrichers.domain.to_dehashed import DomainToDehashed
from flowsint_enrichers.domain.to_ssl import DomainToTLS
from flowsint_enrichers.email.to_dehashed import EmailToDehashed
from flowsint_enrichers.ip.to_dehashed import IpToIntelligence
from flowsint_enrichers.social.to_dehashed import UsernameToDehashed
from flowsint_types.domain import Domain
from flowsint_types.email import Email
from flowsint_types.ip import Ip
from flowsint_types.ssl_certificate import SSLCertificate
from flowsint_types.username import Username


def capture(monkeypatch, enricher):
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
async def test_tls_certificate_fields_and_batch_relationships(monkeypatch):
    calls = []

    class Tool:
        def launch(self, target, args):
            calls.append((target, args))
            return [
                {
                    "url": f"https://{target}",
                    "timestamp": "2026-10-02T12:00:00Z",
                    "tls": {
                        "subject_cn": target,
                        "issuer_cn": "Example CA",
                        "serial": "abc",
                        "not_before": "2026-01-01T00:00:00Z",
                        "not_after": "2027-01-01T00:00:00Z",
                        "subject_an": [target],
                        "fingerprint_hash": {"sha256": target + "-fingerprint"},
                        "self_signed": False,
                    },
                }
            ]

    monkeypatch.setattr("flowsint_enrichers.domain.to_ssl.HttpxTool", Tool)
    enricher = DomainToTLS(sketch_id="s", scan_id="t")
    edges = capture(monkeypatch, enricher)
    inputs = [Domain(domain="first.example"), Domain(domain="second.example")]
    results = await enricher.scan(inputs)
    enricher.postprocess(results, inputs)
    assert all(isinstance(result, SSLCertificate) for result in results)
    assert [(src.domain, dst.subject) for src, dst, _, _ in edges] == [
        (item.domain, item.domain) for item in inputs
    ]
    assert len(edges) == 2
    assert results[0].issuer == "Example CA"
    assert results[0].valid_until == "2027-01-01T00:00:00Z"
    assert results[0].is_self_signed is False
    assert edges[0][3]["source_ref"] == "https://first.example"
    assert all(args == ["-tls-grab"] for _, args in calls)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cls,module,inputs",
    [
        (
            DomainToDehashed,
            "domain",
            [Domain(domain="first.example"), Domain(domain="second.example")],
        ),
        (
            EmailToDehashed,
            "email",
            [Email(email="first@example.com"), Email(email="second@example.com")],
        ),
        (IpToIntelligence, "ip", [Ip(address="1.2.3.4"), Ip(address="5.6.7.8")]),
        (
            UsernameToDehashed,
            "social",
            [Username(value="first"), Username(value="second")],
        ),
    ],
)
async def test_dehashed_results_remain_with_their_input(
    monkeypatch, cls, module, inputs
):
    class Response:
        status_code = 200
        text = ""

        def __init__(self, name):
            self.name = name

        def json(self):
            return {"entries": [{"name": [self.name]}]}

    def post(url, data, **kwargs):
        return Response(json.loads(data)["query"])

    monkeypatch.setattr(f"flowsint_enrichers.{module}.to_dehashed.requests.post", post)
    enricher = cls(sketch_id="s", scan_id="t")
    monkeypatch.setattr(enricher, "get_secret", lambda *a: "k")
    edges = capture(monkeypatch, enricher)
    results = await enricher.scan(inputs)
    enricher.postprocess(results, inputs)
    assert len(results) == 2
    assert len(edges) == 2
    assert edges[0][0] == inputs[0]
    assert edges[0][1] == results[0]
    assert edges[1][0] == inputs[1]
    assert edges[1][1] == results[1]
