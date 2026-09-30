import pytest

from flowsint_core.core.graph.serializer import GraphSerializer
from flowsint_enrichers.file.to_malwarebazaar import FileToMalwareBazaar
from flowsint_enrichers.file.to_threatfox import FileToThreatFox
from flowsint_enrichers.file.to_virustotal import FileToVirusTotal
from flowsint_types.file import File

SHA = "9f0df64cc8a15b2c96e639a975acb9f54ff26721dc60a8035d4bbc65476485e7"
MD5 = "4cda731b2a82dbdcc587b5bec0b84dcd"


class _NoLogger:
    info = warn = error = staticmethod(lambda *a, **k: None)


class _Resp:
    def __init__(self, payload, status=200):
        self._payload, self.status_code, self.text = payload, status, "body"

    def json(self):
        return self._payload


def _setup(monkeypatch, enricher_cls, responses, key="k"):
    calls = []
    responses = list(responses)

    def fake(url, headers=None, data=None, json=None, timeout=None, **kw):
        calls.append((url, data or json))
        payload, status = responses.pop(0)
        return _Resp(payload, status)

    for mod in ("to_malwarebazaar", "to_virustotal"):
        monkeypatch.setattr(f"flowsint_enrichers.file.{mod}.Logger", _NoLogger)
    monkeypatch.setattr("flowsint_enrichers.file.to_threatfox.Logger", _NoLogger)
    monkeypatch.setattr("flowsint_enrichers.ip.to_threatfox.Logger", _NoLogger)
    monkeypatch.setattr("flowsint_enrichers.file.to_malwarebazaar.requests.post", fake)
    monkeypatch.setattr("flowsint_enrichers.ip.to_threatfox.requests.post", fake)
    monkeypatch.setattr("flowsint_enrichers.file.to_virustotal.requests.get", fake)
    enricher = enricher_cls(sketch_id="s", scan_id="t")
    monkeypatch.setattr(enricher, "get_secret", lambda *a, **k: key)
    return enricher, calls


def _mb(**kw):
    return {
        "query_status": "ok",
        "data": [
            {
                "sha256_hash": SHA,
                "md5_hash": MD5,
                "sha1_hash": "5efc1d0e3deb89b747357dac5ce81ed1e3bf5d3a",
                "file_type": "js",
                "file_size": 782324,
                "file_type_mime": "text/plain",
                "signature": "RemcosRAT",
                "first_seen": "2026-09-30 15:34:19",
                "last_seen": None,
                **kw,
            }
        ],
    }


def _props(file):
    return {
        k.removeprefix("nodeProperties.")
        for k in GraphSerializer.flowsint_type_to_neo4j_dict(file)
        if k.startswith("nodeProperties.")
    }


@pytest.mark.asyncio
async def test_malwarebazaar_enriches_label_file_and_links_family(monkeypatch):
    enricher, calls = _setup(monkeypatch, FileToMalwareBazaar, [(_mb(), 200)])
    edges = []
    enricher._graph_service = object()
    monkeypatch.setattr(enricher, "create_node", lambda node: None)
    monkeypatch.setattr(
        enricher, "create_relationship", lambda a, b, rel: edges.append((a, b, rel))
    )
    monkeypatch.setattr(enricher, "log_graph_message", lambda *a: None)

    # Hash typed as the node label only: the filename is the lookup key. Built
    # like the launch route does (full dump), so every None field counts as set.
    file = File.model_validate(
        File(filename=MD5.upper()).model_dump(mode="json", serialize_as_any=True)
    )
    [malware] = await enricher.scan([file])
    enricher.postprocess([malware], [file])

    assert calls[0][1] == {"query": "get_info", "hash": MD5}
    assert (malware.name, malware.source, malware.sample_hashes) == (
        "RemcosRAT",
        "MalwareBazaar",
        [SHA],
    )
    [(enriched, target, rel)] = edges
    assert (target, rel) == (malware, "ASSOCIATED_WITH")
    assert enriched.nodeLabel == MD5.upper()
    assert (enriched.hash_sha256, enriched.is_malicious, enriched.malware_family) == (
        SHA,
        True,
        "RemcosRAT",
    )
    # Only response-provided fields are written: no nulls to clobber the node.
    assert _props(enriched) == {
        "filename",
        "hash_md5",
        "hash_sha1",
        "hash_sha256",
        "file_type",
        "file_size",
        "mime_type",
        "is_malicious",
        "malware_family",
        "source",
    }


@pytest.mark.asyncio
async def test_malwarebazaar_without_signature_still_enriches_file(monkeypatch):
    enricher, _ = _setup(monkeypatch, FileToMalwareBazaar, [(_mb(signature=None), 200)])

    assert await enricher.scan([File(filename="x.exe", hash_sha256=SHA)]) == []
    [(file, malware)] = enricher._pairs
    assert malware is None and file.file_size == 782324


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [({"query_status": "hash_not_found"}, 200), ({}, 500)],
)
async def test_malwarebazaar_unknown_or_failure_yields_nothing(monkeypatch, response):
    enricher, _ = _setup(monkeypatch, FileToMalwareBazaar, [response])

    assert await enricher.scan([File(filename=SHA)]) == []
    assert enricher._pairs == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "enricher_cls", [FileToMalwareBazaar, FileToThreatFox, FileToVirusTotal]
)
async def test_no_hash_or_no_key_makes_no_request(monkeypatch, enricher_cls):
    enricher, calls = _setup(monkeypatch, enricher_cls, [])
    assert await enricher.scan([File(filename="invoice.pdf")]) == []

    enricher, calls2 = _setup(monkeypatch, enricher_cls, [], key=None)
    assert await enricher.scan([File(filename=SHA)]) == []
    assert calls == calls2 == []


@pytest.mark.asyncio
async def test_threatfox_keeps_exact_hash_iocs_only(monkeypatch):
    def ioc(value, name):
        return {"ioc": value, "ioc_type": "sha256_hash", "malware_printable": name}

    payload = {
        "query_status": "ok",
        "data": [ioc(SHA.upper(), "Remcos"), ioc(SHA + "00", "Other")],
    }
    enricher, calls = _setup(monkeypatch, FileToThreatFox, [(payload, 200)])

    [malware] = await enricher.scan([File(filename="a.js", hash_sha256=SHA)])

    assert calls[0][1] == {"query": "search_ioc", "search_term": SHA}
    assert (malware.name, malware.source) == ("Remcos", "ThreatFox")


def _vt(malicious, label=None):
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": 0,
                    "undetected": 44,
                    "harmless": 0,
                    "type-unsupported": 14,
                },
                "popular_threat_classification": {"suggested_threat_label": label}
                if label
                else {},
                "type_description": "JavaScript",
                "size": 782324,
                "md5": MD5,
                "sha256": SHA,
            }
        }
    }


@pytest.mark.asyncio
async def test_virustotal_fills_verdict_without_overwriting(monkeypatch):
    enricher, _ = _setup(
        monkeypatch, FileToVirusTotal, [(_vt(10, "trojan.iacgm/sonbokli"), 200)]
    )
    # A prior MalwareBazaar run already set the family: VT must not replace it.
    file = File(filename=SHA, hash_sha256=SHA, malware_family="RemcosRAT")

    [enriched] = await enricher.scan([file])

    assert enriched.nodeLabel == SHA
    assert (enriched.threat_level, enriched.is_malicious) == (
        "10/54 engines (VirusTotal)",
        True,
    )
    assert (enriched.malware_family, enriched.file_type) == ("RemcosRAT", "JavaScript")


@pytest.mark.asyncio
async def test_virustotal_skips_404_and_stops_on_429(monkeypatch):
    enricher, calls = _setup(
        monkeypatch, FileToVirusTotal, [({}, 404), ({}, 429), (_vt(0), 200)]
    )
    files = [File(filename=c * 64) for c in "abc"]

    assert await enricher.scan(files) == []
    assert len(calls) == 2
