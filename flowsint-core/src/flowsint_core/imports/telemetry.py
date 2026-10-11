"""Validate bounded internal telemetry batches before any graph writes."""

import json
import math
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from flowsint_types import Domain, Ip, Phrase, Website

MAX_BYTES = 2 * 1024 * 1024
MAX_RECORDS = 1000
MAX_EDGES = 2000
FORMATS = {"normalized", "dns", "proxy", "zeek", "suricata", "cloudtrail"}
RELATIONSHIPS = {
    "CONNECTED_TO",
    "QUERIED_DOMAIN",
    "DNS_RESOLVED_TO",
    "ALIASES_TO",
    "REQUESTED_URL",
    "OBSERVED_FROM",
    "CALLED_SERVICE",
    "OBSERVED_CONTACT",
}


def _timestamp(value: Any, *, epoch: bool = False) -> str:
    if epoch and isinstance(value, (int, float)) and not isinstance(value, bool):
        if not math.isfinite(value):
            raise ValueError("Invalid observation timestamp")
        date = datetime.fromtimestamp(value, timezone.utc)
    elif isinstance(value, str):
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if date.tzinfo is None or date.utcoffset() is None:
            raise ValueError("Observation timestamp must include a timezone")
    else:
        raise ValueError("Observation timestamp is required")
    return date.astimezone(timezone.utc).isoformat()


def _entity(value: Any, kind: str | None = None) -> dict[str, Any]:
    if isinstance(value, dict):
        kind, value = value.get("type"), value.get("label")
    if not isinstance(value, str) or not value.strip() or len(value) > 2048:
        raise ValueError("Entity must be a nonempty string of at most 2048 characters")
    value = value.strip()
    if kind is None:
        if value.startswith(("http://", "https://")):
            kind = "website"
        else:
            try:
                ip_address(value)
                kind = "ip"
            except ValueError:
                kind = "domain"
    if kind == "ip":
        node = Ip(address=str(ip_address(value)))
        label, properties = node.address, {"address": node.address}
    elif kind == "domain":
        value = value.lower().rstrip(".")
        if not Domain.detect(value):
            raise ValueError("Invalid domain")
        domain = Domain(domain=value)
        label, properties = domain.domain, {"domain": domain.domain}
    elif kind == "website":
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Invalid HTTP URL")
        host = parsed.hostname
        host = f"[{host}]" if ":" in host else host
        authority = host + (f":{parsed.port}" if parsed.port is not None else "")
        # Request credentials and query strings commonly contain secrets.
        website = Website(
            url=urlunsplit((parsed.scheme, authority, parsed.path, "", ""))
        )
        label = str(website.url)
        properties = {"url": label}
    elif kind == "phrase":
        if len(value) > 512 or any(ord(char) < 32 for char in value):
            raise ValueError("Invalid identity label")
        phrase = Phrase(text=value)
        label, properties = value, {"text": phrase.text}
    else:
        raise ValueError("Entity type must be ip, domain, website or phrase")
    return {"type": kind, "label": label, "properties": properties}


def _edge(
    source: Any, target: Any, relationship: str, observed: str, reference: str
) -> dict[str, Any]:
    if relationship not in RELATIONSHIPS:
        raise ValueError("Unsupported relationship type")
    return {
        "source": _entity(source),
        "target": _entity(target),
        "relationship": relationship,
        "observed_at": observed,
        "source_ref": reference,
    }


def _dns(
    source: Any, query: Any, answers: Any, observed: str, reference: str
) -> list[dict[str, Any]]:
    domain = _entity(query, "domain")
    edges = [_edge(source, domain, "QUERIED_DOMAIN", observed, reference)]
    if not isinstance(answers, list):
        raise ValueError("DNS answers must be a list")
    for answer in answers:
        if isinstance(answer, dict):
            if answer.get("rrtype", answer.get("type")) not in ("A", "AAAA", "CNAME"):
                continue
            answer = answer.get("rdata", answer.get("value"))
        target = _entity(answer)
        if target["type"] not in ("ip", "domain"):
            raise ValueError("DNS answer must be an IP address or domain")
        edges.append(
            _edge(
                domain,
                target,
                "DNS_RESOLVED_TO" if target["type"] == "ip" else "ALIASES_TO",
                observed,
                reference,
            )
        )
        if len(edges) > MAX_EDGES:
            raise ValueError("Telemetry exceeds 2000 normalized edges")
    return edges


def _normalize(
    record: dict[str, Any], format: str, reference: str
) -> list[dict[str, Any]]:
    if format in ("normalized", "dns", "proxy"):
        observed = _timestamp(record.get("timestamp", record.get("time")))
        source = record.get("source", record.get("src_ip", record.get("client_ip")))
        target = record.get(
            "target",
            record.get(
                "dst_ip", record.get("domain", record.get("query", record.get("url")))
            ),
        )
        kind = record.get("relationship", record.get("type", format))
        relation = {
            "normalized": "OBSERVED_CONTACT",
            "dns": "QUERIED_DOMAIN",
            "proxy": "REQUESTED_URL",
            "flow": "CONNECTED_TO",
        }.get(kind, kind)
        if format == "dns" and "answers" in record:
            return _dns(source, target, record["answers"], observed, reference)
        return [_edge(source, target, relation, observed, reference)]
    if format == "zeek":
        observed = _timestamp(record.get("ts"), epoch=True)
        source = _entity(record.get("id.orig_h"), "ip")
        if "query" in record:
            answers = record.get("answers") or []
            if record.get("qtype_name") not in (None, "A", "AAAA", "CNAME"):
                answers = []
            return _dns(source, record["query"], answers, observed, reference)
        target = _entity(record.get("id.resp_h"), "ip")
        return [_edge(source, target, "CONNECTED_TO", observed, reference)]
    if format == "suricata":
        observed = _timestamp(record.get("timestamp"))
        source = _entity(record.get("src_ip"), "ip")
        event = record.get("event_type")
        if event == "dns":
            dns = record["dns"]
            if not isinstance(dns, dict):
                raise ValueError("DNS event must contain a DNS object")
            if dns.get("type") == "answer" and record.get("dest_ip"):
                source = _entity(record["dest_ip"], "ip")
            query = dns.get("rrname")
            if query:
                return _dns(
                    source, query, dns.get("answers") or [], observed, reference
                )
            queries = dns.get("queries")
            if not isinstance(queries, list) or not queries:
                raise ValueError("DNS event is missing query names")
            edges = []
            for query_record in queries:
                edges.extend(
                    _dns(source, query_record["rrname"], [], observed, reference)
                )
            return edges
        if event == "flow":
            return [
                _edge(
                    source,
                    _entity(record.get("dest_ip"), "ip"),
                    "CONNECTED_TO",
                    observed,
                    reference,
                )
            ]
        if event == "http":
            http = record["http"]
            hostname, path = http["hostname"], http.get("url", "/")
            if not isinstance(path, str) or not isinstance(hostname, str):
                raise ValueError("HTTP event requires a hostname and URL")
            url = (
                path
                if path.startswith(("http://", "https://"))
                else f"http://{hostname}/{path.lstrip('/')}"
            )
            return [
                _edge(
                    source,
                    _entity(url, "website"),
                    "REQUESTED_URL",
                    observed,
                    reference,
                )
            ]
        raise ValueError("Supported Suricata events are dns, flow and http")
    observed = _timestamp(record.get("eventTime"))
    identity = record["userIdentity"]["arn"]
    if not isinstance(identity, str) or not identity.startswith("arn:"):
        raise ValueError("CloudTrail requires a userIdentity ARN")
    actor = _entity(identity, "phrase")
    address = record["sourceIPAddress"]
    source = _entity(
        address, "phrase" if address in ("AWS Internal", "AWS Service") else None
    )
    return [
        _edge(actor, source, "OBSERVED_FROM", observed, reference),
        _edge(
            actor,
            _entity(record["eventSource"], "domain"),
            "CALLED_SERVICE",
            observed,
            reference,
        ),
    ]


def parse_telemetry(content: str, format: str) -> list[dict[str, Any]]:
    """Parse a complete JSON/NDJSON batch or raise ValueError without partial results."""
    if format not in FORMATS:
        raise ValueError("Unsupported telemetry format")
    if not isinstance(content, str) or len(content.encode("utf-8")) > MAX_BYTES:
        raise ValueError("Telemetry exceeds the 2 MiB input limit")
    try:
        decoded = json.loads(content)
    except RecursionError:
        raise ValueError("Record 1: JSON nesting is too deep") from None
    except json.JSONDecodeError:
        records = []
        for line in content.splitlines():
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except (json.JSONDecodeError, RecursionError):
                raise ValueError(f"Record {len(records) + 1}: invalid JSON") from None
            if len(records) > MAX_RECORDS:
                raise ValueError("Telemetry exceeds the 1000 record limit")
    else:
        if (
            format == "cloudtrail"
            and isinstance(decoded, dict)
            and "Records" in decoded
        ):
            decoded = decoded["Records"]
        records = decoded if isinstance(decoded, list) else [decoded]
    if not records:
        raise ValueError("Telemetry must contain at least one record")
    if len(records) > MAX_RECORDS:
        raise ValueError("Telemetry exceeds the 1000 record limit")
    edges = []
    for index, record in enumerate(records, 1):
        if not isinstance(record, dict):
            raise ValueError(f"Record {index}: expected a JSON object")
        try:
            edges.extend(_normalize(record, format, f"local:{format}:record:{index}"))
        except (
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            OverflowError,
            OSError,
        ):
            # Validation errors may echo submitted URLs/credentials; return only the location.
            raise ValueError(
                f"Record {index}: invalid or missing entity, event type, or timezone-aware timestamp"
            ) from None
        if len(edges) > MAX_EDGES:
            raise ValueError(f"Record {index}: telemetry exceeds the 2000 edge limit")
    return edges
