from typing import Any, Dict, List, Optional

from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_enrichers.virustotal import KEY_SCHEMA, api_key, request_json, timestamp
from flowsint_types.domain import Domain


@flowsint_enricher
class DomainToDnsDependenciesVirusTotal(Enricher):
    """[VirusTotal] Map indexed NS, MX and CNAME dependencies without querying target DNS."""

    InputType = Domain
    OutputType = Domain

    @classmethod
    def name(cls) -> str:
        return "domain_to_dns_dependencies_virustotal"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [KEY_SCHEMA.copy()]

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        self._pairs = []
        results: list[Domain] = []
        key = api_key(self)
        if not key:
            return results
        for domain in data[:25]:
            url = f"https://www.virustotal.com/api/v3/domains/{domain.domain}"
            payload = request_json(self, url, key)
            if payload:
                try:
                    attrs = payload["data"]["attributes"]
                    observed = timestamp(attrs.get("last_dns_records_date"))
                    records = attrs.get("last_dns_records") or []
                    for row in records[:100]:
                        kind = row.get("type")
                        if kind not in ("NS", "MX", "CNAME"):
                            continue
                        try:
                            target = Domain(domain=row["value"].rstrip("."))
                        except (ValueError, KeyError, AttributeError):
                            self.report_issue(
                                "partial",
                                "An invalid indexed DNS dependency was skipped.",
                            )
                            continue
                        results.append(target)
                        self._pairs.append((domain, target, kind, observed, url))
                    if len(records) > 100:
                        self.report_issue(
                            "partial",
                            "Indexed DNS records truncated at 100 per domain.",
                        )
                except (
                    KeyError,
                    TypeError,
                    ValueError,
                    AttributeError,
                    OverflowError,
                    OSError,
                ):
                    self.report_issue(
                        "partial", "VirusTotal returned malformed DNS metadata."
                    )
            if self._vt_stop:
                break
        if len(data) > 25:
            self.report_issue(
                "partial", "DNS dependency lookup limited to 25 input domains."
            )
        return results

    def postprocess(
        self, results: List[OutputType], input_data: Optional[List[InputType]] = None
    ) -> List[OutputType]:
        if self._graph_service:
            for source, target, kind, observed, url in self._pairs:
                self.create_node(source)
                self.create_node(target)
                self.create_relationship(
                    source,
                    target,
                    {
                        "NS": "USES_NAMESERVER",
                        "MX": "USES_MAILSERVER",
                        "CNAME": "ALIASES_TO",
                    }[kind],
                    observed_at=observed,
                    source_ref=url,
                    provider="VirusTotal",
                )
        return results
