from typing import Any, Dict, List, Optional

from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_enrichers.virustotal import (
    KEY_SCHEMA,
    PAGE_SCHEMA,
    api_key,
    resolutions,
    timestamp,
)
from flowsint_types.domain import Domain
from flowsint_types.ip import Ip


@flowsint_enricher
class DomainToIpsVirusTotal(Enricher):
    """[VirusTotal] Get historical passive DNS resolutions with observation evidence."""

    InputType = Domain
    OutputType = Ip

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [KEY_SCHEMA.copy(), PAGE_SCHEMA.copy()]

    @classmethod
    def name(cls) -> str:
        return "domain_to_ips_virustotal"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        self._pairs = []
        results: List[OutputType] = []
        key = api_key(self)
        if not key:
            return results
        seen = set()
        for item in data:
            url = f"https://www.virustotal.com/api/v3/domains/{item.domain}/resolutions"
            for row in resolutions(self, url, key):
                attrs = row.get("attributes") or {}
                value = attrs.get("ip_address")
                if not value:
                    continue
                try:
                    output = Ip(address=value)
                    observed = timestamp(attrs.get("date"))
                except (ValueError, OverflowError, OSError):
                    continue
                domain, ip = item, output
                source = (row.get("links") or {}).get("self") or url
                self._pairs.append((domain, ip, observed, source))
                if value not in seen:
                    seen.add(value)
                    results.append(output)
            if self._vt_stop:
                break
        return results

    def postprocess(
        self, results: List[OutputType], input_data: Optional[List[InputType]] = None
    ) -> List[OutputType]:
        if not self._graph_service:
            return results
        for domain, ip, observed, source in self._pairs:
            self.create_node(domain)
            self.create_node(ip)
            self.create_relationship(
                domain,
                ip,
                "PASSIVE_DNS_RESOLVED_TO",
                observed_at=observed,
                source_ref=source,
                provider="VirusTotal",
            )
            self.log_graph_message(
                f"DomainToIpsVirusTotal: {domain.domain} -> {ip.address} (passive DNS, observed {observed or 'unknown'})"
            )
        return results


InputType = DomainToIpsVirusTotal.InputType
OutputType = DomainToIpsVirusTotal.OutputType
