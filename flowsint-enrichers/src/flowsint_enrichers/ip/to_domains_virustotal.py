from typing import Any, Dict, List, Optional

from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_enrichers.virustotal import (
    HOSTS_SCHEMA,
    KEY_SCHEMA,
    PAGE_SCHEMA,
    api_key,
    resolutions,
    timestamp,
)
from flowsint_types.domain import Domain
from flowsint_types.ip import Ip


@flowsint_enricher
class IpToDomainsVirusTotal(Enricher):
    """[VirusTotal] Get historical passive DNS resolutions with observation evidence."""

    InputType = Ip
    OutputType = Domain

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [KEY_SCHEMA.copy(), PAGE_SCHEMA.copy(), HOSTS_SCHEMA.copy()]

    @classmethod
    def name(cls) -> str:
        return "ip_to_domains_virustotal"

    @classmethod
    def category(cls) -> str:
        return "Ip"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        self._pairs = []
        results: List[OutputType] = []
        try:
            raw = self.params.get("max_hosts", 0)
            max_hosts = int(raw)
            if isinstance(raw, bool) or float(raw) != max_hosts or max_hosts < 0:
                raise ValueError
        except (TypeError, ValueError):
            self.report_issue("failed", "max_hosts must be a non-negative integer.")
            return results
        key = api_key(self)
        if not key:
            return results
        seen = set()
        for item in data:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{item.address}/resolutions"
            pairs, hosts = [], {}
            for row in resolutions(self, url, key):
                attrs = row.get("attributes") or {}
                value = attrs.get("host_name")
                if not value:
                    continue
                try:
                    output = Domain(domain=value)
                    observed = timestamp(attrs.get("date"))
                except (ValueError, OverflowError, OSError):
                    continue
                source = (row.get("links") or {}).get("self") or url
                pairs.append((output, item, observed, source))
                hosts.setdefault(value, output)
            # ponytail: counts only hostnames in the retrieved max_pages; raise max_pages for a stricter shared-hosting check.
            if max_hosts and len(hosts) > max_hosts:
                self.report_issue(
                    "partial",
                    f"{item.address} resolves {len(hosts)}+ hostnames (shared hosting); skipped. Raise max_hosts to include them.",
                )
            else:
                self._pairs.extend(pairs)
                for value, output in hosts.items():
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
                f"IpToDomainsVirusTotal: {domain.domain} -> {ip.address} (passive DNS, observed {observed or 'unknown'})"
            )
        return results


InputType = IpToDomainsVirusTotal.InputType
OutputType = IpToDomainsVirusTotal.OutputType
