import datetime
import os
from typing import Any, Dict, List, Optional, Tuple

import requests

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.domain import Domain
from flowsint_types.ip import Ip


@flowsint_enricher
class DomainToIpsVirusTotal(Enricher):
    """[VirusTotal] Get historical (passive DNS) IP resolutions of a domain."""

    InputType = Domain
    OutputType = Ip

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": "VT_API_KEY",
                "type": "vaultSecret",
                "description": "The VirusTotal API key.",
                "required": True,
            }
        ]

    @classmethod
    def name(cls) -> str:
        return "domain_to_ips_virustotal"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        results: List[OutputType] = []
        self._pairs: List[Tuple[Domain, Ip, str]] = []

        api_key = self.get_secret("VT_API_KEY", os.getenv("VT_API_KEY"))
        if not api_key:
            Logger.error(
                self.sketch_id,
                {"message": "(DomainToIpsVirusTotal) VT_API_KEY is not configured."},
            )
            return results

        seen: set[str] = set()
        for domain in data:
            try:
                # ponytail: first page only (limit=40); follow links.next to paginate.
                response = requests.get(
                    f"https://www.virustotal.com/api/v3/domains/{domain.domain}/resolutions",
                    params={"limit": 40},
                    headers={"x-apikey": api_key},
                    timeout=30,
                )
                if response.status_code == 404:
                    continue
                if response.status_code == 429:
                    Logger.error(
                        self.sketch_id,
                        {
                            "message": "(DomainToIpsVirusTotal) VirusTotal quota exceeded (429); stopping."
                        },
                    )
                    break
                if response.status_code != 200:
                    Logger.error(
                        self.sketch_id,
                        {
                            "message": f"(DomainToIpsVirusTotal) VirusTotal returned HTTP {response.status_code} for '{domain.domain}'."
                        },
                    )
                    continue

                last_seen: Dict[str, int] = {}
                for item in response.json().get("data", []):
                    attrs = item.get("attributes", {})
                    address = attrs.get("ip_address")
                    if address:
                        last_seen[address] = max(
                            last_seen.get(address, 0), int(attrs.get("date") or 0)
                        )

                for address, ts in last_seen.items():
                    ip = Ip(address=address)
                    date = (
                        datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
                        .date()
                        .isoformat()
                        if ts
                        else "unknown"
                    )
                    self._pairs.append((domain, ip, date))
                    if address not in seen:
                        seen.add(address)
                        results.append(ip)
            except Exception as e:
                Logger.error(
                    self.sketch_id,
                    {
                        "message": f"(DomainToIpsVirusTotal) Exception while querying {domain.domain}: {e}"
                    },
                )

        return results

    def postprocess(
        self, results: List[OutputType], input_data: Optional[List[InputType]] = None
    ) -> List[OutputType]:
        if not self._graph_service:
            return results

        for domain, ip, date in self._pairs:
            self.create_node(domain)
            self.create_node(ip)
            self.create_relationship(domain, ip, "PASSIVE_DNS_RESOLVED_TO")
            self.log_graph_message(
                f"(DomainToIpsVirusTotal) {domain.domain} -> {ip.address} (passive DNS, last seen {date})"
            )

        return results


InputType = DomainToIpsVirusTotal.InputType
OutputType = DomainToIpsVirusTotal.OutputType
