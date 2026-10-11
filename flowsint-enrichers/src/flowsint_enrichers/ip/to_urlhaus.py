import os
from typing import Any, Dict, List, Optional

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.domain.to_urlhaus import search_urlhaus_host
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.ip import Ip
from flowsint_types.website import Website


@flowsint_enricher
class IpToUrlhaus(Enricher):
    """[URLhaus] Find malware distribution URLs hosted on an IP address in abuse.ch URLhaus."""

    InputType = Ip
    OutputType = Website

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": "THREATFOX_API_KEY",
                "type": "vaultSecret",
                "description": "The abuse.ch Auth-Key (shared by ThreatFox, MalwareBazaar and URLhaus).",
                "required": True,
            }
        ]

    @classmethod
    def name(cls) -> str:
        return "ip_to_urlhaus"

    @classmethod
    def category(cls) -> str:
        return "Ip"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        self._pairs: List[tuple[Ip, Website]] = []
        api_key = self.get_secret("THREATFOX_API_KEY", os.getenv("THREATFOX_API_KEY"))
        if not api_key:
            Logger.error(
                self.sketch_id,
                {"message": "(IpToUrlhaus) THREATFOX_API_KEY is not configured."},
            )
            return []

        results: List[OutputType] = []
        for ip in data:
            for website in search_urlhaus_host(self.sketch_id, api_key, ip.address):
                results.append(website)
                self._pairs.append((ip, website))
        return results

    def postprocess(
        self, results: List[OutputType], input_data: Optional[List[InputType]] = None
    ) -> List[OutputType]:
        if not self._graph_service:
            return results

        for ip, website in self._pairs:
            self.create_node(ip)
            self.create_node(website)
            self.create_relationship(ip, website, "HAS_WEBSITE")
            self.log_graph_message(f"(IpToUrlhaus) {ip.address} hosts {website.url}")

        return results


InputType = IpToUrlhaus.InputType
OutputType = IpToUrlhaus.OutputType
