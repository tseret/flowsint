import os
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.ip.to_threatfox import search_threatfox
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.domain import Domain
from flowsint_types.malware import Malware


@flowsint_enricher
class DomainToThreatFox(Enricher):
    """[ThreatFox] Find malware associated with a domain in abuse.ch ThreatFox IOCs."""

    InputType = Domain
    OutputType = Malware

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": "THREATFOX_API_KEY",
                "type": "vaultSecret",
                "description": "The abuse.ch Auth-Key for the ThreatFox API.",
                "required": True,
            }
        ]

    @classmethod
    def name(cls) -> str:
        return "domain_to_threatfox"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        self._pairs: List[tuple[Domain, Malware]] = []
        api_key = self.get_secret("THREATFOX_API_KEY", os.getenv("THREATFOX_API_KEY"))
        if not api_key:
            Logger.error(
                self.sketch_id,
                {"message": "(DomainToThreatFox) THREATFOX_API_KEY is not configured."},
            )
            return []

        results: List[OutputType] = []
        for domain in data:
            name = domain.domain.lower()

            # ioc is the domain itself or a URL on it; anything else is a substring hit.
            def matches(entry: Dict[str, Any], name: str = name) -> bool:
                ioc = str(entry.get("ioc", "")).lower()
                if entry.get("ioc_type") == "url":
                    return urlparse(ioc).hostname == name
                return ioc == name

            for malware in search_threatfox(
                self.sketch_id, api_key, domain.domain, matches
            ):
                results.append(malware)
                self._pairs.append((domain, malware))
        return results

    def postprocess(
        self, results: List[OutputType], input_data: Optional[List[InputType]] = None
    ) -> List[OutputType]:
        if not self._graph_service:
            return results

        for domain, malware in self._pairs:
            self.create_node(domain)
            self.create_node(malware)
            self.create_relationship(domain, malware, "ASSOCIATED_WITH")
            self.log_graph_message(
                f"(DomainToThreatFox) {domain.domain} associated with {malware.name}"
            )

        return results


InputType = DomainToThreatFox.InputType
OutputType = DomainToThreatFox.OutputType
