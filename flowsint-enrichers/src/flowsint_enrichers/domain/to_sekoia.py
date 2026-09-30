import os
from typing import Any, Dict, List, Optional

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.ip.to_sekoia import search_sekoia
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.domain import Domain
from flowsint_types.malware import Malware


@flowsint_enricher
class DomainToSekoia(Enricher):
    """[Sekoia] Find malware associated with a domain in the Sekoia Intelligence Center."""

    InputType = Domain
    OutputType = Malware

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": "SEKOIA_API_KEY",
                "type": "vaultSecret",
                "description": "Sekoia.io API key with Intelligence Center read access.",
                "required": True,
            }
        ]

    @classmethod
    def name(cls) -> str:
        return "domain_to_sekoia"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        self._pairs: List[tuple[Domain, Malware]] = []
        api_key = self.get_secret("SEKOIA_API_KEY", os.getenv("SEKOIA_API_KEY"))
        if not api_key:
            Logger.error(
                self.sketch_id,
                {"message": "(DomainToSekoia) SEKOIA_API_KEY is not configured."},
            )
            return []

        results: List[OutputType] = []
        for domain in data:
            found = search_sekoia(self.sketch_id, api_key, "domain-name", domain.domain)
            if found is None:
                break
            for malware in found:
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
                f"(DomainToSekoia) {domain.domain} associated with {malware.name}"
            )

        return results


InputType = DomainToSekoia.InputType
OutputType = DomainToSekoia.OutputType
