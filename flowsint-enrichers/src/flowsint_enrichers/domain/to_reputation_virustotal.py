from typing import Any, Dict, List, Optional

from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_enrichers.virustotal import KEY_SCHEMA, reputation, reputation_graph
from flowsint_types.domain import Domain
from flowsint_types.reputation_score import ReputationScore


@flowsint_enricher
class DomainToReputationVirusTotal(Enricher):
    """[VirusTotal] Read existing community reputation and engine verdict counts (no rescan)."""

    InputType = Domain
    OutputType = ReputationScore

    @classmethod
    def name(cls) -> str:
        return "domain_to_reputation_virustotal"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [KEY_SCHEMA.copy()]

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        return await reputation(self, data, "domains", "domain")

    def postprocess(
        self, results: List[OutputType], input_data: Optional[List[InputType]] = None
    ) -> List[OutputType]:
        return reputation_graph(self, results)


InputType = DomainToReputationVirusTotal.InputType
OutputType = DomainToReputationVirusTotal.OutputType
