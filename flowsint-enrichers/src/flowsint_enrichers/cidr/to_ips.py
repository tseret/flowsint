from ipaddress import ip_network
from typing import Any, Dict, List

from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.cidr import CIDR
from flowsint_types.ip import Ip


@flowsint_enricher
class CidrToIpsEnricher(Enricher):
    """Expand a CIDR locally, after previewing its size against a strict run budget."""

    InputType = CIDR
    OutputType = Ip

    @classmethod
    def name(cls) -> str:
        return "cidr_to_ips"

    @classmethod
    def category(cls) -> str:
        return "Cidr"

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": "max_results",
                "type": "number",
                "required": False,
                "default": "256",
                "description": "Maximum addresses across all inputs (1–4096). Oversized expansions are rejected before enumeration.",
            },
            {
                "name": "preview_only",
                "type": "select",
                "required": False,
                "default": "false",
                "description": "Report the address count without adding nodes.",
                "options": [
                    {"label": "Preview", "value": "true"},
                    {"label": "Expand", "value": "false"},
                ],
            },
        ]

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        self._cidr_to_ips_map = []
        try:
            limit = int(self.params.get("max_results", "256"))
            if not 1 <= limit <= 4096:
                raise ValueError
            preview = self.params.get("preview_only", "false")
            if preview not in ("true", "false"):
                raise ValueError
            networks = [(cidr, ip_network(str(cidr.network))) for cidr in data]
        except (ValueError, TypeError):
            self.report_issue(
                "failed",
                "Use a valid CIDR, max_results between 1 and 4096, and preview_only true or false.",
            )
            return []
        total = sum(network.num_addresses for _, network in networks)
        if preview == "true" or total > limit:
            self.report_issue(
                "partial",
                f"Expansion preview: {total} addresses across {len(networks)} ranges; budget {limit}. No addresses added. Narrow the ranges or raise the budget (maximum 4096).",
            )
            return []
        results = []
        for cidr, network in networks:
            ips = [Ip(address=str(address)) for address in network]
            self._cidr_to_ips_map.append((cidr, ips))
            results.extend(ips)
        return results

    def postprocess(
        self, results: List[OutputType], original_input: List[InputType]
    ) -> List[OutputType]:
        if self._graph_service:
            for cidr, ips in self._cidr_to_ips_map:
                self.create_node(cidr)
                for ip in ips:
                    self.create_node(ip)
                    self.create_relationship(
                        cidr, ip, "CONTAINS", provider="Local calculation"
                    )
        return results


InputType = CidrToIpsEnricher.InputType
OutputType = CidrToIpsEnricher.OutputType
