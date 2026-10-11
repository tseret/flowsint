import os
from typing import Any, Dict, List

from tools.network.asnmap import AsnmapTool

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.asn import ASN
from flowsint_types.cidr import CIDR


@flowsint_enricher
class AsnToCidrsEnricher(Enricher):
    """[ASNMAP] Takes an ASN and returns its corresponding CIDRs."""

    # Define types as class attributes - base class handles schema generation automatically
    InputType = ASN
    OutputType = CIDR

    @classmethod
    def required_params(cls) -> bool:
        return True

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        """Declare required parameters for this enricher"""
        return [
            {
                "name": "PDCP_API_KEY",
                "type": "vaultSecret",
                "description": "The ProjectDiscovery Cloud Platform API key for asnmap.",
                "required": True,
            },
        ]

    @classmethod
    def name(cls) -> str:
        return "asn_to_cidrs"

    @classmethod
    def category(cls) -> str:
        return "Asn"

    @classmethod
    def key(cls) -> str:
        return "number"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        """Find CIDR from ASN using asnmap."""
        cidrs: List[OutputType] = []
        self._asn_to_cidrs_map = []  # Store mapping for postprocess
        asnmap = AsnmapTool()

        # Retrieve API key from vault or environment
        api_key = self.get_secret("PDCP_API_KEY", os.getenv("PDCP_API_KEY"))

        for asn in data:
            try:
                asn_cidrs = []
                # Use asnmap tool to get CIDR info, passing the API key
                # asnmap expects ASN with "AS" prefix
                cidr_data = asnmap.launch(
                    f"AS{asn.number}", type="asn", api_key=api_key
                )

                if cidr_data and "as_range" in cidr_data and cidr_data["as_range"]:
                    # Add all CIDRs for this ASN
                    for cidr_str in cidr_data["as_range"]:
                        try:
                            cidr = CIDR(network=cidr_str)
                            cidrs.append(cidr)
                            asn_cidrs.append(cidr)
                        except Exception as e:
                            Logger.error(
                                self.sketch_id,
                                {
                                    "message": f"Failed to parse CIDR {cidr_str}: {str(e)}"
                                },
                            )

                    Logger.info(
                        self.sketch_id,
                        {
                            "message": f"[ASNMAP] Found {len(asn_cidrs)} CIDRs for AS{asn.number}"
                        },
                    )
                else:
                    Logger.warn(
                        self.sketch_id,
                        {"message": f"[ASNMAP] No CIDRs found for AS{asn.number}"},
                    )

                if asn_cidrs:  # Only add to mapping if we found valid CIDRs
                    self._asn_to_cidrs_map.append((asn, asn_cidrs))

            except Exception as e:
                Logger.error(
                    self.sketch_id,
                    {"message": f"Error getting CIDRs for ASN {asn.number}: {e}"},
                )
                continue

        return cidrs

    def postprocess(
        self, results: List[OutputType], original_input: List[InputType]
    ) -> List[OutputType]:
        # Create Neo4j relationships between ASNs and their corresponding CIDRs (mapping built in scan)
        for asn, cidr_list in getattr(self, "_asn_to_cidrs_map", []):
            for cidr in cidr_list:
                if str(cidr.network) == "0.0.0.0/0":
                    continue  # Skip default CIDR for unknown ASN
                if self._graph_service:
                    self.create_node(asn)

                    self.create_node(cidr)

                    self.create_relationship(asn, cidr, "ANNOUNCES")

                    self.log_graph_message(
                        f"AS{asn.number} announces CIDR {cidr.network}"
                    )
        return results


# Make types available at module level for easy access
InputType = AsnToCidrsEnricher.InputType
OutputType = AsnToCidrsEnricher.OutputType
