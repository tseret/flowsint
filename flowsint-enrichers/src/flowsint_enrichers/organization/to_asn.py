import os
from typing import Any, Dict, List, Optional

from tools.network.asnmap import AsnmapTool

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.asn import ASN
from flowsint_types.organization import Organization


@flowsint_enricher
class OrgToAsnEnricher(Enricher):
    """Takes an organization and returns its corresponding ASN."""

    # Define types as class attributes - base class handles schema generation automatically
    InputType = Organization
    OutputType = ASN

    def __init__(
        self,
        sketch_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        vault=None,
        params: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            sketch_id=sketch_id,
            scan_id=scan_id,
            params_schema=self.get_params_schema(),
            vault=vault,
            params=params,
        )
        self.org_asn_mapping: List[tuple[Organization, ASN]] = []

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
        return "org_to_asn"

    @classmethod
    def category(cls) -> str:
        return "Organization"

    @classmethod
    def key(cls) -> str:
        return "name"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        """Find ASN information for organizations using asnmap."""
        results: List[OutputType] = []
        self.org_asn_mapping = []
        asnmap = AsnmapTool()

        # Retrieve API key from vault or environment
        api_key = self.get_secret("PDCP_API_KEY", os.getenv("PDCP_API_KEY"))

        for org in data:
            try:
                # Use asnmap tool to get ASN info, passing the API key
                asn_data = asnmap.launch(org.name, type="org", api_key=api_key)
                if asn_data and "as_number" in asn_data:
                    # asn_str is required; the validator normalizes "as16276" and derives number
                    asn = ASN(
                        asn_str=asn_data["as_number"],
                        name=asn_data.get("as_name", ""),
                        country=asn_data.get("as_country", ""),
                        description=asn_data.get("as_name", ""),
                    )
                    results.append(asn)
                    self.org_asn_mapping.append((org, asn))
                    Logger.info(
                        self.sketch_id,
                        {
                            "message": f"[ASNMAP] Found AS{asn.number} ({asn.name}) for organization {org.name}"
                        },
                    )
                else:
                    Logger.warn(
                        self.sketch_id,
                        {
                            "message": f"[ASNMAP] No ASN data or missing 'as_number' field for organization {org.name}. Data keys: {list(asn_data.keys()) if asn_data else 'None'}"
                        },
                    )
            except Exception as e:
                Logger.error(
                    self.sketch_id,
                    {"message": f"Error getting ASN for organization {org.name}: {e}"},
                )
                continue

        return results

    def postprocess(
        self, results: List[OutputType], original_input: List[InputType]
    ) -> List[OutputType]:
        # Create Neo4j relationships between organizations and their corresponding ASNs.
        # Pairs come from scan: zipping inputs with results misaligns when a lookup fails.
        for input_org, result_asn in self.org_asn_mapping:
            # Skip if no valid ASN was found
            if result_asn.number == 0:
                continue
            if self._graph_service:
                # Create organization node
                self.create_node(input_org)
                # Create ASN node
                self.create_node(result_asn)
                # Create relationship
                self.create_relationship(input_org, result_asn, "BELONGS_TO")
                self.log_graph_message(
                    f"Found for {input_org.name} -> ASN {result_asn.number}"
                )

        return results


# Make types available at module level for easy access
InputType = OrgToAsnEnricher.InputType
OutputType = OrgToAsnEnricher.OutputType
