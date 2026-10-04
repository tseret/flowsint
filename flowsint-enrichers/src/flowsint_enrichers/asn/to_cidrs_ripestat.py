from typing import List, Optional

import requests

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.asn import ASN
from flowsint_types.cidr import CIDR


@flowsint_enricher
class AsnToCidrsRipestatEnricher(Enricher):
    """[RIPEstat] Takes an ASN and returns the prefixes it announces (no API key)."""

    InputType = ASN
    OutputType = CIDR

    @classmethod
    def name(cls) -> str:
        return "asn_to_cidrs_ripestat"

    @classmethod
    def category(cls) -> str:
        return "Asn"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        results: List[OutputType] = []
        self._pairs: List[tuple[ASN, CIDR]] = []

        for asn in data:
            try:
                response = requests.get(
                    "https://stat.ripe.net/data/announced-prefixes/data.json",
                    params={"resource": f"AS{asn.number}", "sourceapp": "flowsint"},
                    timeout=30,
                )
                if response.status_code != 200:
                    Logger.error(
                        self.sketch_id,
                        {
                            "message": f"[RIPEstat] HTTP {response.status_code} for AS{asn.number}"
                        },
                    )
                    continue
                prefixes = (response.json().get("data") or {}).get("prefixes") or []
                found = 0
                for item in prefixes:
                    try:
                        cidr = CIDR(network=item["prefix"])
                    except Exception as e:
                        Logger.error(
                            self.sketch_id,
                            {"message": f"Failed to parse CIDR {item}: {e}"},
                        )
                        continue
                    results.append(cidr)
                    self._pairs.append((asn, cidr))
                    found += 1
                Logger.info(
                    self.sketch_id,
                    {"message": f"[RIPEstat] Found {found} CIDRs for AS{asn.number}"},
                )
            except Exception as e:
                Logger.error(
                    self.sketch_id,
                    {"message": f"[RIPEstat] Error for AS{asn.number}: {e}"},
                )
                continue

        return results

    def postprocess(
        self, results: List[OutputType], input_data: Optional[List[InputType]] = None
    ) -> List[OutputType]:
        if not self._graph_service:
            return results
        for asn, cidr in self._pairs:
            self.create_node(asn)
            self.create_node(cidr)
            self.create_relationship(asn, cidr, "ANNOUNCES")
            self.log_graph_message(f"AS{asn.number} announces CIDR {cidr.network}")
        return results


InputType = AsnToCidrsRipestatEnricher.InputType
OutputType = AsnToCidrsRipestatEnricher.OutputType
