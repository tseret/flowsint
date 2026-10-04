from typing import List, Optional

import requests

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.asn import ASN
from flowsint_types.ip import Ip

RIPESTAT = "https://stat.ripe.net/data"


@flowsint_enricher
class IpToAsnRipestatEnricher(Enricher):
    """[RIPEstat] Takes an IP address and returns the ASN announcing it (no API key)."""

    InputType = Ip
    OutputType = ASN

    @classmethod
    def name(cls) -> str:
        return "ip_to_asn_ripestat"

    @classmethod
    def category(cls) -> str:
        return "Ip"

    def _get_data(self, call: str, resource: str) -> Optional[dict]:
        response = requests.get(
            f"{RIPESTAT}/{call}/data.json",
            params={"resource": resource, "sourceapp": "flowsint"},
            timeout=30,
        )
        if response.status_code != 200:
            Logger.error(
                self.sketch_id,
                {
                    "message": f"[RIPEstat] {call} HTTP {response.status_code} for {resource}"
                },
            )
            return None
        return response.json().get("data") or {}

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        results: List[OutputType] = []
        self._pairs: List[tuple[Ip, ASN]] = []

        for ip in data:
            try:
                info = self._get_data("network-info", ip.address)
                if info is None:
                    continue
                numbers = info.get("asns") or []
                if not numbers:
                    Logger.info(
                        self.sketch_id,
                        {"message": f"[RIPEstat] No ASN found for {ip.address}"},
                    )
                    continue
                for number in numbers:
                    overview = self._get_data("as-overview", f"AS{number}") or {}
                    holder = overview.get("holder") or ""
                    # Nodes merge on nodeLabel ("AS54113 - <name>"). asnmap names
                    # the AS by its lowercased handle ("fastly"), so use the same
                    # handle from "FASTLY - Fastly, Inc." to land on one node.
                    # ponytail: only the common handle convention; odd handles still split nodes.
                    asn = ASN(
                        asn_str=f"AS{number}",
                        name=holder.split(" - ", 1)[0].lower() or None,
                        description=holder or None,
                    )
                    results.append(asn)
                    self._pairs.append((ip, asn))
                    Logger.info(
                        self.sketch_id,
                        {
                            "message": f"[RIPEstat] Found AS{asn.number} ({asn.name}) for IP {ip.address}"
                        },
                    )
            except Exception as e:
                Logger.error(
                    self.sketch_id,
                    {"message": f"[RIPEstat] Error for IP {ip.address}: {e}"},
                )
                continue

        return results

    def postprocess(
        self, results: List[OutputType], input_data: Optional[List[InputType]] = None
    ) -> List[OutputType]:
        if not self._graph_service:
            return results
        for ip, asn in self._pairs:
            self.create_node(ip)
            self.create_node(asn)
            self.create_relationship(ip, asn, "BELONGS_TO")
            self.log_graph_message(
                f"IP {ip.address} belongs to AS{asn.number} ({asn.name})"
            )
        return results


InputType = IpToAsnRipestatEnricher.InputType
OutputType = IpToAsnRipestatEnricher.OutputType
