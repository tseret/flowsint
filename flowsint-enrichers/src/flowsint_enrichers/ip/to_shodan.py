import os
from typing import Any, Dict, List, Optional, Tuple

import requests

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.domain import Domain
from flowsint_types.ip import Ip
from flowsint_types.port import Port

KEY = "SHODAN_API_KEY"


@flowsint_enricher
class IpToPortsShodanEnricher(Enricher):
    """[Shodan] Get open ports, services and hostnames for an IP address from Shodan's index (no active scan)."""

    InputType = Ip
    OutputType = Port

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": KEY,
                "type": "vaultSecret",
                "description": "The Shodan API key.",
                "required": True,
            }
        ]

    @classmethod
    def name(cls) -> str:
        return "ip_to_ports_shodan"

    @classmethod
    def category(cls) -> str:
        return "Ip"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        self._ports: List[Tuple[Ip, Port]] = []
        self._domains: List[Tuple[Ip, Domain]] = []
        results: List[OutputType] = []

        api_key = self.get_secret(KEY, os.getenv(KEY))
        if not api_key:
            Logger.error(self.sketch_id, {"message": f"[Shodan] {KEY} is required."})
            return results

        for ip in data:
            try:
                # the key travels as a query param: never log the URL
                response = requests.get(
                    f"https://api.shodan.io/shodan/host/{ip.address}",
                    params={"key": api_key},
                    timeout=30,
                )
                if response.status_code == 404:
                    Logger.info(
                        self.sketch_id,
                        {"message": f"[Shodan] No information for {ip.address}"},
                    )
                    continue
                if response.status_code != 200:
                    Logger.error(
                        self.sketch_id,
                        {
                            "message": f"[Shodan] HTTP {response.status_code} for {ip.address}"
                        },
                    )
                    continue
                payload = response.json()

                seen = set()
                for item in payload.get("data") or []:
                    key = (item["port"], item.get("transport"))
                    if key in seen:
                        continue
                    seen.add(key)
                    service = " ".join(
                        p for p in (item.get("product"), item.get("version")) if p
                    )
                    port = Port(
                        number=item["port"],
                        protocol=item.get("transport"),
                        state="open",
                        service=service or None,
                        banner=(item.get("data") or "")[:500] or None,
                    )
                    results.append(port)
                    self._ports.append((ip, port))

                for hostname in dict.fromkeys(payload.get("hostnames") or []):
                    self._domains.append((ip, Domain(domain=hostname)))
            except Exception as e:
                Logger.error(
                    self.sketch_id,
                    {
                        "message": f"[Shodan] Error looking up {ip.address}: {type(e).__name__}"
                    },
                )
                continue

        return results

    def postprocess(
        self, results: List[OutputType], input_data: Optional[List[InputType]] = None
    ) -> List[OutputType]:
        if not self._graph_service:
            return results
        for ip, port in self._ports:
            self.create_node(ip)
            self.create_node(port)
            self.create_relationship(ip, port, "HAS_PORT")
            self.log_graph_message(
                f"Port {port.number}/{port.protocol} on {ip.address}"
            )
        for ip, domain in self._domains:
            self.create_node(ip)
            self.create_node(domain)
            self.create_relationship(ip, domain, "REVERSE_RESOLVES_TO")
            self.log_graph_message(f"Hostname {domain.domain} for {ip.address}")
        return results


InputType = IpToPortsShodanEnricher.InputType
OutputType = IpToPortsShodanEnricher.OutputType
