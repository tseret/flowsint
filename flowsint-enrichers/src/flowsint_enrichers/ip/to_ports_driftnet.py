import os
from typing import Any, Dict, List, Optional, Tuple

import requests

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.ip import Ip
from flowsint_types.port import Port

KEY = "DRIFTNET_API_KEY"
PORTS_URL = "https://api.driftnet.io/v1/scan/ports"


@flowsint_enricher
class IpToPortsDriftnetEnricher(Enricher):
    """[Driftnet] Get open TCP ports observed on an IP address by Driftnet's internet scans."""

    InputType = Ip
    OutputType = Port

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": KEY,
                "type": "vaultSecret",
                "description": "The Driftnet API token (free community account at driftnet.io).",
                "required": True,
            }
        ]

    @classmethod
    def name(cls) -> str:
        return "ip_to_ports_driftnet"

    @classmethod
    def category(cls) -> str:
        return "Ip"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        self._ports: List[Tuple[Ip, Port]] = []
        results: List[OutputType] = []

        api_key = self.get_secret(KEY, os.getenv(KEY))
        if not api_key:
            Logger.error(self.sketch_id, {"message": f"[Driftnet] {KEY} is required."})
            return results

        for ip in data:
            try:
                response = requests.get(
                    PORTS_URL,
                    params={"ip": ip.address},
                    headers={"Authorization": f"Bearer {api_key}"},
                    timeout=30,
                )
                if response.status_code in (403, 429):
                    # Quota and rate limits are per token: every later call fails too.
                    Logger.error(
                        self.sketch_id,
                        {
                            "message": f"[Driftnet] HTTP {response.status_code}: {response.text[:200]}; stopping."
                        },
                    )
                    break
                if response.status_code != 200:
                    Logger.error(
                        self.sketch_id,
                        {
                            "message": f"[Driftnet] HTTP {response.status_code} for {ip.address}"
                        },
                    )
                    continue
                payload = response.json()
            except Exception as e:
                Logger.error(
                    self.sketch_id,
                    {
                        "message": f"[Driftnet] Error looking up {ip.address}: {type(e).__name__}"
                    },
                )
                continue

            if payload.get("honeypot"):
                Logger.warn(
                    self.sketch_id,
                    {
                        "message": f"[Driftnet] {ip.address} is flagged as a honeypot; ports may be fake."
                    },
                )
            ports = [p for p in (payload.get("values") or {}) if p.isdigit()]
            if not ports:
                Logger.info(
                    self.sketch_id,
                    {"message": f"[Driftnet] No open ports for {ip.address}"},
                )
            for number in ports:
                port = Port(number=int(number), protocol="tcp", state="open")
                results.append(port)
                self._ports.append((ip, port))

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
            self.log_graph_message(f"Port {port.number}/tcp on {ip.address}")
        return results


InputType = IpToPortsDriftnetEnricher.InputType
OutputType = IpToPortsDriftnetEnricher.OutputType
