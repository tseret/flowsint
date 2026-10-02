import os
from typing import Any, Dict, List, Optional, Tuple

import requests

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_core.core.vault import VaultProtocol
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.ip import Ip
from flowsint_types.port import Port

KEY = "MODAT_API_KEY"
HOST_URL = "https://api.magnify.modat.io/host/{ip}/v1"


@flowsint_enricher
class IpToPortsModatEnricher(Enricher):
    """[Modat] Get observed TCP and UDP ports and services for an IP address."""

    InputType = Ip
    OutputType = Port

    def __init__(
        self,
        sketch_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        vault: Optional[VaultProtocol] = None,
        params: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            sketch_id=sketch_id,
            scan_id=scan_id,
            params_schema=self.get_params_schema(),
            vault=vault,
            params=params,
        )

    @classmethod
    def name(cls) -> str:
        return "ip_to_ports_modat"

    @classmethod
    def category(cls) -> str:
        return "Ip"

    @classmethod
    def key(cls) -> str:
        return "address"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        self._ports: List[Tuple[Ip, Port]] = []
        results: List[OutputType] = []
        api_key = (self.vault.get_secret(KEY) if self.vault else None) or os.getenv(KEY)
        if not api_key:
            Logger.error(self.sketch_id, {"message": f"[Modat] {KEY} is required."})
            return results

        for ip in data:
            try:
                response = requests.get(
                    HOST_URL.format(ip=ip.address),
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "User-Agent": "Flowsint-Modat-Connector",
                    },
                    timeout=30,
                )
                if response.status_code in (401, 403, 429):
                    Logger.error(
                        self.sketch_id,
                        {"message": f"[Modat] HTTP {response.status_code}; stopping."},
                    )
                    break
                if response.status_code != 200:
                    Logger.error(
                        self.sketch_id,
                        {
                            "message": f"[Modat] HTTP {response.status_code} for {ip.address}"
                        },
                    )
                    continue
                services = response.json()["data"]["services"]
            except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
                Logger.error(
                    self.sketch_id,
                    {
                        "message": f"[Modat] Error looking up {ip.address}: {type(exc).__name__}"
                    },
                )
                continue

            seen = set()
            for service in services:
                transport = service.get("transport")
                if transport not in ("tcp", "udp"):
                    continue
                name = service.get("protocol")
                for number in service.get("ports") or []:
                    if (
                        not isinstance(number, int)
                        or isinstance(number, bool)
                        or not 1 <= number <= 65535
                        or (number, transport) in seen
                    ):
                        continue
                    seen.add((number, transport))
                    port = Port(
                        host=ip.address,
                        number=number,
                        protocol=transport.upper(),
                        state="open",
                        service=name if name and name != "unknown" else None,
                    )
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
            self.log_graph_message(
                f"Port {port.number}/{port.protocol} on {ip.address}"
            )
        return results


InputType = IpToPortsModatEnricher.InputType
OutputType = IpToPortsModatEnricher.OutputType
