from typing import List, Optional

import requests

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.domain import Domain
from flowsint_types.ip import Ip
from flowsint_types.port import Port


@flowsint_enricher
class IpToInternetDbEnricher(Enricher):
    """[Shodan InternetDB] Lists open ports, hostnames, tags and known CVEs for an IP (no API key)."""

    InputType = Ip
    OutputType = Port

    @classmethod
    def name(cls) -> str:
        return "ip_to_internetdb"

    @classmethod
    def category(cls) -> str:
        return "Ip"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        results: List[OutputType] = []
        self._ports: List[tuple[Ip, Port]] = []
        self._hostnames: List[tuple[Ip, Domain]] = []
        self._notes: List[str] = []

        for ip in data:
            try:
                response = requests.get(
                    f"https://internetdb.shodan.io/{ip.address}", timeout=30
                )
                if response.status_code == 404:
                    Logger.info(
                        self.sketch_id,
                        {"message": f"[InternetDB] No information for {ip.address}"},
                    )
                    continue
                if response.status_code != 200:
                    Logger.error(
                        self.sketch_id,
                        {
                            "message": f"[InternetDB] HTTP {response.status_code} for {ip.address}"
                        },
                    )
                    continue
                body = response.json()
                for number in body.get("ports") or []:
                    port = Port(number=number, protocol="tcp", state="open")
                    results.append(port)
                    self._ports.append((ip, port))
                for hostname in body.get("hostnames") or []:
                    try:
                        self._hostnames.append((ip, Domain(domain=hostname)))
                    except Exception as e:
                        Logger.error(
                            self.sketch_id,
                            {"message": f"[InternetDB] Bad hostname {hostname}: {e}"},
                        )
                for key in ("vulns", "tags"):
                    if body.get(key):
                        self._notes.append(
                            f"{ip.address} {key}: {', '.join(body[key])}"
                        )
                Logger.info(
                    self.sketch_id,
                    {
                        "message": f"[InternetDB] {ip.address}: {len(body.get('ports') or [])} ports, {len(body.get('hostnames') or [])} hostnames"
                    },
                )
            except Exception as e:
                Logger.error(
                    self.sketch_id,
                    {"message": f"[InternetDB] Error for {ip.address}: {e}"},
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
            self.log_graph_message(f"Port {port.number}/tcp open on {ip.address}")
        for ip, domain in self._hostnames:
            self.create_node(ip)
            self.create_node(domain)
            self.create_relationship(ip, domain, "REVERSE_RESOLVES_TO")
            self.log_graph_message(f"Hostname {domain.domain} for IP {ip.address}")
        for note in self._notes:
            self.log_graph_message(f"[InternetDB] {note}")
        return results


InputType = IpToInternetDbEnricher.InputType
OutputType = IpToInternetDbEnricher.OutputType
