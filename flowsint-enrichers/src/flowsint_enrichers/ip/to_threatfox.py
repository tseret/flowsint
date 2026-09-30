import os
from typing import Any, Callable, Dict, List, Optional

import requests

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.ip import Ip
from flowsint_types.malware import Malware

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"


def search_threatfox(
    sketch_id: Optional[str],
    api_key: str,
    term: str,
    matches: Callable[[Dict[str, Any]], bool],
) -> List[Malware]:
    """Search ThreatFox for `term` and return one Malware per family.

    ThreatFox does a wildcard search by default (needed so that "1.2.3.4"
    finds "1.2.3.4:443"), so `matches` drops the substring false positives.
    Never raises; failures are logged and yield [].
    """
    try:
        response = requests.post(
            THREATFOX_URL,
            headers={"Auth-Key": api_key},
            json={"query": "search_ioc", "search_term": term},
            timeout=30,
        )
        if response.status_code != 200:
            Logger.error(
                sketch_id,
                {
                    "message": f"(ThreatFox) HTTP {response.status_code} for '{term}': {response.text}"
                },
            )
            return []
        payload = response.json()
    except Exception as e:
        Logger.error(
            sketch_id, {"message": f"(ThreatFox) Request for '{term}' failed: {e}"}
        )
        return []

    status = payload.get("query_status")
    if status == "no_result":
        Logger.info(sketch_id, {"message": f"(ThreatFox) No result for '{term}'."})
        return []
    if status != "ok":
        Logger.error(
            sketch_id, {"message": f"(ThreatFox) Query status '{status}' for '{term}'."}
        )
        return []

    by_name: Dict[str, Malware] = {}
    for entry in payload.get("data") or []:
        if not matches(entry):
            continue
        name = entry.get("malware_printable") or entry.get("malware")
        if not name:
            continue
        first, last = entry.get("first_seen"), entry.get("last_seen")
        malware = by_name.get(name)
        if malware is None:
            by_name[name] = Malware(
                name=name,
                family=entry.get("malware"),
                type=entry.get("threat_type"),
                first_seen=first,
                last_seen=last,
                source="ThreatFox",
                indicators=[entry["ioc"]],
                description=entry.get("reference"),
            )
            continue
        # ThreatFox timestamps are "YYYY-MM-DD HH:MM:SS UTC": string order is time order.
        malware.first_seen = min(
            filter(None, [malware.first_seen, first]), default=None
        )
        malware.last_seen = max(filter(None, [malware.last_seen, last]), default=None)
        if entry["ioc"] not in (malware.indicators or []):
            malware.indicators = [*(malware.indicators or []), entry["ioc"]]
        malware.description = malware.description or entry.get("reference")
    return list(by_name.values())


@flowsint_enricher
class IpToThreatFox(Enricher):
    """[ThreatFox] Find malware associated with an IP address in abuse.ch ThreatFox IOCs."""

    InputType = Ip
    OutputType = Malware

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": "THREATFOX_API_KEY",
                "type": "vaultSecret",
                "description": "The abuse.ch Auth-Key for the ThreatFox API.",
                "required": True,
            }
        ]

    @classmethod
    def name(cls) -> str:
        return "ip_to_threatfox"

    @classmethod
    def category(cls) -> str:
        return "Ip"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        self._pairs: List[tuple[Ip, Malware]] = []
        api_key = self.get_secret("THREATFOX_API_KEY", os.getenv("THREATFOX_API_KEY"))
        if not api_key:
            Logger.error(
                self.sketch_id,
                {"message": "(IpToThreatFox) THREATFOX_API_KEY is not configured."},
            )
            return []

        results: List[OutputType] = []
        for ip in data:
            # ioc is the bare IP or "IP:port" ("[v6]:port"); anything else is a substring hit.
            def matches(entry: Dict[str, Any], ip: Ip = ip) -> bool:
                ioc = str(entry.get("ioc", ""))
                return (
                    ioc == ip.address or ioc.rsplit(":", 1)[0].strip("[]") == ip.address
                )

            for malware in search_threatfox(
                self.sketch_id, api_key, ip.address, matches
            ):
                results.append(malware)
                self._pairs.append((ip, malware))
        return results

    def postprocess(
        self, results: List[OutputType], input_data: Optional[List[InputType]] = None
    ) -> List[OutputType]:
        if not self._graph_service:
            return results

        for ip, malware in self._pairs:
            self.create_node(ip)
            self.create_node(malware)
            self.create_relationship(ip, malware, "ASSOCIATED_WITH")
            self.log_graph_message(
                f"(IpToThreatFox) {ip.address} associated with {malware.name}"
            )

        return results


InputType = IpToThreatFox.InputType
OutputType = IpToThreatFox.OutputType
