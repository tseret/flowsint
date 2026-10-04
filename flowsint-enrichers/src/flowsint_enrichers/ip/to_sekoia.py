import os
from typing import Any, Dict, List, Optional

import requests

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.ip import Ip
from flowsint_types.malware import Malware

SEKOIA_CONTEXT_URL = "https://api.sekoia.io/v2/inthreat/indicators/context"


def search_sekoia(
    sketch_id: Optional[str], api_key: str, stix_type: str, value: str
) -> Optional[List[Malware]]:
    """Look up an IOC in the Sekoia Intelligence Center and return its malware.

    Only malware targeted by an `indicates` relationship from a non-revoked
    indicator in the context bundle is returned. Returns None on HTTP 429 so
    callers stop querying.
    """
    try:
        response = requests.get(
            SEKOIA_CONTEXT_URL,
            params={"type": stix_type, "value": value},
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=30,
        )
        if response.status_code == 429:
            Logger.error(
                sketch_id, {"message": "(Sekoia) Rate limit reached (429); stopping."}
            )
            return None
        if response.status_code != 200:
            Logger.error(
                sketch_id,
                {
                    "message": f"(Sekoia) HTTP {response.status_code} for '{value}': {response.text[:200]}"
                },
            )
            return []
        bundles = response.json().get("items") or []
    except Exception as e:
        Logger.error(sketch_id, {"message": f"(Sekoia) Error querying '{value}': {e}"})
        return []

    by_name: Dict[str, Malware] = {}
    for bundle in bundles:
        items = bundle.get("objects") or []
        objects = {o.get("id"): o for o in items}
        for rel in items:
            if rel.get("type") != "relationship":
                continue
            if rel.get("relationship_type") != "indicates":
                continue
            indicator = objects.get(rel.get("source_ref"))
            target = objects.get(rel.get("target_ref"))
            if not indicator or indicator.get("type") != "indicator" or not target:
                continue
            if indicator.get("revoked"):
                continue
            name = target.get("name")
            if not name:
                continue
            if target.get("type") != "malware":
                # ponytail: no flowsint type for infrastructure/intrusion-set/actor; log only.
                Logger.info(
                    sketch_id,
                    {
                        "message": f"(Sekoia) '{value}' indicates {target.get('type')} '{name}'."
                    },
                )
                continue
            pattern, first = indicator.get("pattern"), indicator.get("valid_from")
            malware = by_name.get(name)
            if malware is None:
                by_name[name] = Malware(
                    name=name,
                    type=",".join(target.get("malware_types") or []) or None,
                    description=target.get("description"),
                    first_seen=first,
                    source="Sekoia",
                    indicators=[pattern] if pattern else None,
                )
                continue
            # ISO-8601 UTC timestamps: string order is time order.
            malware.first_seen = min(
                filter(None, [malware.first_seen, first]), default=None
            )
            if pattern and pattern not in (malware.indicators or []):
                malware.indicators = [*(malware.indicators or []), pattern]

    if not by_name:
        Logger.info(sketch_id, {"message": f"(Sekoia) No malware for '{value}'."})
    return list(by_name.values())


@flowsint_enricher
class IpToSekoia(Enricher):
    """[Sekoia] Find malware associated with an IP address in the Sekoia Intelligence Center."""

    InputType = Ip
    OutputType = Malware

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": "SEKOIA_API_KEY",
                "type": "vaultSecret",
                "description": "Sekoia.io API key with Intelligence Center read access.",
                "required": True,
            }
        ]

    @classmethod
    def name(cls) -> str:
        return "ip_to_sekoia"

    @classmethod
    def category(cls) -> str:
        return "Ip"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        self._pairs: List[tuple[Ip, Malware]] = []
        api_key = self.get_secret("SEKOIA_API_KEY", os.getenv("SEKOIA_API_KEY"))
        if not api_key:
            Logger.error(
                self.sketch_id,
                {"message": "(IpToSekoia) SEKOIA_API_KEY is not configured."},
            )
            return []

        results: List[OutputType] = []
        for ip in data:
            address = str(ip.address)
            stix_type = "ipv6-addr" if ":" in address else "ipv4-addr"
            found = search_sekoia(self.sketch_id, api_key, stix_type, address)
            if found is None:
                break
            for malware in found:
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
                f"(IpToSekoia) {ip.address} associated with {malware.name}"
            )

        return results


InputType = IpToSekoia.InputType
OutputType = IpToSekoia.OutputType
