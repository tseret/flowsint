import os
from typing import Any, Dict, List, Optional, Tuple

import requests

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.ip import Ip
from flowsint_types.reputation_score import ReputationScore

KEY = "ABUSEIPDB_API_KEY"


@flowsint_enricher
class IpToAbuseIpdbEnricher(Enricher):
    """[AbuseIPDB] Get the abuse confidence score and report stats for an IP address."""

    InputType = Ip
    OutputType = ReputationScore

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": KEY,
                "type": "vaultSecret",
                "description": "The AbuseIPDB API key.",
                "required": True,
            }
        ]

    @classmethod
    def name(cls) -> str:
        return "ip_to_abuseipdb"

    @classmethod
    def category(cls) -> str:
        return "Ip"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        self._pairs: List[Tuple[Ip, ReputationScore]] = []
        results: List[OutputType] = []

        api_key = self.get_secret(KEY, os.getenv(KEY))
        if not api_key:
            Logger.error(self.sketch_id, {"message": f"[AbuseIPDB] {KEY} is required."})
            return results

        for ip in data:
            try:
                response = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": api_key, "Accept": "application/json"},
                    params={"ipAddress": ip.address, "maxAgeInDays": 90},
                    timeout=30,
                )
                if response.status_code != 200:
                    Logger.error(
                        self.sketch_id,
                        {
                            "message": f"[AbuseIPDB] HTTP {response.status_code} for {ip.address}"
                        },
                    )
                    continue
                info = response.json().get("data")
                if not info:
                    Logger.info(
                        self.sketch_id,
                        {"message": f"[AbuseIPDB] No data for {ip.address}"},
                    )
                    continue

                score = info["abuseConfidenceScore"]
                factors = [
                    f"usage: {info.get('usageType')}",
                    f"reports: {info.get('totalReports')}",
                ]
                if info.get("isTor"):
                    factors.append("tor")
                if info.get("isWhitelisted"):
                    factors.append("whitelisted")
                rep = ReputationScore(
                    entity_id=f"AbuseIPDB {ip.address}",
                    entity_type="IP address",
                    score=score,
                    score_type="abuse_confidence",
                    provider="AbuseIPDB",
                    last_updated=info.get("lastReportedAt"),
                    factors=factors,
                    source="AbuseIPDB",
                    risk_level="high"
                    if score >= 75
                    else "medium"
                    if score >= 25
                    else "low",
                )
                results.append(rep)
                self._pairs.append((ip, rep))
            except Exception as e:
                Logger.error(
                    self.sketch_id,
                    {
                        "message": f"[AbuseIPDB] Error checking {ip.address}: {type(e).__name__}"
                    },
                )
                continue

        return results

    def postprocess(
        self, results: List[OutputType], input_data: Optional[List[InputType]] = None
    ) -> List[OutputType]:
        if not self._graph_service:
            return results
        for ip, rep in self._pairs:
            self.create_node(ip)
            self.create_node(rep)
            self.create_relationship(ip, rep, "HAS_REPUTATION")
            self.log_graph_message(f"AbuseIPDB score {rep.score} for {ip.address}")
        return results


InputType = IpToAbuseIpdbEnricher.InputType
OutputType = IpToAbuseIpdbEnricher.OutputType
