from datetime import datetime, timedelta, timezone
from ipaddress import ip_network
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.passive_http import indexed_json
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.asn import ASN
from flowsint_types.cidr import CIDR
from flowsint_types.routing_observation import RoutingObservation


@flowsint_enricher
class CidrToRoutingHistoryRipestat(Enricher):
    """[RIPEstat] Compare historical prefix origins with dated RIS announcement intervals."""

    InputType = CIDR
    OutputType = RoutingObservation

    @classmethod
    def name(cls) -> str:
        return "cidr_to_routing_history_ripestat"

    @classmethod
    def category(cls) -> str:
        return "Cidr"

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": name,
                "type": "string",
                "required": False,
                "description": description,
            }
            for name, description in [
                (
                    "starttime",
                    "ISO8601 interval start (default: 30 days ago). Maximum interval 366 days.",
                ),
                ("endtime", "ISO8601 interval end (default: now)."),
            ]
        ]

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        self._pairs = []
        results: list[RoutingObservation] = []
        try:
            end = (
                datetime.fromisoformat(self.params["endtime"])
                if self.params.get("endtime")
                else datetime.now(timezone.utc)
            )
            start = (
                datetime.fromisoformat(self.params["starttime"])
                if self.params.get("starttime")
                else end - timedelta(days=30)
            )
            start = (
                start.replace(tzinfo=timezone.utc) if start.tzinfo is None else start
            )
            end = end.replace(tzinfo=timezone.utc) if end.tzinfo is None else end
            if not timedelta(0) < end - start <= timedelta(days=366):
                raise ValueError
        except (ValueError, TypeError):
            self.report_issue(
                "failed",
                "Supply ISO8601 dates with start before end and a maximum interval of 366 days.",
            )
            return results
        for cidr in data[:10]:
            params = {
                "resource": str(cidr.network),
                "starttime": start.isoformat(),
                "endtime": end.isoformat(),
                "max_rows": "100",
                "normalise_visibility": "true",
                "sourceapp": "flowsint",
            }
            url = "https://stat.ripe.net/data/routing-history/data.json"
            payload = indexed_json(self, url, params)
            if payload is None:
                break
            try:
                origins = payload["data"]["by_origin"]
                for origin in origins:
                    asn = ASN(asn_str=str(origin["origin"]))
                    for prefix in origin["prefixes"]:
                        network = str(ip_network(prefix["prefix"]))
                        for period in prefix["timelines"]:
                            if len(results) >= 100:
                                self.report_issue(
                                    "partial",
                                    "Routing history truncated at 100 intervals per run.",
                                )
                                return results
                            first, last = period["starttime"], period["endtime"]
                            first_date = datetime.fromisoformat(first)
                            last_date = datetime.fromisoformat(last)
                            first_date = (
                                first_date.replace(tzinfo=timezone.utc)
                                if first_date.tzinfo is None
                                else first_date
                            )
                            last_date = (
                                last_date.replace(tzinfo=timezone.utc)
                                if last_date.tzinfo is None
                                else last_date
                            )
                            if first_date > last_date:
                                raise ValueError("Invalid routing interval")
                            observation = RoutingObservation(
                                reference=f"{network} {asn.asn_str} {first}–{last}",
                                prefix=network,
                                origin_asn=asn.asn_str,
                                start_time=first,
                                end_time=last,
                                visibility=period.get("visibility"),
                                source=f"{url}?{urlencode(params)}",
                            )
                            results.append(observation)
                            self._pairs.append((cidr, observation, asn))
                # RIPE's max_rows is a soft limit and does not expose a completeness flag.
                if sum(len(origin["prefixes"]) for origin in origins) >= 100:
                    self.report_issue(
                        "partial",
                        "RIPEstat reached its route limit; additional origins may be omitted. Narrow the interval.",
                    )
            except (KeyError, TypeError, ValueError):
                self.report_issue(
                    "partial", "RIPEstat returned malformed routing history."
                )
        if len(data) > 10:
            self.report_issue("partial", "Routing history limited to 10 input ranges.")
        return results

    def postprocess(
        self, results: List[OutputType], input_data: Optional[List[InputType]] = None
    ) -> List[OutputType]:
        if self._graph_service:
            for cidr, observation, asn in self._pairs:
                for node in (cidr, observation, asn):
                    self.create_node(node)
                for source, target, relation in [
                    (cidr, observation, "HAS_ROUTING_OBSERVATION"),
                    (observation, asn, "ANNOUNCED_BY"),
                ]:
                    self.create_relationship(
                        source,
                        target,
                        relation,
                        observed_at=observation.start_time,
                        source_ref=observation.source,
                        provider="RIPEstat",
                    )
        return results
