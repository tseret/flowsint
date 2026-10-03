import os
from typing import Any, Dict, List, Optional

import requests

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.domain import Domain
from flowsint_types.website import Website

URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/"


def query_urlhaus(
    sketch_id: Optional[str], api_key: str, endpoint: str, data: Dict[str, str]
) -> Optional[Dict[str, Any]]:
    """POST to URLhaus `endpoint` ("host", "url"); the payload when ok, else None.

    Never raises; failures are logged ("no_results" at info level).
    """
    term = next(iter(data.values()))
    try:
        response = requests.post(
            f"{URLHAUS_URL}{endpoint}/",
            headers={"Auth-Key": api_key},
            data=data,
            timeout=30,
        )
        if response.status_code != 200:
            Logger.error(
                sketch_id,
                {"message": f"(URLhaus) HTTP {response.status_code} for '{term}'."},
            )
            return None
        payload: Dict[str, Any] = response.json()
        status = payload.get("query_status")
    except Exception as e:
        Logger.error(
            sketch_id, {"message": f"(URLhaus) Request for '{term}' failed: {e}"}
        )
        return None

    if status == "no_results":
        Logger.info(sketch_id, {"message": f"(URLhaus) No result for '{term}'."})
        return None
    if status != "ok":
        Logger.error(
            sketch_id,
            {"message": f"(URLhaus) Unexpected status '{status}' for '{term}'."},
        )
        return None
    return payload


def search_urlhaus_host(
    sketch_id: Optional[str], api_key: str, host: str
) -> List[Website]:
    """The malware URLs URLhaus lists on `host` (domain or IP), one Website each."""
    payload = query_urlhaus(sketch_id, api_key, "host", {"host": host})
    websites: Dict[str, Website] = {}
    for entry in (payload or {}).get("urls") or []:
        url = entry.get("url")
        if not url or url in websites:
            continue
        tags = ", ".join(entry.get("tags") or [])
        try:
            websites[url] = Website(
                url=url,
                active=entry.get("url_status") == "online",
                description=f"URLhaus {entry.get('threat') or 'listing'}"
                + (f" ({tags})" if tags else "")
                + f", added {entry.get('date_added')}",
            )
        except ValueError:  # URLhaus lists URLs HttpUrl rejects
            continue
    return list(websites.values())


@flowsint_enricher
class DomainToUrlhaus(Enricher):
    """[URLhaus] Find malware distribution URLs hosted on a domain in abuse.ch URLhaus."""

    InputType = Domain
    OutputType = Website

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": "THREATFOX_API_KEY",
                "type": "vaultSecret",
                "description": "The abuse.ch Auth-Key (shared by ThreatFox, MalwareBazaar and URLhaus).",
                "required": True,
            }
        ]

    @classmethod
    def name(cls) -> str:
        return "domain_to_urlhaus"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        self._pairs: List[tuple[Domain, Website]] = []
        api_key = self.get_secret("THREATFOX_API_KEY", os.getenv("THREATFOX_API_KEY"))
        if not api_key:
            Logger.error(
                self.sketch_id,
                {"message": "(DomainToUrlhaus) THREATFOX_API_KEY is not configured."},
            )
            return []

        results: List[OutputType] = []
        for domain in data:
            for website in search_urlhaus_host(self.sketch_id, api_key, domain.domain):
                results.append(website)
                self._pairs.append((domain, website))
        return results

    def postprocess(
        self, results: List[OutputType], input_data: Optional[List[InputType]] = None
    ) -> List[OutputType]:
        if not self._graph_service:
            return results

        for domain, website in self._pairs:
            self.create_node(domain)
            self.create_node(website)
            self.create_relationship(domain, website, "HAS_WEBSITE")
            self.log_graph_message(
                f"(DomainToUrlhaus) {domain.domain} hosts {website.url}"
            )

        return results


InputType = DomainToUrlhaus.InputType
OutputType = DomainToUrlhaus.OutputType
