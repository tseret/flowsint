import os
from typing import Any, Dict, List, Optional

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.domain.to_urlhaus import query_urlhaus
from flowsint_enrichers.file.to_malwarebazaar import fill_file
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.file import File
from flowsint_types.website import Website


@flowsint_enricher
class WebsiteToUrlhaus(Enricher):
    """[URLhaus] Find the malware payloads a URL served, from abuse.ch URLhaus."""

    InputType = Website
    OutputType = File

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
        return "website_to_urlhaus"

    @classmethod
    def category(cls) -> str:
        return "Website"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        self._pairs: List[tuple[Website, File]] = []
        api_key = self.get_secret("THREATFOX_API_KEY", os.getenv("THREATFOX_API_KEY"))
        if not api_key:
            Logger.error(
                self.sketch_id,
                {"message": "(WebsiteToUrlhaus) THREATFOX_API_KEY is not configured."},
            )
            return []

        results: List[OutputType] = []
        for website in data:
            # ponytail: exact URL lookup; HttpUrl adds a trailing "/" to bare hosts,
            # which URLhaus treats as a different URL (use domain/ip_to_urlhaus there).
            payload = query_urlhaus(
                self.sketch_id, api_key, "url", {"url": str(website.url)}
            )
            seen: set[str] = set()
            for entry in (payload or {}).get("payloads") or []:
                sha = (entry.get("response_sha256") or "").lower()
                if not sha or sha in seen:
                    continue
                seen.add(sha)
                name, size = entry.get("filename"), str(entry.get("response_size"))
                file = fill_file(
                    File(filename=sha),
                    hash_sha256=sha,
                    hash_md5=(entry.get("response_md5") or "").lower() or None,
                    file_type=entry.get("file_type"),
                    file_size=int(size) if size.isdigit() else None,
                    is_malicious=True,
                    malware_family=entry.get("signature"),
                    source="URLhaus",
                    description=f"Served as '{name}'" if name else None,
                )
                results.append(file)
                self._pairs.append((website, file))
        return results

    def postprocess(
        self, results: List[OutputType], input_data: Optional[List[InputType]] = None
    ) -> List[OutputType]:
        if not self._graph_service:
            return results

        for website, file in self._pairs:
            self.create_node(website)
            self.create_node(file)
            self.create_relationship(website, file, "SERVES_PAYLOAD")
            self.log_graph_message(
                f"(WebsiteToUrlhaus) {website.url} served {file.filename}"
            )

        return results


InputType = WebsiteToUrlhaus.InputType
OutputType = WebsiteToUrlhaus.OutputType
