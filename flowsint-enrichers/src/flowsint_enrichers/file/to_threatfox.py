import os
from typing import Any, Dict, List, Optional

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.file.to_malwarebazaar import file_hash
from flowsint_enrichers.ip.to_threatfox import search_threatfox
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.file import File
from flowsint_types.malware import Malware


@flowsint_enricher
class FileToThreatFox(Enricher):
    """[ThreatFox] Find malware associated with a file hash in abuse.ch ThreatFox IOCs."""

    InputType = File
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
        return "file_to_threatfox"

    @classmethod
    def category(cls) -> str:
        return "File"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        self._pairs: List[tuple[File, Malware]] = []
        api_key = self.get_secret("THREATFOX_API_KEY", os.getenv("THREATFOX_API_KEY"))
        if not api_key:
            Logger.error(
                self.sketch_id,
                {"message": "(FileToThreatFox) THREATFOX_API_KEY is not configured."},
            )
            return []

        results: List[OutputType] = []
        for file in data:
            sha = file_hash(file)
            if not sha:
                Logger.info(
                    self.sketch_id,
                    {
                        "message": f"(FileToThreatFox) '{file.filename}' has no hash; skipped."
                    },
                )
                continue

            # search_ioc is a wildcard search; keep exact hash IOCs only.
            def matches(entry: Dict[str, Any], sha: str = sha) -> bool:
                return str(entry.get("ioc", "")).lower() == sha

            for malware in search_threatfox(self.sketch_id, api_key, sha, matches):
                results.append(malware)
                self._pairs.append((file, malware))
        return results

    def postprocess(
        self, results: List[OutputType], input_data: Optional[List[InputType]] = None
    ) -> List[OutputType]:
        if not self._graph_service:
            return results

        for file, malware in self._pairs:
            self.create_node(file)
            self.create_node(malware)
            self.create_relationship(file, malware, "ASSOCIATED_WITH")
            self.log_graph_message(
                f"(FileToThreatFox) {file.filename} associated with {malware.name}"
            )

        return results


InputType = FileToThreatFox.InputType
OutputType = FileToThreatFox.OutputType
