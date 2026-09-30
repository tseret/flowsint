import os
from typing import Any, Dict, List, Optional

import requests

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.file.to_malwarebazaar import file_hash, fill_file
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.file import File


@flowsint_enricher
class FileToVirusTotal(Enricher):
    """[VirusTotal] Get a file hash's detection ratio, threat label and metadata."""

    InputType = File
    OutputType = File

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": "VT_API_KEY",
                "type": "vaultSecret",
                "description": "The VirusTotal API key.",
                "required": True,
            }
        ]

    @classmethod
    def name(cls) -> str:
        return "file_to_virustotal"

    @classmethod
    def category(cls) -> str:
        return "File"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        results: List[OutputType] = []
        api_key = self.get_secret("VT_API_KEY", os.getenv("VT_API_KEY"))
        if not api_key:
            Logger.error(
                self.sketch_id,
                {"message": "(FileToVirusTotal) VT_API_KEY is not configured."},
            )
            return results

        for file in data:
            sha = file_hash(file)
            if not sha:
                Logger.info(
                    self.sketch_id,
                    {
                        "message": f"(FileToVirusTotal) '{file.filename}' has no hash; skipped."
                    },
                )
                continue
            try:
                response = requests.get(
                    f"https://www.virustotal.com/api/v3/files/{sha}",
                    headers={"x-apikey": api_key},
                    timeout=30,
                )
                if response.status_code == 404:
                    Logger.info(
                        self.sketch_id,
                        {"message": f"(FileToVirusTotal) '{sha}' not found."},
                    )
                    continue
                if response.status_code == 429:
                    Logger.error(
                        self.sketch_id,
                        {
                            "message": "(FileToVirusTotal) VirusTotal quota exceeded (429); stopping."
                        },
                    )
                    break
                if response.status_code != 200:
                    Logger.error(
                        self.sketch_id,
                        {
                            "message": f"(FileToVirusTotal) VirusTotal returned HTTP {response.status_code} for '{sha}'."
                        },
                    )
                    continue
                attrs = response.json().get("data", {}).get("attributes", {})
            except Exception as e:
                Logger.error(
                    self.sketch_id,
                    {
                        "message": f"(FileToVirusTotal) Exception while querying {sha}: {e}"
                    },
                )
                continue

            stats = attrs.get("last_analysis_stats") or {}
            malicious = int(stats.get("malicious") or 0)
            engines = sum(
                int(stats.get(k) or 0)
                for k in ("malicious", "suspicious", "undetected", "harmless")
            )
            label = (attrs.get("popular_threat_classification") or {}).get(
                "suggested_threat_label"
            )
            results.append(
                fill_file(
                    file,
                    hash_md5=attrs.get("md5"),
                    hash_sha1=attrs.get("sha1"),
                    hash_sha256=attrs.get("sha256"),
                    file_type=attrs.get("type_description"),
                    file_size=attrs.get("size"),
                    is_malicious=malicious > 0,
                    malware_family=label,
                    threat_level=f"{malicious}/{engines} engines (VirusTotal)"
                    if engines
                    else None,
                )
            )
        return results

    def postprocess(
        self, results: List[OutputType], input_data: Optional[List[InputType]] = None
    ) -> List[OutputType]:
        if not self._graph_service:
            return results

        for file in results:
            self.create_node(file)
            self.log_graph_message(
                f"(FileToVirusTotal) {file.filename}: {file.threat_level or 'no verdict'}"
            )

        return results


InputType = FileToVirusTotal.InputType
OutputType = FileToVirusTotal.OutputType
