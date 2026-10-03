from typing import Any, List, Optional

from flowsint_core.utils import is_valid_domain

from ..dockertool import DockerTool


class SubfinderTool(DockerTool):
    image = "projectdiscovery/subfinder"

    @classmethod
    def name(cls) -> str:
        return "subfinder"

    @classmethod
    def description(cls) -> str:
        return "Fast passive subdomain enumeration tool."

    @classmethod
    def category(cls) -> str:
        return "Subdomain enumeration"

    def version(self) -> str:
        try:
            # subfinder requires input even when checking version, so we provide a dummy domain
            output = self.client.containers.run(
                image=self.image,
                command="--version",
                remove=True,
                stderr=True,
                stdout=True,
            )
            output_str = output.decode()
            import re

            match = re.search(r"(v[\d\.]+)", output_str)
            version = match.group(1) if match else "unknown"
            return version
        except Exception as e:
            return f"unknown (error: {str(e)})"

    def launch(self, domain: str, args: Optional[List[str]] = None) -> Any:
        subdomains: set[str] = set()
        if args is None:
            args = []
        command = f"-d {domain} {' '.join(args)}"
        result = super().launch(command)
        for sub in result.split("\n"):
            if (
                is_valid_domain(sub)
                and sub.endswith(domain)
                and sub != domain
                and not sub.startswith(".")
            ):
                subdomains.add(sub)
        return list(subdomains)
