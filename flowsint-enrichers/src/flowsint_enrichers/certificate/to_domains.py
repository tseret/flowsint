from typing import List, Optional

from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.domain import Domain
from flowsint_types.ssl_certificate import SSLCertificate


@flowsint_enricher
class CertificateToDomains(Enricher):
    """Extract explicit certificate SAN domains locally; wildcard names do not establish live hosts."""

    InputType = SSLCertificate
    OutputType = Domain

    @classmethod
    def name(cls) -> str:
        return "certificate_to_domains"

    @classmethod
    def category(cls) -> str:
        return "Certificate"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        results: list[Domain] = []
        self._pairs: list[tuple[SSLCertificate, Domain]] = []
        for certificate in data:
            for name in certificate.san_domains or []:
                if "*" in name:
                    continue
                try:
                    domain = Domain(domain=name.rstrip("."))
                except ValueError:
                    continue
                if len(self._pairs) >= 500:
                    self.report_issue(
                        "partial", "Certificate names truncated at 500 per run."
                    )
                    return results
                results.append(domain)
                self._pairs.append((certificate, domain))
        return results

    def postprocess(
        self, results: List[OutputType], input_data: Optional[List[InputType]] = None
    ) -> List[OutputType]:
        if self._graph_service:
            for certificate, domain in self._pairs:
                self.create_node(certificate)
                self.create_node(domain)
                self.create_relationship(
                    certificate,
                    domain,
                    "LISTS_DOMAIN",
                    observed_at=certificate.first_seen or certificate.last_seen,
                    source_ref=certificate.source,
                    provider="Certificate metadata",
                )
        return results
