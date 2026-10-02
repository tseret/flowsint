from typing import List, Optional

from tools.network.httpx import HttpxTool

from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.domain import Domain
from flowsint_types.ssl_certificate import SSLCertificate


@flowsint_enricher
class DomainToTLS(Enricher):
    """[httpX] Retrieve the certificate presented by the supplied domain."""

    InputType = Domain
    OutputType = SSLCertificate

    @classmethod
    def name(cls) -> str:
        return "domain_to_tls"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        self._pairs = []
        results = []
        for domain in data:
            try:
                # Grab the supplied host's certificate; do not probe SAN hosts.
                rows = HttpxTool().launch(target=domain.domain, args=["-tls-grab"])
                for row in rows:
                    tls = row.get("tls") or {}
                    if not tls or tls.get("probe_status") is False:
                        continue
                    hashes = tls.get("fingerprint_hash") or {}
                    certificate = SSLCertificate(
                        subject=tls.get("subject_dn")
                        or tls.get("subject_cn")
                        or domain.domain,
                        issuer=tls.get("issuer_dn") or tls.get("issuer_cn"),
                        serial_number=tls.get("serial"),
                        valid_from=tls.get("not_before"),
                        valid_until=tls.get("not_after"),
                        san_domains=tls.get("subject_an"),
                        is_expired=tls.get("expired"),
                        is_self_signed=tls.get("self_signed"),
                        is_wildcard=tls.get("wildcard_certificate"),
                        fingerprint_sha1=hashes.get("sha1"),
                        fingerprint_sha256=hashes.get("sha256"),
                        source="httpx",
                        last_seen=row.get("timestamp"),
                    )
                    results.append(certificate)
                    self._pairs.append(
                        (
                            domain,
                            certificate,
                            row.get("url") or f"https://{domain.domain}",
                        )
                    )
            except Exception as exc:
                self.report_issue(
                    "failed",
                    f"TLS metadata unavailable for {domain.domain} ({type(exc).__name__}).",
                )
        return results

    def postprocess(
        self, results: List[OutputType], input_data: Optional[List[InputType]] = None
    ) -> List[OutputType]:
        if self._graph_service:
            for domain, certificate, source in self._pairs:
                self.create_node(domain)
                self.create_node(certificate)
                self.create_relationship(
                    domain,
                    certificate,
                    "PRESENTS_CERTIFICATE",
                    observed_at=certificate.last_seen,
                    source_ref=source,
                    provider="httpx",
                )
                self.log_graph_message(
                    f"TLS certificate for {domain.domain}: {certificate.subject}"
                )
        return results


InputType = DomainToTLS.InputType
OutputType = DomainToTLS.OutputType
