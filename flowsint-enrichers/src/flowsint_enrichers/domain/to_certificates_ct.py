from typing import List, Optional

from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.passive_http import indexed_json
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.domain import Domain
from flowsint_types.ssl_certificate import SSLCertificate


@flowsint_enricher
class DomainToCertificatesCT(Enricher):
    """[crt.sh] Find publicly logged certificates for an exact domain; never probes endpoints."""

    InputType = Domain
    OutputType = SSLCertificate

    @classmethod
    def name(cls) -> str:
        return "domain_to_certificates_ct"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        self._pairs: list[tuple[Domain, SSLCertificate]] = []
        results: list[SSLCertificate] = []
        seen = set()
        for domain in data[:10]:
            rows = indexed_json(
                self, "https://crt.sh/", {"q": domain.domain, "output": "json"}
            )
            if rows is None:
                break
            if not isinstance(rows, list):
                self.report_issue(
                    "failed", "crt.sh returned an invalid certificate list."
                )
                continue
            for row in rows:
                if len(self._pairs) >= 100:
                    self.report_issue(
                        "partial",
                        "CT results truncated at 100 certificate relationships per run.",
                    )
                    return results
                try:
                    cert_id = int(row["id"])
                    if cert_id <= 0:
                        raise ValueError
                    names = sorted(set(row["name_value"].splitlines()))
                    # Subject is the existing certificate identity; include the record ID to avoid merging renewals.
                    certificate = SSLCertificate(
                        subject=f"{row['common_name']} [crt.sh:{cert_id}]",
                        common_name=row["common_name"],
                        issuer=row.get("issuer_name"),
                        serial_number=row.get("serial_number"),
                        valid_from=row.get("not_before"),
                        valid_until=row.get("not_after"),
                        san_domains=names,
                        first_seen=row.get("entry_timestamp"),
                        source=f"https://crt.sh/?id={cert_id}",
                    )
                except (KeyError, ValueError, TypeError, AttributeError):
                    self.report_issue("partial", "An invalid CT record was skipped.")
                    continue
                pair = (domain.domain, cert_id)
                if pair in seen:
                    continue
                seen.add(pair)
                self._pairs.append((domain, certificate))
                results.append(certificate)
        if len(data) > 10:
            self.report_issue("partial", "CT lookup limited to 10 input domains.")
        return results

    def postprocess(
        self, results: List[OutputType], input_data: Optional[List[InputType]] = None
    ) -> List[OutputType]:
        if self._graph_service:
            for domain, certificate in self._pairs:
                self.create_node(domain)
                self.create_node(certificate)
                self.create_relationship(
                    domain,
                    certificate,
                    "LISTED_IN_CERTIFICATE",
                    observed_at=certificate.first_seen,
                    source_ref=certificate.source,
                    provider="crt.sh",
                )
        return results
