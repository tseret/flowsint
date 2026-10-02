from collections.abc import Iterator
from typing import Any

import requests

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.ip import Ip
from flowsint_types.phrase import Phrase


@flowsint_enricher
class IpToBannerHashShodanEnricher(Enricher):
    """[Shodan] Banner hash hunt for indexed services, gated by independent evidence."""

    InputType = Ip
    OutputType = Ip

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(params_schema=self.get_params_schema(), **kwargs)

    @classmethod
    def name(cls) -> str:
        return "ip_to_banner_hash_shodan"

    @classmethod
    def key(cls) -> str:
        return "address"

    @classmethod
    def category(cls) -> str:
        return "Ip"

    @classmethod
    def get_params_schema(cls) -> list[dict]:
        return [
            {
                "name": "SHODAN_API_KEY",
                "type": "vaultSecret",
                "description": "Shodan API key with search credits.",
                "required": True,
            },
            {
                "name": "port",
                "type": "number",
                "description": "Optional source service port (1-65535); blank searches indexed services automatically.",
            },
            {
                "name": "transport",
                "type": "select",
                "description": "Optional transport filter (TCP or UDP); blank searches both.",
                "options": [
                    {"value": "tcp", "label": "TCP"},
                    {"value": "udp", "label": "UDP"},
                ],
            },
            {
                "name": "target_domain",
                "type": "string",
                "description": "Optional target DNS domain (exact name or subdomains).",
            },
            {
                "name": "target_product",
                "type": "string",
                "description": "Optional Shodan product; inferred from each source service if no target is set. Product-only matches also require matching TLS and HTML fingerprints.",
            },
        ]

    async def scan(self, data: list[Ip]) -> list[Ip]:
        selected_port = self.params.get("port")
        port = int(selected_port) if selected_port not in (None, "") else None
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        transport = self.params.get("transport") or None
        if transport is not None and transport not in ("tcp", "udp"):
            raise ValueError("transport must be tcp or udp")
        domain = (self.params.get("target_domain") or "").strip().lower().rstrip(".")
        product = (self.params.get("target_product") or "").strip().casefold()
        if domain and ("." not in domain or ".." in domain):
            raise ValueError("target_domain must be a DNS domain")
        key = self.get_secret("SHODAN_API_KEY")
        if not key:
            raise ValueError("SHODAN_API_KEY is required")

        self._matches: list[tuple[Ip, Phrase, list[Ip]]] = []
        results: list[Ip] = []
        seen_results: set[str] = set()
        credits_remaining: dict[str, int] = {}
        for source, service, page_limit in self._source_services(
            data, key, port, transport, product, domain, credits_remaining
        ):
            banner_hash = service["hash"]
            source_html_hash = (service.get("http") or {}).get("html_hash")
            source_fingerprint = (
                ((service.get("ssl") or {}).get("cert") or {}).get("fingerprint") or {}
            ).get("sha256")
            source_product = (service.get("product") or "").strip().casefold()
            effective_product = product or (source_product if not domain else "")
            service_port = service["port"]
            service_transport = service.get("transport", "tcp")

            peers: list[Ip] = []
            promoted: set[str] = set()
            review: dict[str, str] = {}
            pages = 0
            query = f"hash:{banner_hash}"
            for page in range(1, page_limit + 1):
                try:
                    matches = requests.get(
                        "https://api.shodan.io/shodan/host/search",
                        params={"key": key, "query": query, "page": page},
                        timeout=30,
                    )
                except requests.RequestException:
                    raise RuntimeError("Shodan banner search failed") from None
                if matches.status_code != 200:
                    raise RuntimeError(
                        f"Shodan banner search failed (HTTP {matches.status_code})"
                    )
                pages += 1
                credits_remaining[source.address] = (
                    credits_remaining.get(source.address, 2) - 1
                )
                payload = matches.json()
                for match in payload.get("matches", []):
                    address = match.get("ip_str")
                    if (
                        not address
                        or address == source.address
                        or address in promoted
                        or match.get("hash") != banner_hash
                    ):
                        continue
                    try:
                        peer = Ip(address=address)
                    except ValueError:
                        continue

                    names = match.get("hostnames") or []
                    domains = match.get("domains") or []
                    domain_match = bool(
                        domain
                        and any(
                            name.lower().rstrip(".") == domain
                            or name.lower().rstrip(".").endswith("." + domain)
                            for name in (*names, *domains)
                            if isinstance(name, str)
                        )
                    )
                    product_match = bool(
                        effective_product
                        and source_product == effective_product
                        and (match.get("product") or "").strip().casefold()
                        == effective_product
                    )
                    html_match = bool(
                        source_html_hash
                        and (match.get("http") or {}).get("html_hash")
                        == source_html_hash
                    )
                    fingerprint_match = bool(
                        source_fingerprint
                        and (
                            ((match.get("ssl") or {}).get("cert") or {}).get(
                                "fingerprint"
                            )
                            or {}
                        ).get("sha256")
                        == source_fingerprint
                    )
                    evidence = ", ".join(
                        label
                        for label, matched in (
                            ("target domain", domain_match),
                            ("product", product_match),
                            ("TLS certificate", fingerprint_match),
                            ("HTML body", html_match),
                        )
                        if matched
                    )
                    qualifies = (
                        (not domain or domain_match)
                        and (not effective_product or product_match)
                        and (fingerprint_match or html_match)
                        and (
                            domain_match
                            or (product_match and fingerprint_match and html_match)
                        )
                    )
                    if qualifies:
                        promoted.add(address)
                        review.pop(address, None)
                        peers.append(peer)
                        if address not in seen_results:
                            results.append(peer)
                            seen_results.add(address)
                    elif not evidence:
                        review.setdefault(address, "banner hash only")
                    elif (
                        address not in review
                        or review[address] == "banner hash only"
                        or evidence.count(",") > review[address].count(",")
                    ):
                        review[address] = evidence

                if len(payload.get("matches", [])) < 100 or (
                    isinstance(payload.get("total"), int)
                    and page * 100 >= payload["total"]
                ):
                    break

            Logger.info(
                self.sketch_id,
                {
                    "message": (
                        f"Shodan {source.address} {service_port}/{service_transport}: {pages} search "
                        f"page(s), {len(peers)} corroborated, {len(review)} for review. "
                        "Search costs up to one credit per page.\r\n"
                        "Review candidates (not graphed):\r\n"
                        + "\r\n".join(
                            f"{address}: {signals}"
                            for address, signals in review.items()
                        )
                    )
                },
            )
            if peers:
                self._matches.append(
                    (source, Phrase(text=f"Shodan banner hash:{banner_hash}"), peers)
                )
        return results

    def _source_services(
        self,
        data: list[Ip],
        key: str,
        port: int | None,
        transport: str | None,
        product: str,
        domain: str,
        credits_remaining: dict[str, int],
    ) -> Iterator[tuple[Ip, dict, int]]:
        seen_sources: set[str] = set()
        for source in data:
            if source.address in seen_sources:
                continue
            seen_sources.add(source.address)
            try:
                host = requests.get(
                    f"https://api.shodan.io/shodan/host/{source.address}",
                    params={"key": key},
                    timeout=30,
                )
            except requests.RequestException:
                raise RuntimeError("Shodan host lookup failed") from None
            if host.status_code == 404:
                continue
            if host.status_code != 200:
                raise RuntimeError(
                    f"Shodan host lookup failed (HTTP {host.status_code})"
                )
            services = [
                banner
                for banner in host.json().get("data", [])
                if banner.get("port") == port or port is None
                if transport is None or banner.get("transport", "tcp") == transport
                if type(banner.get("hash")) is int and banner["hash"] != 0
                if not product
                or (banner.get("product") or "").strip().casefold() == product
            ]
            if not domain and not product:
                services = [
                    service
                    for service in services
                    if service.get("product")
                    and (service.get("http") or {}).get("html_hash")
                    and (
                        ((service.get("ssl") or {}).get("cert") or {}).get(
                            "fingerprint"
                        )
                        or {}
                    ).get("sha256")
                ]
            if not services:
                Logger.info(
                    self.sketch_id,
                    {
                        "message": (
                            f"Shodan {source.address}: no eligible indexed service "
                            "with a banner hash and sufficient corroborating evidence; "
                            "no paid search was run."
                        )
                    },
                )
                continue
            for index, service in enumerate(services):
                remaining = credits_remaining.get(source.address, 2)
                if not remaining:
                    Logger.info(
                        self.sketch_id,
                        {
                            "message": (
                                f"Shodan {source.address}: skipped "
                                f"{len(services) - index} indexed service(s) "
                                "after the two-page search limit."
                            )
                        },
                    )
                    break
                yield source, service, min(remaining, 2 if len(services) == 1 else 1)

    def postprocess(
        self, results: list[Ip], input_data: list[Ip] | None = None
    ) -> list[Ip]:
        for source, banner_hash, peers in self._matches:
            self.create_node(source)
            self.create_node(banner_hash)
            self.create_relationship(source, banner_hash, "HAS_BANNER_HASH")
            for peer in peers:
                self.create_node(peer)
                self.create_relationship(banner_hash, peer, "MATCHES_BANNER_HASH")
        return results


InputType = IpToBannerHashShodanEnricher.InputType
OutputType = IpToBannerHashShodanEnricher.OutputType
