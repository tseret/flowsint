import re
from typing import Any

import requests

from flowsint_core.core.enricher_base import Enricher
from flowsint_core.core.logger import Logger
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.ip import Ip
from flowsint_types.phrase import Phrase

FIELDS = {
    "banner_sha256": ("banner_sha256",),
    "banner_sha1": ("banner_sha1",),
    "banner_mmh3": ("banner_mmh3",),
    "http.body_sha256": ("http", "body_sha256"),
    "http.body_sha1": ("http", "body_sha1"),
    "http.body_mmh3": ("http", "body_mmh3"),
    "http.headers_sha256": ("http", "headers_sha256"),
    "tls.fingerprint_sha256": ("tls", "fingerprint_sha256"),
    "tls.fingerprint_sha1": ("tls", "fingerprint_sha1"),
    "tls.ja3s": ("tls", "ja3s"),
    "tls.ja4s": ("tls", "ja4s"),
    "tls.ja4scan_tls": ("tls", "ja4scan_tls"),
    "tls.ja4x": ("tls", "ja4x"),
    "tls.jarm": ("tls", "jarm"),
    "ssh.hassh": ("ssh", "hassh"),
}
URL = "https://api.magnify.modat.io"


def _fingerprint(service: dict, field: str) -> str:
    value: Any = service
    for part in FIELDS[field]:
        if not isinstance(value, dict):
            return ""
        value = value.get(part)
    if field.endswith("_mmh3"):
        return str(value) if type(value) is int else ""
    if not isinstance(value, str):
        return ""
    normalized = (
        value.replace(":", "").lower()
        if field.endswith(("sha1", "sha256")) or field == "ssh.hassh"
        else value
    )
    if field.endswith("sha256"):
        return normalized if re.fullmatch(r"[0-9a-f]{64}", normalized) else ""
    if field.endswith("sha1"):
        return normalized if re.fullmatch(r"[0-9a-f]{40}", normalized) else ""
    if field == "ssh.hassh":
        return normalized if re.fullmatch(r"[0-9a-f]{32}", normalized) else ""
    return normalized if re.fullmatch(r"[a-zA-Z0-9_.:-]{1,128}", normalized) else ""


@flowsint_enricher
class IpToIpsModatEnricher(Enricher):
    """[Modat] Find related IPs using indexed service hashes and independent evidence."""

    InputType = Ip
    OutputType = Ip

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(params_schema=self.get_params_schema(), **kwargs)

    @classmethod
    def name(cls) -> str:
        return "ip_to_ips_modat"

    @classmethod
    def key(cls) -> str:
        return "address"

    @classmethod
    def category(cls) -> str:
        return "Ip"

    @classmethod
    def required_params(cls) -> bool:
        return True

    @classmethod
    def get_params_schema(cls) -> list[dict]:
        return [
            {
                "name": "port",
                "type": "number",
                "description": "Optional source service port (1-65535); blank discovers indexed services.",
            },
            {
                "name": "transport",
                "type": "select",
                "description": "Optional transport filter; blank searches TCP and UDP.",
                "options": [
                    {"value": "tcp", "label": "TCP"},
                    {"value": "udp", "label": "UDP"},
                ],
            },
            {
                "name": "pivot_field",
                "type": "select",
                "description": "Optional indexed fingerprint to match; blank picks one for each eligible source service.",
                "options": [{"value": field, "label": field} for field in FIELDS],
            },
            {
                "name": "target_domain",
                "type": "string",
                "description": "Optional target DNS domain. Without it, three independent fingerprint families must match for graph promotion.",
            },
        ]

    async def scan(self, data: list[Ip]) -> list[Ip]:
        port = int(self.params["port"]) if self.params.get("port") else None
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        transport = self.params.get("transport") or None
        if transport is not None and transport not in ("tcp", "udp"):
            raise ValueError("transport must be tcp or udp")
        field = self.params.get("pivot_field") or None
        if field is not None and field not in FIELDS:
            raise ValueError("unsupported Modat pivot field")
        domain = (self.params.get("target_domain") or "").strip().lower().rstrip(".")
        if domain and ("." not in domain or ".." in domain):
            raise ValueError("target_domain must be a DNS domain")
        key = self.vault.get_secret("MODAT_API_KEY") if self.vault else None
        if not key:
            raise ValueError("MODAT_API_KEY is required in Vault")
        headers = {
            "Authorization": f"Bearer {key}",
            "User-Agent": "Flowsint-Modat-Connector",
        }

        self._matches: list[tuple[Ip, Phrase, list[Ip]]] = []
        results: list[Ip] = []
        seen_results: set[str] = set()
        for source in {ip.address: ip for ip in data}.values():
            try:
                response = requests.get(
                    f"{URL}/host/{source.address}/v1", headers=headers, timeout=30
                )
                if response.status_code in (401, 403, 429):
                    Logger.error(
                        self.sketch_id,
                        {"message": f"[Modat] HTTP {response.status_code}; stopping."},
                    )
                    break
                if response.status_code == 404:
                    continue
                if response.status_code != 200:
                    Logger.error(
                        self.sketch_id,
                        {
                            "message": f"[Modat] Host lookup HTTP {response.status_code} for {source.address}"
                        },
                    )
                    continue
                services = response.json()["data"]["services"]
            except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
                Logger.error(
                    self.sketch_id,
                    {
                        "message": f"[Modat] Host lookup failed for {source.address}: {type(exc).__name__}"
                    },
                )
                continue

            eligible: list[tuple[int, str, str, str, dict[str, str]]] = []
            seen_pivots: set[tuple[int, str, str, str]] = set()
            for service in services:
                if not isinstance(service, dict):
                    continue
                protocol = service.get("transport")
                if protocol not in ("tcp", "udp") or (
                    transport is not None and protocol != transport
                ):
                    continue
                fingerprints = {
                    name: value
                    for name in FIELDS
                    if (value := _fingerprint(service, name))
                }
                families = {name.split(".")[0].split("_")[0] for name in fingerprints}
                if len(families) < (2 if domain else 3):
                    continue
                selected = field or next(iter(fingerprints), None)
                if selected not in fingerprints:
                    continue
                pivot = fingerprints[selected]
                for source_port in service.get("ports") or []:
                    if (
                        type(source_port) is not int
                        or not 1 <= source_port <= 65535
                        or (port is not None and source_port != port)
                    ):
                        continue
                    identity = (source_port, protocol, selected, pivot)
                    if identity not in seen_pivots:
                        seen_pivots.add(identity)
                        eligible.append(
                            (source_port, protocol, selected, pivot, fingerprints)
                        )

            pages_left = 2
            stop_search = False
            for index, (
                source_port,
                protocol,
                selected,
                pivot,
                fingerprints,
            ) in enumerate(eligible):
                if not pages_left:
                    Logger.info(
                        self.sketch_id,
                        {
                            "message": f"[Modat] Skipped {len(eligible) - index} source service pivot(s) for {source.address}; two-page search limit reached."
                        },
                    )
                    break
                promoted: set[str] = set()
                review: dict[str, str] = {}
                peers: list[Ip] = []
                pages = 0
                # Share the two-page budget across services instead of spending it per port.
                page_limit = pages_left if len(eligible) == 1 else 1
                for page in range(1, page_limit + 1):
                    try:
                        response = requests.post(
                            f"{URL}/service/search/v1",
                            headers=headers,
                            json={
                                "query": f"{selected}={pivot} port={source_port}",
                                "page": page,
                                "page_size": 100,
                            },
                            timeout=30,
                        )
                        if response.status_code in (401, 403, 429):
                            Logger.error(
                                self.sketch_id,
                                {
                                    "message": f"[Modat] Search HTTP {response.status_code}; stopping."
                                },
                            )
                            stop_search = True
                            break
                        if response.status_code != 200:
                            Logger.error(
                                self.sketch_id,
                                {
                                    "message": f"[Modat] Search HTTP {response.status_code} for {source.address}"
                                },
                            )
                            break
                        payload = response.json()
                        matches = payload["page"]
                    except (
                        requests.RequestException,
                        ValueError,
                        KeyError,
                        TypeError,
                    ) as exc:
                        Logger.error(
                            self.sketch_id,
                            {
                                "message": f"[Modat] Search failed for {source.address}: {type(exc).__name__}"
                            },
                        )
                        break
                    pages += 1
                    pages_left -= 1
                    for match in matches:
                        if not isinstance(match, dict):
                            continue
                        address = match.get("ip")
                        item = match.get("service")
                        if (
                            not isinstance(item, dict)
                            or not address
                            or address == source.address
                            or address in promoted
                        ):
                            continue
                        if (
                            item.get("port") != source_port
                            or item.get("transport") != protocol
                            or _fingerprint(item, selected) != pivot
                        ):
                            continue
                        try:
                            peer = Ip(address=address)
                        except ValueError:
                            continue
                        common = [
                            name
                            for name, value in fingerprints.items()
                            if _fingerprint(item, name) == value
                        ]
                        families = {name.split(".")[0].split("_")[0] for name in common}
                        domain_match = bool(
                            domain
                            and any(
                                name.lower().rstrip(".") == domain
                                or name.lower().rstrip(".").endswith("." + domain)
                                for name in (match.get("fqdns") or [])
                                if isinstance(name, str)
                            )
                        )
                        # ponytail: requiring three fingerprint families without a
                        # target domain loses recall; add identity evidence before relaxing.
                        qualifies = (
                            domain_match and len(families) >= 2
                            if domain
                            else len(families) >= 3
                        )
                        if qualifies:
                            promoted.add(address)
                            review.pop(address, None)
                            peers.append(peer)
                            if address not in seen_results:
                                results.append(peer)
                                seen_results.add(address)
                        else:
                            review[address] = ", ".join(
                                common + (["target domain"] if domain_match else [])
                            )
                    if page >= payload.get("total_pages", 1) or len(matches) < 100:
                        break

                Logger.info(
                    self.sketch_id,
                    {
                        "message": (
                            f"Modat {source.address} {source_port}/{protocol} {selected}: "
                            f"{pages} page(s), {len(peers)} corroborated, {len(review)} for review.\r\n"
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
                        (source, Phrase(text=f"Modat {selected}:{pivot}"), peers)
                    )
                if stop_search:
                    break
            if stop_search:
                break
        return results

    def postprocess(
        self, results: list[Ip], input_data: list[Ip] | None = None
    ) -> list[Ip]:
        for source, evidence, peers in self._matches:
            self.create_node(source)
            self.create_node(evidence)
            self.create_relationship(source, evidence, "HAS_MODAT_PIVOT")
            for peer in peers:
                self.create_node(peer)
                self.create_relationship(evidence, peer, "MATCHES_MODAT_PIVOT")
        return results


InputType = IpToIpsModatEnricher.InputType
OutputType = IpToIpsModatEnricher.OutputType
