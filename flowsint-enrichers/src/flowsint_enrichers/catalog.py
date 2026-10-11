"""Presentation metadata; never authorizes an enricher for copilot execution."""

import re
from typing import Any

from flowsint_core.core.enricher_base import Enricher

# Explicitly reviewed behavior, separate from the copilot's execution allowlist.
REVIEWED = {
    "cidr_to_ips": (
        "Preview or expand network addresses",
        "Local calculation",
        True,
        "Calculated from input",
        4096,
    ),
    "domain_to_certificates_ct": (
        "Find publicly logged certificates",
        "crt.sh",
        True,
        "Certificate log entry timestamps",
        100,
    ),
    "certificate_to_domains": (
        "Extract certificate domains",
        "Local calculation",
        True,
        "Dates from supplied certificate",
        500,
    ),
    "domain_to_dns_dependencies_virustotal": (
        "Map DNS dependencies",
        "VirusTotal",
        True,
        "Last indexed DNS observation",
        2500,
    ),
    "cidr_to_routing_history_ripestat": (
        "Find historical routing origins",
        "RIPEstat",
        True,
        "Requested interval, default last 30 days",
        100,
    ),
    "domain_to_ips_virustotal": (
        "Find historical DNS resolutions",
        "VirusTotal",
        True,
        "Dated indexed resolutions (up to 1000 per input)",
        None,
    ),
    "ip_to_domains_virustotal": (
        "Find historical hostnames",
        "VirusTotal",
        True,
        "Dated indexed resolutions (up to 1000 per input)",
        None,
    ),
    "ip_to_ports_shodan": (
        "Inspect observed services",
        "Shodan",
        True,
        "Provider observation timestamps",
        None,
    ),
    "ip_to_ports_modat": (
        "Inspect observed services",
        "Modat",
        True,
        "Provider observation timestamps",
        None,
    ),
    "ip_to_ports_driftnet": (
        "Inspect observed services",
        "Driftnet",
        True,
        "Provider observation timestamps",
        None,
    ),
    "ip_to_internetdb": (
        "Inspect indexed host exposure",
        "InternetDB",
        True,
        "Latest available provider snapshot",
        None,
    ),
    "ip_to_asn_ripestat": (
        "Identify routing origin",
        "RIPEstat",
        True,
        "Latest available routing snapshot",
        None,
    ),
    "asn_to_cidrs_ripestat": (
        "Find announced networks",
        "RIPEstat",
        True,
        "Latest available routing snapshot",
        None,
    ),
    "domain_to_tls": (
        "Inspect a live TLS certificate",
        "httpx",
        False,
        "Live target connection",
        None,
    ),
    "domain_to_dns": (
        "Resolve current IP addresses",
        "dnsx",
        False,
        "Live DNS query",
        None,
    ),
    "domain_to_ip": (
        "Resolve current IP address",
        "DNS resolver",
        False,
        "Live DNS query",
        None,
    ),
}


def metadata(enricher: type[Enricher]) -> dict[str, Any]:
    description = (enricher.__doc__ or "").strip()
    provider_match = re.match(r"\[([^]]+)\]", description)
    default_name = enricher.name().replace("_", " ").capitalize()
    display, provider, passive, freshness, limit = REVIEWED.get(
        enricher.name(),
        (
            default_name,
            provider_match.group(1) if provider_match else "See documentation",
            None,
            "See provider documentation",
            None,
        ),
    )
    return {
        "display_name": display,
        "purpose": display,
        "provider": provider,
        "passive": passive,
        "freshness": freshness,
        "max_results": limit,
    }


def visible(enricher: type[Enricher]) -> bool:
    return (
        "dummy" not in enricher.name().lower() and enricher.category().lower() != "test"
    )
