# Local handoff (local-only fork of reconurge/flowsint)

## 2026-09-30
Done:
- Stock prod stack evaluated (`docker-compose.prod.yml` + local `docker-compose.local.yml`, git-excluded): loopback UI, `group_add: ["0"]` so uid 1001 can use Docker Desktop's root:root 0660 socket, patched enrichers bind-mounted.
- Fixed upstream bug: `ip/domain/organization_to_asn` and `asn_to_cidrs` built `ASN(number=...)` without the required `asn_str`, so every ASN lookup failed validation. Regression test: `flowsint-enrichers/tests/enrichers/test_to_asn.py`.
- Chain verified in UI on python.org: 76 HAS_SUBDOMAIN, RESOLVES_TO 151.101.128.223, BELONGS_TO AS54113 (fastly), 1321 ANNOUNCES CIDRs; 0 Celery tracebacks.
- Review fixes: `org_to_asn` now builds edges from the (org, ASN) pairs recorded in scan (a zip misaligned them when a lookup failed; regression test added). Removed the unreachable `asn_to_cidrs` fallback. Typed the changed enrichers and `tools/network/asnmap.py` (bind-mounted too) so `make typecheck` passes.
- Verified: ruff, `make typecheck BASE_REF=4c05849b`, `make test` (58/416/36/17 passed). Frontend `make lint` step not run: yarn/node_modules absent locally, and no frontend code was changed.

Next:
- Start stack: `docker compose -f docker-compose.prod.yml -f docker-compose.local.yml up -d` (not `make prod`, which drops the override). Stop: `make down`.
- New patched/added enricher files must also be bind-mounted in `docker-compose.local.yml` (the image copy of `flowsint-enrichers/src` differs from HEAD in `social/to_maigret.py`, so the whole dir is not mounted).
- ASN/CIDR enrichers need `PDCP_API_KEY` in Vault; a missing key or Docker error only shows in the sketch logs, the UI shows an empty result.

## 2026-09-30 — local/connector-prep (base = local/eval-fixes @ 605c7ad1)
Done:
- Batch 1 dead-code removal (~22 files): unused orchestrator/utils/events/template-type/yaml_loader helpers, `jsonschema_to_pydantic`, `DockerTool.get_image`, and the unreachable Holehe/Sirene mocks in `flows.py`. Template tests now parse the way production does, `Template(**yaml.safe_load(...))`. The stale uncollected test drafts were deleted.
- The changed-files mypy gate required annotations only, with no behaviour change: `flows.py` routes, `events.py`, `to_crawler.postprocess`, `imports/utils.py`, `registry.py`.
- Verified: ruff, `make typecheck BASE_REF=605c7ad1`, `make test` (58/416/36/17). Smoke run with the whole branch `src/` mounted into api+celery: `/api/flows/raw_materials` and `/api/flows/input_type/*` return 200; ip_to_asn → AS54113 and asn_to_cidrs succeeded, 0 tracebacks.
- Known skew: with the branch source mounted, `GET /api/flows` returns 500 (`flows.owner_id` missing) because the image's DB predates that migration. This is unrelated to this diff.
- Batch 2, enricher base simplification with no behaviour change:
  - `params_schema` defaults to `get_params_schema()`.
  - `key()` defaults to the new `Enricher.primary_field()`. Only the 12 enrichers whose key differs still override it.
  - `DockerTool` subclasses only set `image` (and optionally `default_tag`).
  - Graph docstrings and the developer docs are fixed.
  - The changed-files mypy gate required annotation-only fixes in the touched files, plus a few narrow `type: ignore`s.
  - Verified: ruff; typecheck ×4; `make test` 58/424/36/17; the live smoke run (ip_to_asn, domain_to_dns and asn_to_cidrs all produced results, 0 tracebacks). Impact check: proceed. Review: resolved.

Next:
- Write the first own connector with the slim pattern: `InputType`/`OutputType`, `name`, `category`, `scan`, `postprocess`, plus `get_params_schema` if needed.

## 2026-09-30 — local/connectors (base = local/connector-prep @ 75daab45)
Done:
- Connector batch 1, 9 auto-registered enrichers:
  - Keyless: `ip_to_internetdb` (Shodan InternetDB → Port and hostnames), `ip_to_asn_ripestat`, and `asn_to_cidrs_ripestat` (RIPEstat stands in for bgp.he.net, which has no API).
  - Keyed (Vault): `ip_to_ports_shodan` (`SHODAN_API_KEY`), `ip_to_abuseipdb` (`ABUSEIPDB_API_KEY`), `domain_to_ips_virustotal` and `ip_to_domains_virustotal` (`VT_API_KEY`), `ip_to_threatfox` and `domain_to_threatfox` (`THREATFOX_API_KEY`).
- Graph semantics:
  - VirusTotal uses a `PASSIVE_DNS_RESOLVED_TO` edge, domain→ip, in both directions of lookup.
  - ThreatFox results are filtered client-side against substring and IPv6 lookalikes.
  - The AbuseIPDB score id is `AbuseIPDB <ip>`.
  - The RIPEstat ASN name matches asnmap's, so both merge into one node (`AS54113 - fastly`).
- Tests: 6 new offline test files. The catalog is updated in `docs/sources/available-enrichers.mdx`.
- Verified:
  - ruff and typecheck both pass.
  - `make test`: 58/424/73/17.
  - Live smoke run: the catalogue lists 58 enrichers, and all 9 run_enricher tasks succeeded with 0 tracebacks. InternetDB found ports 80/443 and 3 hostnames; RIPEstat found AS54113 and 1847 prefixes. The keyed enrichers stop cleanly with a "missing vault secret" message.
  - Impact check: proceed. Review: one finding fixed (IPv6), two refuted: Shodan only supports `?key=`, and the env-fallback pattern already exists.
- Known limits:
  - Port nodes merge per `number (protocol)` across IPs, as in `ip/to_ports.py`.
  - VirusTotal fetches one page (40 results).
  - A key set only as an environment variable is ignored when a user vault exists (existing shared behaviour).

Next:
- ~~Add the keys to the Vault and run the keyed enrichers live.~~ Done, see below.
- Connector batch 2: Sekoia (STIX objects plus a relationships call) and Driftnet (verify the API contract first).

## 2026-09-30 — local/connectors live keyed run (base = local/connector-prep @ 75daab45)
Done:
- The Vault now holds SHODAN, ABUSEIPDB, VT and THREATFOX keys. All 6 keyed enrichers were run live on 151.101.128.223 / python.org: 6 tasks succeeded, 0 tracebacks.
  - Shodan: 80/443 plus the python.org and www.python.org hostnames. AbuseIPDB: score 0. ThreatFox: no hits (expected). VT domain→ips: 23 historic IPs.
- Fix `f1f74873`: VT pDNS returned `_.python.map.fastly.net`, which `Domain` rejects, and the exception dropped the rest of the page. VT ip→domains and Shodan now skip invalid hostnames one at a time. The live rerun went from 35 to 39 domains with 0 exceptions. A regression fixture fails 3 tests without the fix.
- Gate: ruff and mypy pass; `make test` 58/424/73/17. Delta review: correct.

Next:
- ~~Connector batch 2~~ Sekoia done, see below. Driftnet was not built, see below.

## 2026-09-30 — local/connectors-2 Sekoia (base = local/connectors @ 7722a01c)
Done:
- `ip_to_sekoia` and `domain_to_sekoia` (`fb6eef90`) call `GET /v2/inthreat/indicators/context?type=&value=`.
  - Only malware that a non-revoked indicator `indicates` is linked, as input -ASSOCIATED_WITH-> Malware. Infrastructure and intrusion-set targets are logged only.
  - 429 stops the loop. A missing key means no request.
- Rejected `objects?match[value]=`: Sekoia ignores that filter and returned the same 20 unrelated indicators for every IOC. `TH_Department/tools/unified_connector.py` `query_sekoia_cti` has the same bug.
- Live run: 91.92.41.94 → Remcos (RAT) and melbettr.co → ClearFake (downloader), 0 tracebacks. Both test nodes remain in sketch ea919303.
- Gate: ruff and mypy pass; `make test` 58/424/79/17. Impact: proceed. Review: correct.
- Driftnet was not built. The web search page is a client-side SPA over `api.driftnet.io`, which returns 401 without a token. The anonymous token requires a Spur Monocle anti-bot bundle, so automating it would bypass bot protection.

Next:
- Driftnet API enricher, once a free Community token is in the Vault as `DRIFTNET_API_KEY` (Bearer).
