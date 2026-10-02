# Local handoff (local-only fork of reconurge/flowsint)

## 2026-09-30
Done:
- Stock prod stack evaluated (`docker-compose.prod.yml` + local `docker-compose.local.yml`, git-excluded): loopback UI, `group_add: ["0"]` so uid 1001 can use Docker Desktop's root:root 0660 socket, patched enrichers bind-mounted.
- Fixed upstream bug: `ip/domain/organization_to_asn` and `asn_to_cidrs` built `ASN(number=...)` without the required `asn_str`, so every ASN lookup failed validation. Regression test: `flowsint-enrichers/tests/enrichers/test_to_asn.py`.
- Chain verified in UI on python.org: 76 HAS_SUBDOMAIN, RESOLVES_TO 151.101.128.223, BELONGS_TO AS54113 (fastly), 1321 ANNOUNCES CIDRs; 0 Celery tracebacks.
- Review fixes: `org_to_asn` now builds edges from the (org, ASN) pairs recorded in scan (a zip misaligned them when a lookup failed; regression test added). Removed the unreachable `asn_to_cidrs` fallback. Typed the changed enrichers and `tools/network/asnmap.py` (bind-mounted too) so `make typecheck` passes.
- Verified: ruff, `make typecheck BASE_REF=4c05849b`, `make test` (58/416/36/17 passed). Frontend `make lint` step not run: yarn/node_modules absent locally, and no frontend code was changed.

Next:
- Start stack: `make prod` or `make up-prod` now includes `docker-compose.local.yml` when present; stop with `make down`. The local override is intentionally git-excluded and must remain beside the repo to load the connectors.
- Patched and added enricher files are bind-mounted individually in `docker-compose.local.yml`; avoid mounting the whole source tree because the image's database/schema and checkout differ.
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
- ~~Connector batch 2~~ Sekoia and Driftnet done, see below.

## 2026-09-30 — local/connectors-2 Sekoia (base = local/connectors @ 7722a01c)
Done:
- `ip_to_sekoia` and `domain_to_sekoia` (`fb6eef90`) call `GET /v2/inthreat/indicators/context?type=&value=`.
  - Only malware that a non-revoked indicator `indicates` is linked, as input -ASSOCIATED_WITH-> Malware. Infrastructure and intrusion-set targets are logged only.
  - 429 stops the loop. A missing key means no request.
- Rejected `objects?match[value]=`: Sekoia ignores that filter and returned the same 20 unrelated indicators for every IOC. `TH_Department/tools/unified_connector.py` `query_sekoia_cti` has the same bug.
- Live run: 91.92.41.94 → Remcos (RAT) and melbettr.co → ClearFake (downloader), 0 tracebacks. Both test nodes remain in sketch ea919303.
- Gate: ruff and mypy pass; `make test` 58/424/79/17. Impact: proceed. Review: correct.
- Driftnet anonymous (web SPA) access was rejected: its token requires a Spur Monocle anti-bot bundle. It was built on the Bearer API instead, see below.

## 2026-09-30 — local/connectors-2 Driftnet (base = local/connectors @ 7722a01c)
Done:
- `ip_to_ports_driftnet` (`d8326d7a`, plus the token-redaction fix `979fe3d5`) calls `GET https://api.driftnet.io/v1/scan/ports?ip=` with Bearer auth. It creates `Port(number, protocol="tcp", state="open")` and an ip -HAS_PORT-> Port edge.
  - Behavior: a honeypot flag is logged as a warning. 403/429 stops the loop, with the token redacted from the logged body. Other non-200 responses skip that input.
- The Vault entry `DRIFNET_API_KEY` (typo) was renamed to `DRIFTNET_API_KEY`. Only the name column changed; AES-GCM AAD is owner_id.
- Live run through the mounted branch source: the key resolved, the request was sent, and Driftnet returned `403 api usage limit hit`. That was logged, the loop stopped, 0 tracebacks. `admin/user` shows quota 1001/1000 with `next_reset` 2026-06-07 (in the past). No live data response has been verified; the mapping follows the documented example.
- Gate: ruff and mypy pass; `make test` 58/424/84/17. Impact: proceed. Review: correct (after the redaction fix).

Next:
- When the Driftnet quota is back, run `ip_to_ports_driftnet` on 8.8.8.8 and confirm the ports match the documented `values` shape.

## 2026-09-30 — local/connectors-2 file hashes and URLhaus (base = local/connectors @ 7722a01c)
Done:
- Added File hash lookups in MalwareBazaar, ThreatFox and VirusTotal; URLhaus host lookups for IP/domain and URL payload lookup for websites. Kept Driftnet unchanged pending quota reset.
- File updates preserve the original label and omit null fields even for UI-launched nodes; per-file samples are represented by File -ASSOCIATED_WITH-> Malware edges, not an overwritten shared Malware sample list.
- Gate: ruff and mypy pass; `make test` 58/424/104/17. Impact: proceed. Final delta review: correct.
- Live smoke: URLhaus IP→websites and website→payload; MalwareBazaar→RemcosRAT, ThreatFox→AMOS, VirusTotal 10/54. Corrected worker rerun retained one File node with MalwareBazaar source/family and VirusTotal verdict, 0 tracebacks. Production compose stack restored.

Next:
- Driftnet response-shape verification remains waiting for its API quota reset. Optional next connector: VirusTotal domain/IP reputation (reuse the existing VT vault key and request pattern).

## 2026-09-30 — deploy local connectors to the running stack
Done:
- The git-excluded `docker-compose.local.yml` now mounts all 18 added enricher modules plus the checkout's Enricher base (`key()` must not be abstract) into both API and Celery, retaining the stock core/API image and existing ASN patches.
- `make prod`, `make up-prod`, and other production targets automatically apply that override when present. No image was published; no database migration or volume reset was performed.
- API and worker each register 67 enrichers; the authenticated API catalog returns 66 visible entries (the internal dummy is excluded). All 18 additions instantiate in the worker. A `website_to_urlhaus` launch through the API logged started, served a payload, finished; no worker traceback after the fix. `make up-prod` preserved all 67 registrations.

Next:
- `phone_to_breaches` is not implemented. Driftnet data mapping remains unverified until its API quota resets.

## 2026-09-30 — repair deployed ip_to_asn
Done:
- The stock image's `DockerTool(image, default_tag)` conflicted with the mounted checkout's `AsnmapTool()`, which expects the checkout's no-argument DockerTool constructor. Extended the git-excluded local Compose override to mount `dockertool.py` and the five other DockerTool network subclasses together for API and Celery. No image or database changes.
- Recreated API and Celery with `make up-prod`; all six DockerTool network subclasses instantiate in the worker. A real `ip_to_asn` Celery task on the existing smoke sketch completed and returned `AS54113 - fastly` for `151.101.128.223`. `make test`: 58/424/104/17 passed.

Next:
- The override remains local and git-excluded; preserve it on this workstation or bake the compatible source into a future image.

## 2026-09-30 — live case refresh
Done:
- Fixed shared Redis pubsub consumption for sketch log and status SSE streams: each connected viewer now owns a subscription, and closing one viewer no longer disconnects others. The local production override bind-mounts the matching core emitter and API route into the stock image; no frontend build or database change.
- Reproduced the failure with two case tabs (one Redis subscriber per channel despite two viewers). After `make up-prod`, Redis showed two log and two status subscribers. A live `ip_to_asn_ripestat` scan of `105.174.46.30` added AS37119 and refreshed both graphs from 13 to 14 nodes without reload; the console showed start, graph edge and completion. Closing one tab left one subscriber per channel; a second scan refreshed the surviving graph and console.
- Verified `make test` (58/425/104/17 passed), Python ruff format/check (358 files), targeted mypy for the changed core/API routes, and browser-relay smoke on the actual case.

Next:
- Keep `docker-compose.local.yml` alongside this checkout to retain the SSE fix and connector mounts; it is intentionally git-excluded. Reload any case tab left open across API recreation so it reconnects to the new stream.

## 2026-10-02 — investigation workspace improvements
Done:
- Added explicit enrichment outcomes, persisted run summaries and dated relationship observations; canonical entity identities include port host/protocol and certificate fingerprints. Fixed batch input/output pairing and retained graph positions during refresh.
- Added evidence filters, infrastructure visibility controls, change highlights, browser-local personal views, readiness/freshness indicators and relationship evidence details.
- Added persistent case questions/comments/findings, assignments, review decisions and actor activity. Analysis and entity edits use optimistic versions and preserve conflicted drafts; analysis autosaves serialize locally.
- Added bounded passive VirusTotal pagination and domain/IP reputation, certificate metadata, diagnostics and matching API/worker/frontend build revisions. Frontend containers now use the root workspace lockfile; removed the stale app lockfile.
- Documented workspace use and protected PostgreSQL/Neo4j/vault backup and recovery. Recorded the user's runtime preference in local AGENTS.md: foreground checks are allowed; no additional app/database services or deployment.
- Verification: 674 Python tests passed (58 types, 462 core, 128 enrichers, 26 API); four opt-in Neo4j tests skipped in the ordinary suite. Three live Neo4j regression tests and the complete empty-PostgreSQL migration chain passed before temporary services were removed. Final focused task checks: 18 passed. Frontend: 23 tests and production build passed. Strict mypy passed all 140 changed Python files; full lint passed (129 existing frontend warnings). Full frontend typecheck still reports 84 inherited errors, down from 88, with no new diagnostic signatures.
- Existing localhost:5173 case loaded without console errors. The new implementation has not been deployed there. Temporary verification services were stopped and removed; the existing stack is unchanged.
- Matching API/frontend images built successfully during verification. The final-commit rebuild stalled while exporting API layers/building frontend; Docker's read-only status query also stopped responding. Only this run's build/status commands were cancelled; Docker and existing services were not restarted. Final-revision images remain unverified.

Next:
- Review the draft PR and explicitly authorize deployment before migrating/replacing the running stack. Verify the new UI journeys after deployment.
- Retry `make build-local` when Docker responds normally; do not start extra services for verification.
- Perform the documented backup/restore rehearsal against separate volumes when additional database services are authorized. Live provider mapping/quota checks remain dependent on provider access; no fresh provider calls were made for this change.

## 2026-10-02 — apply changes to the existing local review stack
Done:
- User clarified the workflow: update the existing localhost:5173 stack while iterating, then deploy for the team once the local result is approved. Updated local AGENTS.md accordingly.
- Preserved the existing hash-hunt/Modat/parameter-dialog changes in local/investigation-workspace under .local/workspace-review. Backed up PostgreSQL and stopped-Neo4j data with verified archive listings and checksums, preserving authentication and vault settings. Updated only existing application services; no extra database services were started.
- Live diagnostics confirmed matching frontend/API/worker revisions, 72 matching connectors, healthy dependencies and current migrations. Graph infrastructure controls and a personal named view survived reload. A separate Workspace verification case confirmed persistent evidence, assignment, status, reviewer decisions and actor history.
- Browser verification reproduced an immediate-edit conflict on newly inserted nodes: the response returned version 0 while Neo4j stored version 1. Fixed add_node to return the stored node/version, and normalized browser-added properties through the type resolver so their canonical identities match enriched entities. Added regression coverage for both behaviors.
- Repeating that journey exposed missing element IDs in single-node reads and a dropped persisted version during optimistic frontend replacement. Fixed the repository result and all three creation callers through the shared replacement helper. Regression checks cover IDs, versions, graph position and edge endpoint preservation. Combined local suite: 708 Python tests; frontend 24 tests and production build passed. Lint passed; full frontend typecheck remains at 84 inherited errors with no new diagnostic signatures.
- Final matching local images v1.2.12-57-g7d8611cfb274 built and were applied using the git-excluded docker-compose.local.yml. Normal local Compose commands now retain these images instead of the previous per-file overlays. Original overrides and data are backed up under backups/workspace-20261002T050710Z. No additional app/database services were created.
- Repeated the failed journey on the final build: a fresh entity's first property edit returned 200, advanced its persisted version to 2 and survived reload. A second tab's stale edit returned 409 while retaining its draft; Load latest recovered the saved version. Analysis title/body autosaves survived reload. Final UI diagnostics: all builds match, 72 connectors match, migrations current and all dependencies healthy.
- Feature branch checks: 676 Python tests; combined local integration: 708 Python tests (four optional live tests skipped). Frontend: 24 tests/build, full lint and changed-file strict mypy passed. The clearly named Workspace verification case contains the browser smoke checks.

Next:
- Review the modified existing localhost:5173 stack, then authorize team deployment when happy with it. A complete backup/restore rehearsal and fresh provider responses remain unverified; no separate database environment was started.

## 2026-10-02 — reviewed investigation copilot
Done:
- Added selected-entity planning, reviewed passive execution through existing enrichment workers, bounded evidence summaries, reusable flow recipes and pending draft findings. Reuses the configured Mistral/OpenAI provider; missing model configuration produces explicitly labelled deterministic suggestions and summaries.
- Plans allow at most ten selected entities and three independent steps: root-domain normalization and exact domain/IP ThreatFox lookups. API checks current permissions, compatible IDs/types, provider prerequisites and entity versions; model text cannot supply commands, URLs, Cypher or new target scope. Structured context is bounded and credential fields removed.
- All steps serialize before queueing; partial broker failures retain the IDs already queued. UI tolerates scan rows appearing after tasks are consumed, preserves reviewed entity labels and offers bounded polling/recovery. Saving recipes after enrichment does not depend on stale node versions and stores no original entity IDs.
- Graph toolbar controls expose their text labels to assistive tools, including the selected-entity copilot action.
- Live verification completed local normalization and saved its flow recipe. Draft-finding saving exposed a pre-existing sketch metadata serialization failure; GET now uses the existing ORM response schema, with nullable descriptions matching stored data. The new regression fails before the fix and passes after it; 24 focused API checks passed.
- Source checks: 721 Python tests passed (58 types, 487 core, 128 enrichers, 48 API); four optional live Neo4j tests skipped. Frontend: 31 tests and production build passed. Full lint passed with 129 inherited frontend warnings; changed Python mypy passed. Frontend typecheck retains 84 inherited diagnostics with none in changed files.

Next:
- Apply the combined source to the existing local API/worker/frontend images, verify the selected-entity journey in the browser, then update the existing draft PR. Team deployment remains pending approval.
