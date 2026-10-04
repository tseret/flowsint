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

## 2026-10-02 — live copilot verification
Done:
- Applied matching local images v1.2.12-67-g2822b10ba7b7 to the existing API, worker and frontend; no extra services or schema changes. Preserved the existing local connector work in .local/workspace-review. Browser diagnostics report matching builds, 72 matching connectors, healthy dependencies and current migrations.
- Selected copilot-review.example.org in the Workspace verification case, generated a plan, removed ThreatFox and ran local normalization with zero external lookup calls. Run b22969f5-a43b-452c-a5c7-6dbf637d53ae completed with one output, added example.org and its relationship, and produced a cited factual summary.
- Saved the completed plan as an ordinary flow (13ec48fd-8536-4ae6-97a9-d03000988b0c) after enrichment updated entity versions; it renders in the normal editor. Repeated the failed draft-finding save after the metadata fix: it succeeds and persists in the case with supporting run references, open status and pending review. Actor activity is recorded.
- Final source checks: 723 Python tests (58/487/128/50); combined local source: 755 (58/488/159/50), with four optional live Neo4j tests skipped. Frontend: 31 tests and final image production build passed. Full lint passed with 129 inherited warnings; the full changed-file Python mypy gate passed. Frontend typecheck retains 84 inherited diagnostics with none in changed files.
- The current account has no configured LLM key: live planning/summaries used the labelled deterministic fallback. Model planning and grounded summary success/failure paths were verified with mocked providers. No fresh intelligence-provider requests were made. Implementation and user guide are included in the existing PR https://github.com/tseret/flowsint/pull/1.

Next:
- Configure the chosen LLM provider's key in Vault for question-specific AI planning, then review the local copilot. Team deployment remains pending approval. Graph arrangement and defensive hunts over imported telemetry remain future capabilities.

## 2026-10-02 — GPT-6.1 Sol configuration
Done:
- Selected GPT-6.1 Sol with medium reasoning effort for the existing local review stack, following the user's cost preference. Added explicit OpenAI reasoning-effort forwarding for complete/stream requests and installed the previously missing OpenAI SDK in the core package and lockfile.
- Exposed provider/model/effort environment settings in production Compose while retaining its existing provider default. Documented the local settings and Vault key name. Corrected the streaming protocol annotation to match the existing async-generator implementations and caller.
- Configuration regression tests cover both request paths, omitted effort, streaming chunks, and invalid effort before client creation. All 726 Python tests passed (58/490/128/50), with four optional Neo4j tests skipped. Full lint passed with 129 inherited frontend warnings; the full changed-file Python typecheck gate passed. Frontend source is unchanged.
- Applied matching local images v1.2.12-71-g1e609c89 to the existing API, worker, and frontend. Both API and worker report openai / gpt-6.1-sol / medium. Production provider construction with a dummy key confirms SDK/model/effort without making an API request. Services are healthy and localhost returns HTTP 200; browser reload preserves the verification graph and opens its copilot.
- Overlapping image builds temporarily stalled Docker and localhost connectivity; both completed successfully and the existing application services recovered after their image update. Run future local image builds sequentially to avoid resource pressure. No database services or volumes were recreated.

Next:
- Add OPENAI_API_KEY in Vault for model-backed runs; live model access and response quality remain unverified. Final-review investigation automation remains follow-on work; the current reviewed-plan workflow is unchanged. Team deployment remains pending approval. Draft PR: https://github.com/tseret/flowsint/pull/1.

## 2026-10-02 — actionable copilot provider errors
Done:
- Reproduced the reported planning failure with the configured Vault provider inside the existing API: OpenAI HTTP 429, credit_balance_exhausted. No key, provider response body, or entity context was printed. This is a project billing/quota failure, unrelated to changed graph entities.
- Planning and summaries now return fixed, actionable messages for OpenAI credit/quota, authentication, model access, rate-limit, and connection failures. Removed the UI's unconditional entity-change advice. Provider response bodies remain private; no automatic model substitution was added.
- Eight regression cases cover both endpoints' quota errors and redaction plus authentication/access/rate-limit messages. All 734 Python tests and 31 frontend tests passed; full lint passed with 129 inherited frontend warnings; the changed-file Python typecheck gate passed.
- Removed the three requested test investigations, the smoke-test sketch within Hexanet, and the generated copilot flow through the existing UI. Hexanet's Infra + seeds graph and the preexisting example flow were preserved.
- Built API/worker and frontend sequentially and applied matching images v1.2.12-75-gf2e8135e. All three services are healthy; localhost returns HTTP 200. A live synthetic prompt using the existing Vault provider reproduces the exhausted-credit error and now returns the fixed billing/quota message. No enrichment tasks were launched.
- Browser automation failed to initialize its native pipe twice. Automatic approval review rejected a repeat planning test with Hexanet context because it would transfer investigation data to OpenAI; used a synthetic prompt instead. API regressions exercise the planning/summary handlers with fixture data. Full frontend typecheck retains 84 inherited errors and none in the changed copilot file.

Next:
- Replenish the OpenAI project's API credits or use a funded project key before successful model planning can be verified. Browser verification of the new text remains unavailable in this session. Team deployment remains pending approval. Draft PR: https://github.com/tseret/flowsint/pull/1.

## 2026-10-02 — ChatGPT subscription connection
Done:
- Added local Continue with ChatGPT sign-in using documented public OAuth and Responses endpoints, with encrypted per-user sessions in the existing Vault. State/nonce/PKCE, one-use callbacks, verified identities, serialized rotating refresh, saved accounts, model discovery, and disconnect/revocation are covered by regressions. Callback secrets are excluded from API and nginx access logs; reserved records cannot be read, overwritten, or deleted through the public key routes.
- Profile now offers explicit subscription or separately paid API billing. Copilot planning, summaries, and chat share the connection; default model is GPT-6.1 Sol with medium reasoning. Unavailable models, disconnected sessions, and subscription limits never trigger API billing or a different model automatically. Failed partial chat streams are not saved as completed answers.
- All 774 Python tests and 39 frontend tests passed, with four optional live Neo4j skips. Full lint passed with 129 inherited frontend warnings; targeted mypy passed for all new/changed Python files. Full frontend typecheck still reports 84 inherited errors and none in the connection/copilot changes.
- The combined managed review checkout passed 806 Python tests, 39 frontend tests, full lint, and its complete changed-file Python typecheck gate after synchronizing locked workspace dev dependencies. Built API/worker and frontend sequentially and applied matching images v1.2.12-79-g32755655 to the existing stack. All three are healthy; Profile returns HTTP 200. Authenticated live diagnostics verify 72 matching connectors, current migrations, healthy PostgreSQL/Redis/Neo4j, and matching API/worker revisions. Live connection status defaults to disconnected subscription, GPT-6.1 Sol, medium; unauthenticated status is rejected and disconnected provider creation returns the actionable sign-in error without API fallback.
- Browser automation remains unavailable because its native pipe cannot start. No extra application/database services or test investigations were created; successful OAuth and inference await personal sign-in/consent. No investigation context was sent to an external model during verification.

Next:
- Complete personal ChatGPT sign-in and consent in Profile to verify account eligibility, the live model catalog, and successful inference. This local loopback flow is not the remote team sign-in flow; team deployment remains pending approval. Draft PR: https://github.com/tseret/flowsint/pull/1.

## 2026-10-02 — passive IP intelligence collection
Done:
- Added Gather IP intelligence for up to ten selected IPs. It runs all installed, credential-ready supported passive lookups and automatically summarizes terminal outcomes, without requiring the model to choose tools. Missing-key providers are shown as gaps and retained in draft findings. Original selected entities are the only execution inputs; related infrastructure remains evidence for human review rather than automatic follow-up requests.
- Expanded planning to seven steps, covering indexed Shodan services, optional installed Modat ports, VirusTotal reputation and two pages of historical DNS, plus existing ThreatFox/root-domain actions. Server-owned credential requirements and fixed DNS limits cannot be overridden by generated plans. Collection checks model/subscription readiness and permissions before queuing provider usage.
- Preserved indexed Shodan banner/HTML/favicon/TLS fingerprints, source references and observation timestamps. Evidence summaries include only relationship observations attributed to the selected authorized runs, alongside actual output records, provider errors and truncation indicators. Provider-observed open ports do not imply current reachability.
- Feature verification: 783 Python tests and 41 frontend tests pass; four optional live Neo4j tests skipped. Full lint retains 129 inherited warnings; frontend typecheck retains 84 inherited errors with none in changed copilot files. The user's connected account uses explicitly selected GPT-5.6 Sol, medium; synthetic subscription inference previously succeeded.

Next:
- Combined checkout passed 815 Python tests, 41 frontend tests, full lint, and its complete changed-file Python typecheck gate. A test-only follow-up corrected the optional installed Modat expectation; production behavior was unchanged. Built API/worker and frontend sequentially and applied matching images v1.2.12-83-ge7fe865d. All three are healthy; localhost and the specified graph page return HTTP 200. Live diagnostics confirm matching worker/API, current migrations and healthy PostgreSQL/Redis/Neo4j. The bounded run-scoped relationship query executes successfully against Neo4j and excludes unrelated evidence. Collection rejects unauthenticated and nonexistent selections before queueing.
- Live readiness confirms all five IP providers have configured keys for the three Hexanet IPs, with no missing-key skips. The active subscription remains connected to GPT-5.6 Sol, medium. Browser automation remains unavailable; no test investigations or live intelligence-provider requests were created for verification. Use Gather IP intelligence in the graph for collection and automatic reporting. Team deployment remains pending approval. Draft PR: https://github.com/tseret/flowsint/pull/1.

## 2026-10-02 — existing related-IP evidence review
Done:
- Added a read-only, sketch-scoped candidate review for existing/imported Modat pivot and shared historical DNS paths. It never calls discovery providers, an LLM or follow-up enrichment. ASN/port-only links are excluded; evidence, dated observations and truncation limits are visible.
- Added pending/accepted/rejected findings using existing versioned collaboration APIs, restored only for the same entity/sketch/evidence. Partial create/update failures retain the created finding and concurrent edits require reload.
- Feature checks: 796 Python tests; combined integration: 828 Python tests. Both pass 44 frontend tests, full lint and complete changed-file Python typecheck gates; four optional live Neo4j skips and 129 inherited lint warnings. Frontend typecheck retains 84 inherited errors with none in the changed files. Both final production images built successfully.
- Applied matching v1.2.12-89-g292fb541 images to the existing API/worker/frontend, all healthy. Authenticated live candidate review of three Hexanet IPs returns zero candidates with no truncation; no supported related-IP path currently exists. Missing entities and anonymous requests are rejected. Live diagnostics confirm 72 matching connectors, current migrations and healthy dependencies; subscription remains GPT-5.6 Sol / medium. No provider requests, extra services or test records were created. Browser verification remains unavailable because its native pipe fails to start.

Next:
- Review existing/imported evidence with the new panel. The ip_to_ips_modat discovery connector is not added to autonomous execution. Team deployment remains pending approval. Draft PR: https://github.com/tseret/flowsint/pull/1.

## 2026-10-02 — recorded Modat service fingerprint visibility
Done:
- Traced the reported HASSH blind spot: the local Modat port connector discarded fingerprints, planning context omitted neighbor port properties, and graph-only review could not show unqueried service leads. The separate local related-IP connector also requires three fingerprint families before a service is eligible; it remains outside autonomous copilot execution.
- Retained returned Modat SSH/banner/HTTP/TLS fingerprints and available observation provenance; surfaced recorded service leads independently of existing peer paths and included bounded port properties in planning evidence. Provider failures are collection gaps, not successful empty results. Shared fingerprints do not establish common control.
- Feature checks: 805 Python tests; combined integration: 833 Python tests. Both pass 44 frontend tests, full lint and complete changed-file Python typecheck gates. Four optional live Neo4j skips; 129 inherited lint warnings. Frontend typecheck retains 84 inherited errors with none in changed files. Both production images built sequentially.
- Applied matching v1.2.12-93-g19f9450d images to the existing stack, all healthy; diagnostics retain 72 matching connectors, current migrations, healthy dependencies and GPT-5.6 Sol / medium. Live read-only review initially showed ten fingerprint-bearing services but zero stored HASSH values; production serialization round-trip preserves an SSH-only hash.
- Refreshed only Modat’s indexed host/service record for the user’s explicitly identified existing IP 185.253.219.31. Run b25d02fe-fbdd-461e-91ed-81d3c56f0e7e completed with 12 ports. The live review now exposes the reported port-22 HASSH 5d77df1447142e23c5f97defc23dbd08 with Modat provenance. No peer search, new-target query, LLM inference, extra services or test investigations were launched. Browser automation remains unavailable.

Next:
- Inspect the refreshed service evidence in the graph and copilot. Other legacy Modat port records need an explicitly chosen passive refresh to recover discarded metadata. Autonomous external infrastructure expansion is not implemented; team deployment remains pending approval. Draft PR: https://github.com/tseret/flowsint/pull/1.

## 2026-10-02 — human-triggered indexed service lookup and Port journey
Done:
- Added contextual Port review and explicit source-IP passive service refreshes, fixing the dead Port-category launcher. Ownership is resolved from a unique scoped HAS_PORT source and checked against the recorded host; missing/ambiguous owners disable actions.
- Added server-owned Modat service-query previews and one-page user-triggered fingerprint lookup. Stored endpoint/hash/version, permissions and credentials are rechecked; no arbitrary query/value inputs, LLM usage, three-family candidate gate, follow-up matched-IP requests or automatic graph insertions. Matches preserve exact hash comparisons, banners, observation dates, source references and truncation.
- Reused pending case findings for indexed candidates with bounded evidence snapshots, exact-evidence retry recovery and ordinary case review controls. Preserved Modat scanned_at and readable banners instead of discarding context.
- Feature checks: 829 Python tests; combined integration: 857 Python tests. Both pass 55 frontend tests, full lint and complete changed-file Python typecheck gates. Four optional live Neo4j skips; 129 inherited lint warnings. Frontend typecheck retains 84 inherited errors and none in changed files. Final production images built sequentially; local connector work remains preserved.
- Applied matching v1.2.12-103-g5d31b59c images to the existing API/worker/frontend, all healthy. Diagnostics verify 72 matching connectors, current migrations, healthy dependencies and retained GPT-5.6 Sol / medium. Browser automation remains unavailable because its native pipe fails to start.
- Refreshed only the existing example IP’s Modat record (run 1349cc68-e365-437a-835b-c5717701a56c, 12 ports), restoring its SSH banner and provider observation date. The live query port=22 protocol="ssh" transport="tcp" ssh.hassh="5d77df1447142e23c5f97defc23dbd08" returned four records, including the source: three verified endpoint/hash matches, no truncation. Saved three pending candidate findings attached to the source Port, with exact query and evidence snapshots. No matched-IP queries, probing, automatic graph insertion, LLM inference, extra services or test investigations were performed. Live guards reject stale snapshots, unsupported fields, missing services and anonymous lookup.

Next:
- Reload the graph, select the source SSH Port and inspect its context, indexed query controls and three pending findings. Review decisions remain human actions. Team deployment remains pending approval. Draft PR: https://github.com/tseret/flowsint/pull/1.

## 2026-10-03 — saved fingerprint candidates into graph
Done:
- Added explicit graph import from lookup results and previously saved case findings. Imports one saved finding ID/version, validates scope, endpoint and exact recorded fingerprint/query, and rejects stale/rejected evidence. No provider call or LLM use.
- Creates candidate IP and its own host-specific Port, HAS_PORT ownership and SHARES_FINGERPRINT evidence links to the source service. Canonical identities and create-only properties preserve existing enrichment; retry deduplicates nodes, links and observations. Review decision stays unchanged.
- Feature checks: 839 Python and 59 frontend tests pass; full lint passes with 129 inherited warnings. Four optional Neo4j skips. API regressions cover import/retry, saved evidence, permissions, stale/deleted graph and invalid findings.
- Both committed changed-file Python typecheck gates pass. Combined integration: 867 Python and 59 frontend tests pass, full lint passes. Sequential API/frontend production builds pass; preserved local connectors. Frontend typecheck retains 84 inherited errors with none in changed files.
- Reproduced live failure: all three saved candidates absent from graph. Applied matching v1.2.12-107-g84099131 images to existing API/worker/frontend; all healthy. Diagnostics confirm matching worker/API, current migrations, healthy dependencies and retained GPT-5.6 Sol / medium subscription.
- Imported all three existing Hexanet findings via the new endpoint. Live graph now has 23 nodes and 20 edges. Verified candidate IPs own distinct host-specific SSH Ports, exact evidence snapshots on SHARES_FINGERPRINT links, correct service-context ownership and pending decisions. Retried all three imports: same IDs, unchanged graph counts. No provider calls, candidate probes, LLM inference, extra services or test investigations. Browser native pipe remains unavailable; live journey verified through authenticated API and graph reads.

Next:
- Reload Hexanet’s graph to inspect the imported candidates. Saved findings now offer Add candidate to graph; review decisions remain separate human actions. Team deployment remains pending approval. Draft PR: https://github.com/tseret/flowsint/pull/1.

## 2026-10-03 — direct fingerprint pivots and expandable services
Done:
- Changed saved-finding import to connect source IP directly to candidate IP, with a readable service/fingerprint caption and exact saved evidence. Existing Port nodes and HAS_PORT ownership stay intact. Explicit reimport copies historical observations to the direct edge and soft-deletes the legacy service-to-service link.
- Source IP ownership and service version are checked in the graph write. Canonical nodes, enrichment properties, observation deduplication and pending review decisions remain preserved. No provider or LLM request is needed.
- Reproduced the current live layout: three candidate IPs exist, connected through three legacy Port-to-Port fingerprint links. Backend Python suites and focused mypy pass.
- Graph view now collapses only the matching pivot service leaves by default; selected services and unrelated relationships stay visible. Show pivot services restores the full view. Tables and the stored graph retain all records. Readable edge details show exact query, endpoints, hashes, banners, observation dates and references; graph captions preserve the underlying relationship type.
- Feature checks: 839 Python tests; combined integration: 867. Both pass 68 frontend tests, full lint and committed changed-file Python typecheck gates. Four optional Neo4j skips, 129 inherited lint warnings, 84 inherited frontend type errors (including the existing GraphMain context-menu diagnostic), no new diagnostic signatures. API and frontend production images built sequentially.
- Applied matching v1.2.12-111-g5b478f88 images to existing API/worker/frontend, all healthy. Diagnostics confirm matching worker/API, current migrations, healthy dependencies and retained GPT-5.6 Sol / medium. No additional services or provider/model requests.
- Updated all three existing Hexanet pivots via saved-finding reimport: three direct IP-to-IP SHARES_FINGERPRINT links captioned Shared SSH HASSH · port 22, zero active legacy Port-to-Port links. Service records, ownership and exact observations remain; findings stay pending. Repeated imports preserve IDs, node/edge counts and observations.
- Executed the compact helper against the live graph snapshot: 19 visible nodes/16 edges, three direct IP pivots and four supporting service nodes collapsed. Expansion restores all 23 nodes/20 edges. Live API/graph checks and rendered component regressions verify the journey; browser native pipe remains unavailable.

Next:
- Reload Hexanet and select a pivot link to inspect its evidence; use Show pivot services for endpoint detail. Team deployment remains pending approval. Draft PR: https://github.com/tseret/flowsint/pull/1.

## 2026-10-03 — autonomous passive investigation agent
Done:
- Replaced the fixed-plan copilot with the `run_investigation_agent` Celery task. The LLM (ChatGPT subscription, GPT-5.6 Sol / medium) picks one allowlisted passive enricher per step (at most 10 nodes per step, `max_steps` 1–50, default 20), then writes a markdown report citing `[scan:<id>]` and up to 5 pending draft findings. Runs persist in `agent_runs` (migration `20261003_agent_runs`). Routes: `POST/GET /api/copilot/agent`, `GET /agent/{id}`, `POST /agent/{id}/cancel`. The old copilot routes were removed.
- Live smoke test in a throwaway sketch, since deleted:
  - Run 1 found 3 bugs from this branch, all now fixed with a regression test. (1) `max_pages` failed validation because `build_params_model` types every param as `str`. (2) CIDR enrichers crashed because legacy identity passed a raw `IPv4Network` to Neo4j; it is now JSON-normalized. (3) The canvas did not refresh as agent steps finished; it now refetches after each step.
  - Run 2 completed 5 steps: VirusTotal 45, InternetDB, RIPEstat ASN, Shodan ports. It added 176 nodes and 4 pending findings, and the UI rendered the report.
- Review fixes:
  - Typed node properties are now redacted before reaching the prompt.
  - `domain_to_asn` was dropped from the allowlist because it performs live DNS.
  - Agent parents now run on a dedicated `agents` queue served by the new `celery-agents` service (`-Q agents --concurrency=4`), so child `run_enricher` tasks never wait behind them. This replaced an admission cap and an in-process enrichment attempt; both failed review.
- Applied images v1.2.12-124-gf0f8745d (api, celery, celery-agents, app). Smoke run on 31.222.235.175: the agent ran on celery-agents, InternetDB and VirusTotal lookups ran on celery, and the run completed with a cited report and 2 pending findings.

Next:
- Any deploy must also start the `celery-agents` service; without it, agent runs stay queued.
- Select 1–10 entities in a sketch, click Investigate selected entities, enter an objective and run. Review the draft findings in the case workspace. Team deployment still needs approval. Draft PR: https://github.com/tseret/flowsint/pull/1.

## 2026-10-04 — fail agent runs whose worker died
Done:
- The worker stamps `agent_runs.started_at` (migration `20261004_agent_run_started`). Reading a run (latest, by id, cancel) marks it `failed` with "The agent worker stopped before finishing. Start a new run." once it has stayed `running`/`publishing` for `AGENT_DEADLINE_S` + 10 min after it started, so the UI stops polling. Queued runs (no `started_at`) are left alone. The cutoff is keyed to the task's own deadline because thread-pool workers do not enforce celery's `task_time_limit`.
- Applied api/celery/celery-agents image v1.2.12-130-g5349295a; the migration ran. On Postgres, throwaway rows started 2 h ago (lost → failed), 1 h ago (live → running) and never (queued → running). The rows were deleted afterwards.

Next:
- Rows already stuck before this migration have no `started_at` and are not reaped; none exist locally. Team deployment still needs approval. Draft PR: https://github.com/tseret/flowsint/pull/1.

## 2026-10-04 — show queued agent runs waiting for a worker
Done:
- Agent run responses now include `started_at`. The copilot sheet shows "Waiting for an agent worker. The run starts when one is available." while a run is `running` without `started_at`, instead of "Running · step 0 of N".
- Applied api/celery/celery-agents/app images v1.2.12-133-g7fac3006. In-container check on Postgres: a queued row returns `started_at: null` and a started row returns its timestamp; the served bundle contains the new text. No browser check: no localhost:5173 tab was open.

Next:
- Open the copilot sheet with `celery-agents` stopped to see the waiting message. Team deployment still needs approval. Draft PR: https://github.com/tseret/flowsint/pull/1.

## 2026-10-04 — stop shared-hosting floods in copilot reverse DNS
Done:
- Reverted agent run 6a071010-ebf5-4a5e-828d-b7855e517cc6 on sketch d15772f2-…: soft-deleted the 501 domains it added (707 edges) and its 3 draft findings; the sketch is back to 56 live nodes. The `agent_runs` row is kept as history.
- `ip_to_domains_virustotal` takes `max_hosts` (default 0 = no limit). An IP whose retrieved passive DNS pages hold more distinct hostnames than the cap is skipped and reported `partial`; other IPs in the batch are kept. The copilot passes `max_pages=1`, `max_hosts=15` and its decision prompt now discourages reverse lookups unless co-hosting is the objective.
- Applied api/celery/celery-agents image v1.2.12-136-g4d720d26. Live launch on 185.18.199.45 with `max_hosts=15`: 0 domains, partial "resolves 40+ hostnames (shared hosting); skipped". `make test`: 58 / 544 (4 skipped) / 147 / 82 passed.

Next:
- No copilot rerun on the real sketch (skipped by choice, to save VT/LLM quota). Neo4j flattens `nodeMetadata.*` keys: query them as ``n.`nodeMetadata.scan_id` ``. Team deployment still needs approval. Draft PR: https://github.com/tseret/flowsint/pull/1.

## 2026-10-04 — keep the first creating scan on graph nodes
Done:
- Node MERGE now sets `nodeMetadata.created_by_scan` once, on create, or when a scan revives a soft-deleted node. Later scans that re-merge the node only restamp `nodeMetadata.scan_id`. Existing nodes have no `created_by_scan`. Nodes created outside a scan (e.g. manual adds) leave it null.
- Applied api/celery/celery-agents image v1.2.13-114-g343d1e5d. In-container smoke on a throwaway sketch, using the batched enricher path: create scan-a → (scan-a, scan-a); re-merge scan-b → (scan-a, scan-b); soft-delete + scan-c → (scan-c, scan-c); cleanup left 0 nodes. Live regression `test_first_creating_scan_survives_later_scans` runs only with `FLOWSINT_TEST_NEO4J_URI`.

Next:
- "Undo agent run": one route that soft-deletes nodes whose `created_by_scan` is in the run's step scan IDs, plus the run's findings. Team deployment still needs approval.

## 2026-10-04 — undo an agent run
Done:
- `POST /api/copilot/agent/{run_id}/undo` (editor+) soft-deletes these live items in the run's sketch:
  - nodes whose `created_by_scan` is one of the run's step scans;
  - the edges of those nodes;
  - edges whose first observation names one of those scans.
  It also deletes run findings still at version 1 (never edited or reviewed), logging a `deleted` case activity, and sets the run status to `undone`. It is idempotent.
- It returns 409 while the run is running or publishing, or while any step scan is still pending and younger than Celery's hard time limit.
- The copilot sheet has an "Undo run" button (with a confirm dialog) on completed, failed and cancelled runs. After an undo it refreshes the graph and the case workspace.
- Applied api/celery/celery-agents/app images v1.2.13-117-gd9cea7cb.
  - Live Cypher smoke on a throwaway sketch removed the scan's node and its edge, plus the scan's edge between pre-existing nodes. It kept another scan's node and edge. A second call removed 0. Cleanup left 0 nodes.
  - In the UI, the button and confirm dialog appear on run 6a071010. The dialog was cancelled.

Next:
- Runs from before the provenance fix (6a071010, 1a9c2dc1) reach 0 nodes, because their nodes have no `created_by_scan`. Team deployment still needs approval. Draft PR: https://github.com/tseret/flowsint/pull/1.
