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
