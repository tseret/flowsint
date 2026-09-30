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
