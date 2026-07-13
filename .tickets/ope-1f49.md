---
id: ope-1f49
status: in_progress
deps: []
links: []
created: 2026-07-13T14:57:26Z
type: task
priority: 1
tags: [migration, shared-lib]
---

# Migrate SCCM onto openhound-collector-common shared library

Migrate the SCCM extension onto the openhound-collector-common shared library (editable path dep), deleting SCCM's duplicated infra. Plan: sccm/sccm/docs/superpowers/specs/2026-07-02-sccm-shared-lib-migration-design.md. Phases: 0 Foundation (merge+graph/gitignore fix+pyproject+unit green), 1 duckdb_safe, 2 log_context core+graph base, 3 source_bridge, 4 discovery/dns, 5 auth primitives, 6 clients/ad, 7 clients/wmi, 8 clients/mssql EPA, 9 cleanup+governance docs+full lab validation. Declines: convert_pipeline, socks (stay local). Read-only lib governance rule.

## Notes

**2026-07-13T14:57:36Z**

Phase 0 complete: (0a) integration branch = ohsccm + ohmssql merged clean; (0b) root-caused missing shared graph/ package to an unanchored '.gitignore graph' pattern, fixed with negation, package now tracked + 8/8 graph tests pass, committed 9d1f895; (0c) SCCM pyproject depends on the lib via editable path + [tool.uv.sources]; (0d) uv sync OK, impacket resolved to >=0.13.1, SCCM unit suite 582 passed/5 skipped - no regression. 0e (lab output baseline) deferred until before live-auth phases 5-8. Next: Phase 1 duckdb_safe.

**2026-07-13T16:46:55Z**

Phase 1 (duckdb_safe) complete: SCCM transforms.py now uses shared safe_execute/ensure_columns/arr_sql via thin local wrappers (names + call sites unchanged; SCCM logger + wmi/adminservice sibling-miss injected). Shared-lib change (user-approved Option 1): safe_execute/ensure_columns gained optional logger= (default module logger; mssql unaffected). Results: SCCM 582 passed/5 skipped (baseline parity), targeted 28 passed, mssql 172 passed, ruff clean, mypy no new errors (15 pre-existing at HEAD -> 14). Note: shared lib lacks py.typed (informational; deferred as hygiene item).
