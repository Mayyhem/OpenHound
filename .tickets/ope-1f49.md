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

**2026-07-13T18:29:35Z**

Phase 2 (MINIMAL, per user decision) complete. (a) log_context.py sources VERBOSE from the shared lib (import registers addLevelName + Logger.verbose); local VERBOSE/_verbose removed; all SCCM-specific logging machinery (resource ctx, completion callbacks, _DebugExcInfoFilter, per_host/per_pair iterators, cached_with_log, trace_*, VerboseLogger, superset install_filter/with_log_context) kept LOCAL. (b) models/graph_edge.py now subclasses the shared graph base (same pattern as mssql): inherits fields/as_node/config, sets traversable_kinds=TRAVERSABLE_EDGE_KINDS, overrides edges for SCCM relay/lean CMBP-cased props. (c) pyproject: mypy override for openhound_collector_common.* (untyped; py.typed deferred as hygiene task). StubNode + full log_context core stay LOCAL (entangled/volatile glue, D5). No shared-lib change this phase -> mssql unaffected. Results: SCCM 582 passed/5 skipped (baseline parity), ruff clean, mypy no new errors (only pre-existing openhound.core untyped + markup/verbose).

**2026-07-13T18:40:39Z**

Phase 3 (source_bridge) DECLINED (principled divergence). Tried to unify the DONE marker + dedup the byte-identical stream primitives by re-exporting DONE/build_streams/broadcast_done from the shared source_bridge into phased_pipeline/streams.py. BLOCKED by a hard, test-enforced invariant: test_pp_engine::test_engine_source_imports_nothing_project_specific forbids 'dlt','ldap3','openhound','openhound_sccm' in ANY phased_pipeline import line -- the engine is deliberately a zero-dependency, liftable-into-its-own-package sub-package. Importing openhound_collector_common.dlt.source_bridge violates it (both 'openhound' and 'dlt' in the path); no alternative path exists (shared lib IS named openhound_collector_common). DONE is identity-compared, so a partial consumer-side adoption would deadlock (engine broadcasts its own DONE; shared StreamBridge.drain_stream hardcodes the shared DONE). Conclusion: SCCM's push->pull machinery is correctly coupled to its portable engine; the shared StreamBridge is the engine-LESS alternative for collectors like mssql. Keep SCCM's engine+streams+source.py emit machinery LOCAL. Reverted streams.py; engine tests green (18 passed). Emerging pattern: architecture-integrated subsystems (log_context, engine/source_bridge) resist sharing; remaining value is the leaf client stacks (dns, auth, ad, wmi, mssql-EPA).

**2026-07-13T18:56:41Z**

Phase 5 (auth leaf helpers) COMPLETE + LIVE-VALIDATED. http_auth.py re-exports EMPTY_LM_HASH/format_hashes/split_user_domain from shared clients/auth (byte-identical; local copies removed). Callers http.py/wmi.py/smb_sso.py import these from http_auth -> now transparently shared. smb_sso._split_user_domain kept LOCAL (different: NetBIOS short domain + None-guard, not the shared full-domain helper). mssql_epa's own copies deferred to Phase 8. Validation: unit 582 passed/5 skipped (parity), ruff clean, mypy no new errors. LIVE LAB (up): pre-migration baseline captured green first, then post-change SMB SSO (ps1-pss) + HTTP Negotiate (ps1-sms) all 3 identities = 4 integration tests passed. First phase validated end-to-end vs live lab per D8. NOTE Phase 3 declined earlier (portable-engine invariant). Lab connection for integration tests: OH_SSO_INTEGRATION=1; OPENHOUND_HTTP_TEST_TARGET=ps1-sms.mayyhem.com DOMAIN=mayyhem.com KDC=dc.mayyhem.com USER=domainadmin PASSWORD=password NTHASH=8846f7eaee8fb117ad06bdd830b7586c.
