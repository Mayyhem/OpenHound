---
id: Ope-6cei
status: closed
deps: []
links: []
created: 2026-05-28T13:27:29Z
type: feature
priority: 1
assignee: Mayyhem
tags: [sccm, performance]
---

# Concurrency / Parallelism

Implement per-host parallel collection using the existing --threads CLI flag. The flag is parsed and mapped to SOURCES__SCCM__THREADS but no collector uses it. Phase 3 (per-host: WMI, HTTP, SMB, AdminService, RemoteRegistry, MSSQL) is the bottleneck in large environments.

## Design

Wire --threads into Phase 3 per-host resource generators. Use concurrent.futures.ThreadPoolExecutor for per-host parallelism. Ensure thread-safe access to TargetQueue, _shared_ad_cache, _shared_discovered_domains (already protected by threading.Lock in context.py). Respect write_disposition=append semantics for DLT. Add [target][phase] prefixed progress logging per host.

## Acceptance Criteria

With --threads 10, Phase 3 runs collectors for up to 10 hosts simultaneously. No data races or duplicate node/edge output. Falls back to sequential (threads=1) without code change.

## Notes

**2026-07-02T20:19:25Z**

Done in code: --threads (default 10) -> main.py::_run_per_host_stage(max_workers=threads) -> phased_pipeline/engine.py ThreadPoolExecutor; Phase 3 runs per-host concurrently. Original 'no collector uses it' premise is stale (delivered by ope-0112 framework + per-host collectors).
