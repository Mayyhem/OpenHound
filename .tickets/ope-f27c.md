---
id: ope-f27c
status: open
deps: []
links: []
created: 2026-07-16T19:27:11Z
type: task
priority: 2
---

# collect sccm --run-all: end-to-end flag + shared orchestration lib fn

Add a --run-all flag to 'openhound collect sccm' that chains preprocess+convert in-process after collect, via a new framework-agnostic shared-lib function openhound_collector_common.orchestration.run_end_to_end (source-agnostic; MSSQL can adopt later). No OpenHound core edit (new top-level verbs are impossible without one; expose as a flag on the existing collect group). Plan: sccm/sccm/docs/superpowers/plans/2026-07-16-openhound-run-all-shared-orchestrator.md. Decisions: flag-not-verb, in-process, land-in-shared-lib-now, stop-on-first-failure, zero-config derived paths, single --progress for all stages.
