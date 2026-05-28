---
id: Ope-4tdt
status: open
deps: []
links: []
created: 2026-05-28T13:30:04Z
type: feature
priority: 2
assignee: Mayyhem
tags: [sccm, collection, opsec]
---
# DCOnly Mode (--dc-only flag)

Add a --dc-only flag that restricts collection to Domain Controller queries (LDAP only, no remote host probing). In environments where running against hosts directly is too risky or noisy, operators want only what is available from the DC: System Management container, site objects, management point objects, computer accounts, group memberships.

## Design

Add --dc-only CLI flag to main.py. When set, force --collection-methods LDAP,DNS and skip all Phase 2/3 per-host collection. Skip TargetQueue loop entirely. Still run preproc and convert on LDAP-only data. Add startup message: DCOnly mode: collecting only from domain controller, skipping host-level probes. Preproc transforms already handle missing Phase 3 tables gracefully via CREATE TABLE IF NOT EXISTS pattern.

## Acceptance Criteria

--dc-only produces a valid graph output from LDAP data only. No TCP connections to any host other than the domain controller. Compatible with --disable-possible-edges.

