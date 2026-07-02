---
id: ope-9d62
status: closed
deps: [ope-0112, ope-d57d]
links: []
created: 2026-06-03T19:29:29Z
type: task
priority: 2
---

# Implement HTTP per-host collector -type task -priority 2 -description Port Invoke-HTTPCollection from ConfigManBearPig.ps1 into the per-host pipeline framework (ope-0112), replacing the HTTP stub. HTTP MP enrollment can discover new targets (register_target -> recursion).

## Notes

**2026-07-02T20:19:26Z**

Done + committed (7ebc474 'HTTP collection working'): http.collect_http wired at per_host_phases.py:79 via shared HttpClient (ope-d57d).
