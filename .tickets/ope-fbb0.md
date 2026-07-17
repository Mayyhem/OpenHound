---
id: ope-fbb0
status: open
deps: []
links: []
created: 2026-07-17T15:49:28Z
type: task
priority: 2
tags: [sccm]
---

# Route ALL SCCM collection traffic through --socks-proxy (shared interception)

Implement --socks-proxy so ALL SCCM collection traffic (discovery + all five per-host protocols) tunnels through a SOCKS5 pivot, via shared openhound-collector-common interception. Plan: sccm/sccm/docs/superpowers/plans/2026-07-15... see 2026-07-17-socks5-proxy-all-collection-traffic.md
