---
id: ope-7da1
status: open
deps: []
links: []
created: 2026-07-20T14:27:20Z
type: task
priority: 2
tags: [mssql, proxy]
---

# Wire --socks-proxy in MSSQL collector via shared proxy interception

Wire --socks-proxy in the MSSQL collector via the shared openhound_collector_common.proxy interception (socks_proxy_installed + parse_proxy_address + active_proxy + make_resolver force_tcp), now built and validated for SCCM under ope-fbb0. MSSQLHound's Go origin had a TDS-only proxydialer; the shared interception now covers TDS + LDAP + the EPA probe in one wrap. Same --dc/--dns requirement and native-SSPI/OS-Kerberos boundary apply. See sccm/sccm/docs/superpowers/plans/2026-07-17-socks5-proxy-all-collection-traffic.md and spike_socks_proxy.md.
