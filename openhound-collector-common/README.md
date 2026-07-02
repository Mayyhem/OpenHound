# openhound-collector-common

Shared **pure-Python, in-process** infrastructure for OpenHound on-prem / Windows-auth
collectors. Factored out of the SCCM extension so collectors (starting with `mssql`) reuse
one implementation of the hard parts instead of copying them.

No child processes, no native database/auth binaries — TDS, NTLM, Kerberos, EPA channel
binding, SPNEGO, LDAP, WMI, and SOCKS5 are all done in Python via `impacket` / `ldap3` /
`pywin32` and the stdlib.

## Layout (built incrementally)

| Subpackage | Purpose |
|---|---|
| `clients/mssql.py` | TDS + TLS-over-TDS + NTLMv2 (EPA CBT/SPN) + Kerberos + SSPI; EPA detection. TLS-1.2 cap. |
| `clients/auth.py` | Kerberos AP-REQ/SPNEGO + NTLM + current-user SSPI token minting. |
| `clients/ad.py` | LDAP transport×bind waterfall (lockout-safe), SPN search, SID→AD-object resolution. |
| `clients/wmi.py` | WMI over impacket DCOM + pywin32 (`Win32_GroupUser`, `Win32_Service`). |
| `discovery/dns.py` | DC/SRV/A discovery + DNS resolver override (proxy-aware). |
| `dlt/source_bridge.py` | push→pull DLT emit-resource bridge for multi-target collection. |
| `dlt/convert_pipeline.py` | convert-reads-DuckDB (self-run pipeline + `opengraph_file` + no-op source). |
| `dlt/duckdb_safe.py` | `_safe`/`_ensure_columns`/`_arr` defenses against dlt column-dropping. |
| `logging/log_context.py` | VERBOSE tier + `[target]`/`[phase]` contextvar tagging. |
| `graph/stub_node.py`, `graph/graph_edge.py` | generic edge model + edge-endpoint stub backfill. |
| `proxy/socks.py` | pure-Python SOCKS5 dialer. |

## Consumers

- `mssql` (`mssql/mssql`) — depends on this via a local path dependency.
- SCCM (`sccm/sccm`) — to be migrated onto this library later (tracked by a separate ticket);
  it currently keeps its own copies, generalized from here.

License: MIT.
