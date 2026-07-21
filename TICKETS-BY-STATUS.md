# Tickets by Status

> **Generated:** 2026-07-21 · **Reconciled:** 2026-07-21 · **Source of truth:** `.tickets/*.md`
>
> This index groups all 91 tickets by their **verified** status — meaning each ticket was read
> in full (`gtk show`) and cross-checked against the actual code and git history on the
> `integration` branch, not just trusting the `status:` field.
>
> The audit found **20 tickets whose recorded status disagreed with the code**. On 2026-07-21
> those were reconciled: **18 statuses were changed** in `gtk` to match the code, and **2 were
> deliberately left closed** (see below). A ⚠️ now marks only the 2 remaining intentional
> exceptions. See [Reconciliation](#reconciliation-applied-2026-07-21) for the full record.
>
> **Why no directories?** `gtk` finds tickets with a *flat* glob of `.tickets/*.md`. Moving the
> files into `open/`, `in_progress/`, `closed/` subfolders makes `gtk list/show/query/start/close`
> report zero tickets. So `.tickets/` is left untouched and this index lives at the repo root.

## Counts

| Status | Before audit | `gtk` now | Code-true state |
|---|---:|---:|---:|
| Closed | 51 | **63** | 61 |
| In&nbsp;Progress | 6 | **6** | 8 |
| Open | 34 | **22** | 22 |
| **Total** | **91** | **91** | **91** |

The 2-ticket gap between "`gtk` now" and "code-true state" is **Ope-f3di** and **Ope-scp1** —
kept `closed` as *superseded* even though their work isn't actually done. Their scope lives in
the still-open umbrella [ope-1f0f](.tickets/ope-1f0f.md), which they link to and which now carries
a note recording that.

The dominant theme the audit surfaced: **12 tickets marked `open`/`in_progress` were actually
finished** — the preproc/convert "Stage" work and the whole MSSQL collector port had shipped but
their tickets were never moved to `closed`.

---

## Reconciliation applied (2026-07-21)

Every change below was made with `gtk` and is reflected in `.tickets/`. Nothing was committed —
that's yours to do after review.

### Set to `closed` (12) — work verified present in code

| Ticket | Was | Why |
|---|---|---|
| [ope-1950](.tickets/ope-1950.md) | in_progress | Stage 3 Containment + RBAC edges present; superseded by later "Stage 5/6/7 complete" commits |
| [ope-2ff3](.tickets/ope-2ff3.md) | in_progress | Stage 2 SCCM nodes + ~9 inline edges committed; `d0857d4` builds on it |
| [ope-3dbc](.tickets/ope-3dbc.md) | in_progress | `convert_pipeline.py:28` `_without_null_properties` wired + tested |
| [ope-9271](.tickets/ope-9271.md) | in_progress | SameHostAs/LocalAdminRequired edges + ClientDevice dedup, commit `b4b2e3a` |
| [ope-a88e](.tickets/ope-a88e.md) | in_progress | SMS_R_UserGroup resolution + node_site/node_group fixes committed |
| [ope-e739](.tickets/ope-e739.md) | in_progress | Fixed by top-of-branch commit `1c50579` + regression tests |
| [Ope-l6fu](.tickets/Ope-l6fu.md) | open | TDS/EPA coverage shipped (registry + `mssql_epa.py`); relay edge EPA-gated |
| [ope-6716](.tickets/ope-6716.md) | open | Stage 5: all 6 MSSQL_* node tables + ~14 MSSQL edges built and called |
| [ope-6aa7](.tickets/ope-6aa7.md) | open | AD split shipped, commit `efb3d1c` (`opengraph_untagged.py` + two-pass emit + tests) |
| [ope-272f](.tickets/ope-272f.md) | open | Full MSSQL extension present + pipeline-wired; notes report Stage 3–7b done, 206 tests pass |
| [ope-3d28](.tickets/ope-3d28.md) | open | Real `collect_mssql` replaces the per-host stub; ticket note confirms core deliverable MET |
| [ope-255b](.tickets/ope-255b.md) | open | Stage 7 docs reconciled to code-truth (14 nodes/37 edges + 3 diagrams) |

### Set to `in_progress` (6) — partial work in code

| Ticket | Was | Why |
|---|---|---|
| [ope-b7b2](.tickets/ope-b7b2.md) | open | 2 of 4 auth paths wired (SMB, RemoteRegistry, WMI done; LDAP + MSSQL not) |
| [Ope-rhzx](.tickets/Ope-rhzx.md) | open | Role-based RBAC done; granular per-op "Individual Permissions" absent |
| [Ope-15m7](.tickets/Ope-15m7.md) | open | AuthUsers seed node synthesized; `ldap_group_memberships` not implemented |
| [Ope-liu7](.tickets/Ope-liu7.md) | open | Container DACL parsed but only GenericAll; no ACL table / takeover edges |
| [ope-1f0f](.tickets/ope-1f0f.md) | open | 1 of 5 cleanup areas done (register_target why-logging) |
| [ope-e512](.tickets/ope-e512.md) | open | Multi-domain principal resolution present; per-domain collector *rerun* not |

### Left `closed` on purpose (2) — superseded

| Ticket | Why not reopened |
|---|---|
| [Ope-f3di](.tickets/Ope-f3di.md) ⚠️ | Closed as superseded by [ope-1f0f](.tickets/ope-1f0f.md) (still open). Reopening would duplicate tracking — its logging-audit scope belongs in the umbrella. A note was added to ope-1f0f. |
| [Ope-scp1](.tickets/Ope-scp1.md) ⚠️ | Same rationale — variable-scope audit scope folded into ope-1f0f. |

---

## Closed (61 code-verified)

Tickets whose requested change is actually present in the code. All are now recorded `closed`
in `gtk`.

- [Ope-6cei](.tickets/Ope-6cei.md) — Concurrency / Parallelism: wire `--threads` into Phase 3 per-host collection
- [Ope-bmyk](.tickets/Ope-bmyk.md) — Abuse Info on Edges: per-edge abuse-path info + technique IDs in graph output
- [Ope-o008](.tickets/Ope-o008.md) — Verify CoerceAndRelayToSMB lifecycle end-to-end
- [Ope-vpdw](.tickets/Ope-vpdw.md) — Add `--dns-resolver` option for a custom DNS nameserver
- [ope-00ca](.tickets/ope-00ca.md) — Silence dlt progress bars by default (`--progress off`)
- [ope-0112](.tickets/ope-0112.md) — Concurrent per-host collection framework (reusable engine + SCCM stubs)
- [ope-0495](.tickets/ope-0495.md) — SCCM collector vs live CMBP unit-test parity audit
- [ope-065f](.tickets/ope-065f.md) — Port test-epa-matrix as live EPA validation harness
- [ope-0f66](.tickets/ope-0f66.md) — Fix local.py mypy at root cause (SourceContext state + typed logger)
- [ope-1201](.tickets/ope-1201.md) — Fix COALESCE type mismatch dropping registry-only SQL servers
- [ope-140f](.tickets/ope-140f.md) — Collect summary prints real next-step commands, not placeholders
- [ope-16f5](.tickets/ope-16f5.md) — Rename SCCM node/edge properties to ConfigManBearPig.ps1 casing
- [ope-194a](.tickets/ope-194a.md) — Fix SCCM_AdminUser displayName/displayname case-collision
- [ope-1f49](.tickets/ope-1f49.md) — Migrate SCCM onto openhound-collector-common shared library
- [ope-215a](.tickets/ope-215a.md) — Return single scalar fsp_hostname from `_parse_mp_capabilities`
- [ope-2732](.tickets/ope-2732.md) — Fix RemoteRegistry trigger-start race + double-logoff
- [ope-334f](.tickets/ope-334f.md) — Windows-safe core log rotation (copy+truncate)
- [ope-38ad](.tickets/ope-38ad.md) — Merge AdminService + WMI collectors into privileged.py; genericize WmiClient
- [ope-3de2](.tickets/ope-3de2.md) — Add samAccountName to User nodes so MSSQL/AD edges resolve
- [ope-3f2a](.tickets/ope-3f2a.md) — SMS Provider WMI fallback collection (AdminService mirror)
- [ope-4483](.tickets/ope-4483.md) — SMB Collection port incl. SMB2 signing scan
- [ope-46ef](.tickets/ope-46ef.md) — Move mssql_epa_test.py into tests/
- [ope-4787](.tickets/ope-4787.md) — Add Kerberos (SSPI + PtT/PtH) to smb_sso.py
- [ope-4c6f](.tickets/ope-4c6f.md) — Collect summary: count rows from dlt per-run trace, not disk scan
- [ope-5186](.tickets/ope-5186.md) — Quiet expected non-client root\CCM namespace error
- [ope-5271](.tickets/ope-5271.md) — Fix invalid server address on NetBIOS-prefixed account resolution
- [ope-57cf](.tickets/ope-57cf.md) — Fix MSSQL login/user under-population (SysResUse role@site)
- [ope-676f](.tickets/ope-676f.md) — Implement SMB per-host collector (superseded by ope-4483)
- [ope-7e54](.tickets/ope-7e54.md) — Implement RemoteRegistry per-host collector
- [ope-7f61](.tickets/ope-7f61.md) — Fix README edge-count banner (Stages 1–2 = 11, not 10)
- [ope-86f8](.tickets/ope-86f8.md) — Realign coerce/relay: NULL NTLM = Windows-default-vulnerable
- [ope-9989](.tickets/ope-9989.md) — Make HasUser edges' abuse info less prescriptive
- [ope-9d62](.tickets/ope-9d62.md) — Implement HTTP per-host collector
- [ope-aa39](.tickets/ope-aa39.md) — Add entity-panel help content to SCCM edge property bags
- [ope-afc8](.tickets/ope-afc8.md) — Fix SCCM_HasMember landing on Computer nodes for non-client members
- [ope-b287](.tickets/ope-b287.md) — Implement AdminService per-host collector (multi-table)
- [ope-b916](.tickets/ope-b916.md) — Wire SCCM version→CVE fingerprinting into HTTP + site node
- [ope-c660](.tickets/ope-c660.md) — Implement WMI per-host collector (folded into privileged.py)
- [ope-c8cc](.tickets/ope-c8cc.md) — Port MSSQLHound TestEPA network EPA scan
- [ope-c8dd](.tickets/ope-c8dd.md) — Write OpenHound SCCM collector README.md
- [ope-d57d](.tickets/ope-d57d.md) — Shared HTTP client (Negotiate auth) for AdminService + HTTP
- [ope-d820](.tickets/ope-d820.md) — Stage 6: Coerce-and-relay possible edges
- [ope-da2a](.tickets/ope-da2a.md) — Filter debug_per_host.py to specific collectors (mirror -m)
- [ope-df0e](.tickets/ope-df0e.md) — Fix SCCM_AssignAllPermissions DB→every-site over-emission
- [ope-ec50](.tickets/ope-ec50.md) — Fix SCCM_ClientDevice name missing @siteCode suffix
- [ope-f27c](.tickets/ope-f27c.md) — `collect sccm --run-all`: end-to-end flag + shared orchestration fn
- [ope-f651](.tickets/ope-f651.md) — Migrate SCCM onto shared library (duplicate stub of ope-1f49)
- [ope-fbb0](.tickets/ope-fbb0.md) — Route ALL SCCM traffic through `--socks-proxy`
- [ope-ff28](.tickets/ope-ff28.md) — Stage 8.1: MSSQLHound output adapter (convert → validator envelope)

**Reconciled to closed on 2026-07-21** (were open/in_progress — see [Reconciliation](#reconciliation-applied-2026-07-21)):

- [ope-1950](.tickets/ope-1950.md) — Stage 3: Containment + RBAC fan-out + property parity
- [ope-2ff3](.tickets/ope-2ff3.md) — Stage 2: SCCM entities + inline edges
- [ope-3dbc](.tickets/ope-3dbc.md) — Drop null OpenGraph properties before convert emit
- [ope-9271](.tickets/ope-9271.md) — Stage 4: SameHostAs + LocalAdminRequired + ClientDevice dedup
- [ope-a88e](.tickets/ope-a88e.md) — Stage 1 hardening: SMS_R_UserGroup + node fixes
- [ope-e739](.tickets/ope-e739.md) — Inferred CmRcService clients attached to CAS root
- [Ope-l6fu](.tickets/Ope-l6fu.md) — TDS and EPA implementation coverage
- [ope-255b](.tickets/ope-255b.md) — Stage 7: Docs + validation
- [ope-272f](.tickets/ope-272f.md) — MSSQL OpenHound collector port (MSSQLHound parity)
- [ope-3d28](.tickets/ope-3d28.md) — Implement MSSQL per-host collector
- [ope-6716](.tickets/ope-6716.md) — Stage 5: MSSQL nodes and edges
- [ope-6aa7](.tickets/ope-6aa7.md) — Split AD nodes/edges into a separate untagged OpenGraph file

> **Note:** [Ope-f3di](.tickets/Ope-f3di.md) and [Ope-scp1](.tickets/Ope-scp1.md) are also recorded
> `closed` but their work is **not** actually done — they were closed as superseded by the open
> [ope-1f0f](.tickets/ope-1f0f.md). They are listed under **In Progress** below to reflect code reality.

---

## In Progress (8 code-verified)

- [ope-b7b2](.tickets/ope-b7b2.md) — Wire `--nt-hash`/`--ticket` into LDAP/SMB/RemoteRegistry/MSSQL (2 of 4 done) *(reconciled → in_progress)*
- [Ope-rhzx](.tickets/Ope-rhzx.md) — Individual Permissions port (role RBAC done, granular per-op not) *(reconciled → in_progress)*
- [Ope-15m7](.tickets/Ope-15m7.md) — Seed Nodes / Edges audit (AuthUsers seed done, group memberships not) *(reconciled → in_progress)*
- [Ope-liu7](.tickets/Ope-liu7.md) — System Management Container abuse (GenericAll only, no takeover edges) *(reconciled → in_progress)*
- [ope-1f0f](.tickets/ope-1f0f.md) — Code-quality pass (1 of 5 areas done; umbrella for f3di + scp1) *(reconciled → in_progress)*
- [ope-e512](.tickets/ope-e512.md) — Per-domain collector rerun (resolution done, rerun not) *(reconciled → in_progress)*
- [Ope-f3di](.tickets/Ope-f3di.md) ⚠️ — Logging audit — **recorded `closed`** (superseded by ope-1f0f, left as-is)
- [Ope-scp1](.tickets/Ope-scp1.md) ⚠️ — Variable-scope audit — **recorded `closed`** (superseded by ope-1f0f, left as-is)

---

## Open (22 code-verified)

Tickets with no meaningful implementation found — genuinely not started. All recorded `open`.

- [Ope-0t3h](.tickets/Ope-0t3h.md) — Client Push Installation Issues (CRED-1 / ELEVATE-1)
- [Ope-4tdt](.tickets/Ope-4tdt.md) — DCOnly Mode (`--dc-only` flag)
- [Ope-8wi2](.tickets/Ope-8wi2.md) — Upload Directly to BloodHound
- [Ope-emhc](.tickets/Ope-emhc.md) — Implement `--enable-bad-opsec` gating (flag defined but never gates)
- [Ope-ew5k](.tickets/Ope-ew5k.md) — WMI Collection (client-side CIM tables)
- [Ope-exvi](.tickets/Ope-exvi.md) — Findings / Remediations layer
- [Ope-gqwo](.tickets/Ope-gqwo.md) — CRED-6: PXE Media Download and Policy Decryption (SMB/TFTP)
- [Ope-o6bh](.tickets/Ope-o6bh.md) — DHCP Collection and PXE Credential Theft Chain (CRED-1)
- [Ope-padv](.tickets/Ope-padv.md) — CRED-4: Local CIM Repository Scraping (Bad Opsec)
- [Ope-pofz](.tickets/Ope-pofz.md) — Add `--skip-ad-enum` option
- [Ope-t7kv](.tickets/Ope-t7kv.md) — CRED-2: Machine Account Registration and Policy Decryption (HTTP)
- [Ope-txs0](.tickets/Ope-txs0.md) — Search Other Discovered Domains via LDAP
- [Ope-zaja](.tickets/Ope-zaja.md) — Relay to Management Point
- [ope-1172](.tickets/ope-1172.md) — Test different port / named instance (QA task)
- [ope-272e](.tickets/ope-272e.md) — LDAP pass-the-hash (`--nt-hash`) support — placeholder
- [ope-7da1](.tickets/ope-7da1.md) — Wire `--socks-proxy` in MSSQL collector
- [ope-90fc](.tickets/ope-90fc.md) — Collapse duplicate cross-site SCCMResourceIDs to canonical entry
- [ope-a214](.tickets/ope-a214.md) — SCCM edge Composition property + admin-user AssignAllPermissions gap
- [ope-ad1c](.tickets/ope-ad1c.md) — AdminService/WMI don't identify DP roles / client-cert status
- [ope-b1e8](.tickets/ope-b1e8.md) — Dead collect flag: `--sms`/`--sms-provider` accepted but ignored
- [ope-e191](.tickets/ope-e191.md) — Recursively expand group members of GenericAll holders
- [ope-f173](.tickets/ope-f173.md) — Add Kerberos to the LDAP auth ladder for explicit CLI creds
