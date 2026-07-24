# Tickets by Status

> **Generated:** 2026-07-21 · **Reconciled:** 2026-07-21 · **Updated:** 2026-07-22 (created ope-76f1 — `-v`=VERBOSE + `--silent`, now in_progress; created ope-00df — per-file log-suppression follow-up, open; created+closed ope-cc0f — renamed `--socks-proxy` flag to `-x` / `--proxy`; created+closed ope-54be — ordered-log per-host grouping fix + always-DEBUG full log + log rename (user-verified); closed ope-76f1 (user-verified); created ope-e10b — emit `SCCM_HasNetworkAccessAccount` from Local collection, open; created+closed ope-2f15 — renamed SCCM edge kinds to match schema.json, live-verified; reorganized collect-sccm `--help` into rich panels (Authentication/Collection/Performance/Output/Logging) and removed the 6 inert CRED-2 flags — removal noted on Ope-t7kv, reserved BloodHound Upload panel noted on Ope-8wi2, created ope-7313 — Testing panel capture, open) · **2026-07-23:** created ope-961c — flesh out `disableLoopbackCheck` + add an NTLM-reflection relay edge (open); created ope-c141 + ope-fb99 — CMBP-parity property gaps found via `--compare-to-zip` (populate all AD node props to CMBP parity; emit missing SCCM ClientDevice/Site/edge props), both open; created+closed ope-6569 — quiet expected `http_*`/`smb_*` fallback-table misses in preproc (WARNING→DEBUG when a privileged transport ran; stays WARNING in HTTP-only/SMB-only runs), offline-verified · **2026-07-24:** created ope-8c44 (open) — implement direct BloodHound CE upload (schema + results) from SCCM via a reusable uploader in `openhound-collector-common`; **linked to Ope-8wi2** ("Upload Directly to BloodHound"), whose original design (reuse OpenHound core's ingest destination) was **pivoted** during an owner grill to porting the Go MSSQLHound flow (PUT `/api/v2/extensions` + `/api/v2/file-upload/*`). Plan: `sccm/sccm/docs/superpowers/plans/2026-07-24-bloodhound-direct-upload.md`; executed the CMBP-parity property plan (ope-c141 Phase A AD props + ope-fb99 Phase B SCCM props: SCCM_Site.siteSystemRoles, SCCM_IsMappedTo.SCCMInfra edge prop, SCCM_ClientDevice telemetry extras) via SDD — code done + green, awaiting user test/commit (both still `open`); created+**fix-applied** ope-c0c0 (bug found during B3) — `SCCM_ClientDevice` lastOnlineTime/lastOfflineTime were always empty due to a `c_n_`-vs-`cn_` raw-column typo (dlt/`_snake` treat "CN" as one token); corrected + regression test (proven red→green), linked to ope-fb99, `open` awaiting commit; created ope-6b93 (open) — investigate parity gap where a Local-only/low-priv collector host builds no `SCCM_ClientDevice` node (CMBP does via Local `Upsert-Node`, ps1:4008), with a note to investigate other remote collection methods available to a local-admin-but-not-SCCM-admin principal, linked to ope-fb99 · **Source of truth:** `.tickets/*.md`
>
> This index groups all 92 tickets by their **verified** status — meaning each ticket was read
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
| Closed | 51 | **72** | 70 |
| In&nbsp;Progress | 6 | **5** | 7 |
| Open | 34 | **26** | 26 |
| **Total** | **91** | **103** | **103** |

> **2026-07-22 additions (not part of the 2026-07-21 audit):** [ope-76f1](.tickets/ope-76f1.md)
> (`-v`=VERBOSE + `--silent`) and [ope-54be](.tickets/ope-54be.md) (ordered-log per-host grouping fix +
> always-DEBUG full log + rename `collect_full_*`/`collect_issues_*` + VERBOSE label fix + HTTP content-log
> truncation) were created and, after the user live-tested and verified them, **closed** — listed under
> [Closed](#closed-67-code-verified). Follow-up
> [ope-00df](.tickets/ope-00df.md) (per-file `--no-diagnostics-log` / `--no-collect-log`) remains `open`. Separately, [ope-cc0f](.tickets/ope-cc0f.md) (rename the
> SOCKS5 pivot flag `--socks-proxy` → `-x` / `--proxy`) was created and **closed** the same day —
> code + offline tests done, listed under [Closed](#closed-67-code-verified). Also [ope-e10b](.tickets/ope-e10b.md)
> (emit `SCCM_HasNetworkAccessAccount` from Local collection, reading the NAA from client WMI) created `open` —
> deferred out of the same-day edge-name schema-alignment change. That change itself, [ope-2f15](.tickets/ope-2f15.md)
> (rename SCCM edge kinds to match `schema.json` — `SCCM_`/`MSSQL_` namespacing), was created and, after the user
> live-tested and verified it, **closed** — listed under [Closed](#closed-67-code-verified).

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
| [ope-b7b2](.tickets/ope-b7b2.md) | open→closed | (at audit time) 2 of 4 auth paths wired; since completed & CLOSED by ope-b7b2 — LDAP PtH/PtT wired + live-validated, MSSQL ticket-only EPA warning |
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

### Closed after the audit (2026-07-21) — implemented + closed this session

Two tickets were implemented (subagent-driven; plan `docs/superpowers/plans/2026-07-21-tier1-tier2-smc-abuse-and-cleanup.md`) and closed *after* the reconciliation above:

| Ticket | Was | What shipped |
|---|---|---|
| [ope-b1e8](.tickets/ope-b1e8.md) | open | Dead `--sms`/`--sms-provider` flag + plumbing removed; README/ARCHITECTURE point at `-c`. |
| [ope-e191](.tickets/ope-e191.md) | open | Recursive GenericAll group expansion in `ldap_system_management_dacl` (cycle-guarded; ldap3 auto_range-aware). |

`ope-1f0f` stays **open** — only its lint half landed; the conditional-logging pass remains. `Ope-liu7`'s takeover edges remain **deferred**.

---

## Closed (68 code-verified)

Tickets whose requested change is actually present in the code. All are now recorded `closed`
in `gtk`.

**Implemented + closed 2026-07-22** (live-tested and verified by the user this session):

- [ope-76f1](.tickets/ope-76f1.md) — `-v`=VERBOSE (was a no-op INFO) + `--silent` console mute (files still written)
- [ope-54be](.tickets/ope-54be.md) — Ordered-log per-host grouping fix + always-DEBUG full log + rename (`collect_full_*` / `collect_issues_*`) + VERBOSE label fix + ccmsetup HTTP content-log truncation
- [ope-2f15](.tickets/ope-2f15.md) — Renamed SCCM edge kinds to match `schema.json` (`SCCM_` prefix on SameHostAs/LocalAdminRequired/CoerceAndRelayToAdminService/CoerceAndRelayToSMB; `MSSQL_CoerceAndRelayToMSSQL` into the MSSQL schema; schema.json `SameAdminsAs`→`AdminsReplicatedTo`). Spun out `SCCM_HasNetworkAccessAccount` to ope-e10b (still open)

**Implemented + closed 2026-07-23** (offline-verified — unit tests + real-DB check; awaiting user commit):

- [ope-6569](.tickets/ope-6569.md) — Quiet expected `http_*`/`smb_*` fallback-table misses in preproc: an absent fallback role table now logs at DEBUG (not WARNING) when a privileged transport (AdminService/WMI) ran, and still WARNs in HTTP-only/SMB-only runs. Root cause (not a bug): the SMS Provider *is* the AdminService host → privileged-collected → HTTP probe skipped → `http_smsproviders` empty by design. Renamed `_sccm_sibling_miss`→`_sccm_expected_miss` + added `_privileged_transport_ran`; 4 new tests in `transforms_safe_fallback_test.py`

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
- [ope-b1e8](.tickets/ope-b1e8.md) — Dead collect flag `--sms`/`--sms-provider` removed; docs point at `-c`
- [ope-b287](.tickets/ope-b287.md) — Implement AdminService per-host collector (multi-table)
- [ope-b916](.tickets/ope-b916.md) — Wire SCCM version→CVE fingerprinting into HTTP + site node
- [ope-c660](.tickets/ope-c660.md) — Implement WMI per-host collector (folded into privileged.py)
- [ope-c8cc](.tickets/ope-c8cc.md) — Port MSSQLHound TestEPA network EPA scan
- [ope-c8dd](.tickets/ope-c8dd.md) — Write OpenHound SCCM collector README.md
- [ope-cc0f](.tickets/ope-cc0f.md) — Rename `--socks-proxy` flag to `-x` / `--proxy`
- [ope-d57d](.tickets/ope-d57d.md) — Shared HTTP client (Negotiate auth) for AdminService + HTTP
- [ope-d820](.tickets/ope-d820.md) — Stage 6: Coerce-and-relay possible edges
- [ope-da2a](.tickets/ope-da2a.md) — Filter debug_per_host.py to specific collectors (mirror -m)
- [ope-df0e](.tickets/ope-df0e.md) — Fix SCCM_AssignAllPermissions DB→every-site over-emission
- [ope-e191](.tickets/ope-e191.md) — Recursively expand group members of GenericAll holders (cycle-guarded)
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
- [ope-272e](.tickets/ope-272e.md) — LDAP pass-the-hash placeholder — **subsumed by ope-b7b2** (LDAP pass-the-hash + pass-the-ticket wired 2026-07-21)
- [ope-b7b2](.tickets/ope-b7b2.md) — Wire `--nt-hash`/`--ticket` into all auth paths — LDAP PtH/PtT wired + **live-validated** (2026-07-21); MSSQL EPA ticket-only warning; MSSQL PtT-for-EPA descoped (owner decision, no follow-up ticket)

> **Note:** [Ope-f3di](.tickets/Ope-f3di.md) and [Ope-scp1](.tickets/Ope-scp1.md) are also recorded
> `closed` but their work is **not** actually done — they were closed as superseded by the open
> [ope-1f0f](.tickets/ope-1f0f.md). They are listed under **In Progress** below to reflect code reality.

---

## In Progress (7 code-verified)

- [Ope-rhzx](.tickets/Ope-rhzx.md) — Individual Permissions port (role RBAC done, granular per-op not) *(reconciled → in_progress)*
- [Ope-15m7](.tickets/Ope-15m7.md) — Seed Nodes / Edges audit (AuthUsers seed done, group memberships not) *(reconciled → in_progress)*
- [Ope-liu7](.tickets/Ope-liu7.md) — System Management Container abuse (GenericAll only, no takeover edges) *(reconciled → in_progress)*
- [ope-1f0f](.tickets/ope-1f0f.md) — Code-quality pass (1 of 5 areas done; umbrella for f3di + scp1) *(reconciled → in_progress)*
- [ope-e512](.tickets/ope-e512.md) — Per-domain collector rerun (resolution done, rerun not) *(reconciled → in_progress)*
- [Ope-f3di](.tickets/Ope-f3di.md) ⚠️ — Logging audit — **recorded `closed`** (superseded by ope-1f0f, left as-is)
- [Ope-scp1](.tickets/Ope-scp1.md) ⚠️ — Variable-scope audit — **recorded `closed`** (superseded by ope-1f0f, left as-is)

---

## Open (26 code-verified)

Tickets with no meaningful implementation found — genuinely not started. All recorded `open`.

- [ope-c141](.tickets/ope-c141.md) — Populate all AD node properties (Computer/User/Group) to CMBP parity instead of relying on SharpHound (links ope-fb99, ope-961c) *(created 2026-07-23)*
- [ope-fb99](.tickets/ope-fb99.md) — Emit missing SCCM node/edge properties (ClientDevice extras, Site.siteSystemRoles, IsMappedTo.SCCMInfra) to CMBP parity *(created 2026-07-23)*
- [ope-961c](.tickets/ope-961c.md) — Flesh out `disableLoopbackCheck` + add an NTLM-reflection relay edge (deferred from the cypher-query ideation session) *(created 2026-07-23)*
- [ope-7313](.tickets/ope-7313.md) — Testing panel: reserve `rich_help_panel`; define its flags (dry-run / auth pre-flight) later *(created 2026-07-22)*
- [ope-00df](.tickets/ope-00df.md) — Per-file log suppression `--no-diagnostics-log` / `--no-collect-log` (follow-up to ope-76f1) *(created 2026-07-22)*
- [ope-e10b](.tickets/ope-e10b.md) — Emit `SCCM_HasNetworkAccessAccount` from Local collection (NAA from client WMI); schema.json placeholder with no emitter yet *(created 2026-07-22)*
- [Ope-0t3h](.tickets/Ope-0t3h.md) — Client Push Installation Issues (CRED-1 / ELEVATE-1)
- [Ope-4tdt](.tickets/Ope-4tdt.md) — DCOnly Mode (`--dc-only` flag)
- [Ope-8wi2](.tickets/Ope-8wi2.md) — Upload Directly to BloodHound *(design pivoted 2026-07-24; implementation planned under linked [ope-8c44](.tickets/ope-8c44.md))*
- [ope-8c44](.tickets/ope-8c44.md) — Direct BloodHound CE upload (schema + results) via shared `openhound-collector-common` uploader *(planned 2026-07-24; links Ope-8wi2)*
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
- [ope-4ba1](.tickets/ope-4ba1.md) — Make shared `AdClient` credential-summary warning flag-name-agnostic (surfaced by ope-b7b2)
- [ope-7da1](.tickets/ope-7da1.md) — Wire `--socks-proxy` in MSSQL collector
- [ope-90fc](.tickets/ope-90fc.md) — Collapse duplicate cross-site SCCMResourceIDs to canonical entry
- [ope-a214](.tickets/ope-a214.md) — SCCM edge Composition property + admin-user AssignAllPermissions gap
- [ope-ad1c](.tickets/ope-ad1c.md) — AdminService/WMI don't identify DP roles / client-cert status
- [ope-f173](.tickets/ope-f173.md) — Add Kerberos to the LDAP auth ladder for explicit CLI creds
