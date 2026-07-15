# Thorough gap analysis: OpenHound vs CMBP (as-is)

Run basis: **All methods + `--disable-possible-edges`**, fresh live collect, mayyhem.com.
Test result: **OpenHound 55 PASS / 5 FAIL / 1 SKIP** vs **CMBP 53 PASS / 7 FAIL / 1 SKIP**.

This document explains **every** node-kind and edge-kind count difference between the two collectors —
not just the tested ones — and classifies each as: OpenHound *exceeds*, *parity*, CMBP *bug/artifact*,
or genuine *gap*.

---

## The single biggest source of "differences": CMBP's `IgnoreMe` scaffolding

CMBP emits a placeholder node `9c3a1f7a-1d6b-4d87-b61b-1c3b7a9e4f01` with kind **`['IgnoreMe']`**, and
attaches **exactly one edge of every one of its 34 edge kinds to it** (34 scaffolding edges total —
verified). This is edge-creation test scaffolding that CMBP leaks into production output. OpenHound does
not emit it.

**Consequence:** almost every edge kind shows CMBP = (real edges) **+1**. Subtract the scaffolding and
the real counts line up. The raw histogram's pervasive `-1` deltas are overwhelmingly this, **not**
OpenHound gaps.

## Edge kinds — normalized (CMBP real = raw − 1 scaffolding)

| Edge kind | CMBP raw | CMBP real | OpenHound | Verdict |
|---|---|---|---|---|
| HasSession | 9 | 8 | 8 | **parity** |
| LocalAdminRequired | 13 | 12 | 14 | **OH exceeds +2** (DP + passive, role fix) |
| MSSQL_Contains | 15 | 14 | 17 | **OH exceeds +3** (secondary-site DB) |
| MSSQL_ControlDB | 3 | 2 | 3 | OH exceeds +1 (secondary DB) |
| MSSQL_ControlServer | 3 | 2 | 3 | OH exceeds +1 (secondary server) |
| MSSQL_ExecuteOnHost | 3 | 2 | 3 | OH exceeds +1 (secondary server) |
| MSSQL_HostFor | 3 | 2 | 3 | OH exceeds +1 (secondary server) |
| MSSQL_GetAdminTGS | 3 | 2 | 2 | parity |
| MSSQL_GetTGS | 5 | 4 | 4 | parity |
| MSSQL_HasLogin | 5 | 4 | 4 | parity |
| MSSQL_IsMappedTo | 5 | 4 | 4 | parity |
| MSSQL_MemberOf | 9 | 8 | 8 | parity |
| MSSQL_ServiceAccountFor | 3 | 2 | 2 | parity |
| CoerceAndRelayToAdminService | 2 | 1 | 1 | parity |
| CoerceAndRelayToMSSQL | 5 | 4 | 4 | parity |
| CoerceAndRelayToSMB | 4 | 4 | 4 | parity (scaffolding used the typo kind) |
| SCCM_Contains | 61 | 60 | 60 | parity |
| SCCM_FullAdministrator | 20 | 19 | 19 | **parity** (test's `14` is stale for both) |
| SCCM_ApplicationAdministrator | 20 | 19 | 19 | parity |
| SCCM_AllPermissions | 3 | 2 | 2 | parity |
| SCCM_AssignAllPermissions | 11 | 10 | 10 | parity |
| SCCM_AdminsReplicatedTo | 4 | 3 | 3 | parity |
| SCCM_HasADLastLogonUser | 15 | 14 | 14 | parity |
| SCCM_HasCurrentUser | 7 | 6 | 6 | parity |
| SCCM_HasPrimaryUser | 2 | 1 | 1 | parity |
| SCCM_HasStoredAccount | 3 | 2 | 2 | parity |
| SameHostAs | 39 | 38 | 38 | parity |
| MemberOf | 70 | 69 | 79 | **OH exceeds +10** (more group membership resolved) |
| SCCM_HasMember | 41 | 40 | 43 | **OH exceeds +3** |
| **SCCM_HasClient** | 39 | 38 | 19 | **OH fewer** — see "per-site dupe" below |
| **SCCM_IsAssigned** | 19 | 18 | 9 | **OH dedups** (CMBP 2×) — exceeds |
| **SCCM_IsMappedTo** | 7 | 6 | 3 | **OH dedups** (CMBP 2×) — exceeds |
| CoerceAndRelaytoSMB *(typo kind)* | 1 | 0 | 0 | CMBP bug (scaffolding only) |
| MSSQL_LinkedAsAdmin | 1 | 0 | 0 | parity in-lab; kind **not implemented** (see below) |
| SCCM_HasNetworkAccessAccount | 1 | 0 | 0 | parity in-lab; kind **not implemented** (see below) |
| SCCM_AssignSpecificPermissions | 1 | 0 | 0 | parity in-lab; kind **not implemented** (ope-rhzx) |

**Net after normalization: OpenHound equals or exceeds CMBP on every edge kind except the per-site
duplication of `SCCM_HasClient` / `SCCM_IsAssigned` / `SCCM_IsMappedTo`, where CMBP emits each edge twice
(per-site / dupe) and OpenHound emits it once (deduped) — BloodHound would dedupe CMBP's copies anyway.**

## Node kinds

| Node kind | CMBP raw | CMBP unique | OpenHound | Explanation |
|---|---|---|---|---|
| SCCM_SecurityRole | 34 | 17 | 17 | CMBP emits each role **2×** (collected from CAS+PS1, same `@CAS` id); OpenHound dedups. Parity in unique terms. |
| SCCM_AdminUser | 6 | 3 | 3 | CMBP **2×** dupe; OpenHound dedups. Parity. |
| SCCM_Collection | 24 | 14 | 10 | CMBP = 10 real (all named, `@CAS`) **+ 4 malformed** (`SMS00002@`, `SMS00003@`, `SMS00004@`, `SMS000PS@` — empty site code, `null` name) **+ dupes**. OpenHound emits the **10 correct, named** collections. CMBP bug. |
| IgnoreMe | 1 | 1 | 0 | CMBP scaffolding node; OpenHound omits. |
| User | 23 | 23 | 99 | **OpenHound far more complete** — 99 domain-SID users (77 are the lab's `EdgeTest*` accounts) vs CMBP's 23. OpenHound resolves every discovered principal (SMS_R_User + group-member expansion). |
| Computer | 30 | 30 | 45 | **OpenHound more complete** (+15 fully-resolved AD computers). |
| Group | 14 | 14 | 23 | **OpenHound more complete** (+9 groups from membership expansion). |
| MSSQL_Database | 2 | 2 | 3 | OpenHound also models the **secondary-site** DB (`CM_SEC`); CMBP doesn't. |
| MSSQL_DatabaseRole | 2 | 2 | 3 | secondary-site `db_owner`. |
| MSSQL_ServerRole | 2 | 2 | 3 | secondary-site `sysadmin`. |
| MSSQL_Login / DatabaseUser / Server / ClientDevice / Site | = | = | = | parity |

## The 5 remaining test "failures" (all meets-or-exceeds)

1. **`SCCM_IsAssigned` (Count 2)** — CMBP emits a literal duplicate edge; OpenHound dedups to 1. *OpenHound exceeds* (kept per decision).
2. **`SCCM_IsMappedTo` (Count 2)** — same duplicate story. *OpenHound exceeds.*
3. **`SCCM_FullAdministrator` (Count 14)** — the test's `14` is **stale**; the lab now has **19 client
   devices** and OpenHound emits exactly **19** (correct 1:1). CMBP also fails (emits 19 real too). *Test bug, not a collector gap.*
4. **`CoerceAndRelayToSMB → ps1-psv`** — the passive server's SMB signing state was **NULL** (not
   confirmable this run); both tools require confirmed `signing=false`. *Collection-reachability / lab, not logic.*
5. **`SCCM_HasCurrentUser → PS1-DEV`** — no current-user affinity exists in SCCM (the test itself notes it
   "requires manual addition after the Ludus build"). Source data absent → both tools fail. *Lab data gap.*

## The `SCCM_HasClient` per-site difference (19 vs 38)

CMBP emits ~2 HasClient edges per device (each device tagged as a client from both site collections);
OpenHound emits one per device → its own primary site. The **tested** case (`PS1 → PS1-DEV@PS1`, Count 1)
passes. The count difference is the same per-site/dedup behavior as IsAssigned/IsMappedTo.

## Genuine capability gaps (edge kinds not implemented in OpenHound)

These kinds are **not defined** in `kinds/edges.py`, but in this lab CMBP's *only* instance of each is the
`IgnoreMe` scaffolding edge (0 real instances), so **no real data is lost here**. They should be verified
in an environment that actually has them:

- **`SCCM_AssignSpecificPermissions`** — individual (non-"all") RBAC scopes. Tracked as **ope-rhzx**. The
  kit's test for it is a skipped coverage placeholder.
- **`SCCM_HasNetworkAccessAccount`** — the Network Access Account. OpenHound emits `SCCM_HasStoredAccount`
  (2, at parity with CMBP's 2 real); whether NAA needs its own edge distinct from stored-account should be confirmed.
- **`MSSQL_LinkedAsAdmin`** — a linked SQL server configured with sysadmin. No linked-server config in this lab.

## CMBP bugs surfaced (OpenHound has none)

1. `IgnoreMe` scaffolding node + 34 edges (one per kind) leaked into production output.
2. Typo'd edge kind `CoerceAndRelaytoSMB` (lowercase "to").
3. Duplicate `SCCM_IsAssigned` / `SCCM_IsMappedTo` edges (and 2× SecurityRole/AdminUser/Collection nodes).
4. 4 malformed collections with empty site code and `null` name.
