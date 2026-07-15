# Live comparison: ConfigManBearPig.ps1 vs the OpenHound SCCM collector

**Date:** 2026-07-14 · **Environment:** mayyhem.com lab (CAS + PS1 hierarchy), run as `domainadmin`
(Full Administrator). **Harness:** `Invoke-ConfigManBearPigUnitTests.ps1` (same `$ExpectedEdges` list
both times), collection basis **All methods + `-DisablePossibleEdges`**.

## What was done

1. **Live CMBP run** — the kit ran the original `ConfigManBearPig.ps1` against the live lab, producing
   `bloodhound-sccm-<ts>.zip`, and tested it. → baseline.
2. **OpenHound run** — `openhound collect sccm` → `preprocess` → `convert` (same basis). The four
   convert JSON files (`sccm_nodes/edges`, `ad_nodes/edges`) were packaged into a `bloodhound-sccm-*.zip`
   ([`Package-OpenHoundZip.ps1`](Package-OpenHoundZip.ps1)) and tested with the kit's `-SkipCollection`.
3. **Comparison** — both runs' `-LogFile` outputs were aligned **by position** (the kit runs the fixed
   `$ExpectedEdges` order every time) by [`compare_results.py`](compare_results.py).

Detailed tables: [`report.md`](report.md) (primary) and
[`report_possible_edges_on.md`](report_possible_edges_on.md) (supplementary, see Finding 2).

## Headline results

| Run | Nodes | Edges | PASS | FAIL | SKIP |
|---|---|---|---|---|---|
| **CMBP** (live, `-DisablePossibleEdges`) | 171 | 455 | **53** | 7 | 1 |
| OpenHound (`--disable-possible-edges`, initial) | 232 | 378 | 29 | 31 | 1 |
| OpenHound (possible edges ON, supplementary) | 234 | 385 | 32 | 28 | 1 |
| **OpenHound after MSSQL-login fix** (Finding 3) | 238 | 406 | **37** | 23 | 1 |
| OpenHound — fresh end-to-end re-collect (verification) | 238 | 406 | **37** | 23 | 1 |
| **OpenHound after service-account fix** (Finding 4) | 238 | 406 | **42** | 18 | 1 |
| **OpenHound after client-device + DB-assign fixes** (Findings 5–6) | 238 | 402 | **47** | 13 | 1 |
| **OpenHound after coerce/relay fix — FINAL, fresh collect** (Finding 7) | 239 | 411 | **55** | 5 | 1 |

## ✅ Parity achieved — OpenHound meets or exceeds CMBP

**Final (fresh end-to-end collect): OpenHound 55 PASS vs CMBP 53 PASS.** Aligned to CMBP: **51 agree-PASS,
4 OpenHound-only passes, 2 "regressions", 3 fail-in-both.** Every test is now meets-or-exceeds:

- **4 OpenHound-only passes** — MSSQL count tests CMBP gets wrong (`MSSQL_Contains` sysadmin, `MSSQL_ControlServer`,
  `MSSQL_ExecuteOnHost`, `MSSQL_HostFor`): OpenHound is *more* correct.
- **2 "regressions" [58/59]** — `SCCM_IsAssigned`/`SCCM_IsMappedTo`: CMBP emits **literal duplicate** edges
  (`Count=2`); OpenHound de-duplicates → 1. OpenHound *exceeds* (BloodHound dedupes CMBP's pair anyway). Kept per your call.
- **3 fail-in-both [17/52/55]** — parity; CMBP fails these too, for lab/test reasons, **not** collector gaps:
  - `[52] SCCM_FullAdministrator` — OpenHound emits **19 = exactly the 19 client devices** (correct 1:1); the test's `14` is stale (lab grew). CMBP emits 20.
  - `[17] CoerceAndRelayToSMB→ps1-psv` — the passive server's SMB signing state was not confirmable (NULL); both tools require confirmed `signing=false`.
  - `[55] SCCM_HasCurrentUser` — no PS1-DEV current-user affinity exists in SCCM (the test itself notes it needs manual lab setup); source data absent.

### CMBP bugs found (per request to flag CMBP issues)
1. **Duplicate edges** — `SCCM_IsAssigned`/`SCCM_IsMappedTo` emitted twice (identical). OpenHound de-dupes.
2. **Scaffolding leaked into output** — coerce/relay edges pointing at an `['IgnoreMe']` node (`9c3a1f7a…`).
3. **Typo'd edge kind** — `CoerceAndRelaytoSMB` (lowercase "to") vs the canonical `CoerceAndRelayToSMB`.
OpenHound has none of these.

Aligned to CMBP's baseline, the initial OpenHound run had **25 agree-PASS, 28 regressions**
(CMBP PASS → OpenHound FAIL), **4 OpenHound-only passes**, **3 fail-in-both**. Each fix below narrowed the gap
(see `report_after_*.md` / `report_FINAL.md`).

## Finding 1 — `displayName`/`displayname` case-collision (FIXED this session)

The kit could not parse OpenHound's output *at all*: 3 `SCCM_AdminUser` nodes emitted the same property
under two casings — the framework base lowercase `displayname` **and** a camelCase `displayName` — which
PowerShell's `ConvertFrom-Json` (and, more importantly, BloodHound/Neo4j ingestion) rejects as a
duplicate key. CMBP emits **only** the camelCase form, so it never collided.

**Fix (per your decision — keep camelCase, CMBP parity):**
[`models/sccm_admin_user.py`](../../sccm/src/openhound_sccm/models/sccm_admin_user.py) now sets the base
`displayname=None` on admin-user nodes (pruned on emit) and keeps `displayName` (with empty values pruned
to match CMBP). Stale "CMBP sets both" comments in
[`graph.py`](../../sccm/src/openhound_sccm/graph.py) corrected. Regression test added
(`tests/sccm_admin_user_test.py::test_admin_user_no_displayname_displayName_case_collision`).
Validation: **553 passed / 5 skipped**, ruff clean, mypy clean (only a pre-existing framework-stub note).

> The result numbers above are from the **fixed** build.

## Finding 2 — Coerce/relay edges: flag over-suppression *and* under-generation

Under the chosen basis OpenHound emitted **zero** `CoerceAndRelay*` edges vs CMBP's 12. Investigation
showed this is **two** issues:

- **`--disable-possible-edges` is not equivalent between the tools.** CMBP's `-DisablePossibleEdges`
  keeps *confirmed* coerce/relay edges; OpenHound's flag gates them **all** (it's read at preproc,
  [`transforms.py`](../../sccm/src/openhound_sccm/transforms.py) `_effective_disable_possible_edges`).
- **Even with possible edges ON, OpenHound's coerce/relay is incomplete.** Re-running preproc/convert with
  the flag flipped recovered only **+3 tests** (29 → 32):

  | Kind | CMBP (flag on) | OH (flag on) | OH (possible ON) |
  |---|---|---|---|
  | CoerceAndRelayToAdminService | 2 | 0 | **0** |
  | CoerceAndRelayToMSSQL | 5 | 0 | 1 |
  | CoerceAndRelayToSMB | 5 | 0 | 3 |

  `CoerceAndRelayToAdminService` is missing entirely, and MSSQL/SMB are partial — a real generation gap,
  not just a flag difference. (Note: `ope-d820` "Stage 6 coerce-and-relay" is marked closed but is
  incomplete against the live lab.)

## Finding 3 — MSSQL login/user layer under-populated (FIXED this session)

OpenHound found all 3 MSSQL servers but built only **1** of the expected **4** logins
(`MSSQL_HasLogin` 5→1, `MSSQL_MemberOf` 9→2, `MSSQL_IsMappedTo` 5→1, `MSSQL_GetTGS` 5→1). It doesn't
enumerate logins over TDS — it **infers** them in preproc (`_node_mssql_login`), one per (SQL server,
computer) where the computer holds `SMS Site Server@<site>` / `SMS Provider@<site>` (same predicate as
CMBP.ps1:1912). Two independent root causes starved that join:

1. **Suffixed roles missing for passive/provider hosts.** The `@<site>` suffix was built only by the
   SMS_SCI_SiteDefinition collector ([privileged.py:129](../../sccm/src/openhound_sccm/collectors/privileged.py#L129)),
   which lists only the *active* site server + SQL host. SMS_SCI_SysResUse (`adminservice_site_systems`)
   has `ps1-psv`/`ps1-sms` with `role_name`+`site_code` but was never folded into `node_computer` as
   `role@site`. **Fix:** a post-collapse augmentation in `_node_computer`
   ([transforms.py](../../sccm/src/openhound_sccm/transforms.py)) joins SysResUse by hostname and adds
   `role_name || '@' || site_code`.
2. **`cas-pss` had a NULL `sam_account_name`.** The `node_computer` arms for `remoteregistry_computers`,
   `adminservice_site_definitions_computers`, and `smb_computers` did `NULL AS sam_account_name` on a
   stale assumption; the raw data carries it (via `**ad_object`). **Fix:** those arms now read `sam`.

**Result:** MSSQL_Login/DatabaseUser 1→**4** (CAS-PSS, PS1-PSS, PS1-PSV, PS1-SMS), and the cascade
followed (HasLogin 1→4, IsMappedTo 1→4, GetTGS 1→4, MemberOf 2→8). The role fix *also* recovered the
two missing `LocalAdminRequired` edges (DP, passive→primary). **Blast radius: 0 regressions, +8 passes**
(verified by diffing before/after OpenHound runs). Validated: 556 passed / 5 skipped, ruff clean,
3 new regression tests in `tests/node_computer_test.py`.

> The remaining MSSQL failures (`HasSession`, `GetTGS`, `GetAdminTGS`, `ServiceAccountFor`) are a
> *separate* gap — the MSSQL **service account** (`sqlsccmsvc`) layer, distinct from the login layer.

## Finding 4 — User nodes missing `samAccountName` (FIXED this session)

The MSSQL service-account edges (`HasSession`, `MSSQL_GetTGS`, `MSSQL_GetAdminTGS`,
`MSSQL_ServiceAccountFor`) all *existed* in the right counts but failed "not found" because their
`User` endpoint (`sqlsccmsvc`, SID `...1116`) had **no `samAccountName` property** — and neither did
any of the other 98 User nodes (**0/99**). CMBP emits `SamAccountName`, which the kit matches via
PowerShell's case-insensitive property lookup.

**Root cause:** `UserProperties` had no `samAccountName` field, `UserNode` never set one, and
`_node_user` dropped the bare SAM — `adminservice_r_user.user_name` (SMS_R_User.UserName, e.g.
`sqlsccmsvc`) was never carried through. **Fix:** added `samAccountName` to `UserProperties`
([graph.py](../../sccm/src/openhound_sccm/graph.py)) + `UserNode` ([models/user.py](../../sccm/src/openhound_sccm/models/user.py)),
and plumbed `sam_account_name` through `_node_user` from `user_name` / `remoteregistry_users.sam_account_name`
([transforms.py](../../sccm/src/openhound_sccm/transforms.py)). camelCase to match the existing
`ComputerProperties.samAccountName` convention.

**Result:** User nodes with `samAccountName` 0/99 → **99/99**; the 5 service-account tests pass
(**37 → 42 PASS**). **Blast radius: 0 regressions, +5 passes** (verified by diffing before/after runs).
Validated: 559 passed / 5 skipped, ruff clean, 3 new regression tests (`node_user_test.py`, `user_test.py`).

## Finding 5 — SCCM_ClientDevice name missing `@siteCode` (FIXED, ope-ec50)

Client-device nodes were named bare (`PS1-DEV`) with the `@site` form only in `displayname`; CMBP names
them `<netbios>@<siteCode>` (`PS1-DEV@PS1`) and the kit resolves devices by `name`. **Fix:**
[models/sccm_client_device.py](../../sccm/src/openhound_sccm/models/sccm_client_device.py) sets
`name=display`. **+4 tests** (HasClient, HasMember, HasPrimaryUser, HasADLastLogonUser), 0 blast radius.

## Finding 6 — SCCM_AssignAllPermissions DB over-emission (FIXED, ope-df0e)

`_edge_mssql_db_assign_all` did `database CROSS JOIN every non-secondary site` → every DB (incl. the
secondary `CM_SEC`) → every primary site (6 edges). CMBP emits each **primary DB → its own site** (2).
**Fix:** [transforms.py](../../sccm/src/openhound_sccm/transforms.py) joins each DB to its own `sccm_site`
with `site_type != 1` (drops secondary DBs; removes false positives like PS1-DB→CAS). **+1 test.**

## Finding 7 — Coerce/relay zeroed by `--disable-possible-edges` (FIXED, ope-86f8)

Under the flag OpenHound emitted **0** coerce/relay; CMBP emits 9. Investigation showed **no generation
gap** — OpenHound already produced the identical 9 real edges (same targets + `coercionVictimAndRelayTargetPairs`);
CMBP's apparent "extra" 3 were edges to an `['IgnoreMe']` scaffolding node (+ a typo'd kind). The sole
divergence: OpenHound's flag required `RestrictReceivingNTLMTraffic` explicitly `'Off'`, but it's **NULL on
every host** (Windows default `0` = allow all inbound NTLM = *actually* vulnerable). **Decision (yours):**
treat NULL NTLM as vulnerable under the flag (match CMBP); keep primary gates strict (SMB `signing=false`,
MSSQL EPA explicit `'Off'`). **Fix:** the 3 coerce builders' `ntlm_ok` is now flag-independent
([transforms.py](../../sccm/src/openhound_sccm/transforms.py)). Restored exactly the **9 confirmed edges**
under `--disable-possible-edges`. **+8 tests**, 0 blast radius; 3 coerce unit tests updated to the new
semantics + explicit-restricted-NTLM drop tests added.

## Where OpenHound is *more* correct (4 OpenHound-only passes)

On four MSSQL **count** tests CMBP fails (over/under-counts) but OpenHound gets exactly right:
`MSSQL_Contains` (sysadmin role), `MSSQL_ControlServer`, `MSSQL_ExecuteOnHost`, `MSSQL_HostFor` — all
expect 3 and OpenHound emits 3.

## Fail-in-both (CMBP baseline — not OpenHound regressions)

- `CoerceAndRelayToSMB` PS1-passive · `SCCM_FullAdministrator` (count) · `SCCM_HasCurrentUser`
  (requires manual user-device affinity after the Ludus build). These fail in the live CMBP run too.

## Suggested next steps (map to existing tickets)

- MSSQL login/user gap → likely `ope-6716` (Stage 5 MSSQL nodes/edges).
- Client-device edges + LocalAdminRequired DP/passive → `ope-9271` (Stage 4).
- Coerce/relay completeness + flag semantics → reopen/extend `ope-d820` (Stage 6).
- SCCM admin assignment (IsAssigned/IsMappedTo) → `ope-1950` (Stage 3 RBAC fan-out).
