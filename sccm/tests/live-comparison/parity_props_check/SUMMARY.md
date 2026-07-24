# CMBP-parity property re-validation (Task C1, step 3)

**Date:** 2026-07-24 · **Branch:** integration · **Tickets:** ope-c141 (Phase A), ope-fb99 (Phase B), ope-c0c0 (bug fix)

## What this checks

After implementing the CMBP-parity property work, re-validate that the new node/edge
properties actually appear in a generated graph — **offline**, by reprocessing a cached
collection bucket (no live collection / no credentials), then diffing property presence
against a CMBP baseline zip.

- **Method:** `openhound preprocess sccm output <lookup.duckdb>` → `openhound convert sccm
  output <graph> --lookup-file <lookup.duckdb>`, then load both graphs with the
  `openhound_collector_common.integration_testing` compare engine and check *actual non-null
  property values* in the current run (not just the only-in-B rollup, which can't tell
  "present in A" from "absent in both").
- **Current run (A):** reprocessed `output/sccm` bucket → 241 nodes / 452 edges.
- **CMBP baseline (B):** `../results/bloodhound-sccm-20260714-141659.zip` → 141 nodes / 455 edges.
- Harness: `_compare.py` (tracked). Bulky artifacts (`lookup.duckdb`, `graph/`,
  `compare_report.json`, `*.err`) are gitignored.

## Result — Phase B + bug fix: VALIDATED (real values present)

Direct non-null counts in the reprocessed graph:

| Property | Kind | Non-null / total | Notes |
|---|---|---:|---|
| `siteSystemRoles` | SCCM_Site | **2 / 3** | 3rd site is a **Secondary Site** → correctly empty (B1 CMBP parity gate, ps1:1861-1865). |
| `currentManagementPoint` | SCCM_ClientDevice | **14 / 20** | AdminService `cn_access_mp`. Sample: `ps1-mp.mayyhem.com`. |
| `currentManagementPointSID` | SCCM_ClientDevice | 1 / 20 | Resolved via `principal_by_name`/Local fallback — only hosts with a resolvable MP. |
| `previousSMSID` | SCCM_ClientDevice | 1 / 20 | **Local-only** (CCM_Client) → only the collector's own host. By design. |
| `previousSMSIDChangeDate` | SCCM_ClientDevice | 1 / 20 | Local-only. By design. |
| `userName` | SCCM_ClientDevice | 14 / 20 | Mirrors `ADLastLogonUser` (same collected value). |
| `userDomainName` | SCCM_ClientDevice | 14 / 20 | Mirrors `ADLastLogonUserDomain`. |
| `lastOnlineTime` | SCCM_ClientDevice | **14 / 20** | **ope-c0c0 fix confirmed** — was **0** before (`c_n_` vs `cn_` typo). Sample: `2026-06-24 14:09:51.173-04`. |
| `lastOfflineTime` | SCCM_ClientDevice | **13 / 20** | ope-c0c0 fix confirmed — was 0 before. |
| `SCCMInfra` (edge) | SCCM_IsMappedTo | **4 / 4** | B2 — every IsMappedTo edge carries `SCCMInfra = true`; no other edge kind does. |

## Result — Phase A (AD props): NOT validatable from this cached bucket (expected, not a bug)

`Domain`, `Enabled`, `IsDomainPrincipal`, `Type`, `objectClass`, `servicePrincipalName`,
`CN` on Computer/User/Group are **0 non-null** in this run. **Cause:** the cached
`output/sccm` bucket was collected *before* the Phase A `ldap_resolved_principals`
collection existed, so it carries no resolved-principals side-table for
`transforms._derive_ad_props` / `_join_ad_props` to join against. Verified: the bucket has
no `ldap_resolved_principals` data, and the reprocessed `lookup.duckdb` has the seven AD
columns on `node_computer`/`node_user`/`node_group` (join wired correctly) but all 0 non-null.

**To validate Phase A end-to-end requires a fresh privileged collect** (which runs the new
`ldap_resolved_principals` resource). The AD-props path is already covered by the offline
unit tests (`tests/` — A3 preproc derive/join + A4 model emit, exercised with synthetic
resolved-principals rows). This offline reprocess simply cannot exercise a collection-side
feature the cached data predates.

## Bottom line

Every property that derives from raw tables present in the cached bucket (all of Phase B and
the ope-c0c0 fix) is confirmed emitting real values in the generated graph, including the
Secondary-Site siteSystemRoles gate and the previously-always-empty `lastOnlineTime`/
`lastOfflineTime`. Phase A AD props are correctly wired but need a fresh privileged collect to
observe live (cached bucket predates the collection feature).
