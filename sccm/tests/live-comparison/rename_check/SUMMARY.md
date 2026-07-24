# Edge-rename parity re-check (2026-07-22)

Confirms the SCCM edge-kind rename (ope-2f15 — `SCCM_`/`MSSQL_` namespacing to match
`schema.json`) did **not** change graph parity vs the original PowerShell tool. Compare this to
the pre-rename baseline in [`../SUMMARY.md`](../SUMMARY.md) (Final: OpenHound **55 PASS** vs CMBP 53).

## Method

The rename is a pure relabel, so no fresh collection was needed:

1. **OpenHound (new names)** — re-ran `preprocess` + `convert` over the **cached live bucket**
   `sccm/sccm/output/sccm/` (collected today), forcing the CMBP-matching high-confidence basis with
   `SOURCES__SCCM__DISABLE_POSSIBLE_EDGES=true` (the bucket itself was collected with possible edges
   ON). Output packaged into `bloodhound-sccm-openhound-*.zip`.
2. **Kit** — copied `Invoke-ConfigManBearPigUnitTests.ps1` to
   [`Invoke-ConfigManBearPigUnitTests-renamed.ps1`](Invoke-ConfigManBearPigUnitTests-renamed.ps1) and
   updated the 5 renamed `Kind` values (`SameHostAs`, `LocalAdminRequired`,
   `CoerceAndRelayToAdminService`, `CoerceAndRelayToSMB`, `CoerceAndRelayToMSSQL`) to their new
   `SCCM_`/`MSSQL_` forms. `SCCM_AdminsReplicatedTo` was already prefixed and is unchanged.
3. **CMBP baseline** — reused the existing CMBP kit log `../results/live_run.log` (CMBP output is
   unaffected by the rename; it still emits the old names).
4. **Compare** — `compare_results.py --cmbp ../results/live_run.log --openhound
   openhound_renamed_run.log` → [`report_rename.md`](report_rename.md).

## Result — parity preserved (both edge bases)

Run in **both** bases (`SOURCES__SCCM__DISABLE_POSSIBLE_EDGES=true` for high-confidence, and unset for
the bucket's native possible-edges-ON). Both give the **same** verdict, itself identical to the
pre-rename FINAL:

| Metric | CMBP (live baseline) | OpenHound — disable-possible | OpenHound — possible-ON |
|---|---|---|---|
| Total nodes | 171 | 239 | 240 |
| Total edges | 455 | 419 | 422 |
| Tests PASSED | 53 | **55** | **55** |
| Tests FAILED | 7 | 5 | 5 |
| Tests SKIPPED | 1 | 1 | 1 |

Position-aligned in **both** bases: **51 agree-PASS, 4 OpenHound-only passes, 2 dedup "regressions",
3 fail-in-both** — **identical to the pre-rename FINAL**. Reports:
[`report_rename.md`](report_rename.md) (disable-possible) and
[`report_rename_possible_on.md`](report_rename_possible_on.md) (possible-ON).

Flipping the possible-edges flag moved only **+1 node / +3 edges** (an extra possible client device and
its `SCCM_SameHostAs` pair) and changed **no** test outcomes — the coerce/relay builders are
flag-independent for confirmed edges (parent SUMMARY Finding 7 / ope-86f8), so the flag shifts
client-device counts, not the attack edges the kit checks.

Every renamed edge passes under its new name (counts below are the disable-possible run):

| Edge (new name) | OpenHound tests P/F/S |
|---|---|
| `SCCM_SameHostAs` | 2/0/0 |
| `SCCM_LocalAdminRequired` | 9/0/0 |
| `SCCM_CoerceAndRelayToAdminService` | 1/0/0 |
| `MSSQL_CoerceAndRelayToMSSQL` | 4/0/0 |
| `SCCM_CoerceAndRelayToSMB` | 3/1/0 |
| `SCCM_AdminsReplicatedTo` (unchanged) | 3/0/0 |

The 5 non-passing tests are the **same known set** as before the rename, none rename-caused:
- **[58/59] `SCCM_IsAssigned` / `SCCM_IsMappedTo`** — CMBP emits literal duplicate edges (`Count=2`);
  OpenHound de-duplicates to 1 (exceeds; BloodHound dedupes CMBP's pair anyway). Accepted previously.
- **[17] `SCCM_CoerceAndRelayToSMB` → `ps1-psv`** — the passive server's SMB signing was unconfirmable
  (NULL); both tools require confirmed `signing=false`. The 5 SMB relay edges that *are* confirmable
  were emitted.
- **[52] `SCCM_FullAdministrator`** (stale expected count; lab grew) and **[55] `SCCM_HasCurrentUser`**
  (no PS1-DEV current-user affinity exists in SCCM) — fail in the live CMBP run too.

## Notes

- The regenerated `lookup.duckdb`, `graph/`, zip, and logs here are gitignored (bulky, reproducible).
  The modified `*.ps1` kit copy and this report are tracked.
- **Deferred follow-up:** porting the PowerShell kit itself to Python (there is no Python port yet —
  `compare_results.py` is only the log-diff tool). Gated on this parity confirmation.
