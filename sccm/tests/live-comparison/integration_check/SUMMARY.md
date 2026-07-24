# Live validation — Python integration-test kit vs PowerShell kit (2026-07-22)

Task 13 of the integration-test-kit plan: prove the new Python kit (`openhound collect sccm
--run-integration-tests`) is a **faithful port** of the PowerShell `Invoke-ConfigManBearPigUnitTests`
kit, and smoke-test `--compare-to-zip`.

## Method
- **Graph:** the validated disable-possible-edges graph at `../rename_check/graph` (239 nodes / 419 edges),
  the same graph the PowerShell kit judged in `../rename_check/openhound_renamed_run.log`.
- **Python kit:** ran `openhound_sccm.integration.run_suite` over that graph (61 edge cases + 10 node
  cases + 2 whole-graph invariants); results in `integration_results.json`.
- **Baseline:** PowerShell-kit verdicts (`../rename_check/openhound_renamed_run.log`) = **55 PASS / 5
  FAIL / 1 SKIP** over 61 edge tests.

## Result — parity achieved
| Case group | Python kit | Notes |
|---|---|---|
| **Edge cases (61)** | **55 PASS / 5 FAIL / 1 SKIP** | **Identical to the PowerShell kit**, same 5 failures. |
| Node cases (10) | 10 PASS | New (no PS equivalent) — per-kind existence/counts anchored to the lab. |
| Invariants (2) | 2 PASS | New — root-site normalization + client-device-under-primary. |

The 5 edge failures are the **same known set** the PowerShell kit fails, none a collector bug:
- `SCCM_IsAssigned` / `SCCM_IsMappedTo` (count=1 vs expected 2) — CMBP emits literal duplicates;
  OpenHound de-dupes (accepted "regressions").
- `SCCM_CoerceAndRelayToSMB`→ps1-psv (passive server SMB signing unconfirmable), `SCCM_FullAdministrator`
  (stale expected count 14 vs lab's 19), `SCCM_HasCurrentUser` (no PS1-DEV affinity in SCCM) — fail in
  the live CMBP run too.

## Fixes made during iteration (both real bugs, not test-loosening)
1. **Stale MSSQL login-id patterns.** 4 fixtures (`edge-haslogin-computers-logins`,
   `edge-gettgs-service-account-logins`, `edge-ismappedto-mssql-logins-dbusers`,
   `edge-memberof-logins-sysadmin-role`) used the PowerShell kit's `*$:1433` target/source id pattern,
   which predates the current `MSSQL_Login` id format `<account>$@<host-sid>:1433`. `-like '*$:1433'`
   matches neither the current login id (verified in PowerShell) — the PS kit only "passed" these against
   an older id format. Updated to `*$@*:1433` (intent-preserving: still requires the machine-account `$`,
   in the current format). The edges genuinely exist (MSSQL_HasLogin=4, MSSQL_MemberOf=8, …); the pattern
   just no longer matched. After the fix these 4 correctly PASS.
2. **UTF-8 BOM in payloads.** `load_graph` decoded as plain `utf-8`; ConfigManBearPig.ps1 writes JSON
   with a BOM, so `--compare-to-zip` against a CMBP zip raised `Unexpected UTF-8 BOM`. Fixed the shared
   loader to decode `utf-8-sig` (no-op for BOM-less OpenHound output). Regression test added
   (`test_integration_graph.py::test_load_utf8_bom_payload`).

## `--compare-to-zip` smoke (vs `../results/bloodhound-sccm-20260714-141659.zip`, a CMBP baseline)
Exit 0 (informational). The diff is sensible and surfaces the expected real differences:
- Renamed kinds appear correctly split: `SCCM_SameHostAs`/`SCCM_LocalAdminRequired` only-in-A (current)
  vs `SameHostAs`/`LocalAdminRequired` only-in-B (CMBP old names).
- Property-level diffs reported (edge + node), plus by-kind rollups — no crash, no false assertion.
- Report: `compare_vs_cmbp.json`.

## Validation commands
- Full new-feature suite (shared engine + SCCM fixtures/wiring/CLI + touched regressions): **47 passed**.
- Regenerated artifacts (`integration_results.json`, `compare_vs_cmbp.json`) are gitignored; this summary
  is tracked.
