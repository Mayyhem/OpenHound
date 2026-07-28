# Privileged live re-validation — CMBP vs OpenHound (2026-07-28)

Plan Task 10, Step 1b. Run as **`MAYYHEM\domainadmin`** (the current logon context — OpenHound
takes no `-u/-p`, CMBP needs no netonly shim), both flag states, both tools, all on 2026-07-28
against the same lab state. Companion to `../lowpriv_check/SUMMARY-20260728.md`.

**Why this exists.** Everything in `docs/superpowers/plans/2026-07-23-low-priv-assumed-edges.md`
was motivated by and measured against a *low-privilege* operator, but the changes landed in code
the privileged path also runs through: `_site_hierarchy` now consumes every site-code source and
infers missing site types, `_node_computer` gained four arms, `_edge_mssql_structural` gained a
resolve-or-drop guard, `_node_mssql_server` changed its `dns_host_name` coalesce, and every
assumed family gained provenance columns. Nothing in Tasks 1-14 exercised that path. **This run is
the regression gate for the whole plan.**

---

## 1. Regression gate: PASSED — nothing lost

The strongest evidence available, and it needed no second collection: HEAD's code and the new code
were each run over the **identical collected bucket**, so the only variable is the diff.

| | HEAD | new |
|---|---:|---:|
| total edges | 445 | **454** |
| edge kinds | 32 | **33** |
| **edge kinds that lost rows** | — | **0** |

Every difference is additive, and each traces to a named task:

| kind | HEAD → new | source |
|---|---|---|
| `GenericAll` | 0 → 5 | Task 11 (System Management container DACL) |
| `MemberOf` | 78 → 80 | Task 12 (SMC group members) |
| `MSSQL_ServiceAccountFor` | 2 → 3 | Task 13 (SPN-holder arm, alongside the privileged one) |
| `HasSession` | 10 → 11 | Task 13 |

## 2. Same-day comparison against CMBP

| | CMBP nodes | CMBP edges | OpenHound nodes | OpenHound edges |
|---|---:|---:|---:|---:|
| possible edges ON | 160 | 468 | 148 | **454** |
| possible edges OFF | 159 | 452 | 147 | **451** |

CMBP's 34 `seed_data.json` self-loops are excluded (see the low-priv summary §4a — they are
schema-registration stubs on a node literally named `IgnoreMe`, not attack-path data).

OpenHound is at ~97% of CMBP's edge count with possible edges on and ~99.8% with them off. Note
CMBP barely changes between its two modes at this privilege level (468 → 452), because most of its
graph comes from AdminService facts rather than assumptions.

## 3. Duration

| | CMBP (self-reported) | OpenHound (wall) |
|---|---:|---:|
| possible edges ON | 4 m 2 s | **40 s** |
| possible edges OFF | 6 m 9 s | **39 s** |

OpenHound is **6-9× faster** here. The gap is much wider than at low privilege (where it was
~15% / 2.3× faster) because a privileged run answers most questions with AdminService queries and
skips the per-host HTTP/SMB/RemoteRegistry probing that dominates a low-priv run — 39 s privileged
vs 187 s low-priv for OpenHound itself.

⚠ Read CMBP's *self-reported* figure, not wall clock: wall time here was 242 s / 369 s, and the
difference is process startup, not collection.

## 4. Provenance stays off privileged data (Task 10 Step 4b)

29 of 454 edges carry `assumed = true`, and they are **exactly** the four families the owner's
§7 ruling designated stamped-but-not-gated:

```
SCCM_LocalAdminRequired            14
SCCM_AssignAllPermissions           8
SCCM_CoerceAndRelayToSMB            6
SCCM_CoerceAndRelayToAdminService   1
```

No AdminService/WMI-sourced row is stamped. The count is identical in both flag modes, which is
correct: those four are inferences (so they are stamped) whose gates are measured evidence (so the
flag does not remove them), and CMBP emits them under its own flag too.

## 5. Integration fixtures: 63 pass / 9 fail / 1 skip — and 8 of the 9 are not ours

Attributed by the same HEAD-vs-new comparison on identical data:

| fixture | HEAD | new | verdict |
|---|---:|---:|---|
| `MSSQL_ServiceAccountFor` | 2 | 3 | **ours** — Task 13 adds the SPN-holder edge; the fixture's expected count is now stale and should be updated |
| `SCCM_CoerceAndRelayToSMB` | 6 | 6 | unchanged — pre-existing |
| `MSSQL_ExecuteOnHost` | 4 | 4 | unchanged — pre-existing |
| `MSSQL_HostFor` | 4 | 4 | unchanged — pre-existing |
| `node-mssql-server-count` | 4 | 4 | unchanged — pre-existing |
| `SCCM_FullAdministrator` | 38 | 38 | unchanged — pre-existing |
| `SCCM_HasCurrentUser` | 8 | 8 | unchanged — pre-existing |
| `SCCM_IsAssigned` | 12 | 12 | unchanged — pre-existing |
| `SCCM_IsMappedTo` | 4 | 4 | unchanged — pre-existing |

Stated plainly: this plan caused **one** of the nine. The other eight were failing before it and
are either stale fixture expectations or lab drift — real fixture-health debt, but not a regression
introduced here. They should be triaged separately rather than folded into this work.

## Honest limits of this evidence

- **The before/after is code-vs-code on one cached bucket**, not two independent collections. That
  is the right design (it removes lab drift as a variable) but it cannot catch a regression that
  only manifests in *collection*, e.g. a probe that stopped running.
- **`--clean` was used on every OpenHound run.** Without it, dlt appends a load package and
  preprocess UNIONs the previous run's rows — 11 of 24 raw tables held two dates during an earlier
  attempt today, invisibly (exit 0, fresh `graph/` timestamps). Any future re-run must pass it.
- **The privileged CMBP runs needed `-MemoryThresholdPercent 100`** on this 12 GB host, and the
  harness must splat CMBP's parameters as a **hashtable**; array splatting bound
  `-DisablePossibleEdges` as the value of `-MemoryThresholdPercent` and killed both runs at 0 s.
- **`uv run` cannot resolve this project** while the packaging migration is mid-flight, so a
  `[tool.uv.sources]` editable path entry was temporarily restored in `sccm/sccm/pyproject.toml`
  and then reverted byte-exactly (`uv.lock` was relocked as a side effect and restored from HEAD).

## Reproduce

```powershell
cd sccm\tests\live-comparison\privileged_check
.\run-both-privileged.ps1        # both tools, both flag states, as the current user
```

Then assert the FULL fixture set in-process — nothing on the CLI passes `privileged` yet:

```python
from pathlib import Path
from openhound_sccm.integration import run_integration_tests
run_integration_tests(Path("openhound/pe-on/graph"), privileged=True)
```
