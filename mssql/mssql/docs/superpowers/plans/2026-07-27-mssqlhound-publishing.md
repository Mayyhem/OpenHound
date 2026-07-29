# MSSQLHound publishing — deferred plan

**Date:** 2026-07-27, simplified 2026-07-29 · **Status:** §1 needed now, §2 deferred

**Do not execute §2 yet.** Only §1 is required, and only because the SCCM publish removes this
extension's shared-library path dependency and because a wrong licence declaration should not sit in the
tree waiting for a release. Everything else waits until the MSSQL collector is feature-complete — a
runbook written months before use is stale when it is finally read.

**§1 is the single copy of these edits.** The SCCM runbook (`PUBLISHING.md`, step 13) points here rather
than restating them; the previous version of both documents carried the same four TOML lines twice and
they had already drifted to a wrong path. Work this section, not a summary of it.

The sibling design lives in the SCCM collector at
`docs/superpowers/specs/2026-07-27-publishing-and-repo-split-design.md` — in the fork that is
`sccm/sccm/docs/...`, and after the split it is in the ConfigManBearPig repo. Deliberately not linked,
because the relative path is different in each layout. Its decisions on naming, dependency shape, data
files, Trusted Publishing, and publishing a tree rather than a history apply here unchanged; this
document records only what differs.

---

## 1. Required now

Two independent pieces. The licence fix can be done today; the dependency fixes are triggered by the
SCCM publish and must wait for it.

### 1a. Licence — do now, unblocked by anything

`pyproject.toml` declares `license = "MIT"` and there is no `LICENSE` file, in a repo whose upstream is
Apache-2.0. This collector is a port of the Apache-2.0 MSSQLHound, so Apache-2.0 is not a preference —
the current declaration misstates the terms of derived work. Same defect the shared library had, same
fix.

- [ ] `pyproject.toml`: `license = "Apache-2.0"` and add `license-files = ["LICENSE"]`.
- [ ] `Copy-Item ..\..\LICENSE.md LICENSE` — the fork root's copy is already the Apache-2.0 text.
      (Valid while this extension is still inside the fork; after its own split, take it from the
      MSSQLHound repo, which also ships Apache-2.0.)
- [ ] `extension.yaml`: `license: Apache-2.0`. Leave `version`, `homepage`, and the `TBD` references
      alone — those belong to the truth pass in §2, and unlike the licence they are cosmetic until
      release.

### 1b. Shared-library dependency — do when the SCCM publish lands

`pyproject.toml` depends on the shared library through `path = "../../openhound-collector-common"`. That
directory is removed from the fork by the SCCM publish (its step 12), so this breaks whether or not
anyone touches MSSQL. **Until that step runs, the current path is correct — do not change it early.**

- [ ] Replace the bare `"openhound-collector-common"` in `[project.dependencies]` with the published,
      capped form:

```toml
    "openhound-collector-common>=0.1.0,<0.2.0",
```

- [ ] Repoint `[tool.uv.sources]` at the shared library's **new** location. The SCCM runbook puts that
      checkout at `~/Desktop\openhound-collector-common`, a sibling of the fork rather than a directory
      inside it, so from `mssql/mssql/` the path gains one level. If you moved it somewhere else, count
      the levels again from *this* file's `pyproject.toml` — uv resolves the path relative to that file
      and reports a miss as *"not found in the package registry"*, which reads like a PyPI problem and
      is not.

```toml
[tool.uv.sources]
# Local development redirect. [project.dependencies] above carries the published
# constraint (that is what reaches wheel METADATA); this is uv-only and never built in.
# ../../../ because the library lives beside the fork, not inside it.
openhound-collector-common = { path = "../../../openhound-collector-common", editable = true }
```

- [ ] Declare the framework in `[project.dependencies]`, matching what the SCCM validation settled on:

```toml
    "openhound>=0.2.12",
```

- [ ] **Delete** the dev group's `openhound @ git+https://github.com/SpecterOps/openhound.git` line —
      do not restate the range there. A direct git reference outranks a version range during resolution,
      so keeping it would leave local runs on an unpublished commit while users resolved 0.2.12.

- [ ] Verify: `cd mssql/mssql && uv run pytest tests/test_extension_methods.py -v`

Add `--no-sync` if you run this before the shared library reaches PyPI.

---

## 2. Deferred — when the collector is feature-complete

Decisions are settled; execution is not scheduled.

| Decision | Value |
|---|---|
| Distribution | **`mssqlhound`** (confirmed free on PyPI). Import package stays `openhound_mssql`; CLI verb stays `mssql` |
| Version | **`3.0.0`** — PowerShell 1.x → Go 2.x (`v2.0.4` current) → OpenHound 3.x |
| Repo | `SpecterOps/MSSQLHound`. Restructure `main` directly: current Go tree → `go_deprecated/`, Python at root — the same shape the repo already uses for `powershell_deprecated/` |
| Release workflow | **`release-pypi.yml`**, *not* `release.yml` — the Go release workflow owns that name. The PyPI trusted-publisher entry must name `release-pypi.yml` |
| CI | **Do not create `ci.yml`.** MSSQLHound's `main` already has one. Extend it, or use `ci-python.yml` |
| Tag safety | No collision: the Go `release.yml` is `workflow_dispatch`-only, so pushing `v3.0.0` will not fire it |

Checklist for that day:

- [ ] `pyproject.toml`: rename to `mssqlhound`, `dynamic = ["version"]` + `hatch-vcs`
      (`local_scheme = "no-local-version"`, `fallback_version = "0.0.0"`),
      classifiers/keywords/`[project.urls]`. (Licence and `license-files` were done in §1a.)
- [ ] `extension.yaml` truth pass: `version: 3.0.0`, real `homepage` and `references` (currently
      `TBD`), and `tags` without the `"extension"` filler. **Keep `version`, `credentials`, and
      `parameters`** — all three are required by OpenHound's pydantic model, so removing them makes it
      reject the file at startup. The existing credentials and parameters blocks are accurate; leave
      them alone.
- [ ] `.github/workflows/release-pypi.yml` — copy SCCM's `release.yml`. Keep its version-matches-tag
      step and its entry-point / METADATA assertions verbatim except for the names (`mssqlhound`,
      `mssql = openhound_mssql.main:app`); change the data-file assertion to `extension.yaml` and
      `seed_data.json`.
- [ ] A short `DEVELOPMENT.md`, self-sufficient (no links into ConfigManBearPig). **No task runner** —
      plain `uv` commands. `uv sync --group dev` already installs the shared library editable via
      `[tool.uv.sources]`, so there is no overlay step to document.
- [ ] `CLAUDE.md` **and** `AGENTS.md` authored from the fork root's shared + MSSQL-only sections (keep
      them identical, as the fork root does — this tree currently carries only `AGENTS.md`), with
      `grill-me` given its own `.agents/skills/grill-me/SKILL.md` path.
- [ ] Repo migration: `git archive -o mssql.tar HEAD:mssql/mssql` then `tar -xf` over a fresh clone,
      Go tree → `go_deprecated/`, Python at root, PyPI pending publisher, then tag `v3.0.0`. Archive
      rather than copy or subtree-split, for the reasons in the SCCM design record: only tracked files
      travel, and there is no merge to resolve. Commit everything first — `git archive` reads `HEAD`,
      so uncommitted work is silently absent.

## 3. Already correct — do not "fix" these

Verified 2026-07-29:

- **`seed_data.json` ships correctly.** It lives inside the package and is read via
  `resources.files("openhound_mssql")` in `output_adapter.py`. This is the pattern SCCM had to be
  *fixed* to match — leave it.
- **`extension.yaml` is force-included** into the wheel via
  `[tool.hatch.build.targets.wheel.force-include]`, keeping one source of truth at the repo root.
  Better than SCCM's copy-inside-the-package approach, which produced a duplicate that rotted to `MIT`
  and `homepage: TBD` before being deleted. **Keep force-include.**
- **No schema JSON of its own** — `output_adapter.py` references the upstream OpenGraph schema by URL,
  so there are no further data files to package.
- **No credential exposure in the working tree.** No hardcoded credential constants and no
  `debug_*`/`spike_*`/`tour_driver_*` files are tracked here. The `ALTER LOGIN … WITH PASSWORD =
  'password'` strings in `edges/properties.py` are abuse-command *documentation text* for the BloodHound
  entity panel, not credentials. Re-check before publishing rather than assuming it stays true — and
  note that SCCM's history did carry scrubbed-since lab credentials, which is one reason the migration
  publishes a tracked-files archive instead of a history.
- **`AGENTS.md`, `.gitignore`, and `.pre-commit-config.yaml` all exist** and travel with the archive.
