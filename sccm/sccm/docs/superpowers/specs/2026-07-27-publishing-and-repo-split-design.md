# Design: Publish `configmanbearpig` + `openhound-collector-common` to PyPI (and split the repos)

**Date:** 2026-07-27 · **Status:** design (grilled + locked) · **Driver:** ship the SCCM collector as a
one-line install for OpenHound users, and make cross-repo development obvious.

## 1. Goal

Turn two directories that only work inside one developer's checkout into two published packages, so a
new user runs exactly one command:

```bash
uv tool install openhound --with configmanbearpig
openhound collect sccm --site-server ps1-sms.mayyhem.com --run-all
```

Secondary, equally weighted goal (owner requirement): **the development experience must stay as simple
as it is today and be documented well enough that a contributor never has to reverse-engineer it.**

## 2. Locked decisions

Every one of these came out of a one-at-a-time design grill on 2026-07-27.

| # | Decision | Rationale |
|---|---|---|
| **D1** | Publish to **public PyPI (pypi.org)** under the owner's **personal** PyPI account. | `openhound-jamf`/`okta`/`github` are all on public PyPI — "the SpecterOps PyPI" is their pypi.org account, not a private index. Personal account ships today with no internal ask; SpecterOps can be added as an owner later with zero URL churn for users. |
| **D2** | SCCM distribution is named **`configmanbearpig`** (confirmed free on PyPI). | Brand recognition. The 100-star repo is already the name people search for. |
| **D3** | **Import package stays `openhound_sccm`; CLI verb stays `sccm`** (`openhound collect sccm`). | Mirrors `openhound-jamf` → package `openhound_jamf` → verb `jamf`: the verb names the *data source*, not the tool. Zero churn across ~40 test modules, ARCHITECTURE.md, and every import. |
| **D4** | SCCM code lives in **`SpecterOps/ConfigManBearPig`**, Python at the **repo root** on `main`; PowerShell moves to **`powershell_deprecated/`**. | Root-level package ⇒ the git fallback install needs no `#subdirectory=`, and the release workflow needs no `working-directory` juggling. |
| **D5** | Shared library lives in **`Mayyhem/openhound-collector-common`** (personal repo), **name unchanged**, PyPI project on the same personal account. | It is genuinely shared infra (SCCM + MSSQL today). Name confirmed free on PyPI. |
| **D6** | **Local dev = sibling checkouts + per-project `.venv` + an editable overlay** driven by a `just dev` recipe. The committed `pyproject.toml` declares only a versioned PyPI dependency. | Preserves the existing `<repo>/.venv` muscle memory and the targeted offline-test commands. Crucially, a contributor who clones **one** repo can still `uv sync` — see §4. |
| **D7** | Releases run through **GitHub Actions + PyPI Trusted Publishing (OIDC)**, triggered by pushing a tag; the version is derived from the tag by **`hatch-vcs`**. | No long-lived API token exists to leak. Matches OpenHound core, which already uses `[tool.hatch.version] source = "vcs"`. |
| **D8** | Migrate with **`git subtree split`** so per-file history/blame survives in both new homes. | Months of porting history stays greppable and bisectable. |
| **D9** | First versions: **`openhound-collector-common` `v0.1.0`**, **`configmanbearpig` `v2.0.0`**. Today's PowerShell `main` is archived as tag **`v1.2-powershell`**. | The PS script self-reports `$script:ScriptVersion = "1.2"`. `2.0.0` reads as "the Python era of the same tool" rather than a regression to `0.x`. |
| **D11** | **Declare `openhound` as a dependency, with a tested range** (`openhound>=<min>,<<next-major>`; the exact bounds come from the validation in D12). | Reverses an earlier draft of this design. `openhound` **is** on PyPI (0.2.12), so the dependency is resolvable, and `pip install configmanbearpig` then works standalone instead of being a documented dead end. More importantly it stops a user pairing the collector with an untested framework: this extension hand-registers against openhound *internals* (`app.converter = _run_convert`, the `openhound.cli.convert` Typer group) because the public decorator exposed no flag-carrying seam, and internals are exactly what moves between minor versions. A resolver error beats an `AttributeError` inside `convert`. |
| **D12** | **Validate against openhound 0.2.12 before tagging `v2.0.0`**, and set D11's bounds from what that finds. | The collector was developed against **0.1.4** (git `cbfc7fc`); PyPI is two minor versions ahead at **0.2.12**, which is what any new user gets today. The upper bound is a guess until it is tested, and a guessed cap is worse than none — it either lies or blocks working versions. |
| **D10** | **Apache-2.0 for everything** — both packages, both repos. Each ships a real `LICENSE` file (copied from the OpenHound `LICENSE.md`), declares `license = "Apache-2.0"` + `license-files = ["LICENSE"]` in `pyproject.toml`, and states it in `extension.yaml` and the README. | Owner decision, 2026-07-27. It is also the only defensible option: the shared library was factored out of the SCCM extension, itself a port of the Apache-2.0 `ConfigManBearPig.ps1`, and Apache-2.0 does not permit silently re-labelling derived work as MIT — derivative portions must keep the Apache-2.0 notice. This replaces the stale `license = "MIT"` the shared library declared with no license text shipped at all. |

## 3. Target architecture

### 3a. Three repos, one dependency arrow

```
SpecterOps/openhound                    (upstream framework — unchanged, never forked for release)
        ▲ host at runtime, NOT a declared dependency (see §3c)
        │
SpecterOps/ConfigManBearPig             PyPI: configmanbearpig       v2.0.0
   └── depends on ─────────────────►    PyPI: openhound-collector-common  >=0.1.0,<0.2.0
                                        Mayyhem/openhound-collector-common
        ▲
Mayyhem/OpenHound (the current fork)    stays as the MSSQL work-in-progress home; sccm/sccm and
                                        openhound-collector-common are removed from it after the split
```

**Publish order is forced:** `openhound-collector-common` must exist on PyPI **before** the first
`configmanbearpig` release, or the SCCM install resolves to nothing.

### 3b. What a user's machine ends up with

`uv tool install openhound --with configmanbearpig` creates one tool environment containing
`openhound` (which owns the `openhound` console script), `configmanbearpig`, and
`openhound-collector-common` plus its transitive `impacket`/`ldap3`/`dnspython`/`cryptography`/
`requests`/`pywin32`/`winkerberos`. OpenHound then finds the collector at runtime through the
`openhound.sources` entry point — no plugin path, no config file.

### 3c. Why `openhound` is **not** a declared dependency

The extension imports `openhound.core.app`, `openhound.cli.collect`, and ten more modules — so
`openhound` is unambiguously required at runtime. It is still deliberately left out of
`[project.dependencies]`, for two reasons:

1. **Verified convention.** Resolving `openhound-jamf==0.2.3` with `uv pip compile` yields exactly one
   package — jamf declares *no* dependencies at all. The framework is the host, not a library the
   extension pulls in.
2. **Avoiding a version fight.** The user chose the `openhound` version when they installed the tool.
   Declaring a range here can only ever *conflict* with that choice; it can never improve it.

The cost — `pip install configmanbearpig` alone gives an unusable package — is handled by documentation,
and by the fact that the only sane way to install it is `--with`.

## 4. The dependency-source problem, and the fix

Today [`sccm/sccm/pyproject.toml:49-53`](../../../pyproject.toml) says:

```toml
[tool.uv.sources]
openhound-collector-common = { path = "../../openhound-collector-common", editable = true }
```

uv's docs are explicit that **"sources are only respected by uv"** and never travel in built wheel
metadata. Two consequences:

- **Published wheel:** the dependency degrades to a bare, unversioned `openhound-collector-common`. If
  the library isn't on the same index, every install fails.
- **Public repo:** any contributor who clones `ConfigManBearPig` alone and runs `uv sync` hits a hard
  `Distribution not found at: file://…/openhound-collector-common` — the sibling only exists on the
  owner's disk.

**Fix (D6).** The committed file declares a real, capped PyPI dependency and *no* source:

```toml
dependencies = ["openhound-collector-common>=0.1.0,<0.2.0", ...]
```

A fresh clone therefore just works. The owner re-attaches the live copy on demand:

```just
# ConfigManBearPig/justfile
dev:
    uv sync --group dev
    uv pip install -e ../openhound-collector-common
    uv pip install -e ../OpenHound
```

`uv pip install -e` overlays the editable copy into the already-synced `.venv`, replacing the PyPI
build in place. The one rule to remember — and it goes in `DEVELOPMENT.md` in bold — is that **any
later `uv sync` reverts the overlay, so re-run `just dev`.** The cap `<0.2.0` matters because a `0.x`
library makes no API-stability promise; without it a future `0.2.0` could silently break installs.

### Expected on-disk layout

```
~/Desktop/dev/
├── OpenHound/                      # SpecterOps/openhound (or the fork) — editable, for local framework work
├── ConfigManBearPig/               # SpecterOps/ConfigManBearPig — the SCCM collector
└── openhound-collector-common/     # Mayyhem/openhound-collector-common — the shared library
```

Only the *relative* arrangement matters (`../openhound-collector-common` from each consumer); the parent
directory name is free. MSSQL, still inside the `Mayyhem/OpenHound` fork at `mssql/mssql`, gets the same
recipe with its own depth (`../../../openhound-collector-common`) until it is split out too.

## 5. Packaging changes

### 5a. `openhound-collector-common`

| Change | Why |
|---|---|
| `version = "0.0.1"` → `dynamic = ["version"]` + `[tool.hatch.version] source = "vcs"`; add `hatch-vcs` to build requires. | D7 — the git tag is the single source of truth. |
| Add `classifiers`, `keywords`, `[project.urls]` (Homepage/Repository/Issues). | A bare PyPI page with no links is a bad first impression, and classifiers drive PyPI filtering. |
| `license = "MIT"` → `license = "Apache-2.0"` + `license-files = ["LICENSE"]`, and add the `LICENSE` file. | D10. It previously declared a license whose text was never shipped, and the wrong license at that. The README's trailing `License: MIT.` line is corrected in the same change — it lands in the wheel's `METADATA` description, so it was actively contradicting the metadata. |
| Add `.github/workflows/release.yml`, `DEVELOPMENT.md`, `justfile`. | D7 + the documented-dev-experience requirement. |

### 5b. `configmanbearpig` (today `sccm/sccm/`)

| Change | Why |
|---|---|
| `name = "sccm"` → `name = "configmanbearpig"`. | D2. Also stops squatting a generic three-letter name. |
| `version = "0.0.1"` → `dynamic` + `hatch-vcs`. | D7/D9. |
| Delete `[tool.uv.sources]`; dependency becomes `openhound-collector-common>=0.1.0,<0.2.0`. | §4. |
| Add `license = "Apache-2.0"` + `LICENSE`, `classifiers`, `keywords`, `[project.urls]`. | The repo is Apache-2.0; the package currently declares nothing. |
| **Move `schema_SCCM.json` + `schema_MSSQL.json` into `src/openhound_sccm/` and load them with `importlib.resources`.** | **Bug fix — see §6.** |
| Fill in `extension.yaml` (`version`, `description`, `homepage`, `references`, real `parameters`). | It is still cookiecutter boilerplate with `homepage: TBD`, and OpenHound parses it on every run. |
| Delete leftovers `src/main.py` + empty `src/__init__.py`. | Cookiecutter residue outside the wheel's package dir; `src/main.py` re-exports `openhound.main:app` and is referenced by nothing. |
| Add `.github/workflows/release.yml`, `DEVELOPMENT.md`, README install section. | D7 + documentation requirement. |

## 6. Bug fix: the schema files never ship

Found while surveying, not previously known.

```python
# src/openhound_sccm/bloodhound_schemas.py:19-21
_SCHEMA_ROOT = Path(__file__).resolve().parents[2]   # → sccm/sccm/  in a checkout
_SCCM_SCHEMA = _SCHEMA_ROOT / "schema_SCCM.json"
```

`[tool.hatch.build.targets.wheel] packages = ["src/openhound_sccm"]` ships **only** that directory, so
`schema_SCCM.json`/`schema_MSSQL.json` — which live one level above it — are absent from the wheel. In
an installed environment `parents[2]` resolves to the directory *above* `site-packages`, and
`load_sccm_schemas()` raises the `FileNotFoundError` it deliberately raises for "a packaging error".
Net effect: **`-B/--bloodhound` direct upload is broken for every user who installs from PyPI**, while
working perfectly in the developer's checkout. `integration/__init__.py:21` has the same defect via
`parents[3]`.

**Fix:** move both JSON files into `src/openhound_sccm/` and resolve them the way OpenHound itself
resolves `extension.yaml` in [`manager.py:114-116`](../../../../src/openhound/core/manager.py) —
`importlib.resources.files("openhound_sccm")`. This is location-independent: it works from a checkout,
a wheel, or a zipimport. Both call sites and the two tests that assert on those paths
(`integration_fixtures_test.py:66`, `integration_wiring_test.py:21`) are updated together.

`extension.yaml` is already correctly placed *inside* `src/openhound_sccm/`, so it needs no fix — which
is exactly why this bug survived: the file OpenHound validates loudly is fine, and the two that fail
quietly are only touched by the upload path.

## 7. Release automation

One workflow per repo, identical in shape:

```yaml
on:
  push:
    tags: ["v*"]
permissions:
  id-token: write        # the OIDC token PyPI trades for an upload token
  contents: read
jobs:
  release:
    environment: pypi    # gives you an approval gate + audit trail
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }        # hatch-vcs needs full history to see the tag
      - uses: astral-sh/setup-uv@v5
      - run: uv build
      - run: uv publish --trusted-publishing always
```

`fetch-depth: 0` is not optional: a shallow clone hides tags, and `hatch-vcs` would stamp a
`0.1.dev…+dirty` version. `--trusted-publishing always` makes a misconfigured publisher **fail loudly**
instead of silently falling back to looking for a token.

Releasing is then: `git tag v2.0.0 && git push origin v2.0.0`.

## 8. Developer experience (owner requirement)

Each repo gets a `DEVELOPMENT.md` covering, in this order:

1. **Prerequisites** — uv, Python 3.13/3.14, `just`, and the Windows `python-preference = "only-system"`
   caveat already recorded in `[tool.uv]` (uv-managed CPython on Windows ships a `libcrypto` without
   the `OPENSSL_Applink` shim, which aborts the process on any TLS handshake).
2. **Clone the siblings** — the exact `git clone` trio and the resulting tree from §4.
3. **`just dev`** — what it does, and the bolded warning that `uv sync` undoes the overlay.
4. **Verify the wiring** — a one-liner that proves the editable overlay is live:
   `uv run python -c "import openhound_collector_common as m; print(m.__file__)"` must print a path
   inside `../openhound-collector-common`, not inside `.venv`.
5. **Targeted tests** — `uv run pytest tests/<file> -v` per the house rule (never the full suite).
6. **Changing the shared library** — the two-repo dance: edit → test in the library → test in CMBP →
   tag the library → bump the floor in CMBP if a new symbol is required.
7. **Cutting a release** — tag, push, watch the action.

A `just` recipe list is the discoverable index of all of it (`just --list`).

## 9. Migration

Ordered because each step depends on the last. Steps marked **[owner]** need credentials or GitHub
permissions an agent does not have.

1. **[owner]** `git subtree split --prefix=openhound-collector-common -b split/common` in the fork; push
   that branch to the new empty `Mayyhem/openhound-collector-common` as `main`.
2. **[owner]** PyPI: create the project by configuring a **pending** trusted publisher
   (`Mayyhem/openhound-collector-common`, workflow `release.yml`, environment `pypi`) — this reserves the
   name without an upload.
3. **[owner]** Tag `v0.1.0`, push, confirm the action publishes.
4. **[owner]** `git tag v1.2-powershell` on today's `SpecterOps/ConfigManBearPig` `main` + cut a GitHub
   Release, so the PowerShell script has a permanent citable download before anything moves.
5. **[owner]** `git subtree split --prefix=sccm/sccm -b split/sccm` in the fork; merge it into
   `ConfigManBearPig` as an unrelated root (`git pull ../fork split/sccm --allow-unrelated-histories`),
   `git mv` the PowerShell files into `powershell_deprecated/`, and land the Python tree at the root.
6. **[owner]** PyPI: pending trusted publisher for `configmanbearpig`
   (`SpecterOps/ConfigManBearPig`, `release.yml`, environment `pypi`).
7. **[owner]** Tag `v2.0.0`, push, confirm.
8. **[owner]** Verify from a clean machine/venv: `uv tool install openhound --with configmanbearpig` →
   `openhound collect sccm --help`.
9. **[owner]** Remove `sccm/sccm/` and `openhound-collector-common/` from the `Mayyhem/OpenHound` fork,
   and repoint `mssql/mssql` at the new sibling path.

Everything *not* marked `[owner]` — every file edit in §5, §6, §7, §8 — is done in-repo now, so each
`[owner]` step is a copy-paste command against an already-correct tree.

## 10. Verification

| Claim | How it is proven |
|---|---|
| The wheel contains the schema files | `uv build && python -m zipfile -l dist/*.whl \| grep schema_` |
| The schema fix works outside a checkout | `pip install dist/*.whl` into a throwaway venv, then `python -c "from openhound_sccm.bloodhound_schemas import load_sccm_schemas; load_sccm_schemas(False)"` |
| Metadata is right | `python -m zipfile -e` the wheel and read `METADATA` — confirm `Name: configmanbearpig`, the capped `Requires-Dist: openhound-collector-common<0.2.0,>=0.1.0`, and **no** path source |
| Existing behavior is unchanged | Targeted tests only: `bloodhound_schemas_test.py`, `bloodhound_upload_test.py`, `integration_wiring_test.py`, `integration_fixtures_test.py` |
| The dev overlay is live | The `__file__` check from §8 step 4 |
| End-user install works | §9 step 8, from a machine that has never seen this source tree |

## 11. Risks

| Risk | Mitigation |
|---|---|
| PyPI filenames are **immutable** — a bad `2.0.0` burns that version forever. | Verify the built wheel locally (§10) before tagging. `2.0.1` is cheap; do not fight it. |
| Trusted publisher misconfigured (wrong workflow filename or environment) → publish fails. | `--trusted-publishing always` fails loudly. Configure the publisher as *pending* first, so the very first run is the test. |
| Shallow checkout → `hatch-vcs` stamps a dev version. | `fetch-depth: 0`, plus §10's METADATA check. |
| Contributor clones one repo and hits a missing sibling. | Precisely the reason D6 keeps the path source out of the committed file. |
| Restructuring `main` breaks `raw.githubusercontent.com` links to `ConfigManBearPig.ps1`. | The `v1.2-powershell` tag + GitHub Release created **before** the move gives a permanent URL; the README points at it. |
| Splitting the shared lib out of the fork breaks MSSQL's path dep. | §9 step 9 repoints it in the same session; MSSQL is pre-release, so no user impact. |

## 12. Out of scope

- Publishing the MSSQL extension (`mssql/mssql`) — it follows the same recipe once it is feature-complete.
- Adding `py.typed` to the shared library (a separate, already-noted hygiene task).
- Moving `Mayyhem/OpenHound` fork changes upstream.
- Any change to OpenHound core.
