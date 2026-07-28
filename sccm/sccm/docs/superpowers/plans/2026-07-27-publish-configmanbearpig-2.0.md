# Publish ConfigManBearPig 2.0 + openhound-collector-common Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **This repo forbids agent git commits** — every task ends at a *green checkpoint* (targeted tests pass, owner reviews and commits), never a `git commit`.

**Design:** [`../specs/2026-07-27-publishing-and-repo-split-design.md`](../specs/2026-07-27-publishing-and-repo-split-design.md)

**Goal:** Make `uv tool install openhound --with configmanbearpig` install a working SCCM collector from public PyPI, and make the three-repo development loop obvious enough that a contributor never has to guess.

**Architecture:** Two distributions published to public PyPI from two GitHub repos via tag-triggered Trusted Publishing (OIDC, no API tokens): `openhound-collector-common` (from `Mayyhem/openhound-collector-common`) and `configmanbearpig` (from `SpecterOps/ConfigManBearPig`, Python at the repo root). The committed dependency is a normal capped PyPI requirement; the owner's live editable copy is re-attached on demand by a `just dev` recipe, so a one-repo clone still works. Version numbers come from git tags via `hatch-vcs`.

**Tech Stack:** Python 3.13/3.14, hatchling + hatch-vcs (build), uv (resolve/build/publish), GitHub Actions + PyPI Trusted Publishing, `just` (task runner), pytest.

## Global Constraints

Copy these verbatim into every task's mental checklist:

- **D1** — Target index is **public pypi.org**, owner's **personal** account.
- **D2** — SCCM distribution name is exactly **`configmanbearpig`** (lowercase; PyPI normalizes it anyway).
- **D3** — Import package stays **`openhound_sccm`**; entry-point key stays **`sccm`** (`openhound collect sccm`). **Do not rename either.**
- **D4** — SCCM lands at the **root** of `SpecterOps/ConfigManBearPig`; PowerShell goes to `powershell_deprecated/`.
- **D5** — Shared library keeps the name **`openhound-collector-common`**, published from `Mayyhem/openhound-collector-common`.
- **D6** — **No `[tool.uv.sources]` in either committed `pyproject.toml`.** The dependency is `openhound-collector-common>=0.1.0,<0.2.0`. Editable copies come from `just dev` only.
- **D7** — Release = push a `v*` tag; version from `hatch-vcs`; publish via Trusted Publishing with `environment: pypi` and `id-token: write`.
- **D9** — First versions: shared lib `v0.1.0`, `configmanbearpig` **`v2.0.0`** (the SCCM extension *is* ConfigManBearPig 2.0). PowerShell `main` archived as `v1.2-powershell`.
- **D10** — **Apache-2.0 for everything.** Both packages declare `license = "Apache-2.0"` + `license-files = ["LICENSE"]`, both ship a real `LICENSE` file, and every other place a license is stated (`extension.yaml`, both READMEs) says Apache-2.0. No MIT anywhere — grep for it before finishing.
- **`openhound` is NOT a declared dependency** of either package — verified convention (`uv pip compile openhound-jamf==0.2.3` resolves to exactly one package). The framework is the host.
- **No OpenHound core edits.** Only `sccm/sccm/`, `openhound-collector-common/`, and new docs.
- **No agent git commits.** Every task ends green; the owner commits.
- **Logging:** every `if`/`else` and `try`/`except` gets an appropriately-levelled log unless truly needless (then a comment).
- **Targeted tests only** — never the full suite. SCCM: `cd sccm/sccm && uv run pytest tests/<file> -v`. Shared lib: `cd openhound-collector-common && uv run pytest tests/<file> -v`.
- **Docs are code-truth.** README/ARCHITECTURE.md updates ship with the change that makes them true.

---

## File Structure

**Modified — shared library:**
- `openhound-collector-common/pyproject.toml` — dynamic version, metadata, license.

**Created — shared library:**
- `openhound-collector-common/LICENSE` — license text (currently declared but absent).
- `openhound-collector-common/.github/workflows/release.yml` — tag-triggered Trusted Publishing.
- `openhound-collector-common/justfile` — `dev`, `test`, `lint`, `build`, `check-wheel`.
- `openhound-collector-common/DEVELOPMENT.md` — the contributor loop.

**Modified — SCCM:**
- `sccm/sccm/pyproject.toml` — rename to `configmanbearpig`, dynamic version, drop `[tool.uv.sources]`, cap the shared-lib dep, add license/classifiers/urls.
- `sccm/sccm/src/openhound_sccm/bloodhound_schemas.py:18-21` — package-relative schema paths.
- `sccm/sccm/src/openhound_sccm/integration/__init__.py:19-21` — package-relative schema path.
- `sccm/sccm/src/openhound_sccm/extension.yaml` — real metadata instead of cookiecutter boilerplate.
- `sccm/sccm/tests/integration_fixtures_test.py:62-69` — read schemas from the package dir.
- `sccm/sccm/tests/integration_wiring_test.py` — unchanged assertions, new `SCHEMA_PATH` location.
- `sccm/sccm/README.md:88-98` — install from PyPI.
- `sccm/sccm/ARCHITECTURE.md` — new "Packaging and distribution" section.
- `TICKETS-BY-STATUS.md` — new tickets.

**Moved — SCCM:**
- `sccm/sccm/schema_SCCM.json` → `sccm/sccm/src/openhound_sccm/schema_SCCM.json`
- `sccm/sccm/schema_MSSQL.json` → `sccm/sccm/src/openhound_sccm/schema_MSSQL.json`

**Deleted — SCCM:**
- `sccm/sccm/src/main.py`, `sccm/sccm/src/__init__.py` — cookiecutter residue outside the wheel.

**Created — SCCM:**
- `sccm/sccm/LICENSE` — Apache-2.0, matching the ConfigManBearPig repo.
- `sccm/sccm/.github/workflows/release.yml`
- `sccm/sccm/justfile`
- `sccm/sccm/DEVELOPMENT.md`
- `sccm/sccm/PUBLISHING.md` — the owner-only runbook (repo creation, PyPI setup, subtree splits, tags).

---

## Interfaces (the contract every task shares)

```python
# openhound_sccm.bloodhound_schemas  (unchanged public API — only path resolution changes)
SCCM_POSSIBLE_EDGE_KINDS: tuple[str, ...]
MSSQL_POSSIBLE_EDGE_KINDS: tuple[str, ...]
def load_sccm_schemas(disable_possible: bool) -> list[bytes]: ...

# openhound_sccm.integration  (unchanged public API)
SCHEMA_PATH: Path                      # must stay a real pathlib.Path — run_suite() types it as `Path | None`
def run_integration_tests(graph_dir: Path, results_path: Path | None = None, log=...) -> int: ...
def compare_to_zip(graph_dir: Path, zip_path: Path, out_path: Path | None = None, log=...) -> int: ...
```

Nothing in this plan changes a signature. Task 3 changes only *where the bytes come from*.

---

### Task 1: Fix the schema-packaging bug (the only behavioral change)

The schema files live one directory above the wheel's package root, so they are absent from every
installed copy and `-B/--bloodhound` upload raises `FileNotFoundError` for real users. Do this task
first: it is the only change that can break existing behavior, and every later task is metadata.

**Files:**
- Move: `sccm/sccm/schema_SCCM.json` → `sccm/sccm/src/openhound_sccm/schema_SCCM.json`
- Move: `sccm/sccm/schema_MSSQL.json` → `sccm/sccm/src/openhound_sccm/schema_MSSQL.json`
- Modify: `sccm/sccm/src/openhound_sccm/bloodhound_schemas.py:18-21`
- Modify: `sccm/sccm/src/openhound_sccm/integration/__init__.py:19-21`
- Modify: `sccm/sccm/tests/integration_fixtures_test.py:62-69`
- Test: `sccm/sccm/tests/bloodhound_schemas_test.py` (add one test)

**Interfaces:**
- Consumes: nothing.
- Produces: `schema_SCCM.json` and `schema_MSSQL.json` importable as package data at
  `openhound_sccm/`; `load_sccm_schemas()` and `SCHEMA_PATH` keep their exact current signatures.

- [ ] **Step 1: Write the failing test**

Add to `sccm/sccm/tests/bloodhound_schemas_test.py`:

```python
def test_schema_files_ship_inside_the_package(tmp_path, monkeypatch):
    """Schemas must resolve from the package dir, not from a path above it.

    Guards the packaging bug where Path(__file__).parents[2] pointed at the repo
    checkout: correct in a source tree, above site-packages once installed.
    """
    import openhound_sccm
    from pathlib import Path
    from openhound_sccm.bloodhound_schemas import load_sccm_schemas

    pkg_dir = Path(openhound_sccm.__file__).resolve().parent
    assert (pkg_dir / "schema_SCCM.json").is_file()
    assert (pkg_dir / "schema_MSSQL.json").is_file()

    # Loading must not depend on the process working directory.
    monkeypatch.chdir(tmp_path)
    schemas = load_sccm_schemas(disable_possible=False)
    assert len(schemas) == 2 and all(s.startswith(b"{") for s in schemas)
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd sccm/sccm && uv run pytest tests/bloodhound_schemas_test.py::test_schema_files_ship_inside_the_package -v
```

Expected: FAIL on the first assert — `schema_SCCM.json` is not in the package directory yet.

- [ ] **Step 3: Move the two schema files into the package**

```bash
cd sccm/sccm && git mv schema_SCCM.json src/openhound_sccm/schema_SCCM.json && git mv schema_MSSQL.json src/openhound_sccm/schema_MSSQL.json
```

(`git mv` keeps the rename in history; this is a file move, not a commit.)

- [ ] **Step 4: Point `bloodhound_schemas.py` at the package directory**

Replace lines 18-21:

```python
# The two hand-maintained schema files ship *inside* the package (see the wheel
# target in pyproject.toml), so a package-relative path resolves identically in a
# source checkout and in site-packages. The previous parents[2] hop pointed at the
# repo directory, which does not exist in an installed copy.
_SCHEMA_ROOT = Path(__file__).resolve().parent
_SCCM_SCHEMA = _SCHEMA_ROOT / "schema_SCCM.json"
_MSSQL_SCHEMA = _SCHEMA_ROOT / "schema_MSSQL.json"
```

- [ ] **Step 5: Point `integration/__init__.py` at the package directory**

Replace lines 19-21:

```python
# schema_SCCM.json ships inside the package alongside this subpackage:
# src/openhound_sccm/integration/__init__.py -> parents[0]=integration, [1]=openhound_sccm.
# Must stay a pathlib.Path — run_suite() types schema_path as `Path | None`.
SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schema_SCCM.json"
```

- [ ] **Step 6: Point the fixture test at the package directory**

In `sccm/sccm/tests/integration_fixtures_test.py`, replace line 64:

```python
    base = pathlib.Path(__file__).resolve().parents[1] / "src" / "openhound_sccm"
```

and update the trailing comment on that line to `# sccm package dir (schemas ship inside the wheel)`.

- [ ] **Step 7: Run the four affected test files**

```bash
cd sccm/sccm && uv run pytest tests/bloodhound_schemas_test.py tests/bloodhound_upload_test.py tests/integration_wiring_test.py tests/integration_fixtures_test.py -v
```

Expected: all PASS, including the new test.

- [ ] **Step 8: Green checkpoint** — report the pytest summary line. Do not commit.

---

### Task 2: Shared-library packaging metadata + LICENSE

`openhound-collector-common` must be publishable and must be published *before* CMBP, since CMBP
depends on it.

**Files:**
- Modify: `openhound-collector-common/pyproject.toml:1-14`
- Create: `openhound-collector-common/LICENSE`

**Interfaces:**
- Consumes: nothing.
- Produces: a distribution named `openhound-collector-common` whose version comes from git tags, so
  Task 4's dependency floor (`>=0.1.0,<0.2.0`) is satisfiable.

- [ ] **Step 1: Create the `LICENSE` file (Apache-2.0)**

Per **D10**, everything is Apache-2.0. The shared library previously declared `license = "MIT"` and
shipped no license text at all — both wrong: it was factored out of the SCCM extension, itself a port of
the Apache-2.0 `ConfigManBearPig.ps1`, and Apache-2.0 derivative work cannot be silently relabelled.
Copy the canonical text from the repo root (it is already the Apache-2.0 text):

```bash
cp LICENSE.md openhound-collector-common/LICENSE
cp LICENSE.md sccm/sccm/LICENSE
```

Both packages get the same file in the same step, so the two `pyproject.toml` edits in Tasks 2 and 3
can each declare `license-files = ["LICENSE"]` without a missing-file build error.

- [ ] **Step 2: Replace the metadata block in `openhound-collector-common/pyproject.toml`**

Replace lines 1-14 (`[build-system]` through the `authors` block) with:

```toml
[build-system]
requires = ["hatchling", "hatch-vcs"]
build-backend = "hatchling.build"

[project]
name = "openhound-collector-common"
dynamic = ["version"]                     # from the git tag, via hatch-vcs (see below)
description = "Shared pure-Python infrastructure for OpenHound on-prem/Windows-auth collectors (TDS/NTLM/Kerberos/EPA, LDAP/AD, WMI, DNS discovery, SOCKS5, DLT bridges, logging, graph stubs)"
readme = "README.md"
requires-python = ">=3.13,<3.15"
authors = [
  {name = "Chris Thompson (@_Mayyhem)", email = "cthompson@specterops.io"}
]
license = "Apache-2.0"
license-files = ["LICENSE"]
keywords = ["bloodhound", "opengraph", "openhound", "ntlm", "kerberos", "epa", "ldap", "impacket"]
classifiers = [
  "Development Status :: 4 - Beta",
  "Intended Audience :: Information Technology",
  "Programming Language :: Python :: 3.13",
  "Programming Language :: Python :: 3.14",
  "Topic :: Security",
]

[project.urls]
Homepage = "https://github.com/Mayyhem/openhound-collector-common"
Repository = "https://github.com/Mayyhem/openhound-collector-common"
Issues = "https://github.com/Mayyhem/openhound-collector-common/issues"
```

- [ ] **Step 3: Append the version-source config at the end of the same file**

```toml
[tool.hatch.version]
source = "vcs"

[tool.hatch.version.raw-options]
local_scheme = "no-local-version"        # PyPI rejects local version segments (+g1a2b3c)
fallback_version = "0.0.0"               # keeps `uv build` working in a tagless/shallow checkout
```

`no-local-version` is not cosmetic: PyPI refuses any upload whose version carries a `+local` segment,
which is exactly what `hatch-vcs` produces by default on a non-tag commit. OpenHound core sets the same
option for the same reason.

- [ ] **Step 4: Build and inspect**

```bash
cd openhound-collector-common && uv build
python -m zipfile -l dist/*.whl | head -20
```

Expected: a wheel named `openhound_collector_common-<version>-py3-none-any.whl`. **The version will
look wrong right now** (it derives from the enclosing fork's `v0.1.1` tag) — that is expected and
self-corrects once the directory is its own repo. What must be right is the *name* and the presence of
`openhound_collector_common/` modules.

- [ ] **Step 5: Confirm the metadata**

```bash
cd openhound-collector-common && python -c "import zipfile,glob; w=glob.glob('dist/*.whl')[0]; print([l for l in zipfile.ZipFile(w).read([n for n in zipfile.ZipFile(w).namelist() if n.endswith('METADATA')][0]).decode().splitlines() if l.startswith(('Name:','License','Requires-Dist','Project-URL'))])"
```

Expected: `Name: openhound-collector-common`, an Apache-2.0 license expression, the impacket/ldap3/
dnspython/pyasn1/cryptography/requests requirements, and the three project URLs.

- [ ] **Step 6: Correct the README's license line**

`openhound-collector-common/README.md` ends with `License: MIT.` — and because `readme = "README.md"`,
that line is embedded verbatim in the wheel's `METADATA` description, actively contradicting the
`License-Expression: Apache-2.0` field two lines above it. Replace it with a proper section:

```markdown
## License

Apache-2.0 (see [LICENSE](LICENSE)). This code was factored out of the SCCM collector, itself a port of
the Apache-2.0 `ConfigManBearPig.ps1`, so it inherits those terms.
```

While in the file, fix the stale **Consumers** section too: it claims SCCM "is to be migrated onto this
library later" and describes a local path dependency. Both are now false — SCCM depends on a published,
capped release. Name ConfigManBearPig and the PyPI dist, and link `DEVELOPMENT.md`.

- [ ] **Step 7: Run the shared library's targeted tests**

```bash
cd openhound-collector-common && uv run pytest tests/test_bloodhound_exports.py tests/test_graph.py -v
```

Expected: PASS — metadata changes must not touch behavior.

- [ ] **Step 8: Green checkpoint.** Delete the throwaway `dist/` (`rm -rf openhound-collector-common/dist`). Do not commit.

---

### Task 3: SCCM packaging metadata — rename to `configmanbearpig`

**Files:**
- Modify: `sccm/sccm/pyproject.toml` (whole file)
- Create: `sccm/sccm/LICENSE`
- Delete: `sccm/sccm/src/main.py`, `sccm/sccm/src/__init__.py`

**Interfaces:**
- Consumes: Task 2's published-name `openhound-collector-common`.
- Produces: a distribution named `configmanbearpig` exposing entry point
  `openhound.sources` → `sccm = "openhound_sccm.main:app"`, with
  `Requires-Dist: openhound-collector-common<0.2.0,>=0.1.0`.

- [ ] **Step 1: Confirm the Apache-2.0 license file is in place**

Task 2 Step 1 already copied it. Verify, and copy it now if that task was skipped:

```bash
test -f sccm/sccm/LICENSE || cp LICENSE.md sccm/sccm/LICENSE
```

The ConfigManBearPig repo is already Apache-2.0; the package currently declares no license at all, so
this is the SCCM half of **D10**.

- [ ] **Step 2: Replace the `[project]` header of `sccm/sccm/pyproject.toml` (lines 1-9)**

```toml
[project]
name = "configmanbearpig"
dynamic = ["version"]                     # from the git tag, via hatch-vcs
description = "ConfigManBearPig 2.0 — OpenHound/BloodHound OpenGraph collector for Microsoft Configuration Manager (SCCM/MECM)"
readme = "README.md"
requires-python = "<3.15,>=3.13"
authors = [
  {name = "Chris Thompson (@_Mayyhem)", email = "cthompson@specterops.io"}
]
license = "Apache-2.0"
license-files = ["LICENSE"]
keywords = ["sccm", "mecm", "configmgr", "bloodhound", "opengraph", "openhound", "attack-paths"]
classifiers = [
  "Development Status :: 4 - Beta",
  "Intended Audience :: Information Technology",
  "Programming Language :: Python :: 3.13",
  "Programming Language :: Python :: 3.14",
  "Topic :: Security",
]

[project.urls]
Homepage = "https://github.com/SpecterOps/ConfigManBearPig"
Repository = "https://github.com/SpecterOps/ConfigManBearPig"
Issues = "https://github.com/SpecterOps/ConfigManBearPig/issues"
```

- [ ] **Step 3: Cap the shared-library dependency (line 17)**

Replace the bare `"openhound-collector-common",` with:

```toml
    # Published to PyPI from https://github.com/Mayyhem/openhound-collector-common.
    # Capped below 0.2 because a 0.x library makes no API-stability promise — an
    # unpinned floor would let a breaking 0.2 land silently in users' installs.
    # For local development against a live checkout, run `just dev` (see DEVELOPMENT.md);
    # do NOT add [tool.uv.sources] here — it would break `uv sync` for anyone who
    # clones this repo without the sibling directory.
    "openhound-collector-common>=0.1.0,<0.2.0",
```

- [ ] **Step 4: Delete the `[tool.uv.sources]` block (lines 49-53)**

Remove the table entirely, including its comment. Keep `[tool.uv] python-preference = "only-system"`.

- [ ] **Step 5: Switch the build backend to hatch-vcs**

Replace the `[build-system]` block:

```toml
[build-system]
requires = ['hatchling', 'hatch-vcs']
build-backend = 'hatchling.build'
```

and append at the end of the file:

```toml
[tool.hatch.version]
source = "vcs"

[tool.hatch.version.raw-options]
local_scheme = "no-local-version"        # PyPI rejects +local version segments
fallback_version = "0.0.0"               # keeps `uv build` working in a tagless/shallow checkout
```

- [ ] **Step 6: Delete the cookiecutter residue**

```bash
cd sccm/sccm && git rm src/main.py src/__init__.py
```

Both sit outside `src/openhound_sccm/` and are excluded from the wheel; `src/main.py` only re-exports
`openhound.main:app` and nothing imports it. Confirm nothing references them:

```bash
cd sccm/sccm && grep -rn "from src\|import src\b" --include=*.py . | grep -v ".venv" | head
```

Expected: no output.

- [ ] **Step 7: Re-resolve and build**

```bash
cd sccm/sccm && uv lock && uv build
```

`uv lock` will now try to resolve `openhound-collector-common>=0.1.0,<0.2.0` from PyPI, where it does
not exist yet. **This is the expected pre-publish failure.** Until Task 2's package is live, run the
build with the local library injected:

```bash
cd sccm/sccm && uv build --no-sources 2>/dev/null || uv build
```

If `uv lock` blocks, note it in the checkpoint and move on — the lock is regenerated after the shared
library is published (runbook step 4). The wheel build itself does not need the dependency resolved.

- [ ] **Step 8: Verify the wheel name, contents, and metadata**

```bash
cd sccm/sccm && python -c "import zipfile,glob; w=glob.glob('dist/*.whl')[0]; z=zipfile.ZipFile(w); print(w); print([n for n in z.namelist() if n.endswith(('.json','.yaml'))]); m=z.read([n for n in z.namelist() if n.endswith('METADATA')][0]).decode(); print([l for l in m.splitlines() if l.startswith(('Name:','Requires-Dist','License','Project-URL'))])"
```

Expected: wheel named `configmanbearpig-<version>-py3-none-any.whl`; the file list includes
`openhound_sccm/extension.yaml`, `openhound_sccm/schema_SCCM.json`, `openhound_sccm/schema_MSSQL.json`
(**this is the Task 1 fix proving itself**); METADATA shows `Name: configmanbearpig` and
`Requires-Dist: openhound-collector-common<0.2.0,>=0.1.0`.

- [ ] **Step 9: Confirm the entry point survived the rename**

```bash
cd sccm/sccm && python -c "import zipfile,glob; w=glob.glob('dist/*.whl')[0]; print(zipfile.ZipFile(w).read([n for n in zipfile.ZipFile(w).namelist() if n.endswith('entry_points.txt')][0]).decode())"
```

Expected exactly:

```
[openhound.sources]
sccm = openhound_sccm.main:app
```

- [ ] **Step 10: Green checkpoint.** Remove `sccm/sccm/dist/`. Do not commit.

---

### Task 4: Make `extension.yaml` true

OpenHound parses this file on **every** run ([`manager.py:114-130`](../../../../src/openhound/core/manager.py))
and logs an error if it is invalid. It is still cookiecutter boilerplate advertising an "example
credential" and `homepage: TBD`.

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/extension.yaml`
- Test: `sccm/sccm/tests/extension_metadata_test.py` (create)

**Interfaces:**
- Consumes: nothing.
- Produces: metadata that OpenHound's `Extension.from_yaml` accepts, with real `homepage`/`references`.

- [ ] **Step 1: Write the failing test**

Create `sccm/sccm/tests/extension_metadata_test.py`:

```python
"""extension.yaml is parsed by OpenHound on every run — keep it true and loadable."""
from pathlib import Path

import yaml

import openhound_sccm

METADATA = Path(openhound_sccm.__file__).resolve().parent / "extension.yaml"


def test_extension_yaml_ships_in_the_package():
    assert METADATA.is_file()


def test_extension_yaml_has_no_placeholder_metadata():
    data = yaml.safe_load(METADATA.read_text(encoding="utf-8"))
    assert data["name"] == "sccm"                     # must match the entry-point key
    assert "TBD" not in yaml.safe_dump(data)
    assert data["homepage"].startswith("https://github.com/SpecterOps/ConfigManBearPig")
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd sccm/sccm && uv run pytest tests/extension_metadata_test.py -v
```

Expected: `test_extension_yaml_has_no_placeholder_metadata` FAILS on the `"TBD" not in ...` assertion.

- [ ] **Step 3: Rewrite `src/openhound_sccm/extension.yaml`**

```yaml
name: "sccm"
description: "ConfigManBearPig 2.0 — collects Microsoft Configuration Manager (SCCM/MECM) attack paths into BloodHound via OpenGraph"
authors:
  - name: "Chris Thompson (@_Mayyhem)"
    email: "cthompson@specterops.io"

type: local
license: Apache-2.0
homepage: https://github.com/SpecterOps/ConfigManBearPig
references:
  - name: ConfigManBearPig
    url: https://github.com/SpecterOps/ConfigManBearPig
  - name: OpenHound
    url: https://github.com/SpecterOps/openhound
  - name: BloodHound OpenGraph
    url: https://bloodhound.specterops.io/opengraph/overview

tags: ["sccm", "mecm", "configmgr", "opengraph", "bloodhound", "openhound"]
```

Note the `version:` key is **removed** — it duplicated the packaging version and would silently rot
now that the real version comes from the git tag. Also removed: the boilerplate `credentials:` and
`parameters:` blocks, which described an "example credential" and a `size` batch parameter this
collector does not have. If `Extension.from_yaml` rejects the file for a missing required key,
re-add only that key with a truthful value and note it in the checkpoint.

- [ ] **Step 4: Run the test**

```bash
cd sccm/sccm && uv run pytest tests/extension_metadata_test.py -v
```

Expected: both tests PASS.

- [ ] **Step 5: Prove OpenHound still loads the extension**

```bash
cd sccm/sccm && uv run openhound collect sccm --help
```

Expected: the SCCM help screen renders, with **no** `missing 'extension.yaml'` or `invalid metadata`
error in the log output.

- [ ] **Step 6: Green checkpoint.** Do not commit.

---

### Task 5: Release workflows for both repos

**Files:**
- Create: `openhound-collector-common/.github/workflows/release.yml`
- Create: `sccm/sccm/.github/workflows/release.yml`

**Interfaces:**
- Consumes: the `hatch-vcs` version sources from Tasks 2 and 3.
- Produces: the workflow **filename** (`release.yml`) and **environment name** (`pypi`) that the owner
  must type into PyPI's trusted-publisher form. Both must match exactly or publishing fails.

- [ ] **Step 1: Create the shared-library workflow**

`openhound-collector-common/.github/workflows/release.yml`:

```yaml
name: Build and Publish

# Publishing is driven entirely by tags: `git tag v0.1.0 && git push origin v0.1.0`.
# hatch-vcs reads that tag for the version, so the tag IS the release.
on:
  push:
    tags:
      - "v*"

permissions:
  contents: read
  id-token: write          # the OIDC token PyPI trades for a short-lived upload token

jobs:
  build:
    environment: pypi      # gate + audit trail; must match the PyPI trusted-publisher config
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v6
        with:
          fetch-depth: 0   # hatch-vcs needs full history + tags, or it stamps a dev version

      - name: Install uv
        uses: astral-sh/setup-uv@v7

      - name: Build package
        run: uv build

      - name: Verify the built version matches the tag
        run: |
          set -euo pipefail
          version="$(ls dist/*.whl | head -1 | cut -d- -f2)"
          expected="${GITHUB_REF_NAME#v}"
          echo "built=$version tag=$expected"
          test "$version" = "$expected"

      - name: Publish package
        run: uv publish --trusted-publishing always
```

The version-check step exists because the most common release failure is a shallow or tag-less
checkout producing `0.0.0`/`0.1.dev…`, which uploads *successfully* under the wrong version and burns
it forever (PyPI filenames are immutable). Failing the job is much cheaper.

`--trusted-publishing always` makes a misconfigured publisher fail loudly rather than silently falling
back to looking for a token that does not exist.

- [ ] **Step 2: Create the SCCM workflow**

`sccm/sccm/.github/workflows/release.yml` — byte-identical to Step 1's file. The two repos are
independent, so each needs its own copy; there is nothing to share.

- [ ] **Step 3: Validate both files parse as YAML**

```bash
cd "c:/Users/domainadmin/Desktop/OpenHound" && uv run --with pyyaml python -c "import yaml;[print(p, bool(yaml.safe_load(open(p)))) for p in ['openhound-collector-common/.github/workflows/release.yml','sccm/sccm/.github/workflows/release.yml']]"
```

Expected: `True` for both.

- [ ] **Step 4: Green checkpoint.** Note in the report that these workflows are inert until the
directories become their own repo roots — GitHub only runs workflows found at `.github/workflows/` in
the repository root.

---

### Task 6: Developer experience — justfiles + DEVELOPMENT.md

The owner's explicit requirement: keep the dev loop as simple as it is today, and document it.

**Files:**
- Create: `openhound-collector-common/justfile`
- Create: `openhound-collector-common/DEVELOPMENT.md`
- Create: `sccm/sccm/justfile`
- Create: `sccm/sccm/DEVELOPMENT.md`

**Interfaces:**
- Consumes: the capped dependency from Task 3 (which is what makes an overlay necessary).
- Produces: `just dev` — the single command that re-attaches editable copies of the shared library and
  OpenHound into an already-synced `.venv`.

- [ ] **Step 1: Create `sccm/sccm/justfile`**

```just
# ConfigManBearPig 2.0 — developer tasks. Run `just --list` to see everything.
set dotenv-load := true

# Full local dev setup: PyPI deps, then overlay the live sibling checkouts.
# Re-run this after ANY `uv sync` — sync reinstalls the PyPI build and drops the overlay.
dev:
    uv sync --group dev
    uv pip install -e ../openhound-collector-common
    uv pip install -e ../OpenHound

# Prove the overlay is live: both paths must be OUTSIDE this repo's .venv.
check-dev:
    uv run python -c "import openhound_collector_common as c, openhound as o; print('common ->', c.__file__); print('openhound ->', o.__file__)"

# Targeted tests only — never the full suite (house rule).
test +files:
    uv run pytest {{files}} -v

lint:
    uv run ruff check src tests

typecheck:
    uv run mypy src/openhound_sccm

build:
    uv build

# Inspect what would actually be published.
check-wheel: build
    uv run python -c "import zipfile,glob; w=glob.glob('dist/*.whl')[0]; z=zipfile.ZipFile(w); print(w); print('\n'.join(n for n in z.namelist() if n.endswith(('.json','.yaml','.txt'))))"
```

- [ ] **Step 2: Create `openhound-collector-common/justfile`**

```just
# openhound-collector-common — developer tasks. Run `just --list` to see everything.
set dotenv-load := true

dev:
    uv sync --group dev

test +files:
    uv run pytest {{files}} -v

lint:
    uv run ruff check src tests

build:
    uv build

check-wheel: build
    uv run python -c "import zipfile,glob; w=glob.glob('dist/*.whl')[0]; print(w); print('\n'.join(zipfile.ZipFile(w).namelist()[:20]))"
```

The shared library needs no overlay recipe — it is the bottom of the dependency chain.

- [ ] **Step 3: Create `sccm/sccm/DEVELOPMENT.md`**

````markdown
# Developing ConfigManBearPig 2.0

ConfigManBearPig 2.0 is a Python **extension** to [OpenHound](https://github.com/SpecterOps/openhound).
OpenHound owns the `openhound` command; this repo adds the `sccm` collector to it through an entry
point. That means you never run a `configmanbearpig` binary — you run `openhound collect sccm`.

## 1. Prerequisites

- **Python 3.13 or 3.14**, installed from python.org or the Microsoft Store — *not* a uv-managed build.
  This repo sets `python-preference = "only-system"` on purpose: uv's bundled CPython on Windows ships
  a `libcrypto-3-x64.dll` without the `OPENSSL_Applink` shim, and any TLS handshake aborts the process.
- **[uv](https://docs.astral.sh/uv/)** — resolves, builds, and runs everything.
- **[just](https://github.com/casey/just)** — the task runner. `just --list` is the index of every
  command in this document.

## 2. Clone the three repos as siblings

Two of the three are only needed if you want to edit them live. The layout matters because `just dev`
uses relative paths.

```bash
mkdir dev && cd dev
git clone https://github.com/SpecterOps/ConfigManBearPig.git
git clone https://github.com/Mayyhem/openhound-collector-common.git
git clone https://github.com/SpecterOps/openhound.git OpenHound
```

```
dev/
├── ConfigManBearPig/            # you are here
├── openhound-collector-common/  # shared auth/LDAP/WMI/upload library
└── OpenHound/                   # the framework
```

**Only want to run the collector, not develop it?** Skip all of this:

```bash
uv tool install openhound --with configmanbearpig
openhound collect sccm --help
```

## 3. Set up

```bash
cd ConfigManBearPig
just dev
```

That runs three things: `uv sync --group dev` (installs the *published* dependencies into `.venv`),
then two `uv pip install -e` calls that **overlay** your live sibling checkouts on top.

> **The one thing to remember:** any later `uv sync` reinstalls the published builds and silently drops
> the overlay. Re-run `just dev` afterward. If something you just changed in the shared library isn't
> taking effect, this is almost always why.

Verify the overlay is live:

```bash
just check-dev
```

Both printed paths must point at your sibling checkouts (`.../openhound-collector-common/src/...`),
**not** into `ConfigManBearPig/.venv/`.

### Why the dependency isn't a path

`pyproject.toml` declares `openhound-collector-common>=0.1.0,<0.2.0` — a plain PyPI dependency — rather
than a `[tool.uv.sources]` path. A path entry would be convenient for one machine and broken for
everyone else: cloning this repo alone would fail `uv sync` with
*"Distribution not found at: file://…/openhound-collector-common"*. The overlay gets the same result
without putting a machine-specific path in a public file.

## 4. Run tests

Targeted files only — the full suite is slow and some tests need lab infrastructure:

```bash
just test tests/bloodhound_schemas_test.py
just test tests/integration_wiring_test.py tests/convert_pipeline_test.py
```

## 5. Change the shared library

1. Edit in `../openhound-collector-common/`.
2. Test it there: `cd ../openhound-collector-common && just test tests/test_graph.py`.
3. Test it from here — with the overlay active, your edit is already live: `just check-dev` then
   `just test tests/<affected>_test.py`.
4. When it's ready to release: tag the library (`git tag v0.1.1 && git push origin v0.1.1`).
5. If CMBP now *requires* a symbol that only exists in the new version, raise the floor in
   `pyproject.toml` (`>=0.1.1,<0.2.0`). If it doesn't, leave the floor alone.

## 6. Cut a release

Releases are tag-driven; there is no manual upload step and no API token anywhere.

```bash
git tag v2.0.1
git push origin v2.0.1
```

`.github/workflows/release.yml` builds the wheel, asserts the built version matches the tag, and
publishes to PyPI via Trusted Publishing. Watch it in the repo's Actions tab.

Before tagging, sanity-check what will be published:

```bash
just check-wheel
```

The output must include `openhound_sccm/extension.yaml`, `openhound_sccm/schema_SCCM.json`, and
`openhound_sccm/schema_MSSQL.json`. If a data file is missing there, it will be missing for every user.
````

- [ ] **Step 4: Create `openhound-collector-common/DEVELOPMENT.md`**

````markdown
# Developing openhound-collector-common

Shared, pure-Python infrastructure for OpenHound on-prem / Windows-auth collectors: TDS, NTLM,
Kerberos, EPA channel binding, LDAP, WMI, DNS discovery, SOCKS5, DLT bridges, and the BloodHound CE
uploader. It is a **library** — it has no CLI and is never installed on its own by a user.

Consumers today: [ConfigManBearPig](https://github.com/SpecterOps/ConfigManBearPig) (SCCM) and the
in-progress MSSQL collector.

## 1. Prerequisites

- **Python 3.13 or 3.14** (system/python.org build).
- **[uv](https://docs.astral.sh/uv/)**, **[just](https://github.com/casey/just)**.

## 2. Set up

```bash
git clone https://github.com/Mayyhem/openhound-collector-common.git
cd openhound-collector-common
just dev
```

Nothing to overlay: this is the bottom of the dependency chain.

## 3. Test

```bash
just test tests/test_graph.py
just test tests/test_bloodhound_uploader.py
```

## 4. Working on it alongside a collector

Clone it as a **sibling** of the collector repo, then run `just dev` **in the collector**. That overlays
this checkout into the collector's virtualenv, so your edits take effect immediately with no reinstall.
See the collector's `DEVELOPMENT.md`.

## 5. Releasing — and the compatibility rule

```bash
git tag v0.1.1
git push origin v0.1.1
```

The workflow builds, asserts the version matches the tag, and publishes via Trusted Publishing.

**This library is `0.x`, and consumers cap it at `<0.2.0`.** So:

- **Backwards-compatible change** → bump the patch/minor within `0.1.x`. Consumers pick it up
  automatically on their next resolve.
- **Breaking change** → it goes in `0.2.0`, which every consumer's cap deliberately excludes. Bump each
  consumer's floor *and* cap in the same change that adapts its code. This is the whole point of the
  cap: a breaking release can never reach a user's install by accident.
````

- [ ] **Step 5: Verify both justfiles parse**

```bash
cd sccm/sccm && just --list && cd ../../openhound-collector-common && just --list
```

Expected: both print their recipe lists. If `just` is not installed, note it in the checkpoint and
verify by reading — the recipes are plain shell.

- [ ] **Step 6: Green checkpoint.** Do not commit.

---

### Task 7: The owner runbook (`PUBLISHING.md`)

Everything an agent cannot do: create repos, create PyPI projects, split history, push tags.

**Files:**
- Create: `sccm/sccm/PUBLISHING.md`

**Interfaces:**
- Consumes: the workflow filename `release.yml` and environment name `pypi` from Task 5 — the runbook
  must tell the owner to type exactly those into PyPI's form.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Write `sccm/sccm/PUBLISHING.md`**

````markdown
# Publishing runbook — ConfigManBearPig 2.0 + openhound-collector-common

Every step here needs credentials or GitHub permissions. Do them in order: the shared library **must**
exist on PyPI before ConfigManBearPig can resolve.

Design: [`docs/superpowers/specs/2026-07-27-publishing-and-repo-split-design.md`](docs/superpowers/specs/2026-07-27-publishing-and-repo-split-design.md)

---

## Phase 0 — One-time PyPI account setup

1. Create an account at <https://pypi.org/account/register/> if you don't have one.
2. Enable 2FA (PyPI requires it to upload).
3. You do **not** need an API token. Trusted Publishing replaces it.

## Phase 1 — Ship `openhound-collector-common` v0.1.0

1. **Create the GitHub repo** — <https://github.com/new>, owner `Mayyhem`, name
   `openhound-collector-common`, **empty** (no README, no .gitignore, no license).

2. **Split the history out of the fork**, preserving per-file blame:

   ```bash
   cd ~/Desktop/OpenHound
   git subtree split --prefix=openhound-collector-common -b split/common
   ```

   `git subtree split` rewrites just that subdirectory's commits as if it had always been the repo
   root. It creates a branch and touches nothing else.

3. **Push it as the new repo's `main`:**

   ```bash
   cd ~/Desktop/dev
   git clone ~/Desktop/OpenHound openhound-collector-common --branch split/common --single-branch
   cd openhound-collector-common
   git remote set-url origin https://github.com/Mayyhem/openhound-collector-common.git
   git branch -M main
   git push -u origin main
   ```

4. **Configure the trusted publisher (this also reserves the name):**

   <https://pypi.org/manage/account/publishing/> → *Add a new pending publisher* →

   | Field | Value |
   |---|---|
   | PyPI Project Name | `openhound-collector-common` |
   | Owner | `Mayyhem` |
   | Repository name | `openhound-collector-common` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

   All five must match exactly. "Pending" means the project doesn't exist yet — the first successful
   publish creates it.

5. **Create the `pypi` environment on GitHub:** repo → Settings → Environments → *New environment* →
   name it `pypi`. (Optional but recommended: add yourself as a required reviewer, which turns every
   release into a deliberate click.)

6. **Tag and release:**

   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```

7. **Verify:** the Actions run is green, and <https://pypi.org/project/openhound-collector-common/>
   shows 0.1.0. Then prove a real install works:

   ```bash
   uv run --with openhound-collector-common --no-project python -c "import openhound_collector_common; print('ok')"
   ```

## Phase 2 — Archive the PowerShell ConfigManBearPig

Do this **before** restructuring, so the old script keeps a permanent, citable URL.

```bash
cd ~/Desktop/dev
git clone https://github.com/SpecterOps/ConfigManBearPig.git
cd ConfigManBearPig
git tag v1.2-powershell        # $script:ScriptVersion = "1.2"
git push origin v1.2-powershell
```

Then cut a GitHub Release from that tag titled *ConfigManBearPig 1.2 (PowerShell)*, noting that v2.0 is
a Python OpenHound collector and that the script remains available at this tag. Its permanent raw URL
becomes:

`https://raw.githubusercontent.com/SpecterOps/ConfigManBearPig/v1.2-powershell/ConfigManBearPig.ps1`

## Phase 3 — Move the Python collector in

1. **Split it out of the fork:**

   ```bash
   cd ~/Desktop/OpenHound
   git subtree split --prefix=sccm/sccm -b split/sccm
   ```

2. **Merge it into ConfigManBearPig as a second root:**

   ```bash
   cd ~/Desktop/dev/ConfigManBearPig
   git checkout -b python-port
   git pull ~/Desktop/OpenHound split/sccm --allow-unrelated-histories --no-rebase
   ```

   `--allow-unrelated-histories` is required and harmless: the two histories share no ancestor, so
   `git log` will show two beginnings. That's the point — both are preserved.

3. **Resolve the layout:** move PowerShell down, leave Python at the root.

   ```bash
   mkdir -p powershell_deprecated
   git mv ConfigManBearPig.ps1 Invoke-ConfigManBearPigUnitTests.ps1 seed_data.json sample_data cypher_queries powershell_deprecated/
   git rm -r --cached powershell_deprecated/powershell_deprecated 2>/dev/null || true
   ```

   The incoming tree already contains a `powershell_deprecated/` copy of the script — keep one, delete
   the duplicate. Merge the two `README.md` files: the Python one is the new front page; link the old
   PowerShell documentation from `powershell_deprecated/README.md`.

4. **Sanity-check the tree.** The repo root must now hold `pyproject.toml`, `src/openhound_sccm/`,
   `tests/`, `justfile`, `DEVELOPMENT.md`, `.github/workflows/release.yml`, `LICENSE`, `README.md`.

5. **Prove it still works before you publish anything:**

   ```bash
   just dev
   just test tests/bloodhound_schemas_test.py tests/extension_metadata_test.py
   uv run openhound collect sccm --help
   just check-wheel      # must list openhound_sccm/schema_SCCM.json + schema_MSSQL.json
   ```

6. **Regenerate the lock now that the shared library is on PyPI:**

   ```bash
   uv lock
   ```

7. Open a PR into `main`, review the file moves, merge.

## Phase 4 — Ship `configmanbearpig` v2.0.0

1. **Pending trusted publisher** at <https://pypi.org/manage/account/publishing/>:

   | Field | Value |
   |---|---|
   | PyPI Project Name | `configmanbearpig` |
   | Owner | `SpecterOps` |
   | Repository name | `ConfigManBearPig` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

2. **Create the `pypi` environment** in SpecterOps/ConfigManBearPig → Settings → Environments.

3. **Tag and push:**

   ```bash
   git tag v2.0.0
   git push origin v2.0.0
   ```

4. **Verify from a machine that has never seen the source:**

   ```bash
   uv tool install openhound --with configmanbearpig
   openhound collect sccm --help
   ```

## Phase 5 — Clean up the fork

```bash
cd ~/Desktop/OpenHound
git rm -r sccm/sccm openhound-collector-common
```

Then repoint MSSQL's dev overlay at the new sibling checkout (`mssql/mssql/justfile`) and re-run its
`just dev`. The fork keeps only the in-progress MSSQL work.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Action fails: *"Trusted publishing exchange failure"* | Owner / repo / workflow filename / environment don't match the PyPI form exactly | Re-read the pending-publisher entry; every field is literal and case-sensitive |
| Published version is `0.0.0` or `0.1.dev4+g1a2b3c` | Shallow checkout — no tags visible to `hatch-vcs` | `fetch-depth: 0` in the checkout step (already set); the workflow's version-check step should have caught this |
| *"File already exists"* on upload | That version was already published; PyPI filenames are immutable | Bump to the next patch and tag again. Never try to overwrite |
| `uv sync` fails with *"Distribution not found at file://…"* | A `[tool.uv.sources]` path entry crept back into a committed `pyproject.toml` | Remove it; use `just dev` for editable copies |
| Collector installs but `openhound collect sccm` doesn't exist | Entry point missing from the wheel | `just check-wheel` and confirm `entry_points.txt` contains `sccm = openhound_sccm.main:app` |
| `-B/--bloodhound` upload raises `FileNotFoundError` on a schema | Schema JSON not shipped inside the package | `just check-wheel` must list `openhound_sccm/schema_SCCM.json` |
````

- [ ] **Step 2: Verify every internal link resolves**

```bash
cd sccm/sccm && ls docs/superpowers/specs/2026-07-27-publishing-and-repo-split-design.md
```

Expected: the path prints.

- [ ] **Step 3: Green checkpoint.** Do not commit.

---

### Task 8: Documentation truth pass + tickets

**Files:**
- Modify: `sccm/sccm/README.md:88-98` (Quick Start install) and the Table of Contents at line 22
- Modify: `sccm/sccm/ARCHITECTURE.md` (append a "Packaging and distribution" section)
- Modify: `TICKETS-BY-STATUS.md`

**Interfaces:**
- Consumes: the final install command and package names from Tasks 3-7.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Rewrite the README Quick Start install section (lines 90-98)**

```markdown
The collector is an OpenHound extension: OpenHound provides the `openhound` command, and this package
adds the `sccm` collector to it.

### 1. Install

```powershell
uv tool install openhound --with configmanbearpig
```

That single command installs the OpenHound framework, this collector, and every dependency it needs
(`openhound-collector-common`, `impacket`, `ldap3`, `dnspython`, `cryptography`, `requests`, and — on
Windows — `pywin32` and `winkerberos`). Verify it:

```powershell
openhound collect sccm --help
```

To install the not-yet-released `main` instead of the published version:

```powershell
uv tool install openhound --with "configmanbearpig @ git+https://github.com/SpecterOps/ConfigManBearPig.git"
```

**Developing the collector rather than running it?** See [DEVELOPMENT.md](DEVELOPMENT.md) — you'll want
sibling checkouts and `just dev`, and the commands below become `uv run openhound …` from inside the repo.
```

- [ ] **Step 2: Update the README's Table of Contents at line 22**

Add entries for the new top-level docs so they're discoverable: a `Developing` link to
`DEVELOPMENT.md` and a `Publishing` link to `PUBLISHING.md`. Match the existing bullet style exactly —
read lines 22-86 first and mirror the formatting rather than inventing a new one.

- [ ] **Step 3: Append a "Packaging and distribution" section to `ARCHITECTURE.md`**

`AGENTS.md` requires ARCHITECTURE.md to be updated in the same change as any cross-cutting subsystem
divergence, and how this collector is packaged and shipped is exactly that. Cover, in prose matching
the file's existing voice:

- The distribution is `configmanbearpig`; the import package is `openhound_sccm`; the CLI verb is
  `sccm`. Three different names, deliberately — the verb names the data source, matching every other
  OpenHound collector.
- `openhound` is a runtime requirement but **not** a declared dependency, because the framework is the
  host environment (verified: `openhound-jamf` declares no dependencies at all). Declaring it could
  only conflict with the version the user already chose.
- The shared library is a capped PyPI dependency (`>=0.1.0,<0.2.0`), never a path source, because a
  path source breaks `uv sync` for anyone cloning a single repo. Editable copies come from `just dev`.
- Data files (`extension.yaml`, `schema_SCCM.json`, `schema_MSSQL.json`) **must** live inside
  `src/openhound_sccm/`, because the wheel ships only that directory. Anything resolved with
  `Path(__file__).parents[2]` or higher is invisible to installed users — the bug fixed in this change.
- Versions come from git tags via `hatch-vcs`; releases are tag-triggered Trusted Publishing.

- [ ] **Step 4: File the tickets**

```bash
cd "c:/Users/domainadmin/Desktop/OpenHound"
gtk create --type task --status closed "Fix schema_SCCM/MSSQL.json packaging: ship inside openhound_sccm package"
gtk create --type task --status closed "Publish configmanbearpig 2.0 + openhound-collector-common to PyPI (metadata, workflows, docs)"
gtk create --type task --status open "Owner runbook: split repos, create PyPI trusted publishers, tag v0.1.0 / v2.0.0"
gtk create --type task --status closed "Relicense openhound-collector-common MIT -> Apache-2.0 to match its ConfigManBearPig provenance"
gtk create --type task --status open "Repoint mssql/mssql at the sibling openhound-collector-common checkout after the split"
```

Flags go **before** the title positional or they leak into the title.

- [ ] **Step 5: Update `TICKETS-BY-STATUS.md`**

Read the file first and follow its existing grouping and formatting exactly; add the five new tickets
under the correct status headings.

- [ ] **Step 6: Verify the docs claim nothing false**

```bash
cd sccm/sccm && grep -n "uv sync\|pip install\|uv tool install" README.md | head -20
```

Every install line must now be either `uv tool install openhound --with configmanbearpig` (users) or an
explicitly-labelled contributor command. No bare `uv sync` should be presented as the way to install.

- [ ] **Step 7: Green checkpoint.** Report which files changed. Do not commit.

---

## Self-Review

**Spec coverage:**

| Spec section | Task |
|---|---|
| §2 D1/D2 dist name, index | Task 3 |
| §2 D3 package + verb unchanged | Tasks 3, 4 (asserted in `extension_metadata_test.py`) |
| §2 D4 repo shape | Task 7 Phase 3 |
| §2 D5 shared lib repo/name | Tasks 2, 7 Phase 1 |
| §2 D6 dev loop | Tasks 3 (drop sources), 6 (justfile + DEVELOPMENT.md) |
| §2 D7 trusted publishing, hatch-vcs | Tasks 2, 3, 5 |
| §2 D8 subtree split | Task 7 Phases 1, 3 |
| §2 D9 versions | Tasks 2, 3 (config), 7 (tags) |
| §2 D10 Apache-2.0 everywhere | Task 2 Steps 1-2 + 6 (shared lib + its README), Task 3 Steps 1-2 (SCCM), Task 4 Step 3 (`extension.yaml`) |
| §3c `openhound` not a dependency | Task 3 (unchanged), Task 8 Step 3 (documented) |
| §4 dependency-source fix | Task 3 Steps 3-4, Task 6 |
| §5a shared-lib metadata | Task 2 |
| §5b SCCM metadata + leftovers + extension.yaml | Tasks 3, 4 |
| §6 schema packaging bug | Task 1 |
| §7 release automation | Task 5 |
| §8 developer experience | Task 6 |
| §9 migration | Task 7 |
| §10 verification | Task 1 Step 7, Task 2 Steps 4-6, Task 3 Steps 8-9, Task 7 Phase 3 Step 5 |
| §11 risks | Task 5 (version-check step), Task 7 (troubleshooting table) |

No gaps.

**Placeholder scan:** No TBD/TODO. Every code step carries real content. The two places that say "read
the existing file first and match its formatting" (Task 8 Steps 2 and 5) are deliberate — both edit
files whose house style must be preserved and neither can be specified without the current text in
front of you.

**Type consistency:** `load_sccm_schemas(disable_possible: bool) -> list[bytes]` and
`SCHEMA_PATH: Path` are unchanged across Tasks 1, 3, and 6. `SCHEMA_PATH` stays a real `pathlib.Path`
because `run_suite()` types `schema_path` as `Path | None` — this is why Task 1 uses
`Path(__file__).resolve().parents[1]` rather than `importlib.resources.files()`, which returns a
`Traversable` with no `.exists()`. Workflow filename `release.yml` and environment `pypi` match between
Task 5 and Task 7's PyPI tables.
