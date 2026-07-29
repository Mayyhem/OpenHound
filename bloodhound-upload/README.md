# Archived: direct BloodHound CE upload

Removed from both published packages on **2026-07-29**, during the PyPI publishing run
(ticket `ope-60fe`). Kept here, in the fork, as working code with its history intact.

## Why it was removed

It was built to make development and testing faster: `-B` pushed the schema and the freshly
converted graph straight into a local BloodHound CE, so a collect→verify loop took one
command instead of a manual zip-and-drag through the UI. That was worth a lot while the
collector was being ported. Once the port was feature-complete, it stopped paying for itself
and started costing:

- Every user of `configmanbearpig` would carry an HTTP client, an HMAC/Bearer auth
  implementation, a zip bundler and a schema mutator for a workflow most operators do not
  use — they upload through the BloodHound UI.
- `openhound-collector-common` needed `requests` **solely** for this. Removing the feature
  removed a dependency from a package whose entire purpose is shared infrastructure.
- Sixteen CLI options across two commands (eight on `collect sccm`, eight on
  `convert sccm`), each one a thing to document, keep truthful, and support.

Nothing about it was broken. It was live-verified against BloodHound CE at
`127.0.0.1:8080` on 2026-07-28 — HMAC auth, both schema `PUT`s, the file-upload job and
kind registration all succeeded.

## Why it lives at the fork root

The two public repos are built with `git archive HEAD:sccm/sccm` and
`git archive HEAD:openhound-collector-common`, which copy **every tracked file under that
prefix**. Anything left inside either directory ships — including a `dev/` or `archive/`
subfolder. A sibling directory at the fork root is reachable by neither archive, so this
cannot leak into a published package while staying browsable here.

## What is here

| Path | Was |
|---|---|
| `openhound_collector_common/bloodhound/` | `openhound-collector-common/src/openhound_collector_common/bloodhound/` — `auth.py` (HMAC + Bearer signing), `client.py` (retrying HTTP client over the BH CE schema and file-upload endpoints), `uploader.py` (orchestration + credential resolution), `zip_bundle.py`, `schema.py` (`disable_possible_edges`) |
| `openhound_sccm/bloodhound_schemas.py` | `sccm/sccm/src/openhound_sccm/bloodhound_schemas.py` — loads `schema_SCCM.json` **and** `schema_MSSQL.json`, because this collector emits `MSSQL_*` kinds alongside its `SCCM_*` ones |
| `openhound_sccm/bloodhound_upload.py` | `sccm/sccm/src/openhound_sccm/bloodhound_upload.py` — `run_upload`, the single dispatch shared by both CLI commands |
| `openhound_sccm/cli_integration.py` | **Not a module.** This code was inline in `main.py`, so it is extracted verbatim: the two helpers, both option blocks, and all four body dispatch sites. It does not import as-is |
| `tests/library/` (6 files) | `openhound-collector-common/tests/` |
| `tests/sccm/` (3 files) | `sccm/sccm/tests/` |
| `docs/` | The two design plans, from `sccm/sccm/docs/superpowers/plans/` |

## To bring it back

1. Move `openhound_collector_common/bloodhound/` back under the library's
   `src/openhound_collector_common/`, and the two `openhound_sccm/` modules back under
   `sccm/sccm/src/openhound_sccm/`. Return the tests to each package's `tests/`.
2. Restore `"requests>=2.31.0"` to the library's `[project.dependencies]`.
3. Re-apply `cli_integration.py` into `main.py` — its docstring names where each piece sat.
4. Add the test files back to `sccm/sccm/.github/workflows/ci.yml`'s curated list. The
   library's `ci.yml` runs `pytest tests` entire, so it needs no edit.
5. Re-add the README's "Upload to BloodHound" Quick Start step and its "BloodHound Upload"
   options section, and restore §15 of `ARCHITECTURE.md`.

**Two traps worth knowing before you do.**

`--disable-possible-edges` looks like it belongs to this feature on `convert sccm`, and on
that command it effectively did: possible edges are gated during **preprocess**
(`transforms._read_disable_possible`, reading the collect-time value persisted in
`collection_settings`, optionally tightened by `SOURCES__SCCM__DISABLE_POSSIBLE_EDGES`). By
convert time the decision is already baked into the lookup DB, so the flag's only remaining
job there was flipping `is_traversable` in the schema being uploaded. It was removed from
`convert` along with the upload path, and **kept on `collect`**, where it genuinely changes
the graph. If you restore upload, re-add it to `convert` only for the schema mutation, and
say so in its help text.

The schema JSON files stayed in the package and are **not** upload-only:
`integration/__init__.py` reads `schema_SCCM.json` for the test kit's coverage check.
`schema_MSSQL.json` now has no code reader and ships as a deliverable operators upload by
hand — do not "clean it up".
