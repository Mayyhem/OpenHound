# BloodHound Upload CLI Feedback + Exit Code Fix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax. **This repo forbids agent git commits** — end at a *green checkpoint* (targeted tests pass), the owner commits.

**Ticket:** ope-feb0 (bug) · linked to ope-8c44 (the upload feature)

**Goal:** Make the SCCM BloodHound upload give the operator clear, always-visible feedback on the console and fail loudly (non-zero exit) when an upload fails — on every path, including the pipeline-less `--skip-collection` / `--upload-dir` upload-only paths.

**Problem (live-verified 2026-07-28 vs BloodHound CE at 127.0.0.1:8080):** the upload *works* (schema `PUT /api/v2/extensions` ×2 and results `file-upload` job both succeed, kinds registered). But `openhound collect sccm <out> --skip-collection --upload-schema-only -B <id>:<key>@<url>` exits **0 with zero console output at any verbosity (`-v`, `--debug`)**. Root cause: OpenHound's console log handler defaults to level `ERROR` (`cli_level` default `"ERROR"`, `openhound/core/logging.py:282`) and is only finalized inside `Collector.run`/`Converter.run` (`set_handler`). The upload-only short-circuit runs the upload *before any pipeline is constructed*, so the extension's `INFO` upload logs reach no visible handler. Separately, `_dispatch_bloodhound_upload` **discards** the `UploadSummary`, so a failed upload logs only at `WARNING` (also invisible on this path) and the command still exits 0 — a silent failure.

**Architecture:** Don't fight OpenHound's logging (it's core, unmodifiable here). Report the upload outcome on **stdout via `typer.echo`** — independent of logging handler levels — and raise `typer.Exit(1)` on failure. Fix lives entirely in the single shared helper `_dispatch_bloodhound_upload`, which all five call sites already funnel through, so every path (collect `--skip-collection`, collect `--run-all`, collect no-run-all `else`, and both `convert` paths) gets consistent behavior with no call-site edits.

**Tech Stack:** Python 3.13+, Typer, pytest. SCCM extension only — no shared-lib or OpenHound-core changes.

## Global Constraints

- **No OpenHound core edits, no shared-lib edits.** Change only `sccm/sccm/src/openhound_sccm/main.py` (+ its test + a one-line README note). The upload *mechanism* (shared lib) is proven correct and untouched.
- **No git commits by the agent.** Green checkpoint = targeted tests pass; the owner commits.
- **Behavior contract for `_dispatch_bloodhound_upload`:**
  - `url` falsy → upload not requested → silent no-op (debug log only), no echo, no exit. (Preserves today's behavior when `-B`/`--bloodhound-url` absent.)
  - `url` set but `build_uploader` returns `None` (missing token) → the operator asked to upload but creds are incomplete → echo an error to **stderr** and `raise typer.Exit(1)`.
  - `url` set, uploader built → echo a start line to stdout; run the upload; then echo a definitive result: on `summary.ok` echo `"BloodHound upload complete: N schema(s), M results file(s)."` to stdout; otherwise echo a `FAILED` line (with `summary.errors`) + an "output on disk is intact" line to stderr and `raise typer.Exit(1)`.
- **Secrets:** never echo `token_key` (echo only the `url`, counts, and error strings — `UploadSummary.errors` never contains the key).
- **`run_upload` already returns an `UploadSummary`** (`schemas_uploaded`, `files_uploaded`, `files_failed`, `errors`, `.ok`) — capture it; do not change `run_upload` or `bloodhound_upload.py`.
- **Tests** live in `sccm/sccm/tests/`; run with `cd sccm/sccm && uv run --no-sync pytest tests/bloodhound_cli_test.py -v` (use `--no-sync`: an online re-resolve trips a pre-existing `openhound-collector-common>=0.1.0` vs installed `0.0.1` pyproject constraint; the existing venv is correct).

---

## File Structure

- **Modify:** `sccm/sccm/src/openhound_sccm/main.py` — rewrite the body of `_dispatch_bloodhound_upload` (currently lines ~375-397; locate by name). No signature change, no call-site changes.
- **Modify (tests):** `sccm/sccm/tests/bloodhound_cli_test.py` — add 4 tests for the new echo/exit behavior.
- **Modify (docs, one line):** `sccm/sccm/README.md` — in the BloodHound Upload subsection, note that a failed upload prints a `FAILED` line and exits non-zero (so scripts can detect it).

---

### Task 1: Make `_dispatch_bloodhound_upload` report + fail loudly

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/main.py` (`_dispatch_bloodhound_upload`)
- Test: `sccm/sccm/tests/bloodhound_cli_test.py`
- Docs: `sccm/sccm/README.md` (one line)

**Interfaces:**
- Consumes (unchanged): `build_uploader` (shared lib), `load_sccm_schemas`, `run_upload` (returns `UploadSummary`), `typer`.
- Produces: same `_dispatch_bloodhound_upload(*, url, token_id, token_key, disable_possible, results_dir, work_dir, upload_schema, upload_results, logger) -> None` signature; new behavior = stdout echo + `typer.Exit(1)` on failure.

- [ ] **Step 1: Write the failing tests**

Add to `sccm/sccm/tests/bloodhound_cli_test.py`:

```python
import logging

import pytest
import typer

import openhound_sccm.main as main
from openhound_collector_common.bloodhound import UploadSummary


class _FakeUploader:
    """Truthy stand-in so _dispatch proceeds past build_uploader."""


def _patch(monkeypatch, *, uploader, summary=None):
    monkeypatch.setattr(main, "build_uploader", lambda *a, **k: uploader)
    monkeypatch.setattr(main, "load_sccm_schemas", lambda _disable: [b"{}"])
    if summary is not None:
        monkeypatch.setattr(main, "run_upload", lambda **k: summary)


def _dispatch(**over):
    kw = dict(
        url="http://127.0.0.1:8080", token_id="i", token_key="k",
        disable_possible=False, results_dir=None, work_dir=main.pathlib.Path("."),
        upload_schema=True, upload_results=False, logger=logging.getLogger("t"),
    )
    kw.update(over)
    return main._dispatch_bloodhound_upload(**kw)


def test_dispatch_echoes_success(monkeypatch, capsys):
    _patch(monkeypatch, uploader=_FakeUploader(),
           summary=UploadSummary(schemas_uploaded=2, files_uploaded=1))
    _dispatch()
    out = capsys.readouterr().out
    assert "BloodHound upload complete" in out
    assert "2 schema" in out and "1 results file" in out


def test_dispatch_exits_nonzero_on_upload_failure(monkeypatch, capsys):
    _patch(monkeypatch, uploader=_FakeUploader(),
           summary=UploadSummary(files_failed=1, errors=["graph.zip: HTTP 500"]))
    with pytest.raises(typer.Exit) as ei:
        _dispatch()
    assert ei.value.exit_code == 1
    err = capsys.readouterr().err
    assert "FAILED" in err and "HTTP 500" in err


def test_dispatch_exits_when_url_given_but_no_token(monkeypatch, capsys):
    # build_uploader returns None when a URL is set but credentials are incomplete.
    _patch(monkeypatch, uploader=None)
    with pytest.raises(typer.Exit) as ei:
        _dispatch(token_key=None)
    assert ei.value.exit_code == 1
    assert "token" in capsys.readouterr().err.lower()


def test_dispatch_noop_without_url(monkeypatch, capsys):
    # No URL => upload not requested => silent no-op, no echo, no exit.
    _patch(monkeypatch, uploader=None)
    assert _dispatch(url=None) is None
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd sccm/sccm && uv run --no-sync pytest tests/bloodhound_cli_test.py -k dispatch -v`
Expected: the 3 new echo/exit tests FAIL (current `_dispatch` returns None silently, never echoes or raises); `test_dispatch_noop_without_url` may already pass.

- [ ] **Step 3: Rewrite `_dispatch_bloodhound_upload`**

Replace its body (keep the signature and docstring intent) with:

```python
def _dispatch_bloodhound_upload(
    *,
    url: Optional[str],
    token_id: Optional[str],
    token_key: Optional[str],
    disable_possible: bool,
    results_dir: "Optional[pathlib.Path]",
    work_dir: pathlib.Path,
    upload_schema: bool,
    upload_results: bool,
    logger: logging.Logger,
) -> None:
    """Build the uploader and push schema/results, reporting the outcome to the
    operator on stdout and failing the command (exit 1) on any upload error.

    Feedback goes through ``typer.echo`` rather than the logging framework: the
    upload-only paths (``--skip-collection`` / ``--upload-dir``) run before any
    Collector/Converter finalizes OpenHound's console log handler, so logging
    alone would be invisible (the handler defaults to ERROR).
    """
    if not url:
        # No -B / --bloodhound-url supplied: upload was not requested. Stay silent.
        logger.debug("BloodHound upload not configured (no URL); skipping")
        return

    uploader = build_uploader(url, token_id, token_key, logger_=logger)
    if uploader is None:
        # A URL was given but credentials are incomplete — the operator asked to
        # upload, so fail loudly instead of silently doing nothing.
        typer.echo(
            "BloodHound upload FAILED: a token is required "
            "(pass --token-id/--token-key or -B <token-id>:<token-key>@<url>).",
            err=True,
        )
        raise typer.Exit(code=1)

    typer.echo(f"Uploading to BloodHound at {url} ...")
    schemas = load_sccm_schemas(disable_possible) if upload_schema else []
    summary = run_upload(
        uploader=uploader, schemas=schemas, results_dir=results_dir,
        work_dir=work_dir, upload_schema=upload_schema, upload_results=upload_results,
        logger=logger,
    )
    if summary.ok:
        typer.echo(
            f"BloodHound upload complete: {summary.schemas_uploaded} schema(s), "
            f"{summary.files_uploaded} results file(s)."
        )
        return

    # Upload had failures — surface them and exit non-zero so a script/operator
    # cannot mistake a silent failure for success. Collected/converted output on
    # disk is untouched.
    typer.echo(
        f"BloodHound upload FAILED ({summary.files_failed} file(s) failed): "
        f"{'; '.join(summary.errors) or 'see logs'}",
        err=True,
    )
    typer.echo("Your collected/converted output on disk is intact.", err=True)
    raise typer.Exit(code=1)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd sccm/sccm && uv run --no-sync pytest tests/bloodhound_cli_test.py -v`
Expected: PASS (all existing bloodhound_cli tests + the 4 new ones).

- [ ] **Step 5: Regression — the wider CLI/convert suites still pass**

Run: `cd sccm/sccm && uv run --no-sync pytest tests/bloodhound_cli_test.py tests/bloodhound_upload_test.py tests/test_cli_option_panels.py tests/convert_integration_test.py -v`
Expected: PASS (no regressions; `_dispatch` signature unchanged so call sites are unaffected).

- [ ] **Step 6: One-line README note**

In `sccm/sccm/README.md`, BloodHound Upload subsection, add a sentence: a successful upload prints `BloodHound upload complete: N schema(s), M results file(s).`; a failed upload prints a `FAILED` line to stderr and exits non-zero (so automation can detect it), while any collected/converted output on disk is left intact.

- [ ] **Step 7: Green checkpoint** — targeted tests pass; stop for owner review (no commit).

---

## Live re-verification (owner or agent, against a running BloodHound CE)

Not an automated test. After the fix, re-run the exact command that was silent and confirm it now reports:

```bash
cd sccm/sccm
uv run --no-sync openhound collect sccm <scratch_out> --skip-collection --upload-schema-only \
  --bloodhound-url http://127.0.0.1:8080 \
  --token-id <id> --token-key '<key>'
```
Expected on the console now: `Uploading to BloodHound at http://127.0.0.1:8080 ...` then `BloodHound upload complete: 2 schema(s), 0 results file(s).`, exit 0. Then test a failure (e.g. a bad token) and confirm a `FAILED` line on stderr + non-zero exit.

## Notes / decisions for the owner

- **`--run-all` + upload failure now exits non-zero.** This is deliberate (a failed upload must not pass unnoticed), and the message states local output is intact. If you'd rather a failed upload NOT fail a `--run-all` run whose collect+convert succeeded, say so — that's a one-line change (echo the failure but don't `raise typer.Exit`), but it reintroduces the "exit 0 on failed upload" risk this ticket is closing.
- **Ordering edge:** on `--run-all`, the upload dispatch runs before the `--compare-to-zip` / `--run-integration-tests` block. If both an upload and `--run-integration-tests` are requested and the upload fails, the command exits on the upload failure before the integration-test exit code. Acceptable (both are terminal); flagged for awareness. Moving the dispatch after the test block is optional and out of scope.

## Self-Review

- Single-helper fix covers all 5 call sites (collect ×3, convert ×2) — verified they all funnel through `_dispatch_bloodhound_upload` and none pass `url` when upload isn't requested except the run-all site (which is `build_uploader`-None-safe → now `url`-None-safe via the early return).
- No secret echoed (only `url` + counts + `summary.errors`).
- No shared-lib/core change; `run_upload`/`UploadSummary` used as-is.
