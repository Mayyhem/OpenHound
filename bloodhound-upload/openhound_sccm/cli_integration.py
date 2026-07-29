"""ARCHIVED: the CLI integration that wired BloodHound upload into `openhound_sccm.main`.

This code was **inline in main.py**, not a module, so it could not be moved as a file --
it is extracted here verbatim so the feature stays recoverable. It does not import and is
not meant to run as-is.

Removed 2026-07-29 (ope-60fe side quest): direct upload existed to speed up development
and testing against a local BloodHound CE, and once the collector was feature-complete it
was no longer worth shipping to every user. See ../README.md for the full rationale and a
re-wiring checklist.

Where each piece lived in main.py at the time of removal:
  * the two helpers below            -- module level, after `_per_host_expected`
  * `_COLLECT_OPTIONS`               -- the "BloodHound Upload" rich_help_panel block in
                                        `collect_sccm`'s signature
  * `_COLLECT_BODY_*`                -- three dispatch sites in `collect_sccm`: the
                                        --skip-collection early return, the post-convert
                                        upload under --run-all, and the no-run-all
                                        schema-only path
  * `_CONVERT_OPTIONS` / `_CONVERT_BODY` -- the identical surface on `convert_sccm`

Imports it required at the top of main.py:

    from .bloodhound_schemas import load_sccm_schemas
    from .bloodhound_upload import run_upload
    from openhound_collector_common.bloodhound import build_uploader, resolve_credentials
"""

# --------------------------------------------------------------------------
# Module-level helpers (verbatim)
# --------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Direct BloodHound CE upload (`-B`/`--bloodhound-url` + friends)
# ---------------------------------------------------------------------------
# Shared by `collect --run-all` (Task 9) and `convert` (Task 10): resolve creds
# once, then dispatch through one helper so the schema/results decision logic
# lives in exactly one place.
def _resolve_upload_mode(upload_schema_only: bool, upload_results_only: bool) -> tuple[bool, bool]:
    """Map the two upload-only switches to (upload_schema, upload_results).

    Default is both. The two switches are mutually exclusive.
    """
    if upload_schema_only and upload_results_only:
        raise typer.BadParameter(
            "--upload-schema-only and --upload-results-only are mutually exclusive.",
            param_hint="--upload-results-only",
        )
    if upload_schema_only:
        return True, False
    if upload_results_only:
        return False, True
    return True, True


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
    alone would be invisible (that handler defaults to ERROR). See ope-feb0.
    """
    if not url:
        # No -B / --bloodhound-url supplied: upload was not requested. Stay silent.
        logger.debug("BloodHound upload not configured (no URL); skipping")
        return

    uploader = build_uploader(url, token_id, token_key, logger_=logger)
    if uploader is None:
        # A URL was given but credentials are incomplete -- the operator asked to
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

    # Upload had failures -- surface them and exit non-zero so a script/operator
    # cannot mistake a silent failure for success. Collected/converted output on
    # disk is untouched.
    typer.echo(
        f"BloodHound upload FAILED ({len(summary.errors)} error(s)): "
        f"{'; '.join(summary.errors) or 'see logs'}",
        err=True,
    )
    typer.echo("Your collected/converted output on disk is intact.", err=True)
    raise typer.Exit(code=1)

# --------------------------------------------------------------------------
# collect_sccm: the "BloodHound Upload" option block (verbatim)
# --------------------------------------------------------------------------
_COLLECT_OPTIONS = """
    # ---- BloodHound Upload ----
    bloodhound: Optional[str] = typer.Option(None, "-B", "--bloodhound", rich_help_panel="BloodHound Upload", help="BloodHound CE credentials shorthand: <token-id>:<token_key>@<url> (uploads both schema and results)."),
    bloodhound_url: Optional[str] = typer.Option(None, "--bloodhound-url", rich_help_panel="BloodHound Upload", help="BloodHound CE instance URL (env: BLOODHOUND_URL)."),
    token_id: Optional[str] = typer.Option(None, "--token-id", rich_help_panel="BloodHound Upload", help="BloodHound API token ID (env: BLOODHOUND_TOKEN_ID)."),
    token_key: Optional[str] = typer.Option(None, "--token-key", rich_help_panel="BloodHound Upload", help="BloodHound API token key (env: BLOODHOUND_TOKEN_KEY)."),
    upload_schema_only: bool = typer.Option(False, "--upload-schema-only", rich_help_panel="BloodHound Upload", help="Only upload schema definitions (skip results)."),
    upload_results_only: bool = typer.Option(False, "--upload-results-only", rich_help_panel="BloodHound Upload", help="Only upload collection results (skip schema)."),
    skip_collection: bool = typer.Option(False, "--skip-collection", rich_help_panel="BloodHound Upload", help="Skip collection; with -B, push the schema only (or upload --upload-dir results)."),
    upload_dir: Optional[pathlib.Path] = typer.Option(None, "--upload-dir", rich_help_panel="BloodHound Upload", help="Upload existing OpenGraph files from this directory instead of collecting/converting."),
"""

# --------------------------------------------------------------------------
# collect_sccm: body dispatch sites (verbatim)
# --------------------------------------------------------------------------
_COLLECT_BODY_RESOLVE_AND_SKIP = """

    # Resolve BloodHound creds up front so both the skip-collection and the
    # --run-all paths use the same values. `upload_mode` also validates the
    # mutually-exclusive switches early (before any collection work).
    bh_url, bh_token_id, bh_token_key = resolve_credentials(
        bloodhound, bloodhound_url, token_id, token_key)
    upload_schema, upload_results = _resolve_upload_mode(upload_schema_only, upload_results_only)

    # --skip-collection: do no collection. With creds, push schema (and, if
    # --upload-dir is given, those existing results). Mirrors the Go tool.
    if skip_collection:
        logger.info("--skip-collection set: skipping collection.")
        _dispatch_bloodhound_upload(
            url=bh_url, token_id=bh_token_id, token_key=bh_token_key,
            disable_possible=disable_possible_edges, results_dir=upload_dir,
            work_dir=output_path, upload_schema=upload_schema,
            upload_results=upload_results and upload_dir is not None,
            logger=logger,
        )
        return None
"""
_COLLECT_BODY_AFTER_CONVERT = """
            _diag.warning_count + _diag.error_count,
        )
        # Direct BloodHound upload of the graph convert just produced (or an
        # explicit --upload-dir). results_dir is None-safe inside run_upload.
        _dispatch_bloodhound_upload(
            url=bh_url, token_id=bh_token_id, token_key=bh_token_key,
            disable_possible=disable_possible_edges,
            results_dir=upload_dir or _paths.graph_out,
            work_dir=output_path, upload_schema=upload_schema,
            upload_results=upload_results, logger=logger,
        )
"""
_COLLECT_BODY_NO_RUN_ALL = """
            raise typer.Exit(code=rc)
    else:
        # Even without --run-all there is no graph to upload, but the operator
        # may still want the schema (or an explicit --upload-dir) pushed.
        if bh_url:
            _dispatch_bloodhound_upload(
                url=bh_url, token_id=bh_token_id, token_key=bh_token_key,
                disable_possible=disable_possible_edges, results_dir=upload_dir,
                work_dir=output_path, upload_schema=upload_schema,
                upload_results=upload_results and upload_dir is not None,
                logger=logger,
            )
"""

# --------------------------------------------------------------------------
# convert_sccm: options + body (verbatim)
# --------------------------------------------------------------------------
_CONVERT_OPTIONS = """
    # ---- BloodHound Upload (identical surface to collect) ----
    bloodhound: Optional[str] = typer.Option(None, "-B", "--bloodhound", rich_help_panel="BloodHound Upload", help="BloodHound CE credentials shorthand: <token-id>:<token_key>@<url>."),
    bloodhound_url: Optional[str] = typer.Option(None, "--bloodhound-url", rich_help_panel="BloodHound Upload", help="BloodHound CE instance URL (env: BLOODHOUND_URL)."),
    token_id: Optional[str] = typer.Option(None, "--token-id", rich_help_panel="BloodHound Upload", help="BloodHound API token ID (env: BLOODHOUND_TOKEN_ID)."),
    token_key: Optional[str] = typer.Option(None, "--token-key", rich_help_panel="BloodHound Upload", help="BloodHound API token key (env: BLOODHOUND_TOKEN_KEY)."),
    upload_schema_only: bool = typer.Option(False, "--upload-schema-only", rich_help_panel="BloodHound Upload", help="Only upload schema definitions."),
    upload_results_only: bool = typer.Option(False, "--upload-results-only", rich_help_panel="BloodHound Upload", help="Only upload results."),
    skip_collection: bool = typer.Option(
        False, "--skip-collection", rich_help_panel="BloodHound Upload",
        help="Skip conversion; with -B, push the schema only (or upload --upload-dir "
        "results). Named to match `collect --skip-collection` so the same flags work "
        "against either subcommand.",
    ),
    upload_dir: Optional[pathlib.Path] = typer.Option(None, "--upload-dir", rich_help_panel="BloodHound Upload", help="Upload existing OpenGraph files from this dir instead of converting."),
"""
_CONVERT_BODY = """
) -> None:
    _apply_log_level(verbose=False, debug=False, silent=False)
    bh_url, bh_token_id, bh_token_key = resolve_credentials(bloodhound, bloodhound_url, token_id, token_key)
    upload_schema, upload_results = _resolve_upload_mode(upload_schema_only, upload_results_only)

    if skip_collection:
        # Mirrors collect_sccm's --skip-collection: push the schema only (or the
        # --upload-dir results too), without running the convert step at all.
        logger.info("--skip-collection set: skipping convert.")
        _dispatch_bloodhound_upload(
            url=bh_url, token_id=bh_token_id, token_key=bh_token_key,
            disable_possible=disable_possible_edges, results_dir=upload_dir,
            work_dir=output_path, upload_schema=upload_schema,
            upload_results=upload_results and upload_dir is not None,
            logger=logger,
        )
        return

    if upload_dir is not None:
        # Standalone re-upload: skip convert, push the given graph dir.
        logger.info("--upload-dir set: uploading existing graph, skipping convert.")
        results_dir = upload_dir
    else:
        # Normal path: run the convert, then upload what it produced.
        _run_convert(
            input_path=input_path, output_path=output_path, lookup_file=lookup_file,
            progress=_resolve_progress(progress), method=Method.write,
        )
        results_dir = output_path

    _dispatch_bloodhound_upload(
        url=bh_url, token_id=bh_token_id, token_key=bh_token_key,
        disable_possible=disable_possible_edges, results_dir=results_dir,
        work_dir=output_path, upload_schema=upload_schema, upload_results=upload_results,
        logger=logger,
    )
"""
