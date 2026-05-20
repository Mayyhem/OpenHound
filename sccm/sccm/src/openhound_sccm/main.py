"""Entry point for the OpenHound SCCM extension.

Registers ``collect`` / ``preprocess`` / ``convert`` subcommands directly on
the framework's public Typer groups (`openhound.cli.{collect,preproc,convert}`)
with every ``configmanbearpig.py`` CLI flag exposed as a real ``--flag``. The
flags translate to ``SOURCES__SCCM__*`` env vars before the framework's
``dlt.config.value`` injection runs, so users can choose freely between flags,
env vars, or a ``.env`` file.

Also exposes a local ``package`` Typer subcommand for the BloodHound ZIP output
(no framework hook exists for post-convert packaging).
"""

from __future__ import annotations

import logging
import os
import pathlib
import platform
import socket
from typing import List, Optional

# Disable DLT anonymous telemetry before `dlt` is imported. The DLT-internal
# `dlt.config[...] = False` knob runs too late to suppress the telemetry HTTPS
# call because the pipeline takes a config snapshot at construction time.
os.environ.setdefault("RUNTIME__DLTHUB_TELEMETRY", "false")
os.environ.setdefault("DLT__RUNTIME__DLTHUB_TELEMETRY", "false")

import typer  # noqa: E402
from dlt.common.pipeline import LoadInfo  # noqa: E402
from openhound.cli.collect import collect as _collect_typer  # noqa: E402
from openhound.cli.convert import convert as _convert_typer  # noqa: E402
from openhound.cli.preproc import preprocess as _preprocess_typer  # noqa: E402
from openhound.core.app import (  # noqa: E402
    DEFAULT_LOOKUP_FILE,
    Contract,
    InputPath,
    OpenHound,
    OutputPath,
)
from openhound.core.collect import CollectContext, Collector  # noqa: E402
from openhound.core.convert import ConvertContext, Converter, Method  # noqa: E402
from openhound.core.preproc import PreProcContext, PreProcessor  # noqa: E402
from openhound.core.progress import Progress  # noqa: E402

from .lookup import SCCMLookup
from .transforms import transforms

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OpenHound app instance. Still owns `source_kind` (flows into the OpenGraph
# metadata block) plus the asset registry that ``Converter.run`` reads. The
# `@app.collect/@app.preproc/@app.convert` convenience decorators are
# intentionally *not* used here — we register richer Typer commands on the
# framework's public Typer groups directly so we can add CMBP-style flags.
# ---------------------------------------------------------------------------
app = OpenHound(
    "sccm",
    source_kind="SCCM_Base",
    help="OpenGraph collector for Microsoft Endpoint Configuration Manager (SCCM)",
)


# ---------------------------------------------------------------------------
# Flag → env-var translation
# ---------------------------------------------------------------------------
# Every CMBP-style flag on `collect` / `preprocess` / `convert` maps to a
# ``SOURCES__SCCM__*`` env var. The Typer command sets the env var BEFORE the
# DLT source factory resolves its `dlt.config.value` parameters, so the user
# can supply config equivalently via CLI flag, env var, or `.env` file. Flag
# values win because they're applied last (just before the framework's
# Collector/Converter/PreProcessor is constructed).
# ---------------------------------------------------------------------------
_FLAG_TO_ENV: dict[str, str] = {
    # Connection
    "domain": "SOURCES__SCCM__DOMAIN",
    "domain_controller": "SOURCES__SCCM__DOMAIN_CONTROLLER",
    "username": "SOURCES__SCCM__USERNAME",
    "password": "SOURCES__SCCM__PASSWORD",
    "ldap_port": "SOURCES__SCCM__LDAP_PORT",
    # Collection
    "collection_methods": "SOURCES__SCCM__COLLECTION_METHODS",
    "computers": "SOURCES__SCCM__COMPUTERS",
    "computer_file": "SOURCES__SCCM__COMPUTER_FILE",
    "sms_provider": "SOURCES__SCCM__SMS_PROVIDER",
    "site_codes": "SOURCES__SCCM__SITE_CODES",
    # Behavior flags
    "disable_possible_edges": "SOURCES__SCCM__DISABLE_POSSIBLE_EDGES",
    "enable_bad_opsec": "SOURCES__SCCM__ENABLE_BAD_OPSEC",
    "threads": "SOURCES__SCCM__THREADS",
    "show_cleartext_passwords": "SOURCES__SCCM__SHOW_CLEARTEXT_PASSWORDS",
    # CRED-2 / Machine Account (flags accepted; implementation chain deferred)
    "machine_name": "SOURCES__SCCM__MACHINE_NAME",
    "machine_pass": "SOURCES__SCCM__MACHINE_PASS",
    "client_name": "SOURCES__SCCM__CLIENT_NAME",
    "create_machine_account": "SOURCES__SCCM__CREATE_MACHINE_ACCOUNT",
    "use_altauth": "SOURCES__SCCM__USE_ALTAUTH",
    "registration_sleep": "SOURCES__SCCM__REGISTRATION_SLEEP",
    # Network
    "socks_proxy": "SOURCES__SCCM__SOCKS_PROXY",
}


def _apply_env_overrides(flag_kwargs: dict) -> None:
    """Map CMBP-style flag values to ``SOURCES__SCCM__*`` env vars.

    Skips values that are ``None`` or default-``False`` so a flag that wasn't
    passed doesn't overwrite a higher-priority env-var or ``.env`` entry.
    Booleans serialise as ``"true"`` / ``"false"`` (lowercased); paths
    serialise via ``str()``.
    """
    for flag_name, env_name in _FLAG_TO_ENV.items():
        if flag_name not in flag_kwargs:
            continue
        value = flag_kwargs[flag_name]
        if value is None:
            continue
        if isinstance(value, bool):
            if not value:
                continue
            os.environ[env_name] = "true"
        elif isinstance(value, pathlib.Path):
            os.environ[env_name] = str(value)
        else:
            os.environ[env_name] = str(value)


def _apply_log_level(verbose: int, debug: bool) -> None:
    """Adjust console logging based on verbosity flags + install the
    ``[target][phase]`` prefix filter.

    ``-v``      → INFO   (collection-step summaries: "Starting LDAP collection…")
    ``-vv``     → VERBOSE (PS1 ``[Verbose]`` parity tier: per-AD-resolution, per-
                  node-add, per-edge dedupe traces)
    ``--debug`` → DEBUG  (everything, including dlt and ldap3 internals)

    Highest-set wins. Neither flag → framework default (file-only at INFO).

    The framework's default config uses a ``RichHandler`` (or stdout
    ``StreamHandler`` in container mode) wired up by
    ``openhound/core/logging.py``. We keep those handlers in place — the
    user prefers the framework's ``time=…, msg=…`` format — and only swap
    the formatter to drop the trailing ``(openhound_version=…)`` suffix
    that ``OpenHoundRichFormatter`` appends to every line.
    """
    from .log_context import VERBOSE, install_filter

    if debug:
        level_name, level = "DEBUG", logging.DEBUG
    elif verbose >= 2:
        level_name, level = "VERBOSE", VERBOSE
    elif verbose >= 1:
        level_name, level = "INFO", logging.INFO
    else:
        level_name, level = None, None

    if level_name is not None:
        os.environ["RUNTIME__LOG_LEVEL"] = level_name
        os.environ["RUNTIME__LOG_CLI_LEVEL"] = level_name
        root = logging.getLogger()
        # Lower the root logger so records of the requested level can reach
        # any handler. Existing file handlers keep their own level.
        if root.level == 0 or root.level > level:
            root.setLevel(level)
        for log in (root, logging.getLogger("dlt")):
            for handler in log.handlers:
                if handler.level == 0 or handler.level > level:
                    handler.setLevel(level)
        # The OpenHound framework's CLI handler uses ``OpenHoundRichFormatter``
        # (see ``openhound/core/logging.py:170``) which appends
        # `` (openhound_version=<v>)`` to every line. Swap the formatter
        # for one that produces the same ``time=…, msg=…`` shape minus
        # that suffix — keeps the framework's preferred format without
        # touching OpenHound code. The JSON file handler keeps its own
        # formatter so the structured log is untouched.
        _strip_version_suffix_from_handlers()

    install_filter()


class _NoVersionRichFormatter(logging.Formatter):
    """Mirror of ``openhound.core.logging.OpenHoundRichFormatter`` minus the
    trailing ``(openhound_version=…)`` suffix. Used by ``_apply_log_level``
    to swap the framework's CLI formatter in place."""

    def format(self, record: logging.LogRecord) -> str:
        return f"time={self.formatTime(record, '%Y-%m-%d %H:%M:%S')}, msg={record.getMessage()}"


def _strip_version_suffix_from_handlers() -> None:
    """Replace any ``OpenHoundRichFormatter`` instance on console handlers
    with ``_NoVersionRichFormatter``. Identifies by class name to avoid
    importing the framework symbol (which would tie us to its module layout).
    Idempotent: re-running it on already-swapped handlers is a no-op.

    Also installs a defensive ``doRollover`` shim on the framework's
    ``RotatingFileHandler`` instances so a rollover triggered while
    ``alive_progress`` has wrapped the standard streams doesn't crash with
    ``AttributeError: 'NoneType' object has no attribute 'close'`` (the
    alive_progress ``hook_manager`` proxies ``self.stream.close()`` to its
    inner ``_stream`` which is ``None`` once the progress bar finishes).
    The original method is called inside a try/except so on success
    rotation still works; on the alive_progress collision the rollover is
    skipped and logging continues to the existing file.
    """
    seen_loggers = (
        logging.getLogger(),
        logging.getLogger("dlt"),
        logging.getLogger("openhound"),
    )
    replacement = _NoVersionRichFormatter()
    for log in seen_loggers:
        for handler in log.handlers:
            fmt = handler.formatter
            if fmt is None:
                continue
            if type(fmt).__name__ == "OpenHoundRichFormatter":
                handler.setFormatter(replacement)
    # Wrap doRollover on every rotating handler we can find.
    _patch_rollover_for_alive_progress(seen_loggers)


def _patch_rollover_for_alive_progress(loggers) -> None:
    """Swallow errors raised by ``doRollover`` so a midnight-crossing run
    doesn't print noisy ``Logging error`` tracebacks. Two failure modes:

    1. ``AttributeError: 'NoneType' object has no attribute 'close'`` —
       ``alive_progress.hook_manager`` proxies ``self.stream.close()`` to a
       ``_stream`` that is ``None`` once the progress bar finishes.

    2. ``PermissionError: [WinError 32]`` — Windows refuses to rename
       ``openhound.log`` because another handle (this process, a concurrent
       ``openhound`` instance, or the OS not yet releasing) still has it
       open. Native ``TimedRotatingFileHandler.rotate`` does ``os.rename``
       which is non-atomic with the prior ``self.stream.close()``.

    Both are non-fatal — the existing log file just doesn't roll until next
    invocation. Idempotent via ``_oh_sccm_rollover_safe`` sentinel.
    """
    for log in loggers:
        for handler in log.handlers:
            if getattr(handler, "_oh_sccm_rollover_safe", False):
                continue
            original = getattr(handler, "doRollover", None)
            if original is None:
                continue
            # Only wrap classes that look like file rollers (avoid touching
            # arbitrary StreamHandlers that don't have rollover semantics).
            if not hasattr(handler, "baseFilename"):
                continue

            def _safe_rollover(_orig=original, _h=handler):
                try:
                    _orig()
                except (AttributeError, OSError):
                    # AttributeError: alive_progress NoneType stream wrap.
                    # OSError (includes PermissionError WinError 32):
                    # Windows file-in-use during rename. Either way, leave
                    # the existing log file in place and continue.
                    #
                    # Critical: advance ``rolloverAt`` so subsequent log
                    # emits don't keep retrying the failing rollover —
                    # otherwise every log line in the rest of the run
                    # triggers the same crash again. Native
                    # ``TimedRotatingFileHandler.doRollover`` does this at
                    # its end; we have to mirror it manually because the
                    # rename step raised before that statement ran.
                    if hasattr(_h, "computeRollover") and hasattr(_h, "rolloverAt"):
                        import time as _t
                        try:
                            _h.rolloverAt = _h.computeRollover(int(_t.time()))
                        except Exception:
                            # Worst case: bump by one day so we don't keep
                            # retrying every emit.
                            _h.rolloverAt = int(_t.time()) + 86400
                    # Re-open the file if the handler ended up with a
                    # closed stream after the failed rollover. Native
                    # ``FileHandler._open`` returns a fresh handle.
                    try:
                        if getattr(_h, "stream", None) is not None:
                            try:
                                _h.stream.close()
                            except Exception:
                                pass
                        if hasattr(_h, "_open"):
                            _h.stream = _h._open()
                    except Exception:
                        pass
                    return

            handler.doRollover = _safe_rollover  # type: ignore[method-assign]
            handler._oh_sccm_rollover_safe = True  # type: ignore[attr-defined]


# Patch the framework's RotatingFileHandler at module-import time so the
# very first ``logger.info`` call from the framework's extension-loader
# (which fires before ``collect_sccm`` runs) doesn't crash on rollover.
# ``_strip_version_suffix_from_handlers`` is safe to call before
# ``_apply_log_level``; it only touches handlers that already exist.
try:
    _strip_version_suffix_from_handlers()
except Exception:
    # Pre-CLI patching is best-effort — if it fails the in-CLI call from
    # ``_apply_log_level`` still fires later and patches before any
    # user-visible work runs.
    pass


def _detect_windows_domain() -> Optional[str]:
    """Derive the AD domain from the current Windows user context.

    Mirrors ``ConfigManBearPig.ps1``'s order:
      1. ``$env:USERDNSDOMAIN`` (set by the LSA at logon for a domain-joined
         session).
      2. DNS suffix of ``socket.getfqdn()`` (the computer's domain), used as
         a fallback when USERDNSDOMAIN is missing.

    Returns ``None`` on non-Windows or when discovery fails — callers should
    treat the field as still-unset and surface a clear required-flag error.
    """
    if platform.system() != "Windows":
        return None
    domain = os.environ.get("USERDNSDOMAIN")
    if not domain:
        fqdn = socket.getfqdn()
        if "." in fqdn:
            domain = fqdn.split(".", 1)[1]
    if not domain:
        return None
    return domain.strip().rstrip(".").lower()


def _resolve_dc_via_dns(domain: str) -> Optional[str]:
    """Resolve a domain controller FQDN from the domain via DNS SRV.

    Looks up ``_ldap._tcp.dc._msdcs.<domain>`` — the path .NET's
    ``Domain.FindDomainController()`` ultimately takes via DC Locator.
    Cross-platform: works wherever the host has DNS reachability to the AD
    DNS zone, not just Windows.
    """
    try:
        import dns.resolver  # type: ignore[import-not-found]

        answers = dns.resolver.resolve(f"_ldap._tcp.dc._msdcs.{domain}", "SRV", lifetime=5)
        srvs = sorted(answers, key=lambda r: (r.priority, -r.weight))
        if srvs:
            return str(srvs[0].target).rstrip(".")
    except Exception as exc:  # dnspython errors, timeouts, no SRV records
        logger.debug("DNS SRV lookup for domain controller failed: %s", exc)
    return None


def _apply_connection_context(flag_kwargs: dict) -> None:
    """Backfill domain (Windows current-user context) and domain controller
    (DNS SRV from the resolved domain) when those values weren't supplied
    via flag or env.

    Domain auto-detection is Windows-only — Linux/macOS users must pass
    ``-d`` / ``--domain`` explicitly. DC resolution is cross-platform: as
    long as the domain is known (from flag, env, or Windows auto-detect),
    we try to resolve the DC via DNS SRV before failing.
    """
    has_domain = bool(flag_kwargs.get("domain")) or bool(os.environ.get("SOURCES__SCCM__DOMAIN"))
    has_dc = bool(flag_kwargs.get("domain_controller")) or bool(
        os.environ.get("SOURCES__SCCM__DOMAIN_CONTROLLER")
    )

    if not has_domain:
        domain = _detect_windows_domain()
        if domain:
            os.environ["SOURCES__SCCM__DOMAIN"] = domain
            logger.info("Auto-detected domain from current user context: %s", domain)
            has_domain = True

    if has_domain and not has_dc:
        # Prefer flag value, then env (already set above if auto-detected).
        domain = (
            flag_kwargs.get("domain")
            or os.environ.get("SOURCES__SCCM__DOMAIN")
            or ""
        ).strip().rstrip(".").lower()
        if domain:
            dc = _resolve_dc_via_dns(domain)
            if dc:
                os.environ["SOURCES__SCCM__DOMAIN_CONTROLLER"] = dc
                logger.info("Resolved domain controller via DNS SRV: %s", dc)


def _require_domain_or_explain(flag_kwargs: dict) -> None:
    """Fail fast with a clear message if ``domain`` is still unresolved.

    On Linux/macOS this is the dominant failure mode (no Windows current-user
    context to fall back on). Surfacing it before dlt's config-resolver fires
    avoids the noisy ``ConfigFieldMissingException`` traceback.
    """
    if flag_kwargs.get("domain") or os.environ.get("SOURCES__SCCM__DOMAIN"):
        return
    if platform.system() == "Windows":
        msg = (
            "Could not auto-detect the Active Directory domain from the current "
            "user context (USERDNSDOMAIN unset and FQDN has no DNS suffix). "
            "Pass -d / --domain explicitly."
        )
    else:
        msg = (
            "Running on a non-Windows host: -d / --domain is required "
            "(auto-detection of the current user's domain context is Windows-only). "
            "-dc / --domain-controller will be resolved from the domain via DNS SRV "
            "if omitted. -u / --username and -p / --password are also required for "
            "any phase that needs AD/SCCM auth."
        )
    raise typer.BadParameter(msg, param_hint="--domain")


# ---------------------------------------------------------------------------
# `openhound collect sccm ...` — full CMBP-style flag surface
# ---------------------------------------------------------------------------
@_collect_typer.command(
    name="sccm",
    help="Collect SCCM resources from LDAP, AdminService, MSSQL, WMI, etc. Accepts CMBP-style flags or SOURCES__SCCM__* env vars.",
)
def collect_sccm(
    # ---- standard framework arguments ----
    output_path: OutputPath,
    resources: Optional[List[str]] = typer.Argument(None, help="Optional subset of resource names; default = all."),
    progress: Progress = typer.Option(Progress.tqdm, help="Progress tracker (tqdm / log / alive_progress)."),
    tables: Contract = typer.Option(Contract.evolve, help="Contract for newly-seen resources/tables."),
    columns: Contract = typer.Option(Contract.evolve, help="Contract for unknown fields."),
    data_type: Contract = typer.Option(Contract.freeze, help="Contract for type mismatches."),
    # ---- Connection (CMBP -d/-dc/-u/-p/--ldap-port/--ldaps) ----
    domain: Optional[str] = typer.Option(None, "-d", "--domain", help="Domain (e.g. mayyhem.com). On Windows, auto-detected from $env:USERDNSDOMAIN; on Linux/macOS this flag is required."),
    domain_controller: Optional[str] = typer.Option(None, "-dc", "--domain-controller", help="DC hostname or IP. If omitted, resolved from --domain via DNS SRV (_ldap._tcp.dc._msdcs.<domain>)."),
    username: Optional[str] = typer.Option(None, "-u", "--username", help="DOMAIN\\\\user for explicit auth."),
    password: Optional[str] = typer.Option(None, "-p", "--password", help="Password for explicit auth."),
    ldap_port: Optional[int] = typer.Option(None, "--ldap-port", help="Pin LDAP port. Omit to auto-detect (LDAPS:636 → StartTLS:389 → LDAP:389+sign/seal). 636/3269 → LDAPS; any other port → LDAP."),
    # ---- Collection (CMBP -m/-c/-cf/-sms/-sc) ----
    collection_methods: Optional[str] = typer.Option(
        None, "-m", "--collection-methods",
        help="Comma-separated methods: All, LDAP, Local, DNS, DHCP, RemoteRegistry, MSSQL, AdminService, WMI, HTTP, SMB.",
    ),
    computers: Optional[str] = typer.Option(None, "-c", "--computers", help="Comma-separated computer targets."),
    computer_file: Optional[pathlib.Path] = typer.Option(None, "-cf", "--computer-file", help="File with computer targets (one per line)."),
    sms_provider: Optional[str] = typer.Option(None, "-sms", "--sms-provider", help="Specific SMS Provider host."),
    site_codes: Optional[str] = typer.Option(None, "-sc", "--site-codes", help="Site codes for DNS collection (CSV or file path)."),
    # ---- Behavior flags (CMBP --disable-possible-edges / --enable-bad-opsec / -t / --show-cleartext-passwords) ----
    disable_possible_edges: bool = typer.Option(False, "--disable-possible-edges", help="Disable uncertain/possible edges."),
    enable_bad_opsec: bool = typer.Option(False, "--enable-bad-opsec", help="Enable bad-opsec operations (NAA decryption, etc.)."),
    threads: int = typer.Option(1, "-t", "--threads", help="Per-host phase parallelism."),
    show_cleartext_passwords: bool = typer.Option(False, "--show-cleartext-passwords", help="Display cleartext passwords when discovered."),
    # ---- Machine Account / CRED-2 (flags wired; chain deferred) ----
    machine_name: Optional[str] = typer.Option(None, "--machine-name", help="DOMAIN\\\\MACHINE$ for SCCM client registration. CRED-2 chain not yet implemented."),
    machine_pass: Optional[str] = typer.Option(None, "--machine-pass", help="Machine account password. CRED-2 chain not yet implemented."),
    client_name: Optional[str] = typer.Option(None, "--client-name", help="Client FQDN to register. CRED-2 chain not yet implemented."),
    create_machine_account: Optional[str] = typer.Option(None, "--create-machine-account", help="Create a machine account for CRED-2. Pass 'auto' or a name. Not yet implemented."),
    use_altauth: bool = typer.Option(False, "--use-altauth", help="Use ccm_system_altauth endpoint. Not yet implemented."),
    registration_sleep: int = typer.Option(10, "--registration-sleep", help="Seconds to wait post-registration before policy request. Not yet implemented."),
    # ---- Network (CMBP --socks-proxy) ----
    socks_proxy: Optional[str] = typer.Option(None, "--socks-proxy", help="SOCKS5 proxy HOST:PORT for DHCP/TFTP collection."),
    # ---- General (CMBP -v / --verbose, --debug) ----
    verbose: int = typer.Option(0, "-v", "--verbose", count=True, help="Verbose output. -v=INFO (step summaries), -vv=VERBOSE (PS1 [Verbose] parity: per-resolution / per-node-add / per-edge dedupe traces)."),
    debug: bool = typer.Option(False, "--debug", help="Debug output (DEBUG level; very chatty, includes dlt and ldap3 internals)."),
) -> Optional[LoadInfo]:
    _apply_log_level(verbose, debug)
    flag_kwargs = locals()
    _apply_env_overrides(flag_kwargs)
    _apply_connection_context(flag_kwargs)
    _require_domain_or_explain(flag_kwargs)

    collector = Collector(name=app.name, output_path=output_path, resources=resources, progress=progress)
    ctx = CollectContext(pipeline=collector)
    from .source import source as sccm_source

    src = sccm_source()
    if not src:
        return None
    load_info = collector.run(src)
    # Clear the [target][phase] log context so the summary block reads as a
    # global section rather than inheriting whatever phase ran last.
    from .log_context import phase_context, target_context
    with target_context(None), phase_context(None):
        _log_collect_summary(load_info, output_path)
    return load_info


def _log_collect_summary(load_info: "Optional[LoadInfo]", output_path: pathlib.Path) -> None:
    """Emit a PS1-equivalent end-of-collection summary at INFO level.

    PS1's ConfigManBearPig.ps1 prints a ``Collection Statistics:`` block at
    the end of every run; mirror the same intent for ``openhound collect
    sccm …``. The final node/edge totals aren't known yet at this phase —
    those come from ``output.py::package`` after convert. We emit row
    counts per resource so the operator sees what was extracted before
    moving on to preprocess/convert.

    Row counts are read by counting JSONL rows on disk under
    ``<output>/sccm/<table>/`` — that's authoritative and avoids the
    DLT ``LoadInfo`` schema-version dance (the structured ``extract_data_info``
    layout shifted between DLT 0.5 and 1.x).
    """
    logger.info("Collection complete.")
    logger.info("Raw output directory: %s", output_path)
    try:
        dataset_dir = output_path / "sccm"
        if not dataset_dir.is_dir():
            return
        per_resource: dict[str, int] = {}
        import gzip
        for table_dir in sorted(dataset_dir.iterdir()):
            if not table_dir.is_dir() or table_dir.name.startswith("_dlt"):
                continue
            row_count = 0
            for f in table_dir.glob("*.jsonl*"):
                try:
                    opener = gzip.open if f.suffix == ".gz" else open
                    with opener(f, "rt", encoding="utf-8", errors="replace") as fh:
                        row_count += sum(1 for line in fh if line.strip())
                except OSError:
                    continue
            per_resource[table_dir.name] = row_count
        if per_resource:
            total = sum(per_resource.values())
            logger.info("Extracted %d rows across %d resources:", total, len(per_resource))
            for name, count in sorted(per_resource.items(), key=lambda kv: (-kv[1], kv[0])):
                logger.info("    %-40s %d", name, count)
        logger.info("Next steps: 'openhound preprocess sccm <raw> <lookup.duckdb>' then 'openhound convert sccm <raw>/sccm <graph> --lookup-file <lookup.duckdb>'")
    except Exception as exc:  # noqa: BLE001
        # Summary is best-effort — never fail the collect because of a log line.
        logger.debug("Collection-summary emit failed: %s", exc)


# Set at module scope so `CollectorManager.validate_extension` (which runs at
# import time, before any command is invoked) sees a non-None hook. The
# `@app.collect()` convenience decorator would do this for us, but we register
# directly on the framework's Typer group to keep CMBP-style flag surface.
app.collector = collect_sccm


# ---------------------------------------------------------------------------
# `openhound preprocess sccm ...` — slim flag surface (most config is on collect)
# ---------------------------------------------------------------------------
@_preprocess_typer.command(
    name="sccm",
    help="Build a DuckDB lookup from collected SCCM JSONL. Accepts the same SOURCES__SCCM__* env vars as `collect` (most apply at convert time).",
)
def preprocess_sccm(
    input_path: InputPath,
    output_file: pathlib.Path = typer.Argument(DEFAULT_LOOKUP_FILE, help="Path to write the DuckDB lookup file."),
    progress: Progress = typer.Option(Progress.tqdm, help="Progress tracker."),
    domain: Optional[str] = typer.Option(None, "-d", "--domain", help="Domain (e.g. mayyhem.com). On Windows, auto-detected from $env:USERDNSDOMAIN. Required on Linux/macOS."),
    domain_controller: Optional[str] = typer.Option(None, "-dc", "--domain-controller", help="DC hostname or IP. If omitted, resolved from --domain via DNS SRV (_ldap._tcp.dc._msdcs.<domain>)."),
    username: Optional[str] = typer.Option(None, "-u", "--username"),
    password: Optional[str] = typer.Option(None, "-p", "--password"),
    verbose: int = typer.Option(0, "-v", "--verbose", count=True, help="Verbose output. -v=INFO (step summaries), -vv=VERBOSE (PS1 [Verbose] parity: per-resolution / per-node-add / per-edge dedupe traces)."),
    debug: bool = typer.Option(False, "--debug", help="Debug output (DEBUG level; very chatty, includes dlt internals)."),
) -> Optional[LoadInfo]:
    _apply_log_level(verbose, debug)
    flag_kwargs = locals()
    _apply_env_overrides(flag_kwargs)
    _apply_connection_context(flag_kwargs)
    _require_domain_or_explain(flag_kwargs)

    preprocessor = PreProcessor(
        name=app.name,
        input_path=input_path,
        output_file=output_file,
        progress=progress,
        transformer=transforms,
    )

    resource_list = _preproc_table_map()
    return preprocessor.run(resources=resource_list)


app.preprocessor = preprocess_sccm


def _preproc_table_map() -> dict[str, str]:
    """Return the DuckDB-table → JSONL-path mapping consumed by ``preprocess``.

    Tables that aren't present yet are still listed so future phases land
    without an extra edit — DLT silently skips entries whose JSONL directory
    is missing.
    """
    base_tables = [
        # LDAP base tables (Phase 1)
        "ldap_computers",
        "ldap_users",
        "ldap_groups",
        "ldap_sites",
        "ldap_mp_site_classifications",
        "ldap_sms_providers",
        "ldap_cmrc_devices",
        "ldap_network_boot_servers",
        "ldap_system_management_acl",
        "ldap_group_memberships",
        # Once-phase enrichment (Phase 2)
        "local_management_points",
        "local_distribution_points",
        "local_naa_secrets",
        "dns_management_points",
        "dhcp_pxe_dps",
        # Per-host enrichment (Phase 3)
        "registry_sccm_databases",
        "registry_current_users",
        "registry_sccm_components",
        "registry_mssql_settings",
        "mssql_epa_flags",
        "adminservice_admins",
        "adminservice_collections",
        "adminservice_collection_members",
        "adminservice_security_roles",
        "adminservice_role_members",
        "adminservice_client_devices",
        "adminservice_task_sequences",
        "adminservice_collection_variables",
        "adminservice_site_systems",
        "adminservice_sites",
        "adminservice_site_definitions",
        "adminservice_r_system_security_groups",
        "adminservice_r_user_security_groups",
        "adminservice_reserved_accounts",
        "wmi_clients",
        "wmi_users_seen",
        "wmi_sql_service_accounts",
        "http_management_points",
        "http_smsproviders",
        "http_distribution_points",
        "http_naa_secrets",
        "http_collection_secrets",
        "smb_site_servers",
        "smb_distribution_points",
        "smb_signing_status",
        # Phase 4 — single sentinel row that triggers DerivedEdges aggregator.
        "derived_edges",
        # Phase 6 — one row per synthesised MSSQL principal node.
        "derived_nodes",
    ]
    return {table: f"sccm/{table}" for table in base_tables}


# ---------------------------------------------------------------------------
# `openhound convert sccm ...` — slim flag surface
# ---------------------------------------------------------------------------
@_convert_typer.command(
    name="sccm",
    help="Convert collected JSONL + DuckDB lookup into OpenGraph nodes/edges.",
)
def convert_sccm(
    input_path: InputPath,
    output_path: OutputPath,
    progress: Progress = typer.Option(Progress.tqdm, help="Progress tracker."),
    lookup_file: pathlib.Path = typer.Option(DEFAULT_LOOKUP_FILE, "--lookup-file", help="DuckDB lookup file path."),
    domain: Optional[str] = typer.Option(None, "-d", "--domain", help="Domain (e.g. mayyhem.com). On Windows, auto-detected from $env:USERDNSDOMAIN. Required on Linux/macOS."),
    domain_controller: Optional[str] = typer.Option(None, "-dc", "--domain-controller", help="DC hostname or IP. If omitted, resolved from --domain via DNS SRV (_ldap._tcp.dc._msdcs.<domain>)."),
    username: Optional[str] = typer.Option(None, "-u", "--username"),
    password: Optional[str] = typer.Option(None, "-p", "--password"),
    verbose: int = typer.Option(0, "-v", "--verbose", count=True, help="Verbose output. -v=INFO (step summaries), -vv=VERBOSE (PS1 [Verbose] parity: per-resolution / per-node-add / per-edge dedupe traces)."),
    debug: bool = typer.Option(False, "--debug", help="Debug output (DEBUG level; very chatty, includes dlt internals)."),
) -> Optional[LoadInfo]:
    import duckdb

    _apply_log_level(verbose, debug)
    flag_kwargs = locals()
    _apply_env_overrides(flag_kwargs)
    _apply_connection_context(flag_kwargs)
    _require_domain_or_explain(flag_kwargs)

    client = duckdb.connect(str(lookup_file), read_only=True)
    lookup_session = SCCMLookup(client)
    converter = Converter(
        name=app.name,
        source_kind=app.source_kind,
        input_path=input_path,
        output_path=output_path,
        lookup=lookup_session,
        progress=progress,
        method=Method.write,
    )

    from .source import source as sccm_source

    src = sccm_source()
    return converter.run(
        src,
        graph_resources=app.assets,
        extra_context={},
    )


app.converter = convert_sccm


# ---------------------------------------------------------------------------
# Local `package` subcommand (no framework hook exists for post-convert).
# ---------------------------------------------------------------------------
package_app = typer.Typer(name="package", help="Package convert output into a BloodHound-compatible ZIP")


@package_app.callback(invoke_without_command=True)
def package_cmd(
    graph_dir: pathlib.Path = typer.Option(..., "--graph-dir", exists=True, file_okay=False, dir_okay=True, resolve_path=True, help="Directory containing OpenHound convert output (e.g. graph/sccm/)"),
    output_dir: Optional[pathlib.Path] = typer.Option(None, "--output-dir", file_okay=False, dir_okay=True, resolve_path=True, help="Where to drop the ZIP (defaults to cwd)"),
    timestamp: Optional[str] = typer.Option(None, "--timestamp", help="Override the timestamp suffix (default: now in YYYYMMDD-HHMMSS)"),
    keep_temp: bool = typer.Option(False, "--keep-temp", help="Keep the intermediate per-file JSON outputs alongside the ZIP"),
) -> None:
    """Package convert output into bloodhound-sccm-<timestamp>.zip."""
    from .output import package as run_package

    zip_path = run_package(graph_dir=graph_dir, output_dir=output_dir, timestamp=timestamp, keep_temp=keep_temp)
    if zip_path is None:
        typer.echo("Nothing to package — no nodes or edges found.", err=True)
        raise typer.Exit(code=1)
    typer.echo(str(zip_path))


def cli() -> None:
    """Direct entry point for ``python -m openhound_sccm.main package ...``."""
    package_app()


if __name__ == "__main__":
    cli()
