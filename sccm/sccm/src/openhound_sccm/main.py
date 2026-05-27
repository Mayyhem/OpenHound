import datetime
import logging
import os
import pathlib
import platform
import socket
import sys
import typer
from openhound.cli.collect import collect as _collect_typer  # noqa: E402

from typing import List, Optional, Sequence

from openhound.core.app import (
    Contract,
    OpenHound,
    OutputPath,
)
from openhound.core.collect import CollectContext, Collector
from openhound.core.convert import ConvertContext
from openhound.core.lookup import LookupManager
from openhound.core.preproc import PreProcContext
from openhound.core.progress import Progress
from dlt.common.pipeline import LoadInfo
from dlt.extract.source import DltSource
from .transforms import transforms

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OpenHound app instance. Still owns `source_kind` (flows into the OpenGraph
# metadata block) plus the asset registry that ``Converter.run`` reads. The
# `@app.collect/@app.preproc/@app.convert` convenience decorators are
# intentionally *not* used here — we register richer Typer commands on the
# framework's public Typer groups directly so we can add CLI options/flags.
# ---------------------------------------------------------------------------
app = OpenHound(
    "sccm", 
    source_kind="Kind", 
    help="OpenGraph collector for sccm"
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
    # Behavior
    "disable_possible_edges": "SOURCES__SCCM__DISABLE_POSSIBLE_EDGES",
    "enable_bad_opsec": "SOURCES__SCCM__ENABLE_BAD_OPSEC",
    "threads": "SOURCES__SCCM__THREADS",
    "show_cleartext_passwords": "SOURCES__SCCM__SHOW_CLEARTEXT_PASSWORDS",
    # CRED-2
    "machine_name": "SOURCES__SCCM__MACHINE_NAME",
    "machine_pass": "SOURCES__SCCM__MACHINE_PASS",
    "client_name": "SOURCES__SCCM__CLIENT_NAME",
    "create_machine_account": "SOURCES__SCCM__CREATE_MACHINE_ACCOUNT",
    "use_altauth": "SOURCES__SCCM__USE_ALTAUTH",
    "registration_sleep": "SOURCES__SCCM__REGISTRATION_SLEEP",
    # Network
    "socks_proxy": "SOURCES__SCCM__SOCKS_PROXY",
}

_TYPED_DLT_ENV = {
    "SOURCES__SCCM__LDAP_PORT",
    "SOURCES__SCCM__THREADS",
    "SOURCES__SCCM__REGISTRATION_SLEEP",
    "SOURCES__SCCM__DISABLE_POSSIBLE_EDGES",
    "SOURCES__SCCM__ENABLE_BAD_OPSEC",
    "SOURCES__SCCM__SHOW_CLEARTEXT_PASSWORDS",
    "SOURCES__SCCM__USE_ALTAUTH",
}


def _drop_empty_dlt_env_values() -> None:
    for env_name in _FLAG_TO_ENV.values():
        if os.environ.get(env_name) == "":
            os.environ.pop(env_name, None)

    for env_name in _TYPED_DLT_ENV:
        value = os.environ.get(env_name)
        if value is not None and value.strip() == "":
            os.environ.pop(env_name, None)


_SHORT_OPTIONS_WITH_VALUES: dict[str, str] = {
    "-d": "--domain",
    "-u": "--username",
    "-p": "--password",
    "-m": "--collection-methods",
    "-c": "--computers",
    "-t": "--threads",
}
_LONG_OPTIONS_WITH_VALUES: set[str] = {
    "--progress",
    "--tables",
    "--columns",
    "--data-type",
    "--domain",
    "--dc",
    "--domain-controller",
    "--username",
    "--password",
    "--ldap-port",
    "--collection-methods",
    "--computers",
    "--cf",
    "--computer-file",
    "--sms",
    "--sms-provider",
    "--sc",
    "--site-codes",
    "--threads",
    "--machine-name",
    "--machine-pass",
    "--client-name",
    "--create-machine-account",
    "--registration-sleep",
    "--socks-proxy",
}
_SENSITIVE_OPTIONS: set[str] = {
    "-p",
    "--password",
    "--machine-pass",
}


def _display_cli_value(option: str, value: str) -> str:
    if option in _SENSITIVE_OPTIONS:
        return "<value>"
    return value


def _suspicious_cli_argument_warnings(argv: Sequence[str]) -> list[str]:
    """Build warnings for short-option attachments that leave a value behind.

    Click accepts ``-dc`` as ``-d c`` because ``-d`` takes a value. That means
    typos like ``-dc 10.2.10.100`` make it through parsing and silently turn
    the intended domain-controller value into a positional argument.
    """
    warnings: list[str] = []
    for index, token in enumerate(argv):
        if not token.startswith("-") or token.startswith("--") or token == "-":
            continue

        next_token = argv[index + 1] if index + 1 < len(argv) else None
        if next_token is None or next_token.startswith("-"):
            continue

        one_dash_long = f"-{token}"
        if one_dash_long in _LONG_OPTIONS_WITH_VALUES:
            value = _display_cli_value(one_dash_long, next_token)
            warnings.append(
                f'Suspicious CLI option "{token} {value}" was parsed as a '
                "short option with an attached value, leaving the next value "
                f'as a separate argument. Did you mean "{one_dash_long} {value}"?'
            )
            continue

        for short_option in _SHORT_OPTIONS_WITH_VALUES:
            if not token.startswith(short_option) or token == short_option:
                continue

            attached_value = token[len(short_option):]
            if len(attached_value) > 2:
                break

            canonical = _SHORT_OPTIONS_WITH_VALUES[short_option]
            value = _display_cli_value(short_option, f"{attached_value} {next_token}")
            if short_option in _SENSITIVE_OPTIONS:
                warnings.append(
                    f'Suspicious CLI option "{short_option}" has an attached '
                    "value followed by another value token. Did you mean to "
                    f'quote the {canonical} value, for example "{short_option} {value}"?'
                )
            else:
                warnings.append(
                    f'Suspicious CLI option "{token} {next_token}" looks like '
                    f'a split value for {canonical}. Did you mean '
                    f'"{short_option} {value}"?'
                )
            break

    return warnings


def _warn_for_suspicious_cli_arguments(argv: Sequence[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    for warning in _suspicious_cli_argument_warnings(args):
        logger.warning(warning)


def _apply_env_overrides(flag_kwargs: dict) -> None:
    """Map CLI option/flag values to ``SOURCES__SCCM__*`` env vars.

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


# Hard-frozen to the framework's current timestamp format. We identify the
# formatter to swap by class name, so format divergence is a visible signal.
_LOG_TIMESTAMP_FMT = "%Y-%m-%d %H:%M:%S"


class _NoVersionRichFormatter(logging.Formatter):
    """Mirror of ``openhound.core.logging.OpenHoundRichFormatter`` minus the
    trailing ``(openhound_version=…)`` suffix. Used by ``_apply_log_level``
    to swap the framework's CLI formatter in place."""

    def format(self, record: logging.LogRecord) -> str:
        return f"time={self.formatTime(record, _LOG_TIMESTAMP_FMT)}, msg={record.getMessage()}"


def _strip_version_suffix_from_handlers() -> None:
    """Replace any ``OpenHoundRichFormatter`` instance on console handlers
    with ``_NoVersionRichFormatter``. Identifies by class name to avoid
    importing the framework symbol (which would tie us to its module layout).
    Idempotent: re-running it on already-swapped handlers is a no-op.
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
        logger.warning("DNS SRV lookup for domain controller failed: %s", exc)
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
            logger.verbose("No domain controller (--dc) provided, trying to find one via DNS")
            dc = _resolve_dc_via_dns(domain)
            if dc:
                os.environ["SOURCES__SCCM__DOMAIN_CONTROLLER"] = dc
                logger.info("Resolved domain controller via DNS SRV: %s", dc)
            else:
                logger.error("Could not identify a domain controller via DNS. Try specifying a domain controller FQDN or IP with the --dc option.")
                sys.exit(1)
        

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
            "--dc / --domain-controller will be resolved from the domain via DNS SRV "
            "if omitted. -u / --username and -p / --password are also required for "
            "any phase that needs AD/SCCM auth."
        )
    raise typer.BadParameter(msg, param_hint="--domain")


class _DiagnosticFileHandler(logging.FileHandler):
    """Writes WARNING+ records with full traceback to a per-run diagnostics file.

    Attached to the root logger for the lifetime of ``collect_sccm``. Uses
    ``delay=True`` so the file is only created when at least one record is
    emitted. Injects ``sys.exc_info()`` for its own formatting when the record
    has no traceback attached, then restores both ``record.exc_info`` and
    ``record.exc_text`` (the formatter's cached string) so the console handler
    is never affected.
    """

    def __init__(self, path: pathlib.Path) -> None:
        super().__init__(str(path), mode="w", encoding="utf-8", delay=True)
        self.setLevel(logging.WARNING)
        self.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        self.warning_count = 0
        self.error_count = 0

    def emit(self, record: logging.LogRecord) -> None:
        if record.levelno < logging.WARNING:
            return
        if record.levelno >= logging.ERROR:
            self.error_count += 1
        else:
            self.warning_count += 1

        injected = False
        if not record.exc_info:
            exc = sys.exc_info()
            if exc[0] is not None:
                record.exc_info = exc
                injected = True

        super().emit(record)

        if injected:
            record.exc_info = False
            record.exc_text = None  # clear cached formatted traceback so console sees nothing


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
    # ---- Connection ----
    domain: Optional[str] = typer.Option(None, "-d", "--domain", help="Domain (e.g. mayyhem.com). On Windows, auto-detected from $env:USERDNSDOMAIN; on Linux/macOS this flag is required."),
    domain_controller: Optional[str] = typer.Option(None, "--dc", "--domain-controller", help="DC hostname or IP. If omitted, resolved from --domain via DNS SRV (_ldap._tcp.dc._msdcs.<domain>)."),
    username: Optional[str] = typer.Option(None, "-u", "--username", help="DOMAIN\\\\user for explicit auth."),
    password: Optional[str] = typer.Option(None, "-p", "--password", help="Password for explicit auth."),
    ldap_port: Optional[int] = typer.Option(None, "--ldap-port", help="Pin LDAP port. Omit to auto-detect (LDAPS:636 → StartTLS:389 → LDAP:389+sign/seal). 636/3269 → LDAPS; any other port → LDAP."),
    # ---- Collection ----
    collection_methods: Optional[str] = typer.Option(
        None, "-m", "--collection-methods",
        help="Comma-separated methods: All, LDAP, Local, DNS, DHCP, RemoteRegistry, MSSQL, AdminService, WMI, HTTP, SMB.",
    ),
    computers: Optional[str] = typer.Option(None, "-c", "--computers", help="Comma-separated computer targets."),
    computer_file: Optional[pathlib.Path] = typer.Option(None, "--cf", "--computer-file", help="File with computer targets (one per line)."),
    sms_provider: Optional[str] = typer.Option(None, "--sms", "--sms-provider", help="Specific SMS Provider host."),
    site_codes: Optional[str] = typer.Option(None, "--sc", "--site-codes", help="Site codes for DNS collection (CSV or file path)."),
    # ---- Behavior ----
    disable_possible_edges: bool = typer.Option(False, "--disable-possible-edges", help="Disable uncertain/possible edges."),
    enable_bad_opsec: bool = typer.Option(False, "--enable-bad-opsec", help="Enable bad-opsec operations (NAA decryption, etc.)."),
    threads: int = typer.Option(1, "-t", "--threads", help="Per-host phase parallelism."),
    show_cleartext_passwords: bool = typer.Option(False, "--show-cleartext-passwords", help="Display cleartext passwords when discovered."),
    # ---- Machine Account / CRED-2 ----
    machine_name: Optional[str] = typer.Option(None, "--machine-name", help="DOMAIN\\\\MACHINE$ for SCCM client registration. CRED-2 chain not yet implemented."),
    machine_pass: Optional[str] = typer.Option(None, "--machine-pass", help="Machine account password. CRED-2 chain not yet implemented."),
    client_name: Optional[str] = typer.Option(None, "--client-name", help="Client FQDN to register. CRED-2 chain not yet implemented."),
    create_machine_account: Optional[str] = typer.Option(None, "--create-machine-account", help="Create a machine account for CRED-2. Pass 'auto' or a name. Not yet implemented."),
    use_altauth: bool = typer.Option(False, "--use-altauth", help="Use ccm_system_altauth endpoint. Not yet implemented."),
    registration_sleep: int = typer.Option(10, "--registration-sleep", help="Seconds to wait post-registration before policy request. Not yet implemented."),
    # ---- Network ----
    socks_proxy: Optional[str] = typer.Option(None, "--socks-proxy", help="SOCKS5 proxy HOST:PORT for DHCP/TFTP collection."),
    # ---- General ----
    verbose: int = typer.Option(0, "-v", "--verbose", count=True, help="Verbose output. -v=INFO (step summaries), -vv=VERBOSE (PS1 [Verbose] parity: per-resolution / per-node-add / per-edge dedupe traces)."),
    debug: bool = typer.Option(False, "--debug", help="Debug output (DEBUG level; very chatty, includes dlt and ldap3 internals)."),
) -> Optional[LoadInfo]:
    _apply_log_level(verbose, debug)

    _ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = output_path / f"collect_diagnostics_{_ts}.log"
    _diag = _DiagnosticFileHandler(log_path)
    logging.root.addHandler(_diag)
    try:
        _warn_for_suspicious_cli_arguments()
        flag_kwargs = locals()
        _apply_env_overrides(flag_kwargs)
        _drop_empty_dlt_env_values()
        _apply_connection_context(flag_kwargs)
        _require_domain_or_explain(flag_kwargs)

        from openhound_collector_utils import TargetQueue
        from .source import PER_HOST_RESOURCE_NAMES, set_shared_queue, set_shared_ad_cache, set_shared_discovered_domains
        from .source import source as sccm_source

        queue = TargetQueue(list(PER_HOST_RESOURCE_NAMES))
        ad_cache: dict = {}
        discovered_domains: set = set()
        set_shared_queue(queue)
        set_shared_ad_cache(ad_cache)
        set_shared_discovered_domains(discovered_domains)

        collector = Collector(name=app.name, output_path=output_path, resources=resources, progress=progress)
        ctx = CollectContext(pipeline=collector)

        src = sccm_source()
        if not src:
            set_shared_queue(None)
            set_shared_ad_cache(None)
            set_shared_discovered_domains(None)
            return None

        # Pass 0 — full initial run (replace disposition, all resources).
        load_info = collector.run(src)

        # Queue loop — run subsequent passes for any targets discovered mid-run
        # (e.g. hosts found via HTTP MPKEYINFORMATION that weren't in LDAP).
        pass_num = 1
        while queue.has_pending():
            new_hosts = sorted(queue.pending_hosts())
            logger.info(
                "Queue pass %d: %d new host(s) with pending phases: %s\n",
                pass_num, len(new_hosts), "\n".join(new_hosts),
            )
            os.environ["SOURCES__SCCM__COMPUTERS"] = ",".join(new_hosts)
            try:
                sub_src = sccm_source()
                if sub_src:
                    sub_src = sub_src.with_resources(*PER_HOST_RESOURCE_NAMES)
                    collector.pipeline.run(
                        sub_src,
                        write_disposition="append",
                        loader_file_format="jsonl",
                    )
            finally:
                os.environ.pop("SOURCES__SCCM__COMPUTERS", None)
            pass_num += 1

        set_shared_queue(None)
        set_shared_ad_cache(None)
        set_shared_discovered_domains(None)

        # Clear the [target][phase] log context so the summary block reads as a
        # global section rather than inheriting whatever phase ran last.
        from .log_context import phase_context, target_context
        with target_context(None), phase_context(None):
            _log_collect_summary(load_info, output_path)
        return load_info
    finally:
        logging.root.removeHandler(_diag)
        if _diag.warning_count or _diag.error_count:
            w, e = _diag.warning_count, _diag.error_count
            parts = []
            if w:
                parts.append(f"{w} WARNING{'s' if w != 1 else ''}")
            if e:
                parts.append(f"{e} ERROR{'s' if e != 1 else ''}")
            detail = ", ".join(parts)
            if log_path.exists():
                logger.warning(
                    "%s detected. Traceback details available in: %s",
                    detail, log_path,
                )
            else:
                logger.warning(
                    "%s detected. Run with --debug to display traceback details after WARNING/ERROR logs.",
                    detail,
                )

def _log_collect_summary(load_info: "Optional[LoadInfo]", output_path: pathlib.Path) -> None:
    """Emit an end-of-collection summary at INFO level.

    The final node/edge totals aren't known yet at this phase —
    those come from ``output.py::package`` after convert. We emit row
    counts per resource so the operator sees what was extracted before
    moving on to preprocess/convert.

    Row counts are read by counting JSONL rows on disk under
    ``<output>/sccm/<table>/``
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
    except Exception as ex:
        # Summary is best-effort — never fail the collect because of a log line.
        logger.debug("Collection-summary emit failed: %s", ex)


# Set at module scope so `CollectorManager.validate_extension` (which runs at
# import time, before any command is invoked) sees a non-None hook. The
# `@app.collect()` convenience decorator would do this for us, but we register
# directly on the framework's Typer group to keep CMBP-style flag surface.
app.collector = collect_sccm


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
        "ldap_management_points_raw",
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
        "derived_edges",
        "derived_nodes",
    ]
    return {table: f"sccm/{table}" for table in base_tables}


@app.preproc(transformer=transforms)
def preproc(ctx: PreProcContext) -> dict[str, str]:
    """Build a DuckDB lookup database from collected SCCM JSONL."""
    return _preproc_table_map()