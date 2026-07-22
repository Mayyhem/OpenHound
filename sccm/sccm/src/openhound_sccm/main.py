import copy
import datetime
import logging
import os
import pathlib
import platform
import shutil
import socket
import sys
import threading
import time
import traceback as _traceback
import types
from enum import Enum
import typer
from openhound.cli.collect import collect as _collect_typer  # noqa: E402

from typing import TYPE_CHECKING, List, Optional, Sequence

from openhound.core.app import (
    Contract,
    OpenHound,
    OutputPath,
)
from openhound.core.collect import CollectContext, Collector
from openhound.core.convert import ConvertContext
from openhound.core.preproc import PreProcContext
from openhound.core.progress import Progress
from dlt.common.pipeline import LoadInfo
import dlt
from .convert_pipeline import emit_graph_from_duckdb
from .lookup import SCCMLookup
from .models.computer import ComputerNode
from .models.group import GroupNode
from .models.graph_edge import GraphEdge
from .models.mssql_database import MSSQLDatabase
from .models.mssql_database_role import MSSQLDatabaseRole
from .models.mssql_database_user import MSSQLDatabaseUser
from .models.mssql_login import MSSQLLogin
from .models.mssql_server import MSSQLServer
from .models.mssql_server_role import MSSQLServerRole
from .models.sccm_admin_user import SCCMAdminUser
from .models.sccm_client_device import SCCMClientDevice
from .models.sccm_collection import SCCMCollection
from .models.sccm_security_role import SCCMSecurityRole
from .models.sccm_site import SCCMSite
from .models.stub_node import StubNode
from .models.user import UserNode
from .transforms import transforms

if TYPE_CHECKING:
    # Type-only import: StagePaths annotates the --run-all output-summary helpers.
    # The runtime import stays deferred inside the functions so importing this
    # module never pulls the shared library in at import time.
    from openhound_collector_common.orchestration import StagePaths
    # Type-only import: ProxyConfig annotates the --socks-proxy helpers below.
    # The runtime import stays deferred inside _parse_proxy_or_exit for the same reason.
    from openhound_collector_common.proxy import ProxyConfig

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Progress backend selection (`--progress`)
# ---------------------------------------------------------------------------
# dlt draws a live counter for every resource it extracts (the
# `adminservice_r_system: 69it [...]` lines). Those redraws smear into the
# collector's own [target][phase] INFO/VERBOSE records, so the default here is
# "off": no dlt progress at all, leaving only our structured logs. tqdm / log /
# alive_progress stay available as opt-ins for anyone who wants a live bar.
#
# The framework's core Progress enum (off-limits to edit) has no "off" member,
# and core's Collector always forwards `progress.value` to
# `dlt.pipeline(progress=...)`. dlt maps a `None` progress arg to its no-op
# NULL_COLLECTOR, so we express "off" as a tiny stand-in whose `.value` is None
# rather than touching OpenHound core.
# ---------------------------------------------------------------------------
class ProgressOption(str, Enum):
    off = "off"
    tqdm = "tqdm"
    log = "log"
    alive_progress = "alive_progress"


class _SilentProgress:
    """Progress stand-in that disables dlt's progress output entirely.

    Collector reads only `.value` and hands it to `dlt.pipeline(progress=...)`;
    `None` resolves to dlt's NULL_COLLECTOR (no bars, no periodic log dumps).
    """

    value = None


def _resolve_progress(choice: ProgressOption):
    """Translate a `--progress` choice into what core's Collector expects.

    'off' -> silent stand-in (dlt NULL_COLLECTOR); anything else -> the matching
    core Progress enum member (tqdm / log / alive_progress).
    """
    if choice is ProgressOption.off:
        logger.debug("Progress output disabled (--progress off); using dlt NULL_COLLECTOR")
        return _SilentProgress()
    # A real backend was explicitly requested; hand core the matching enum member.
    logger.debug("Progress backend selected: %s", choice.value)
    return Progress(choice.value)


# ---------------------------------------------------------------------------
# OpenHound app instance. Still owns `source_kind` (flows into the OpenGraph
# metadata block) plus the asset registry that ``Converter.run`` reads. The
# `@app.collect/@app.preproc/@app.convert` convenience decorators are
# intentionally *not* used here — we register richer Typer commands on the
# framework's public Typer groups directly so we can add CLI options/flags.
# ---------------------------------------------------------------------------
app = OpenHound(
    "sccm",
    # source_kind tags every emitted node/edge as belonging to the SCCM data source in
    # BloodHound (used for source-scoped re-ingest/deletion). Was the Stage-0 spike
    # placeholder "Kind"; set to the real collector source name.
    source_kind="SCCM",
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
    "nt_hash": "SOURCES__SCCM__NT_HASH",
    "kerberos_ticket": "SOURCES__SCCM__KERBEROS_TICKET",
    "ldap_port": "SOURCES__SCCM__LDAP_PORT",
    # Collection
    "collection_methods": "SOURCES__SCCM__COLLECTION_METHODS",
    "computers": "SOURCES__SCCM__COMPUTERS",
    "computer_file": "SOURCES__SCCM__COMPUTER_FILE",
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
    # DNS
    "dns_resolver": "SOURCES__SCCM__DNS_RESOLVER",
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
    "--nt-hash",
    "--ticket",
    "--ldap-port",
    "--collection-methods",
    "--computers",
    "--cf",
    "--computer-file",
    "--sc",
    "--site-codes",
    "--threads",
    "--machine-name",
    "--machine-pass",
    "--client-name",
    "--create-machine-account",
    "--registration-sleep",
    "--socks-proxy",
    "--dns",
    "--dns-resolver",
}
_SENSITIVE_OPTIONS: set[str] = {
    "-p",
    "--password",
    "--machine-pass",
    "--nt-hash",
    "--ticket",
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

    (no flags) → INFO    (collection-step summaries by default)
    ``-v``      → INFO   (same as default; kept for backwards compatibility)
    ``-vv``     → VERBOSE (PS1 ``[Verbose]`` parity tier: per-AD-resolution, per-
                  node-add, per-edge dedupe traces)
    ``--debug`` → DEBUG  (everything, including dlt and ldap3 internals)

    Highest-set wins.

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
    else:
        level_name, level = "INFO", logging.INFO

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


# ---------------------------------------------------------------------------
# Windows-safe core log rotation
# ---------------------------------------------------------------------------
# OpenHound core attaches a TimedRotatingFileHandler (``when="midnight"``) to
# BOTH the root and ``dlt`` loggers, each pointed at the same ``openhound.log``
# (see ``openhound/core/logging.py``). The first record after midnight fires a
# rollover whose ``os.rename(openhound.log -> openhound.log.<date>)`` fails on
# Windows with ``WinError 32``, because the sibling handler still holds the
# file open — so core's daily rotation has never worked on Windows. We cannot
# edit core, so we mutate the live handler instances from our side:
#
#   1. Repoint each to a per-run timestamped file so every run owns a distinct
#      log and a stale rotated file never collides with a fresh rename target.
#   2. Replace ``doRollover`` with a copy+truncate that never renames, so a run
#      crossing midnight (or tripping the size cap) rotates without needing
#      exclusive access to the open file.


def _copytruncate_rollover(self: logging.Handler) -> None:
    """Windows-safe ``doRollover`` for core's ``RotatingFileHandler``.

    Copies the live log to a dated sibling, then truncates it in place rather
    than renaming it — so the sibling handler's open handle stays valid and
    Windows never raises ``WinError 32``. Mirrors core's suffix scheme: a date
    for time-based rollovers, date + time for size-triggered ones.
    """
    self.acquire()
    try:
        if self.stream:
            self.stream.close()
            self.stream = None
        if getattr(self, "_size_triggered", False):
            stamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        else:
            stamp = time.strftime("%Y-%m-%d")
        src = pathlib.Path(self.baseFilename)
        if src.exists():
            shutil.copy2(src, src.with_name(f"{src.name}.{stamp}"))
            open(src, "w").close()  # truncate in place; keeps path + handle valid
        self.rolloverAt = self.computeRollover(int(time.time()))
    finally:
        self.release()


def _make_core_rotation_windows_safe() -> None:
    """Neutralize the Windows-broken daily rotation in core's log handlers.

    See the section comment above. No-op off Windows, where core's
    rename-based rollover works correctly. Runs once at module import, after
    core has already attached its handlers, so it covers every CLI subcommand.
    """
    if platform.system() != "Windows":
        return
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    for log in (logging.getLogger(), logging.getLogger("dlt")):
        for handler in log.handlers:
            if type(handler).__name__ != "RotatingFileHandler":
                continue
            base = pathlib.Path(handler.baseFilename)
            handler.acquire()
            try:
                if handler.stream:
                    handler.stream.close()
                handler.baseFilename = str(base.with_name(f"{base.stem}_{ts}{base.suffix}"))
                handler.rolloverAt = handler.computeRollover(int(time.time()))
                handler.doRollover = types.MethodType(_copytruncate_rollover, handler)
                # Open the new file now (core constructs with delay=False). Core's
                # shouldRollover calls os.path.getsize(baseFilename) on every record,
                # so the file must exist before the first log line.
                handler.stream = handler._open()
            finally:
                handler.release()


_make_core_rotation_windows_safe()


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


def _resolve_dc_via_dns(domain: str, dns_resolver: Optional[str] = None) -> Optional[str]:
    """Resolve a domain controller FQDN from the domain via DNS SRV.

    Looks up ``_ldap._tcp.dc._msdcs.<domain>`` — the path .NET's
    ``Domain.FindDomainController()`` ultimately takes via DC Locator.
    Cross-platform: works wherever the host has DNS reachability to the AD
    DNS zone, not just Windows.

    The resolver is built via the shared ``discovery.dns.make_resolver`` (explicit
    nameserver when ``dns_resolver`` is set, else the host's configured resolvers).
    SCCM keeps its own SRV query here — ``_ldap._tcp.dc._msdcs.<domain>`` is the
    precise DC-Locator record (.NET ``Domain.FindDomainController``), narrower than
    the shared ``resolve_dc``'s general ``_ldap._tcp.<domain>``.
    """
    try:
        from openhound_collector_common.discovery.dns import make_resolver
        from openhound_collector_common.proxy import active_proxy

        resolver = make_resolver(dns_resolver, lifetime=5, force_tcp=active_proxy() is not None)
        answers = resolver.resolve(f"_ldap._tcp.dc._msdcs.{domain}", "SRV")
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
            dc = _resolve_dc_via_dns(domain, dns_resolver=flag_kwargs.get("dns_resolver"))
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


def _parse_proxy_or_exit(socks_proxy: Optional[str]) -> Optional["ProxyConfig"]:
    """Parse --socks-proxy into a ProxyConfig, or exit(2) with a clear error."""
    from openhound_collector_common.proxy import SocksError, parse_proxy_address
    if not socks_proxy:
        return None
    try:
        cfg = parse_proxy_address(socks_proxy)
        logger.info("SOCKS5 proxy configured: %s:%s", cfg.host, cfg.port)
        return cfg
    except SocksError as ex:
        logger.error("Invalid --socks-proxy value %r: %s", socks_proxy, ex)
        raise typer.Exit(2)


def _require_dc_or_dns_for_proxy(flag_kwargs: dict, proxy: Optional["ProxyConfig"]) -> None:
    """Under a proxy, we can't resolve internal names locally, so demand a pin."""
    if proxy is None:
        return  # direct mode: nothing to enforce
    if flag_kwargs.get("domain_controller") or flag_kwargs.get("dns_resolver"):
        logger.debug("_require_dc_or_dns_for_proxy: DC/DNS pin present; ok")
        return
    logger.error(
        "--socks-proxy requires --dc <ip/host> or --dns <internal-resolver-ip>: "
        "target names can't be resolved from the outside box under a pivot."
    )
    raise typer.Exit(2)


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
        self.setLevel(logging.DEBUG)
        self.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        self.warning_count = 0
        self.error_count = 0

    def emit(self, record: logging.LogRecord) -> None:
        if record.levelno == logging.DEBUG:
            # Only capture companion debug lines emitted from inside an except block.
            # The purpose is to preserve contextual data (e.g. the raw entry that failed)
            # alongside the WARNING/ERROR that precedes it in the file.
            if sys.exc_info()[0] is None:
                return
            super().emit(record)
            return

        if record.levelno < logging.WARNING:
            return  # drop INFO / VERBOSE / etc.

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
# Ordered-log file handler
# ---------------------------------------------------------------------------
# Buffers every log record in a per-resource dict keyed by the active
# _current_resource contextvar value.  When a resource generator exhausts
# (signalled by the completion callback registered in gen_wrapper), the whole
# batch for that resource is appended to the file as a labelled section —
# giving human-readable, resource-sequential output regardless of how dlt
# interleaves the generators at runtime.
#
# Records that arrive outside any resource context (CLI setup, summary lines,
# etc.) are collected under the "__root__" key and flushed by flush_all().
# ---------------------------------------------------------------------------

_ORDERED_LEVEL_LABEL: dict[int, str] = {
    logging.DEBUG:    "DEBUG   ",
    logging.INFO:     "INFO    ",
    logging.WARNING:  "WARNING ",
    logging.ERROR:    "ERROR   ",
    logging.CRITICAL: "CRITICAL",
}
_ORDERED_TS_FMT = "%Y-%m-%d %H:%M:%S"


class _OrderedLogFileHandler(logging.Handler):
    """Buffers log records per resource; flushes each resource's batch to a
    file in completion order when notified via flush_resource().

    Register flush_resource as a resource-complete callback::

        register_resource_complete_callback(_handler.flush_resource)

    Call close() (which calls flush_all()) before removing the handler to
    drain any in-flight buffers (e.g. resources that errored before exhausting).
    """

    def __init__(self, path: pathlib.Path, level: int = logging.NOTSET) -> None:
        super().__init__(level=level)
        self._path = path.resolve()  # absolute so CWD changes don't affect later writes
        self._buffers: dict[str, list] = {}
        self._lock = threading.Lock()
        self._write_lock = threading.Lock()  # serialize block writes across worker threads
        # Import once at construction time so the relative import never runs
        # inside emit() (which fires on every log record).
        from .log_context import get_current_resource, get_current_target
        self._get_current_resource = get_current_resource
        self._get_current_target = get_current_target

    def _bucket_key(self) -> str:
        """Key the current record's block by resource if one is active (discovery
        / DLT resources), else by per-host target (worker-pool records), else the
        catch-all root bucket."""
        resource = self._get_current_resource()
        if resource:
            return resource
        return self._get_current_target() or "__root__"

    def emit(self, record: logging.LogRecord) -> None:
        try:
            key = self._bucket_key()
            # Freeze the message string now so args (possibly mutable) are no
            # longer needed when we format at flush time.
            rec = copy.copy(record)
            try:
                rec.msg = record.getMessage()
            except Exception:
                rec.msg = str(record.msg)
            rec.args = None
            with self._lock:
                self._buffers.setdefault(key, []).append(rec)
        except Exception:
            self.handleError(record)  # writes traceback to sys.stderr

    def flush_resource(self, resource_name: str) -> None:
        """Write *resource_name*'s buffered records to the file and clear the buffer.

        Records are only removed from the buffer on a successful write so that
        flush_all() can retry them if the output directory didn't exist yet
        (dlt creates it lazily during the load phase, after extraction).
        """
        with self._lock:
            records = list(self._buffers.get(resource_name, []))
        if records and self._write_section(resource_name, records):
            with self._lock:
                self._buffers.pop(resource_name, None)

    def flush_host(self, hostname: str) -> None:
        """Flush a host's buffered records as one labelled block.

        Registered as a host-completion callback; fires (possibly from several
        worker threads at once) when a target finishes its full phase sequence.
        Block writes are serialized by ``_write_section`` so concurrent host
        flushes never interleave in the file.
        """
        self.flush_resource(hostname)

    def flush_all(self) -> None:
        """Flush every remaining buffer — called at handler close time."""
        with self._lock:
            remaining = list(self._buffers.items())
            self._buffers.clear()
        for resource_name, records in remaining:
            if records:
                self._write_section(resource_name, records)

    def _write_section(self, resource_name: str, records: list) -> bool:
        """Write records to file. Returns True on success, False on failure."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            lines: list[str] = [f"\n{'=' * 72}\n# {resource_name}\n{'=' * 72}\n"]
            for rec in records:
                label = _ORDERED_LEVEL_LABEL.get(rec.levelno) or f"L{rec.levelno:<6}"
                ts = datetime.datetime.fromtimestamp(rec.created).strftime(_ORDERED_TS_FMT)
                lines.append(f"{label} time={ts}, msg={rec.msg}\n")
                if rec.exc_info and rec.exc_info[0] is not None:
                    lines.append(
                        "".join(_traceback.format_exception(*rec.exc_info))
                    )
            with self._write_lock:
                with open(self._path, "a", encoding="utf-8") as fh:
                    fh.writelines(lines)
            return True
        except Exception:
            return False

    def close(self) -> None:
        self.flush_all()
        super().close()


# ---------------------------------------------------------------------------
# Per-host stage helpers (Stage 2 of collect_sccm)
# ---------------------------------------------------------------------------

def _cli_seed_targets(computers: Optional[str], computer_file) -> list[str]:
    """Hostnames given on the command line, to seed onto the work queue."""
    hosts: list[str] = []
    if computers:
        hosts.extend(token.strip() for token in computers.split(",") if token.strip())
    if computer_file:
        p = pathlib.Path(computer_file)
        if p.exists():
            hosts.extend(line.strip() for line in p.read_text().splitlines() if line.strip())
    return hosts


def _build_phase_scope():
    """Return a context manager factory that tags log lines [target][phase]."""
    import contextlib

    from .log_context import phase_context, target_context

    @contextlib.contextmanager
    def _phase_scope(target: str, phase_name: str):
        with target_context(target), phase_context(phase_name):
            yield

    return _phase_scope


def _run_per_host_stage(pipeline, work_queue, ctx, threads, maxsize: int = 1000, phases=None) -> dict[str, int]:
    """Stage 2: drain the work queue with a worker pool while streaming each
    per-host table to disk through its emit resource.

    Runs the engine on a background thread (it produces rows onto the bounded
    per-table streams and, at quiescence, closes them with DONE) while the emit
    resources drain those streams on this thread via ``pipeline.run``. Returns
    only after both halves finish. As each target finishes its phase sequence,
    ``fire_host_complete`` notifies the ordered-log handler to flush that host's
    block (a no-op when no handler is registered, e.g. in unit tests).

    Not reentrant: it plants a process-global stream bridge (``set_bridge``) and
    temporarily raises the process-wide ``EXTRACT__WORKERS`` env var (via
    ``extract_workers_for``), so a single collect run per process is assumed
    (true for the CLI).
    """
    from openhound_collector_common.dlt.source_bridge import StreamBridge, extract_workers_for

    from . import source as _source
    from .log_context import fire_host_complete
    from .per_host_phases import PER_HOST_PHASES, all_table_names, should_run_phase
    from .phased_pipeline import run_pipeline

    # `phases` is injectable so integration tests can drive the stage with stub
    # phases; production always uses the real PER_HOST_PHASES.
    default_phases = phases is None
    if phases is None:
        phases = PER_HOST_PHASES
    table_names = all_table_names(phases)
    # The shared StreamBridge owns this run's bounded per-table queues (the
    # backpressure bound) and the blocking drain. The engine pushes rows onto
    # bridge.streams; the emit resources (via source._drain_stream) drain them.
    bridge = StreamBridge(table_names, maxsize=maxsize)
    _source.set_bridge(bridge)
    phase_scope = _build_phase_scope()

    def _pool() -> None:
        run_pipeline(
            work_queue,
            ctx,
            phases,
            bridge.streams,
            max_workers=threads,
            should_run=should_run_phase,
            phase_scope=phase_scope,
            on_target_complete=fire_host_complete,
        )

    per_host_counts: dict[str, int] = {}
    pool_thread = threading.Thread(target=_pool, name="per-host-pool", daemon=True)
    pool_thread.start()
    try:
        # Each emit resource blocks on its queue until DONE, so it holds a dlt
        # extract worker for the whole run. extract_workers_for raises dlt's
        # worker cap to one-per-table (plus a margin) for the duration and
        # restores it after — without it, more tables than workers would wedge an
        # undrained queue and deadlock. (parallelized=True on each emit resource
        # is the other half of that guard; see source._make_emit_resource.)
        with extract_workers_for(len(table_names)):
            pipeline.run(
                # Production reuses the cached emit resources; an injected phase
                # set gets emit resources matching its own tables.
                _source.build_emit_resources(None if default_phases else table_names),
                write_disposition="append",
                loader_file_format="jsonl",
            )
        # Capture this run's per-table row counts from dlt's normalize step while
        # the in-memory trace still reflects the per-host pass — a later run on the
        # same pipeline would replace it.
        per_host_counts = _normalize_row_counts(pipeline)
    finally:
        # Always await the engine thread. If pipeline.run raised, the emit
        # consumers stopped draining, so a worker may be blocked on a full queue;
        # empty the queues until the engine finishes so it reaches quiescence and
        # join() can never hang. No-op on the success path (queues already
        # drained, engine already finishing).
        while pool_thread.is_alive():
            bridge.drain_to_unblock()
            pool_thread.join(timeout=0.1)
        _source.clear_bridge()
    return per_host_counts


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
    progress: ProgressOption = typer.Option(
        ProgressOption.off,
        help="Progress backend. 'off' (default) silences dlt's progress counters so only the "
        "collector's own logs print; 'tqdm' / 'log' / 'alive_progress' re-enable a live tracker.",
    ),
    tables: Contract = typer.Option(Contract.evolve, help="Contract for newly-seen resources/tables."),
    columns: Contract = typer.Option(Contract.evolve, help="Contract for unknown fields."),
    data_type: Contract = typer.Option(Contract.freeze, help="Contract for type mismatches."),
    # ---- Connection ----
    domain: Optional[str] = typer.Option(None, "-d", "--domain", help="Domain (e.g. mayyhem.com). On Windows, auto-detected from $env:USERDNSDOMAIN; on Linux/macOS this flag is required."),
    domain_controller: Optional[str] = typer.Option(None, "--dc", "--domain-controller", help="DC hostname or IP. If omitted, resolved from --domain via DNS SRV (_ldap._tcp.dc._msdcs.<domain>)."),
    username: Optional[str] = typer.Option(None, "-u", "--username", help="DOMAIN\\\\user for explicit auth."),
    password: Optional[str] = typer.Option(None, "-p", "--password", help="Password for explicit auth."),
    nt_hash: Optional[str] = typer.Option(None, "--nt-hash", help="NT hash for pass-the-hash auth (bare 32-hex NT hash; LM half assumed empty). Used by LDAP, AdminService (Kerberos RC4 key and NTLM), the SMB-based phases (RemoteRegistry, SMB), and the MSSQL EPA probe."),
    ticket: Optional[str] = typer.Option(None, "--ticket", help="Base64-encoded Kerberos ticket (.kirbi / KRB-CRED) for pass-the-ticket. Kerberos only, no NTLM fallback. Honored by LDAP, AdminService/WMI, and the SMB-based phases (RemoteRegistry, SMB). Not used for the MSSQL EPA probe (it cannot probe channel binding — use -p/--password or --nt-hash there)."),
    ldap_port: Optional[int] = typer.Option(None, "--ldap-port", help="Pin LDAP port. Omit to auto-detect (LDAPS:636 → StartTLS:389 → LDAP:389+sign/seal). 636/3269 → LDAPS; any other port → LDAP."),
    # ---- Collection ----
    collection_methods: Optional[str] = typer.Option(
        None, "-m", "--collection-methods",
        help="Comma-separated methods: All, LDAP, Local, DNS, DHCP, RemoteRegistry, MSSQL, AdminService, WMI, HTTP, SMB.",
    ),
    computers: Optional[str] = typer.Option(None, "-c", "--computers", help="Comma-separated computer targets."),
    computer_file: Optional[pathlib.Path] = typer.Option(None, "--cf", "--computer-file", help="File with computer targets (one per line)."),
    site_codes: Optional[str] = typer.Option(None, "--sc", "--site-codes", help="Site codes for DNS collection (CSV or file path)."),
    # ---- Behavior ----
    disable_possible_edges: bool = typer.Option(False, "--disable-possible-edges", help="Disable uncertain/possible edges."),
    enable_bad_opsec: bool = typer.Option(False, "--enable-bad-opsec", help="Enable bad-opsec operations (NAA decryption, etc.)."),
    threads: int = typer.Option(10, "-t", "--threads", help="Number of machines collected concurrently (per-host worker pool size; default 10)."),
    show_cleartext_passwords: bool = typer.Option(False, "--show-cleartext-passwords", help="Display cleartext passwords when discovered."),
    run_all: bool = typer.Option(
        False, "--run-all",
        help="After collecting, automatically run preprocess and convert in-process so a "
        "single command produces the OpenGraph files. All paths are derived from OUTPUT_PATH "
        "(lookup.duckdb, the sccm/ dataset dir, and graph/).",
    ),
    # ---- Machine Account / CRED-2 ----
    machine_name: Optional[str] = typer.Option(None, "--machine-name", help="DOMAIN\\\\MACHINE$ for SCCM client registration. CRED-2 chain not yet implemented."),
    machine_pass: Optional[str] = typer.Option(None, "--machine-pass", help="Machine account password. CRED-2 chain not yet implemented."),
    client_name: Optional[str] = typer.Option(None, "--client-name", help="Client FQDN to register. CRED-2 chain not yet implemented."),
    create_machine_account: Optional[str] = typer.Option(None, "--create-machine-account", help="Create a machine account for CRED-2. Pass 'auto' or a name. Not yet implemented."),
    use_altauth: bool = typer.Option(False, "--use-altauth", help="Use ccm_system_altauth endpoint. Not yet implemented."),
    registration_sleep: int = typer.Option(10, "--registration-sleep", help="Seconds to wait post-registration before policy request. Not yet implemented."),
    # ---- Network ----
    socks_proxy: Optional[str] = typer.Option(
        None, "--socks-proxy",
        help="Route ALL collection traffic through a SOCKS5 proxy. Forms: "
             "socks5://[user:pass@]host:port or bare host:port. Requires --dc "
             "or --dns (internal names can't be resolved locally under a pivot).",
    ),
    dns_resolver: Optional[str] = typer.Option(None, "--dns", "--dns-resolver", help="DNS nameserver IP for all lookups (DC discovery, SRV probes). Omit to use system default."),
    # ---- General ----
    verbose: int = typer.Option(0, "-v", "--verbose", count=True, help="Verbose output. -v=INFO (step summaries), -vv=VERBOSE (PS1 [Verbose] parity: per-resolution / per-node-add / per-edge dedupe traces)."),
    debug: bool = typer.Option(False, "--debug", help="Debug output (DEBUG level; very chatty, includes dlt and ldap3 internals)."),
) -> Optional[LoadInfo]:
    _apply_log_level(verbose, debug)

    _ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    log_path = output_path / f"collect_diagnostics_{_ts}.log"
    _diag = _DiagnosticFileHandler(log_path)

    # Ordered log — same records as the console, written resource-by-resource
    # in completion order rather than dlt's interleaved round-robin order.
    _ordered_log_path = output_path / f"collect_log_{_ts}.log"
    _root_level = logging.root.level or logging.WARNING
    _ordered_level = min(_root_level, logging.INFO)  # floor at INFO; lower if -v/-vv/--debug
    _ordered = _OrderedLogFileHandler(_ordered_log_path, level=_ordered_level)

    from .log_context import (
        register_host_complete_callback,
        register_resource_complete_callback,
        unregister_host_complete_callback,
        unregister_resource_complete_callback,
    )
    logging.root.addHandler(_diag)
    logging.root.addHandler(_ordered)
    register_resource_complete_callback(_ordered.flush_resource)
    register_host_complete_callback(_ordered.flush_host)
    # Lower the openhound_sccm namespace to DEBUG so companion debug lines emitted
    # inside except blocks reach the file handler. Console handlers (pinned to WARNING
    # by _apply_log_level) are unaffected — the file handler's own emit() guard drops
    # any debug record that is NOT inside an active exception context.
    _oh_logger = logging.getLogger("openhound_sccm")
    _oh_original_level = _oh_logger.level
    _oh_logger.setLevel(logging.DEBUG)
    try:
        _warn_for_suspicious_cli_arguments()
        flag_kwargs = locals()
        # The Typer param is `ticket`; the env map keys it as `kerberos_ticket`.
        flag_kwargs["kerberos_ticket"] = flag_kwargs.pop("ticket", None)
        _apply_env_overrides(flag_kwargs)
        _drop_empty_dlt_env_values()
        # Parse + validate the proxy BEFORE connection-context auto-detect, so
        # the --dc/--dns check sees the user's flags (not an auto-filled DC) and
        # so DC discovery itself runs inside the tunnel.
        proxy_cfg = _parse_proxy_or_exit(
            flag_kwargs.get("socks_proxy") or os.environ.get("SOURCES__SCCM__SOCKS_PROXY")
        )
        _require_dc_or_dns_for_proxy(flag_kwargs, proxy_cfg)

        # Route ALL collection traffic through the SOCKS5 proxy for the whole
        # window — including DC discovery (SRV over TCP) — no-op when proxy_cfg is None.
        from openhound_collector_common.proxy import socks_proxy_installed
        with socks_proxy_installed(proxy_cfg):
            _apply_connection_context(flag_kwargs)
            _require_domain_or_explain(flag_kwargs)

            from .per_host_phases import PER_HOST_PHASES
            from .phased_pipeline import WorkQueue
            from .source import (
                DISCOVERY_RESOURCE_NAMES,
                get_last_ctx,
                set_shared_ad_cache,
                set_shared_discovered_domains,
                set_shared_queue,
            )
            from .source import source as sccm_source

            work_queue = WorkQueue()
            set_shared_queue(work_queue)
            set_shared_ad_cache({})
            set_shared_discovered_domains(set())

            collector = Collector(name=app.name, output_path=output_path, resources=resources, progress=_resolve_progress(progress))
            ctx = CollectContext(pipeline=collector)

            src = sccm_source()
            if not src:
                set_shared_queue(None)
                set_shared_ad_cache(None)
                set_shared_discovered_domains(None)
                return None

            # Reuse the exact context discovery built, so the per-host stage shares
            # its target accumulator, allow-list, caches, and work queue.
            per_host_ctx = get_last_ctx()

            # Stage 1 — discovery (once-phases): run only the discovery resources.
            # They seed the work queue via register_target (allow-list applied).
            load_info = collector.run(src.with_resources(*DISCOVERY_RESOURCE_NAMES))
            # Capture discovery row counts from the pipeline that just ran (held via
            # LoadInfo.pipeline) before the per-host pass replaces the trace.
            discovery_counts = _normalize_row_counts(load_info.pipeline) if load_info else {}

            # Seed CLI-specified targets through the same register_target path, so
            # the allow-list / resolution / dedup is identical for them.
            if per_host_ctx is not None:
                for host in _cli_seed_targets(computers, computer_file):
                    per_host_ctx.register_target(host, source="CLI")

            # Stage 2 — per-host collection: a worker pool runs each target's phases
            # in order while emit resources stream the tables to disk, looping
            # recursively until the work queue drains.
            per_host_counts: dict[str, int] = {}
            per_host_expected = bool(per_host_ctx is not None and PER_HOST_PHASES)
            if per_host_expected:
                per_host_counts = _run_per_host_stage(collector.pipeline, work_queue, per_host_ctx, threads)

        set_shared_queue(None)
        set_shared_ad_cache(None)
        set_shared_discovered_domains(None)

        # Clear the [target][phase] log context so the summary block reads as a
        # global section rather than inheriting whatever phase ran last.
        from .log_context import phase_context, target_context
        with target_context(None), phase_context(None):
            _log_collect_summary(
                discovery_counts, per_host_counts, per_host_expected, output_path, run_all=run_all
            )
    finally:
        _oh_logger.setLevel(_oh_original_level)
        unregister_resource_complete_callback(_ordered.flush_resource)
        unregister_host_complete_callback(_ordered.flush_host)
        _ordered.close()  # flushes any in-flight buffers before removal
        logging.root.removeHandler(_ordered)
        logging.root.removeHandler(_diag)
        if _ordered_log_path.exists():
            logger.info("Collection log: %s", _ordered_log_path)
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

    # Collection succeeded here — an exception in the try above would have
    # propagated past the finally and never reached this point. Chain the
    # remaining phases only when the operator asked for it.
    if run_all:
        _paths = _run_e2e_after_collect(output_path, progress)
        # Re-surface every artifact's location in one block at the very end, so the
        # operator doesn't have to scroll back through the collect/preproc/convert
        # logs to find where each output landed.
        _log_all_output_locations(
            output_path, _paths, _ordered_log_path, log_path,
            _diag.warning_count + _diag.error_count,
        )
    else:
        logger.debug("--run-all not set; leaving preprocess/convert to the operator.")
    return load_info

def _normalize_row_counts(pipeline) -> dict[str, int]:
    """Return ``{table_name: rows}`` from *pipeline*'s most recent normalize step.

    dlt records per-run row counts on the pipeline trace. ``last_trace`` is
    replaced by each multi-step ``pipeline.run``, so callers must read this right
    after the run whose counts they want — not once at the end. dlt bookkeeping
    tables (``_dlt_*``) are dropped. Returns ``{}`` when no trace or normalize
    info is available (e.g. a run that failed before normalize); the summary
    treats an empty result from an expected stage as a "partial run" signal.
    """
    try:
        trace = pipeline.last_trace
        if trace is None:
            # No run has completed on this pipeline object yet.
            logger.debug("No dlt trace on pipeline; row counts unavailable")
            return {}
        info = trace.last_normalize_info
        if info is None:
            # Trace exists but the run never reached the normalize step.
            logger.debug("No dlt normalize info on trace; row counts unavailable")
            return {}
        return {
            table: int(rows)
            for table, rows in info.row_counts.items()
            if not table.startswith("_dlt")
        }
    except Exception as ex:
        # A metrics read must never break the collection summary.
        logger.warning("Could not read dlt row counts for the collection summary: %s", ex)
        return {}

def _cli_path_arg(path: pathlib.Path) -> str:
    """Render *path* as one shell argument for the copy-pasteable "next steps" hint.

    Wraps the path in double quotes only when it contains whitespace, so a normal
    path prints bare (``.\\out``) while one with spaces stays a single argument
    (``"C:\\Program Files\\out"``). Double quotes are honored by both cmd.exe and
    PowerShell, the shells an operator is most likely pasting into on Windows.
    """
    text = str(path)
    # Pure string formatting for a log line — a no-whitespace path needs no
    # quoting, so leave it bare for readability; nothing here warrants a log.
    return f'"{text}"' if any(ch.isspace() for ch in text) else text

def _log_collect_summary(
    discovery_counts: dict[str, int],
    per_host_counts: dict[str, int],
    per_host_expected: bool,
    output_path: pathlib.Path,
    run_all: bool = False,
) -> None:
    """Emit an end-of-collection summary at INFO level.

    Row counts are a TRUE per-run metric: they come from dlt's normalize step
    for this run's two passes (discovery + per-host), merged here. This replaces
    the old on-disk directory scan, which double-counted stale tables left by
    older code or prior runs. The final node/edge totals aren't known yet — those
    come from ``output.py::package`` after convert.
    """
    logger.info("Collection complete.")
    logger.info("Raw output directory: %s", output_path)

    # Merge the two stages. Their table sets are disjoint (discovery emits
    # ldap_*/dns_*/local_*/collection_settings; per-host emits the rest), but sum
    # on overlap so a future shared table can never silently drop rows.
    counts: dict[str, int] = dict(discovery_counts)
    for table, rows in per_host_counts.items():
        counts[table] = counts.get(table, 0) + rows

    # A stage we expected to run but got no counts from means the numbers below
    # are partial — e.g. the stage raised before dlt normalized, or its trace was
    # lost. Surface it rather than silently under-reporting.
    if not discovery_counts:
        logger.warning("Discovery stage reported no row counts; the collection summary may be incomplete.")
    if per_host_expected and not per_host_counts:
        logger.warning("Per-host stage reported no row counts; the collection summary may be incomplete.")

    if counts:
        total = sum(counts.values())
        logger.info("Extracted %d rows across %d resources:", total, len(counts))
        for name, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
            logger.info("    %-40s %d", name, count)
    else:
        # Both stages empty — nothing was extracted at all.
        logger.warning("No rows were extracted during this collection run.")

    # Flag stale/orphan table folders so an operator notices data left by older
    # code or earlier runs (e.g. a renamed resource). Compared against the
    # authoritative table universe (the preproc map) rather than this run's
    # counts, so a current table that legitimately got 0 rows is never mis-flagged.
    try:
        dataset_dir = output_path / "sccm"
        if dataset_dir.is_dir():
            known = set(_preproc_table_map().keys())
            on_disk = {
                d.name
                for d in dataset_dir.iterdir()
                if d.is_dir() and not d.name.startswith("_dlt")
            }
            orphans = sorted(on_disk - known)
            if orphans:
                logger.warning(
                    "Found %d stale table folder(s) under %s not produced by any current "
                    "collector (likely from older code or prior runs): %s. Preprocess/convert "
                    "ignore them, but you may want to delete them.",
                    len(orphans), dataset_dir, ", ".join(orphans),
                )
            else:
                logger.debug("No orphan table folders under %s", dataset_dir)
        else:
            logger.debug("Dataset dir %s missing; skipping orphan-folder check", dataset_dir)
    except Exception as ex:
        # Orphan detection is best-effort — never fail collect because of it.
        logger.error("Orphan-folder check failed: %s", ex)

    # When --run-all is set, preprocess and convert run automatically right after
    # this summary, so the manual copy-paste hint would only mislead. Derive the
    # printed paths from the shared convention so this hint and --run-all can
    # never disagree about where files land.
    if run_all:
        logger.info("--run-all set: preprocess and convert will run automatically next.")
        return

    # Derive every next-stage path from the one path the operator gave collect
    # (OUTPUT_PATH), so both printed commands are ready to copy and run: the
    # lookup DB and graph land alongside the raw data, and convert reads the
    # "sccm" dataset dir dlt wrote beneath it. Commands are prefixed with
    # `uv run` (matching the README) so they resolve to the sccm project's venv
    # when run from the sccm/sccm dir — a bare `openhound` would resolve to
    # whatever venv happens to be active, which may lack the SCCM extension.
    from openhound_collector_common.orchestration import derive_stage_paths

    paths = derive_stage_paths(app, output_path)
    preprocess_cmd = (
        f"uv run openhound preprocess sccm {_cli_path_arg(output_path)} {_cli_path_arg(paths.lookup_db)}"
    )
    convert_cmd = (
        f"uv run openhound convert sccm {_cli_path_arg(paths.dataset_dir)} {_cli_path_arg(paths.graph_out)} "
        f"--lookup-file {_cli_path_arg(paths.lookup_db)}"
    )
    logger.info("Next steps: '%s' then '%s'", preprocess_cmd, convert_cmd)


def _run_e2e_after_collect(output_path: pathlib.Path, progress: ProgressOption) -> "StagePaths":
    """Chain preprocess + convert in-process after a successful --run-all collect.

    Maps the collector's --progress choice to what the shared orchestrator wants
    (a framework Progress member, or None for silent), then delegates to
    run_end_to_end and returns the StagePaths it produced (dataset dir, lookup DB,
    graph dir) so the caller can report every output location. If a stage fails,
    the raw collected data is left intact and the equivalent manual commands are
    logged so the operator can resume from preprocess without recollecting.
    """
    from openhound_collector_common.orchestration import (
        derive_stage_paths,
        run_end_to_end,
    )

    # 'off' -> None (dlt NULL_COLLECTOR in both stages); any real backend -> the
    # matching framework Progress member. (Note: unlike collect, we can't reuse
    # _resolve_progress here — its 'off' path returns a .value=None *object*,
    # which the preprocess stage would hand raw to dlt. run_end_to_end needs the
    # None/Progress form and applies the convert-side shim itself.)
    if progress is ProgressOption.off:
        e2e_progress = None
        logger.debug("--run-all: preprocess/convert progress disabled (matches --progress off).")
    else:
        e2e_progress = Progress(progress.value)
        logger.debug("--run-all: preprocess/convert progress backend: %s", progress.value)

    logger.info("--run-all: continuing with preprocess and convert (in-process).")
    try:
        return run_end_to_end(app, output_path, progress=e2e_progress)
    except Exception:
        # Collect already succeeded, so the raw data on disk is still good; tell
        # the operator exactly how to resume rather than lose that work. Commands
        # are prefixed with `uv run`, matching the manual "Next steps" hint above,
        # so they resolve to the sccm project's venv regardless of which venv
        # happens to be active.
        paths = derive_stage_paths(app, output_path)
        logger.error(
            "--run-all: preprocess/convert failed after a successful collect. Your raw data "
            "is intact at %s. Resume manually: 'uv run openhound preprocess sccm %s %s' then "
            "'uv run openhound convert sccm %s %s --lookup-file %s'.",
            output_path,
            _cli_path_arg(output_path), _cli_path_arg(paths.lookup_db),
            _cli_path_arg(paths.dataset_dir), _cli_path_arg(paths.graph_out),
            _cli_path_arg(paths.lookup_db),
        )
        raise


def _log_all_output_locations(
    output_path: pathlib.Path,
    paths: "StagePaths",
    collect_log_path: pathlib.Path,
    collect_diag_path: pathlib.Path,
    diag_issue_count: int,
) -> None:
    """Log a consolidated list of every artifact a ``--run-all`` run produced.

    Printed once at the very end (after convert) so the operator sees, in a single
    block, where the raw data, collect logs, lookup DB, and OpenGraph files all
    landed — the collect-phase paths plus the preprocess/convert outputs, gathered
    back together rather than scattered across three phases of log output.
    """
    # output_path, the raw dataset dir, and the lookup DB always exist on the
    # success path (a completed run_end_to_end guarantees them), so they are listed
    # unconditionally; the logs and graph files below are guarded on existence.
    logger.info("--run-all complete. Output files:")
    logger.info("    Output directory:    %s", output_path)
    logger.info("    Raw data (JSONL):    %s", paths.dataset_dir)

    # Collect-phase logs (written during collection; re-surfaced here for one-stop
    # reference). Both are created lazily and may be absent: the ordered log only
    # if collection produced records, and the diagnostics file (delay=True) only
    # if a WARNING+ was emitted — so a clean run has no diagnostics file to list.
    # Each line is therefore guarded on existence.
    if collect_log_path.exists():
        logger.info("    Collection log:      %s", collect_log_path)
    else:
        logger.debug("Collection log not found at %s; omitting from summary.", collect_log_path)
    if collect_diag_path.exists():
        note = (
            f"{diag_issue_count} warning(s)/error(s), with tracebacks"
            if diag_issue_count
            else "no warnings/errors"
        )
        logger.info("    Diagnostics log:     %s  (%s)", collect_diag_path, note)
    else:
        logger.debug("Diagnostics log not found at %s; omitting from summary.", collect_diag_path)

    logger.info("    Lookup DB:           %s", paths.lookup_db)

    # OpenGraph files emitted by convert (SCCM + untagged-AD split, one or more each).
    if paths.graph_out.exists():
        graph_files = sorted(paths.graph_out.glob("*.json"))
        if graph_files:
            logger.info("    OpenGraph files (%d):", len(graph_files))
            for graph_file in graph_files:
                logger.info("        %s", graph_file)
        else:
            logger.warning("    OpenGraph output has no .json files: %s", paths.graph_out)
    else:
        logger.warning("    OpenGraph output directory is missing: %s", paths.graph_out)


# Set at module scope so `CollectorManager.validate_extension` (which runs at
# import time, before any command is invoked) sees a non-None hook. The
# `@app.collect()` convenience decorator would do this for us, but we register
# directly on the framework's Typer group to keep CMBP-style flag surface.
app.collector = collect_sccm


def _preproc_table_map() -> dict[str, str]:
    """Return the DuckDB-table → JSONL-path mapping consumed by ``preprocess``.

    Each entry maps the exact DuckDB table name to the JSONL directory path
    that DLT writes during collection. Only tables that an actual collector
    emits are listed here — stale names that no collector produces are omitted
    so preproc does not silently load wrong data.

    The canonical source of truth for each table name is:
    - LDAP/DNS/Local: the ``name=`` argument on ``@app.resource`` in
      ``collectors/ldap.py``, ``collectors/dns.py``, ``collectors/local.py``.
    - RemoteRegistry/MSSQL/HTTP/SMB: the ``"table_name"`` string passed to
      ``yield "table_name", row`` in those per-host collectors.
    - AdminService/WMI: ``run.table("suffix")`` in ``privileged.py``, which
      expands to ``adminservice_<suffix>`` or ``wmi_<suffix>`` from
      ``PER_HOST_PHASES`` in ``per_host_phases.py``.
    """
    base_tables = [
        # LDAP discovery phase (ldap.py @app.resource name=...)
        "ldap_sites",
        "ldap_management_points_raw",
        "ldap_cmrc_devices",
        "ldap_network_boot_servers",
        "ldap_pattern_matches",
        "ldap_system_management_dacl",
        # DNS discovery phase (dns.py @app.resource name=...)
        "dns_management_points",
        # Local discovery phase (local.py @app.resource name=...)
        "local_wmi_sms_authority",
        "local_wmi_sms_lookupmp",
        "local_wmi_ccm_client",
        "local_client_logs_targets",
        "collection_settings",
        # RemoteRegistry per-host phase (registry.py yield "table", row)
        "remoteregistry_sites",
        "remoteregistry_computers",
        "remoteregistry_users",
        "remoteregistry_mssql_servers",
        # MSSQL per-host phase (mssql.py yield "table", row)
        "mssql_server_instances",
        # AdminService per-host phase (privileged.py run.table("suffix"))
        "adminservice_sites",
        "adminservice_site_definitions",
        "adminservice_site_definitions_computers",
        "adminservice_reserved_accounts",
        "adminservice_client_devices",
        "adminservice_r_system",
        "adminservice_r_user",
        "adminservice_user_group",
        "adminservice_collections",
        "adminservice_collection_members",
        "adminservice_security_roles",
        "adminservice_admins",
        "adminservice_site_systems",
        # WMI per-host phase (privileged.py run.table("suffix"); same suffixes as AdminService)
        "wmi_sites",
        "wmi_site_definitions",
        "wmi_site_definitions_computers",
        "wmi_reserved_accounts",
        "wmi_client_devices",
        "wmi_r_system",
        "wmi_r_user",
        "wmi_user_group",
        "wmi_collections",
        "wmi_collection_members",
        "wmi_security_roles",
        "wmi_admins",
        "wmi_site_systems",
        # HTTP per-host phase (http.py yield via _role_row / _sitesigncert_probe)
        "http_management_points",
        "http_distribution_points",
        "http_smsproviders",
        "http_site_servers",
        "http_site_versions",
        # SMB per-host phase (smb.py yield "table", row)
        "smb_computers",
        "smb_sites",
    ]
    return {table: f"sccm/{table}" for table in base_tables}


@app.preproc(transformer=transforms)
def preproc(ctx: PreProcContext) -> dict[str, str]:
    """Build a DuckDB lookup database from collected SCCM JSONL."""
    return _preproc_table_map()


@dlt.source(name="sccm_convert_noop")
def _noop_convert_source():
    """The framework runs Converter.run over whatever @app.convert returns. All real
    emission happens in the Convert2-Read-DB pipeline (run in `convert` below), so this source carries
    no graph-resource models — Converter.run finds no models and its own pipeline is a
    no-op. opengraph_file appends uniquely-numbered files, so the two pipelines writing
    to the same output dir never collide."""

    @dlt.resource(name="_noop")
    def _empty():
        return
        yield  # unreachable; makes _empty a generator yielding nothing

    return _empty


# Registry of (table_name, ModelClass) pairs the convert pipeline iterates, split into the
# two OpenGraph payloads (ARCHITECTURE.md §11f):
#   - SCCM payload  -> source_kind="SCCM"  (custom SCCM_* kinds only)
#   - AD payload    -> NO source_kind      (native Computer/User/Group + backfill stubs;
#                                           BloodHound merges these into its AD graph)
SCCM_NODE_SPECS: list[tuple[str, type]] = [
    ("node_site", SCCMSite),
    ("node_collection", SCCMCollection),
    ("node_security_role", SCCMSecurityRole),
    ("node_admin_user", SCCMAdminUser),
    ("node_client_device", SCCMClientDevice),
    # MSSQL nodes are SCCM-owned (source_kind="SCCM") — they are not AD principals and
    # must not appear in the AD payload. node_backfill lives in AD_NODE_SPECS.
    ("node_mssql_server", MSSQLServer),
    ("node_mssql_database", MSSQLDatabase),
    ("node_mssql_server_role", MSSQLServerRole),
    ("node_mssql_database_role", MSSQLDatabaseRole),
    ("node_mssql_login", MSSQLLogin),
    ("node_mssql_database_user", MSSQLDatabaseUser),
]

AD_NODE_SPECS: list[tuple[str, type]] = [
    ("node_computer", ComputerNode),
    ("node_user", UserNode),
    ("node_group", GroupNode),
    # node_backfill is LAST so a real AD node wins any id overlap via append semantics.
    # Every backfill stub is an AD principal (User/Group/Computer or bare Base).
    ("node_backfill", StubNode),
]

# graph_edges_sccm / graph_edges_ad are the partition built by transforms._graph_edges_split.
SCCM_EDGE_SPECS: list[tuple[str, type]] = [("graph_edges_sccm", GraphEdge)]
AD_EDGE_SPECS: list[tuple[str, type]] = [("graph_edges_ad", GraphEdge)]


def _emit_split_graph(lookup: SCCMLookup, output_path) -> None:
    """Emit the SCCM graph as two payloads into the same directory.

    The SCCM payload (sccm_* files) carries source_kind="SCCM"; the AD payload (ad_* files)
    carries no source_kind so BloodHound merges its Computer/User/Group/stub nodes and the
    edges touching them into the native AD graph. See ARCHITECTURE.md §11f.
    """
    emit_graph_from_duckdb(
        lookup, output_path, app.source_kind,
        SCCM_NODE_SPECS, SCCM_EDGE_SPECS, resource_prefix="sccm",
    )
    emit_graph_from_duckdb(
        lookup, output_path, None,
        AD_NODE_SPECS, AD_EDGE_SPECS, resource_prefix="ad",
    )


@app.convert(lookup=SCCMLookup)
def convert(ctx: ConvertContext):
    """Emit the SCCM graph by reading the preproc DuckDB directly (Convert2-Read-DB), as two
    payloads (SCCM-tagged + untagged AD), then hand the framework a no-op source."""
    _emit_split_graph(ctx.lookup, ctx.output_path)
    return _noop_convert_source(), {}
