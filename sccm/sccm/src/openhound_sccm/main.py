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


def _apply_log_level(verbose: bool, debug: bool) -> None:
    """Adjust console logging when ``-v`` / ``--verbose`` or ``--debug`` is set,
    and install the ``[target][phase]`` prefix filter.

    ``-v``      → INFO (status messages like auto-detected domain / resolved DC).
    ``--debug`` → DEBUG (everything, including dlt and ldap3 internals).
    Both        → DEBUG wins.
    Neither     → leave the framework's default (CLI level ERROR).

    Stdlib-only: keeps the openhound framework's RichHandler in place and just
    plugs in a ``LogContextFilter`` that rewrites each ``LogRecord.msg`` to
    prepend ``[<host>][<phase>] `` based on the currently-active
    ``target_context`` / ``phase_context`` (see ``log_context.py``). The
    framework keeps colorizing levels / timestamps as before; only the message
    text gets the prefix.
    """
    from .log_context import install_filter

    if debug:
        level_name, level = "DEBUG", logging.DEBUG
    elif verbose:
        level_name, level = "INFO", logging.INFO
    else:
        level_name, level = None, None

    if level_name is not None:
        os.environ["RUNTIME__LOG_LEVEL"] = level_name
        os.environ["RUNTIME__LOG_CLI_LEVEL"] = level_name
        for log in (logging.getLogger(), logging.getLogger("dlt")):
            log.setLevel(level)
            for handler in log.handlers:
                handler.setLevel(level)

    install_filter()


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
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Verbose output (INFO level)."),
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
    return collector.run(src)


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
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Verbose output (INFO level)."),
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
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Verbose output (INFO level)."),
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
