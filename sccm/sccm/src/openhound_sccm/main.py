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
    "ldaps": "SOURCES__SCCM__USE_SSL",
    "ldap_start_tls": "SOURCES__SCCM__LDAP_START_TLS",
    "ldap_signing": "SOURCES__SCCM__LDAP_SIGNING",
    "ldap_channel_binding": "SOURCES__SCCM__LDAP_CHANNEL_BINDING",
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


def _apply_verbose(verbose: bool) -> None:
    """Bump logging to DEBUG when ``-v`` / ``--verbose`` is set."""
    if verbose:
        os.environ.setdefault("OPENHOUND_LOG_LEVEL", "DEBUG")
        logging.getLogger().setLevel(logging.DEBUG)


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
    domain: Optional[str] = typer.Option(None, "-d", "--domain", help="Domain (e.g. mayyhem.com)."),
    domain_controller: Optional[str] = typer.Option(None, "-dc", "--domain-controller", help="DC hostname or IP."),
    username: Optional[str] = typer.Option(None, "-u", "--username", help="DOMAIN\\\\user for explicit auth."),
    password: Optional[str] = typer.Option(None, "-p", "--password", help="Password for explicit auth."),
    ldap_port: Optional[int] = typer.Option(None, "--ldap-port", help="LDAP port (default 389; 636 for LDAPS)."),
    ldaps: bool = typer.Option(False, "--ldaps", help="Use LDAPS (SSL)."),
    ldap_start_tls: bool = typer.Option(False, "--ldap-start-tls", help="Upgrade LDAP to TLS before binding (mutually exclusive with --ldaps)."),
    ldap_signing: str = typer.Option("auto", "-ls", "--ldap-signing", help="NTLM LDAP signing/sealing: auto (retry on strongerAuthRequired), required, or disabled."),
    ldap_channel_binding: str = typer.Option("auto", "-cb", "--ldap-channel-binding", help="LDAP channel binding tokens over TLS: auto, required, or disabled."),
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
    # ---- General (CMBP -v / --verbose) ----
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Enable verbose (DEBUG-level) output."),
) -> Optional[LoadInfo]:
    _apply_verbose(verbose)
    _apply_env_overrides(locals())

    collector = Collector(name=app.name, output_path=output_path, resources=resources, progress=progress)
    app.collector = collect_sccm  # noqa: F841 — keep framework introspection happy
    ctx = CollectContext(pipeline=collector)
    from .source import source as sccm_source

    src = sccm_source()
    if not src:
        return None
    return collector.run(src)


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
    domain: Optional[str] = typer.Option(None, "-d", "--domain", help="Domain (e.g. mayyhem.com). Also accepts SOURCES__SCCM__DOMAIN."),
    domain_controller: Optional[str] = typer.Option(None, "-dc", "--domain-controller"),
    username: Optional[str] = typer.Option(None, "-u", "--username"),
    password: Optional[str] = typer.Option(None, "-p", "--password"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Enable verbose (DEBUG-level) output."),
) -> Optional[LoadInfo]:
    _apply_verbose(verbose)
    _apply_env_overrides(locals())

    preprocessor = PreProcessor(
        name=app.name,
        input_path=input_path,
        output_file=output_file,
        progress=progress,
        transformer=transforms,
    )
    app.preprocessor = preprocess_sccm  # noqa: F841

    resource_list = _preproc_table_map()
    return preprocessor.run(resources=resource_list)


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
        "mssql_logins",
        "mssql_databases",
        "mssql_database_users",
        "mssql_server_roles",
        "mssql_database_roles",
        "mssql_role_members",
        "mssql_linked_servers",
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
    domain: Optional[str] = typer.Option(None, "-d", "--domain", help="Domain (e.g. mayyhem.com). Also accepts SOURCES__SCCM__DOMAIN."),
    domain_controller: Optional[str] = typer.Option(None, "-dc", "--domain-controller"),
    username: Optional[str] = typer.Option(None, "-u", "--username"),
    password: Optional[str] = typer.Option(None, "-p", "--password"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Enable verbose (DEBUG-level) output."),
) -> Optional[LoadInfo]:
    import duckdb

    _apply_verbose(verbose)
    _apply_env_overrides(locals())

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
    app.converter = convert_sccm  # noqa: F841

    from .source import source as sccm_source

    src = sccm_source()
    return converter.run(
        src,
        graph_resources=app.assets,
        extra_context={},
    )


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
