import logging
import os
import pathlib
import threading

import dlt
import typer
from openhound.cli.collect import collect as _collect_typer  # noqa: E402

from typing import Optional

from openhound.core.app import (
    OpenHound,
    OutputPath,
)
from openhound.core.collect import Collector
from openhound.core.convert import ConvertContext
from openhound.core.preproc import PreProcContext
from .lookup import MSSQLLookup
from .transforms import transforms
from .convert_pipeline import emit_graph_from_duckdb

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OpenHound app instance. Owns `source_kind` (flows into the OpenGraph metadata
# block — MSSQLHound's `MSSQL_Base` so BloodHound ingest + the existing
# validators agree) plus the asset registry that `Converter.run` reads. We do
# NOT use the `@app.collect` convenience decorator: instead we register a richer
# Typer command on the framework's public `collect` group directly so we can add
# the full MSSQLHound-style CLI flag surface (spec §4).
# ---------------------------------------------------------------------------
app = OpenHound(
    "mssql",
    source_kind="MSSQL_Base",
    help="OpenGraph collector for Microsoft SQL Server attack paths",
)

# ---------------------------------------------------------------------------
# Flag -> env-var translation
# ---------------------------------------------------------------------------
# Every flag on `collect mssql` maps to a `SOURCES__MSSQL__*` env var. The Typer
# command sets the env var BEFORE the DLT source factory resolves its config, so
# the user can supply config equivalently via CLI flag, env var, or `.env` file.
# Flag values win because they're applied last (just before the framework's
# Collector is constructed). The two Kerberos-ticket params key to
# `KERBEROS_TICKET` / `LDAP_KERBEROS_TICKET` (mirrors SCCM's `kerberos_ticket`).
# ---------------------------------------------------------------------------
_FLAG_TO_ENV: dict[str, str] = {
    # Authentication — SQL
    "user": "SOURCES__MSSQL__USER",
    "password": "SOURCES__MSSQL__PASSWORD",
    "nt_hash": "SOURCES__MSSQL__NT_HASH",
    "kerberos_ticket": "SOURCES__MSSQL__KERBEROS_TICKET",
    # Authentication — LDAP/AD
    "ldap_user": "SOURCES__MSSQL__LDAP_USER",
    "ldap_password": "SOURCES__MSSQL__LDAP_PASSWORD",
    "ldap_nt_hash": "SOURCES__MSSQL__LDAP_NT_HASH",
    "ldap_kerberos_ticket": "SOURCES__MSSQL__LDAP_KERBEROS_TICKET",
    # Connection / Collection
    "targets": "SOURCES__MSSQL__TARGETS",
    "domain": "SOURCES__MSSQL__DOMAIN",
    "domain_controller": "SOURCES__MSSQL__DC",
    "dns_resolver": "SOURCES__MSSQL__DNS_RESOLVER",
    "proxy": "SOURCES__MSSQL__PROXY",
    # Collection toggles
    "scan_all_computers": "SOURCES__MSSQL__SCAN_ALL_COMPUTERS",
    "scan_all_computer_ports": "SOURCES__MSSQL__SCAN_ALL_COMPUTER_PORTS",
    "skip_private_address": "SOURCES__MSSQL__SKIP_PRIVATE_ADDRESS",
    "domain_enum_only": "SOURCES__MSSQL__DOMAIN_ENUM_ONLY",
    "skip_linked_servers": "SOURCES__MSSQL__SKIP_LINKED_SERVERS",
    "collect_from_linked": "SOURCES__MSSQL__COLLECT_FROM_LINKED",
    "skip_ad_nodes": "SOURCES__MSSQL__SKIP_AD_NODES",
    "disable_nontraversable_edges": "SOURCES__MSSQL__DISABLE_NONTRAVERSABLE_EDGES",
    "disable_possible_edges": "SOURCES__MSSQL__DISABLE_POSSIBLE_EDGES",
    "skip_ip_dedupe": "SOURCES__MSSQL__SKIP_IP_DEDUPE",
    # Performance
    "linked_timeout": "SOURCES__MSSQL__LINKED_TIMEOUT",
    "port_check_timeout": "SOURCES__MSSQL__PORT_CHECK_TIMEOUT",
    "memory_threshold": "SOURCES__MSSQL__MEMORY_THRESHOLD",
    "workers": "SOURCES__MSSQL__WORKERS",
    # Output
    "temp_dir": "SOURCES__MSSQL__TEMP_DIR",
    "log_per_target": "SOURCES__MSSQL__LOG_PER_TARGET",
}

# Env vars dlt parses as non-string types. dlt chokes on an empty string for an
# int/bool field, so we drop those when blank (in addition to all blank flags).
_TYPED_DLT_ENV = {
    "SOURCES__MSSQL__SCAN_ALL_COMPUTER_PORTS",
    "SOURCES__MSSQL__LINKED_TIMEOUT",
    "SOURCES__MSSQL__PORT_CHECK_TIMEOUT",
    "SOURCES__MSSQL__MEMORY_THRESHOLD",
    "SOURCES__MSSQL__WORKERS",
    "SOURCES__MSSQL__SCAN_ALL_COMPUTERS",
    "SOURCES__MSSQL__SKIP_PRIVATE_ADDRESS",
    "SOURCES__MSSQL__DOMAIN_ENUM_ONLY",
    "SOURCES__MSSQL__SKIP_LINKED_SERVERS",
    "SOURCES__MSSQL__COLLECT_FROM_LINKED",
    "SOURCES__MSSQL__SKIP_AD_NODES",
    "SOURCES__MSSQL__DISABLE_NONTRAVERSABLE_EDGES",
    "SOURCES__MSSQL__DISABLE_POSSIBLE_EDGES",
    "SOURCES__MSSQL__SKIP_IP_DEDUPE",
    "SOURCES__MSSQL__LOG_PER_TARGET",
}


def _drop_empty_dlt_env_values() -> None:
    """Remove blank env vars so they don't shadow a real config value.

    A flag left unset can serialise to ``""`` via `_apply_env_overrides`; an
    empty string would override a higher-priority env-var or `.env` entry (and
    breaks dlt's int/bool parsing). Drop any blank entry.
    """
    for env_name in _FLAG_TO_ENV.values():
        if os.environ.get(env_name) == "":
            os.environ.pop(env_name, None)

    for env_name in _TYPED_DLT_ENV:
        value = os.environ.get(env_name)
        if value is not None and value.strip() == "":
            os.environ.pop(env_name, None)


def _apply_env_overrides(flag_kwargs: dict) -> None:
    """Map CLI flag values to ``SOURCES__MSSQL__*`` env vars.

    Skips values that are ``None`` or default-``False`` so a flag that wasn't
    passed doesn't overwrite a higher-priority env-var or ``.env`` entry.
    Booleans serialise as ``"true"`` (only when set); paths serialise via
    ``str()``; everything else via ``str()``.
    """
    for flag_name, env_name in _FLAG_TO_ENV.items():
        if flag_name not in flag_kwargs:
            # Flag not present in this invocation's locals — nothing to map.
            continue
        value = flag_kwargs[flag_name]
        if value is None:
            # Unset optional flag: leave any env/.env value untouched.
            continue
        if isinstance(value, bool):
            if not value:
                # Default-False switch: don't write "false" over a real value.
                continue
            os.environ[env_name] = "true"
        elif isinstance(value, pathlib.Path):
            os.environ[env_name] = str(value)
        else:
            os.environ[env_name] = str(value)


def _apply_log_level(verbose: int, debug: bool) -> None:
    """Adjust console logging from the verbosity flags.

    ``--debug`` -> DEBUG (everything, incl. dlt/ldap3 internals).
    ``-v`` (or any ``verbose``) -> INFO (collection-step summaries).
    (no flags) -> leave the framework's default level in place.

    Stage 0 keeps logging on the stdlib ``logging`` module only — the VERBOSE
    tier and ``[target]`` contextvar tagging arrive in a later stage. We set the
    framework's ``RUNTIME__LOG_*`` env vars (read by ``openhound/core/logging``)
    and lower existing handler levels so records of the requested level reach
    the console.
    """
    if debug:
        level_name, level = "DEBUG", logging.DEBUG
    elif verbose >= 1:
        level_name, level = "INFO", logging.INFO
    else:
        # No verbosity flag: defer entirely to the framework's default config.
        return

    os.environ["RUNTIME__LOG_LEVEL"] = level_name
    os.environ["RUNTIME__LOG_CLI_LEVEL"] = level_name
    root = logging.getLogger()
    # Lower the root logger so records of the requested level can reach any
    # handler. (A level of 0 means "unset / inherit".)
    if root.level == 0 or root.level > level:
        root.setLevel(level)
    for log in (root, logging.getLogger("dlt")):
        for handler in log.handlers:
            if handler.level == 0 or handler.level > level:
                handler.setLevel(level)


def _validate_auth_exclusions(
    user: Optional[str],
    password: Optional[str],
    nt_hash: Optional[str],
    ticket: Optional[str],
    ldap_user: Optional[str],
    ldap_password: Optional[str],
    ldap_nt_hash: Optional[str],
    ldap_ticket: Optional[str],
) -> None:
    """Reject mutually-exclusive auth-secret combinations (spec §4).

    A principal may present at most one secret. SQL: ``--nt-hash`` xor
    ``--password``, ``--ticket`` xor ``--password``, ``--ticket`` xor
    ``--nt-hash``. LDAP: the same three with the ``ldap-`` prefix. Raising
    ``typer.BadParameter`` produces a clean CLI error (no traceback).
    """
    # SQL secret exclusions.
    if password and nt_hash:
        raise typer.BadParameter("--password and --nt-hash are mutually exclusive.", param_hint="--nt-hash")
    if password and ticket:
        raise typer.BadParameter("--password and --ticket are mutually exclusive.", param_hint="--ticket")
    if nt_hash and ticket:
        raise typer.BadParameter("--nt-hash and --ticket are mutually exclusive.", param_hint="--ticket")

    # LDAP secret exclusions.
    if ldap_password and ldap_nt_hash:
        raise typer.BadParameter("--ldap-password and --ldap-nt-hash are mutually exclusive.", param_hint="--ldap-nt-hash")
    if ldap_password and ldap_ticket:
        raise typer.BadParameter("--ldap-password and --ldap-ticket are mutually exclusive.", param_hint="--ldap-ticket")
    if ldap_nt_hash and ldap_ticket:
        raise typer.BadParameter("--ldap-nt-hash and --ldap-ticket are mutually exclusive.", param_hint="--ldap-ticket")


def _run_collection(output_path: pathlib.Path) -> None:
    """Run the per-target SQL collection and stream raw JSONL to *output_path*.

    The flow mirrors the SCCM extension's per-host stage, minus the multi-phase
    machinery (MSSQL has a single per-target step):

    1. Build the run config from the ``SOURCES__MSSQL__*`` env vars the CLI set.
    2. Resolve the target list (explicit / list / file / SPN-enum / scan-all)
       via :func:`resolve_targets`, using the LDAP credentials.
    3. Build a :class:`StreamBridge` over the canonical table set and install it
       so ``source()``'s emit resources drain the same queues the workers fill.
    4. Run the worker pool (:func:`collect_targets`) on a *background* thread: it
       connects to each target, runs ``collect_server``, and pushes rows onto the
       bridge, then broadcasts ``DONE`` at quiescence.
    5. On *this* thread, run the DLT extract pass (``collector.run(source())``),
       which drains the queues and writes one JSONL table per emit resource.
       :func:`extract_workers_for` raises DLT's worker cap to one-per-table so the
       blocking emit resources don't deadlock.

    The ``finally`` block joins the producer thread while draining the queues, so
    a crash in the extract pass can never leave a worker wedged on a full queue
    (it would otherwise block forever and ``join`` would hang).
    """
    from openhound_collector_common.dlt.source_bridge import StreamBridge, extract_workers_for

    from .auth import CollectionConfig, build_ldap_auth
    from .collection.run import collect_targets
    from .collection.targets import resolve_targets
    from . import source as _source
    from .source import COLLECTED_TABLES, source as mssql_source

    cfg = CollectionConfig.from_env()

    # 2) Resolve targets. A resolution error here is fatal (no work to do); a
    # single unreachable target is handled per-target inside the worker pool.
    try:
        ldap_auth = build_ldap_auth(cfg)
        targets = resolve_targets(cfg, ldap_auth)
    except Exception as ex:  # noqa: BLE001 - surface a clean message, no traceback spam
        logger.error("Target resolution failed: %s", ex)
        return
    if not targets:
        logger.warning("No targets resolved; nothing to collect")
        return
    logger.info("Collecting %d target(s) into %s", len(targets), output_path)

    # 3) Bridge + emit-resource handoff.
    bridge = StreamBridge(COLLECTED_TABLES)
    _source.set_bridge(bridge)

    # 4) Producer on a background thread.
    def _producer() -> None:
        collect_targets(targets, cfg, bridge)

    pool_thread = threading.Thread(target=_producer, name="mssql-collect-pool", daemon=True)
    collector = Collector(name=app.name, output_path=output_path)

    pool_thread.start()
    try:
        # 5) Extract pass drains the queues and writes JSONL. One DLT worker per
        # table (each emit resource blocks until DONE) avoids the bounded-queue
        # deadlock.
        with extract_workers_for(len(COLLECTED_TABLES)):
            load_info = collector.run(mssql_source())
        logger.info("Collection load complete: %s", _summarize_load(load_info))
    finally:
        # Await the producer. If the extract pass raised, the emit resources
        # stopped draining, so a worker may be blocked on a full queue; drain the
        # queues until the producer finishes so join() can never hang. No-op on
        # the success path (queues already drained, DONE already broadcast).
        while pool_thread.is_alive():
            bridge.drain_to_unblock()
            pool_thread.join(timeout=0.1)
        _source.set_bridge(None)


def _summarize_load(load_info) -> str:
    """Best-effort one-line summary of a DLT LoadInfo for the success log."""
    try:
        return str(load_info)
    except Exception:  # noqa: BLE001 - logging convenience only
        return "<load complete>"


# ---------------------------------------------------------------------------
# `openhound collect mssql ...` — full MSSQLHound-style flag surface (spec §4)
# ---------------------------------------------------------------------------
@_collect_typer.command(
    name="mssql",
    help="Collect Microsoft SQL Server attack-path data. Accepts MSSQLHound-style flags or SOURCES__MSSQL__* env vars.",
)
def collect_mssql(
    # ---- standard framework argument ----
    output_path: OutputPath,
    # ---- Authentication — SQL ----
    user: Optional[str] = typer.Option(None, "-u", "--user", help="SQL/Windows login (DOMAIN\\\\user for domain auth, or a SQL login name).", rich_help_panel="Authentication — SQL"),
    password: Optional[str] = typer.Option(None, "-p", "--password", help="Password for the SQL/Windows login.", rich_help_panel="Authentication — SQL"),
    nt_hash: Optional[str] = typer.Option(None, "--nt-hash", help="NT hash for pass-the-hash auth (bare 32-hex NT hash; LM half assumed empty). Mutually exclusive with --password / --ticket.", rich_help_panel="Authentication — SQL"),
    ticket: Optional[str] = typer.Option(None, "--ticket", help="Base64-encoded Kerberos ticket (.kirbi / KRB-CRED) for pass-the-ticket. Kerberos only, no NTLM fallback. Mutually exclusive with --password / --nt-hash.", rich_help_panel="Authentication — SQL"),
    # ---- Authentication — LDAP/AD ----
    ldap_user: Optional[str] = typer.Option(None, "--ldap-user", help="LDAP/AD login for SPN discovery, SID resolution, EPA testing. Falls back to the SQL login when domain-shaped and unset.", rich_help_panel="Authentication — LDAP/AD"),
    ldap_password: Optional[str] = typer.Option(None, "--ldap-password", help="Password for the LDAP/AD login. Mutually exclusive with --ldap-nt-hash / --ldap-ticket.", rich_help_panel="Authentication — LDAP/AD"),
    ldap_nt_hash: Optional[str] = typer.Option(None, "--ldap-nt-hash", help="NT hash for LDAP/AD pass-the-hash auth. Mutually exclusive with --ldap-password / --ldap-ticket.", rich_help_panel="Authentication — LDAP/AD"),
    ldap_ticket: Optional[str] = typer.Option(None, "--ldap-ticket", help="Base64-encoded Kerberos ticket (.kirbi / KRB-CRED) for LDAP/AD pass-the-ticket. Mutually exclusive with --ldap-password / --ldap-nt-hash.", rich_help_panel="Authentication — LDAP/AD"),
    # ---- Connection / Collection ----
    targets: Optional[str] = typer.Option(None, "-t", "--targets", help="Target(s): [user:pass@]host | host:port | host\\\\instance | MSSQLSvc/host:port | comma-list | file path. Empty => SPN enumeration via LDAP.", rich_help_panel="Connection / Collection"),
    domain: Optional[str] = typer.Option(None, "-d", "--domain", help="AD domain (e.g. mayyhem.com). On Windows, auto-detected from the current user context; elsewhere required for AD operations.", rich_help_panel="Connection / Collection"),
    domain_controller: Optional[str] = typer.Option(None, "--dc", help="DC hostname or IP. If omitted, resolved from --domain via DNS SRV (_ldap._tcp) then A record.", rich_help_panel="Connection / Collection"),
    dns_resolver: Optional[str] = typer.Option(None, "--dns-resolver", help="DNS nameserver IP for all lookups (DC discovery, SPN/SRV probes). Omit to use the system default.", rich_help_panel="Connection / Collection"),
    proxy: Optional[str] = typer.Option(None, "-x", "--proxy", help="SOCKS5 proxy (socks5://[user:pass@]host:port) for all TCP connections.", rich_help_panel="Connection / Collection"),
    # ---- Collection toggles ----
    scan_all_computers: bool = typer.Option(False, "-A", "--scan-all-computers", help="Enumerate every AD computer object and probe it for SQL Server (objectClass=computer).", rich_help_panel="Collection toggles"),
    scan_all_computer_ports: str = typer.Option("1433", "--scan-all-computer-ports", help="Comma-separated TCP ports to probe under --scan-all-computers (default 1433).", rich_help_panel="Collection toggles"),
    skip_private_address: bool = typer.Option(False, "--skip-private-address", help="Skip targets that resolve to RFC1918 / private addresses.", rich_help_panel="Collection toggles"),
    domain_enum_only: bool = typer.Option(False, "--domain-enum-only", help="Only enumerate SQL Servers via SPN discovery; do not connect or collect.", rich_help_panel="Collection toggles"),
    skip_linked_servers: bool = typer.Option(False, "--skip-linked-servers", help="Do not enumerate linked servers.", rich_help_panel="Collection toggles"),
    collect_from_linked: bool = typer.Option(False, "--collect-from-linked", help="Enqueue discovered linked servers as new targets and collect from them.", rich_help_panel="Collection toggles"),
    skip_ad_nodes: bool = typer.Option(False, "--skip-ad-nodes", help="Do not create AD (Computer/Group/User) nodes.", rich_help_panel="Collection toggles"),
    disable_nontraversable_edges: bool = typer.Option(False, "--disable-nontraversable-edges", help="Omit non-traversable edges (Alter/Control/Impersonate/Connect/... informational edges).", rich_help_panel="Collection toggles"),
    disable_possible_edges: bool = typer.Option(False, "--disable-possible-edges", help="Mark uncertain/possible edges (LinkedTo, IsTrustedBy, ServiceAccountFor, *Cred) non-traversable.", rich_help_panel="Collection toggles"),
    skip_ip_dedupe: bool = typer.Option(False, "--skip-ip-dedupe", help="Do not de-duplicate targets that resolve to the same IP.", rich_help_panel="Collection toggles"),
    # ---- Performance ----
    linked_timeout: int = typer.Option(300, "--linked-timeout", help="Per-target timeout (seconds) for linked-server enumeration (default 300).", rich_help_panel="Performance"),
    port_check_timeout: int = typer.Option(2, "--port-check-timeout", help="TCP port-reachability check timeout in seconds (default 2).", rich_help_panel="Performance"),
    memory_threshold: int = typer.Option(90, "--memory-threshold", help="Pause spawning new workers above this memory-usage percentage (default 90).", rich_help_panel="Performance"),
    workers: int = typer.Option(0, "-w", "--workers", help="Number of targets collected concurrently. 0 = sequential (default).", rich_help_panel="Performance"),
    # ---- Output ----
    temp_dir: Optional[pathlib.Path] = typer.Option(None, "--temp-dir", help="Directory for scratch/intermediate files. Defaults to the system temp dir.", rich_help_panel="Output"),
    log_per_target: bool = typer.Option(False, "--log-per-target", help="Write a separate log file per target.", rich_help_panel="Output"),
    # ---- General ----
    verbose: int = typer.Option(0, "-v", "--verbose", count=True, help="Verbose output (INFO level: collection-step summaries)."),
    debug: bool = typer.Option(False, "--debug", help="Debug output (DEBUG level; very chatty, includes dlt and ldap3 internals)."),
) -> None:
    _validate_auth_exclusions(
        user, password, nt_hash, ticket,
        ldap_user, ldap_password, ldap_nt_hash, ldap_ticket,
    )
    _apply_log_level(verbose, debug)

    flag_kwargs = locals()
    # The Typer params are `ticket` / `ldap_ticket`; the env map keys them as
    # `kerberos_ticket` / `ldap_kerberos_ticket` (mirrors SCCM's --ticket key).
    flag_kwargs["kerberos_ticket"] = flag_kwargs.pop("ticket", None)
    flag_kwargs["ldap_kerberos_ticket"] = flag_kwargs.pop("ldap_ticket", None)
    _apply_env_overrides(flag_kwargs)
    _drop_empty_dlt_env_values()

    # Stage 0: collection is a stub. Real per-target SQL collection (target
    # discovery, connect/EPA, .ps1-ordered queries, push->pull bridge) lands in
    # Stage 3.
    _run_collection(output_path)


# Set at module scope so `CollectorManager.validate_extension` (which runs at
# import time, before any command is invoked) sees a non-None hook. The
# `@app.collect()` convenience decorator would do this for us, but we register
# directly on the framework's Typer group to keep the MSSQLHound-style flags.
app.collector = collect_mssql


@app.preproc(transformer=transforms)
def preproc(ctx: PreProcContext) -> dict[str, str]:
    """Load the raw MSSQL JSONL into DuckDB, then build the derived lookup tables.

    The returned ``{duckdb_table_name: jsonl_subpath}`` map tells the framework
    which raw tables to load into the ``mssql`` schema (only listed tables are
    loaded). dlt's collect pass writes each table's JSONL under
    ``<bucket>/<dataset>/<table>/`` and the dataset name is the source name
    (``mssql``), so each subpath is ``mssql/<table>`` (the framework globs
    ``**/*.jsonl.gz`` beneath it). Every table ``collect_server`` yields
    (``source.COLLECTED_TABLES``) is loaded under its own name so the convert
    stage can read both the raw rows and the tables ``transforms()`` derives from
    them (principal maps, role closures, effective high-priv, fixed-role
    permissions, linked-server flags).
    """
    from .source import COLLECTED_TABLES

    table_map = {table: f"{app.name}/{table}" for table in COLLECTED_TABLES}
    logger.debug("preproc: loading %d raw table(s) into the lookup DuckDB", len(table_map))
    return table_map


@dlt.source(name="mssql_convert_noop")
def _noop_convert_source():
    """A source with no graph-resource models.

    All real emission happens in the convert-reads-DuckDB pipeline
    (`emit_graph_from_duckdb`, run inside `convert` below), so the source we hand
    the framework carries nothing — `Converter.run` finds no models and its own
    pipeline is a no-op. `opengraph_file` appends uniquely-numbered files, so the
    two pipelines writing to the same output dir never collide. Mirrors SCCM.
    """

    @dlt.resource(name="_noop")
    def _empty():
        return
        yield  # unreachable; makes _empty a generator that yields nothing

    return _empty


@app.convert(lookup=MSSQLLookup)
def convert(ctx: ConvertContext):
    """Emit the MSSQL graph by reading the preproc DuckDB directly (convert-reads-
    DuckDB), then hand the framework a no-op source.

    `NODE_SPECS` / `EDGE_SPECS` (defined at the bottom of this module, after `app`
    so the model imports don't cause a circular import) are the
    `(raw_table, AssetClass)` pairs the convert pipeline iterates. Each asset's
    `as_node` / `edges` enrich from the preproc-derived tables via `ctx.lookup`.
    Stage 6 edges are emitted from the preproc-built `graph_edges` table via the
    `("graph_edges", GraphEdge)` edge spec (SCCM-proven pattern) — no convert-time
    edge derivation.
    """
    node_specs, edge_specs = _convert_specs()
    emit_graph_from_duckdb(
        ctx.lookup, ctx.output_path, app.source_kind,
        node_specs, edge_specs,
    )
    return _noop_convert_source(), {}


def _convert_specs() -> tuple[list[tuple[str, type]], list[tuple[str, type]]]:
    """Build the `(raw_table, AssetClass)` specs the convert pipeline iterates.

    The model modules do `from ..main import app` for their `@app.asset(...)`
    registration, so importing the asset classes at module top here would be a
    circular import. We import them lazily (convert runs long after both modules
    are fully loaded). MSSQL_ServerRole / MSSQL_DatabaseRole / MSSQL_ApplicationRole
    are emitted by the *principal* assets (they switch on `type_desc`), so only the
    four table-backed assets appear. The Stage-7a AD nodes (Computer/User/Group +
    Base) come from the preproc-built `ad_nodes` table via the plain `ADNode` asset
    (no NodeDef — AD kinds carry no icon). The Stage-6 edge set is emitted from the
    preproc-built `graph_edges` table via the shared `GraphEdge` model. The
    AD/linked/cred/Kerberos edges arrive in Stage 7b.
    """
    from .models.server import MSSQLServer
    from .models.server_principal import MSSQLServerPrincipal
    from .models.database import MSSQLDatabase
    from .models.database_principal import MSSQLDatabasePrincipal
    from .models.ad_node import ADNode
    from .models.linked_server_node import LinkedServerStubNode
    from .models.graph_edge import GraphEdge

    node_specs: list[tuple[str, type]] = [
        ("servers", MSSQLServer),
        ("server_principals", MSSQLServerPrincipal),
        ("databases", MSSQLDatabase),
        ("database_principals", MSSQLDatabasePrincipal),
        # Stage 7a: AD nodes from the preproc ad_nodes table (empty when
        # --skip-ad-nodes builds the table empty, so this spec stays harmless).
        ("ad_nodes", ADNode),
        # Stage 7b: foreign linked-server stub MSSQL_Server nodes (e.g. CAS-DB),
        # from the preproc linked_server_targets table (empty when no foreign links).
        ("linked_server_targets", LinkedServerStubNode),
    ]
    edge_specs: list[tuple[str, type]] = [
        ("graph_edges", GraphEdge),
    ]
    return node_specs, edge_specs


# Register the node assets (NodeDefs) for the catalog/docs + conformance tests.
# A package-level `from . import models` is cycle-safe (module bind, not a name
# bind on a partially-initialized module): models/__init__ imports the submodules,
# each of which does `from ..main import app` — `app` is defined above, so it
# resolves whether main or models is imported first.
from . import models  # noqa: E402,F401
