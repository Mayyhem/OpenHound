"""Entry point for the OpenHound SCCM extension.

Registers the OpenHound `app` and the three pipeline phases (collect / preproc / convert),
plus a custom `package` Typer subcommand that wraps the convert output into a
BloodHound-compatible ZIP matching ConfigManBearPig's 5-file layout.
"""

from __future__ import annotations

import os
import pathlib
from typing import Optional

# Disable DLT anonymous telemetry before `dlt` is imported. The DLT-internal
# `dlt.config[...] = False` knob runs too late to suppress the telemetry HTTPS
# call because the pipeline takes a config snapshot at construction time.
os.environ.setdefault("RUNTIME__DLTHUB_TELEMETRY", "false")
os.environ.setdefault("DLT__RUNTIME__DLTHUB_TELEMETRY", "false")

import typer  # noqa: E402
from dlt.extract.source import DltSource  # noqa: E402
from openhound.core.app import OpenHound  # noqa: E402
from openhound.core.collect import CollectContext  # noqa: E402
from openhound.core.convert import ConvertContext  # noqa: E402
from openhound.core.preproc import PreProcContext  # noqa: E402

from .lookup import SCCMLookup
from .transforms import transforms

# Initialise the SCCM extension app.
# `source_kind` flows through to the OpenGraph metadata block (matches CMBP's
# `metadata.source_kind: "SCCM_Base"`).
app = OpenHound("sccm", source_kind="SCCM_Base", help="OpenGraph collector for Microsoft Endpoint Configuration Manager (SCCM)")


@app.collect()
def collect(ctx: CollectContext) -> DltSource:
    """Collect SCCM resources from LDAP, AdminService, MSSQL, WMI, etc., write JSONL to disk."""
    from .source import source as sccm_source

    return sccm_source()


@app.preproc(transformer=transforms)
def preproc(ctx: PreProcContext) -> dict[str, str]:
    """Build a DuckDB lookup database from collected JSONL.

    Maps DuckDB table name -> path under the input root where collect's JSONL lives.
    DLT's filesystem destination writes to `<input_root>/sccm/<table>/`, so each
    value here must include the `sccm/` dataset prefix. Only tables listed here are
    loaded into the lookup DB used by `convert`.

    Tables that aren't present yet (Phase 2/3 enrichment) are still listed so that as
    each future phase comes online, no main.py edit is needed — the resource_files
    source silently skips entries whose JSONL directory is missing.
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


@app.convert(lookup=SCCMLookup)
def convert(ctx: ConvertContext) -> tuple[DltSource, dict]:
    """Read JSONL + DuckDB lookup, emit OpenGraph nodes/edges to graph/sccm/*.json."""
    from .source import source as sccm_source

    return sccm_source(), {}


# ---------------------------------------------------------------------------
# Custom Typer subcommand: `package`
# ---------------------------------------------------------------------------
# OpenHound has no `post_convert` hook and the framework is read-only for this work,
# so we add our own packager as a sibling Typer subcommand. It consumes the OpenGraph
# `graph_dir` produced by `convert` and emits a `bloodhound-sccm-<ts>.zip` with the
# 5-file layout the existing ConfigManBearPig test runner expects.

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


# Wire the package command into the `openhound-sccm` Typer tree if invoked through main.
# The `openhound` CLI auto-discovers extensions; users normally run:
#     uv run src/main.py package --graph-dir graph/sccm
# which works because the openhound `collect`/`preproc`/`convert` Typer commands are
# registered globally above and `package_app` is reachable via the same module's CLI.
def cli() -> None:
    """Direct entry point for `python -m openhound_sccm.main package ...`."""
    package_app()


if __name__ == "__main__":
    cli()
