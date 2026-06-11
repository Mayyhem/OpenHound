"""DuckDB SQL transforms run during the preproc phase.

This file is the SQL counterpart to ``ConfigManBearPig/python/lib/post_processing.py``.
Where the original mutates an in-memory ``GraphStore`` by computing derived edges from
the union of all phase outputs, here we materialise *tables* of derived rows that the
``models/derived/*`` edge-only ``BaseAsset`` classes will read from at convert time.

The SQL is intentionally defensive about missing tables — preproc may run with only a
subset of phases having produced output (e.g. an LDAP-only collection, or a low-priv
user who couldn't reach AdminService). Each ``CREATE OR REPLACE`` is wrapped to be
idempotent and tolerant of empty inputs.

Tables produced (referenced by ``models/derived/*`` and ``lookup.py``):
  - sccm.targets                            — union of all phase-discovered hostnames
  - sccm.site_types                         — derived (site_code, site_type, parent_code)
  - sccm.hierarchies                        — recursive (root_code, member_code) pairs
  - sccm.admins_replicated_to_edges         — bidirectional CAS<->Primary, unidirectional Primary->Secondary
  - sccm.contains_edges                     — non-secondary site -> global object
  - sccm.role_assignment_edges              — admin user -> client device per security role
  - sccm.all_permissions_edges              — Full Admin with all collections -> all sites
  - sccm.same_host_as_edges                 — SCCM_ClientDevice <-> Computer (bidirectional)
  - sccm.local_admin_required_edges         — site server -> co-located site systems
  - sccm.assign_all_permissions_edges       — SMS Provider / site DB -> primary sites
  - sccm.mssql_sysadmin_edges               — site-server / SMS-provider sysadmin facts
  - sccm.coerce_and_relay_edges             — Authenticated Users -> AdminService/MSSQL/SMB targets
  - sccm.mssql_gettgs_edges                 — MSSQL service account -> domain logins
  - sccm.secret_policy_edges                — collected NAA / stored-account / collection-var secrets

Implementation notes
============================
The original CMBP ``post_processing.py`` runs in a stateful Python in-memory graph
(``GraphStore``); we deliberately expose each derived edge category as its own
DuckDB table so that:

  1. Each table is unit-testable (``CREATE TABLE ... AS SELECT`` is reproducible).
  2. The convert-time fan-out is a simple ``SELECT *`` on the table.
  3. Missing upstream data degrades gracefully — we ``CREATE OR REPLACE TABLE foo
     (start_id VARCHAR, end_id VARCHAR, ...)`` with the right schema even if no
     rows are produced, so the consumer model never crashes.
"""


from __future__ import annotations

import logging

import duckdb

logger = logging.getLogger(__name__)


def _table_exists(con: duckdb.DuckDBPyConnection, schema: str, table: str) -> bool:
    res = con.execute(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = ? AND table_name = ?",
        [schema, table],
    ).fetchone()
    return bool(res and res[0])


def _column_exists(con: duckdb.DuckDBPyConnection, schema: str, table: str, column: str) -> bool:
    res = con.execute(
        "SELECT COUNT(*) FROM information_schema.columns "
        "WHERE table_schema = ? AND table_name = ? AND column_name = ?",
        [schema, table, column],
    ).fetchone()
    return bool(res and res[0])


def _safe_exec(con: duckdb.DuckDBPyConnection, sql: str, label: str) -> None:
    try:
        con.execute(sql)
    except Exception as exc:
        logger.warning("transform %s skipped: %s", label, exc)


# ---------------------------------------------------------------------------
# Schema for each derived edge table (used to create empty placeholders so
# convert-time consumers always have something to SELECT against).
# ---------------------------------------------------------------------------
_EMPTY_SCHEMAS: dict[str, str] = {
    "site_types": "(site_code VARCHAR, site_type VARCHAR, parent_site_code VARCHAR)",
    "hierarchies": "(root_code VARCHAR, member_code VARCHAR)",
    "computer_mp_roles": "(hostname VARCHAR, role VARCHAR, site_code VARCHAR)",
    "computer_fsp_roles": "(hostname VARCHAR, role VARCHAR, site_code VARCHAR)",
    "computer_site_system_roles": "(hostname VARCHAR, role VARCHAR, site_code VARCHAR)",
}


def _ensure_empty(con: duckdb.DuckDBPyConnection, schema: str, table: str) -> None:
    cols = _EMPTY_SCHEMAS.get(table, "(start_id VARCHAR, end_id VARCHAR)")
    con.execute(f"CREATE OR REPLACE TABLE {schema}.{table} {cols}")


# ---------------------------------------------------------------------------
# Convert-time lookup precomputation views.
# These materialise multi-table UNION / JOIN logic that ``lookup.py`` used to
# perform per-call, so each ``SCCMLookup`` method is a single-key
# ``WHERE ... = ?`` query.
# ---------------------------------------------------------------------------
def _build_computer_sccm_infra(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Pre-compute the per-host union behind ``SCCMLookup.computer_is_sccm_infra``.

    Each contributing source table marks a hostname (and where available a SID)
    as SCCM-infrastructure. The view holds three columns:
        hostname_low   — full lower-cased hostname (NULL for SID-only rows)
        hostname_short — short lower-cased hostname (NULL for SID-only rows)
        object_sid     — lower-cased SID (NULL for hostname-only rows)
    The lookup method is then a single indexed ``SELECT 1 ... WHERE ...`` query.
    """
    parts: list[str] = []
    for table in (
        "smb_site_servers",
        "smb_distribution_points",
        "http_management_points",
        "http_smsproviders",
        "http_distribution_points",
    ):
        if _table_exists(con, schema, table) and _column_exists(con, schema, table, "hostname"):
            parts.append(
                f"SELECT LOWER(hostname) AS hostname_low, "
                f"LOWER(SPLIT_PART(hostname, '.', 1)) AS hostname_short, "
                f"CAST(NULL AS VARCHAR) AS object_sid "
                f"FROM {schema}.{table} WHERE hostname IS NOT NULL AND hostname <> ''"
            )
    if _table_exists(con, schema, "ldap_sms_providers") and _column_exists(con, schema, "ldap_sms_providers", "object_sid"):
        parts.append(
            f"SELECT CAST(NULL AS VARCHAR) AS hostname_low, CAST(NULL AS VARCHAR) AS hostname_short, LOWER(object_sid) AS object_sid "
            f"FROM {schema}.ldap_sms_providers WHERE object_sid IS NOT NULL AND object_sid <> ''"
        )
    if _table_exists(con, schema, "adminservice_r_system") and _column_exists(
        con, schema, "adminservice_r_system", "machine_name"
    ):
        # SMS_R_System matches on short hostname (no FQDN), so hostname_low is NULL.
        parts.append(
            f"SELECT CAST(NULL AS VARCHAR) AS hostname_low, LOWER(machine_name) AS hostname_short, CAST(NULL AS VARCHAR) AS object_sid "
            f"FROM {schema}.adminservice_r_system "
            f"WHERE machine_name IS NOT NULL AND machine_name <> ''"
        )
    if not parts:
        con.execute(
            f"CREATE OR REPLACE TABLE {schema}.computer_sccm_infra "
            "(hostname_low VARCHAR, hostname_short VARCHAR, object_sid VARCHAR)"
        )
        return
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.computer_sccm_infra AS {' UNION ALL '.join(parts)}"
    )



def _build_site_types(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    if not _table_exists(con, schema, "ldap_management_points_raw"):
        _ensure_empty(con, schema, "site_types")
        return
    _safe_exec(
        con,
        f"""CREATE OR REPLACE TABLE {schema}.site_types AS
            SELECT site_code, site_type, parent_site_code
            FROM {schema}.ldap_management_points_raw
            WHERE site_code IS NOT NULL""",
        "site_types",
    )


def _build_computer_mp_roles(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    if not _table_exists(con, schema, "ldap_management_points_raw"):
        _ensure_empty(con, schema, "computer_mp_roles")
        return
    _safe_exec(
        con,
        f"""CREATE OR REPLACE TABLE {schema}.computer_mp_roles AS
            SELECT
                mp_hostname AS hostname,
                'SMS Management Point@' || site_code AS role,
                site_code
            FROM {schema}.ldap_management_points_raw
            WHERE mp_hostname IS NOT NULL AND site_code IS NOT NULL""",
        "computer_mp_roles",
    )


def _build_computer_fsp_roles(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    if not _table_exists(con, schema, "ldap_management_points_raw"):
        _ensure_empty(con, schema, "computer_fsp_roles")
        return
    _safe_exec(
        con,
        f"""CREATE OR REPLACE TABLE {schema}.computer_fsp_roles AS
            SELECT
                fsp_hostname AS hostname,
                'SMS Fallback Status Point@' || site_code AS role,
                site_code
            FROM {schema}.ldap_management_points_raw
            WHERE fsp_hostname IS NOT NULL""",
        "computer_fsp_roles",
    )


def _build_computer_site_system_roles(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    parts: list[str] = []
    for table in ("computer_mp_roles", "computer_fsp_roles"):
        if _table_exists(con, schema, table):
            parts.append(
                f"SELECT hostname, role, site_code FROM {schema}.{table}"
            )
    if not parts:
        _ensure_empty(con, schema, "computer_site_system_roles")
        return
    _safe_exec(
        con,
        f"CREATE OR REPLACE TABLE {schema}.computer_site_system_roles AS "
        + " UNION ALL ".join(parts),
        "computer_site_system_roles",
    )


def transforms(con: duckdb.DuckDBPyConnection, schema: str = "sccm") -> None:
    """Apply all preprocessing transformations to the DuckDB lookup database.

    Args:
        con: The DuckDB connection to use for creating computed tables.
        schema: The DuckDB schema name containing the source tables.
    """
    _build_site_types(con, schema)
    _build_computer_mp_roles(con, schema)
    _build_computer_fsp_roles(con, schema)
    _build_computer_site_system_roles(con, schema)
    _build_computer_sccm_infra(con, schema)
