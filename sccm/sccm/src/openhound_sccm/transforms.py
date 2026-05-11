"""DuckDB SQL transforms run during the preproc phase.

This file is the SQL counterpart to ``sccm/ConfigManBearPig/python/lib/post_processing.py``.
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

Phase-4 implementation notes
============================
The original CMBP ``post_processing.py`` runs in a stateful Python in-memory graph
(``GraphStore``); we deliberately expose each derived edge category as its own
DuckDB table so that:

  1. Each table is unit-testable (``CREATE TABLE ... AS SELECT`` is reproducible).
  2. The convert-time fan-out is a simple ``SELECT *`` on the table.
  3. Missing upstream data degrades gracefully — we ``CREATE OR REPLACE TABLE foo
     (start_id VARCHAR, end_id VARCHAR, ...)`` with the right schema even if no
     rows are produced, so the consumer model never crashes.

Hierarchy detection (Risk 1 supplement)
---------------------------------------
``ldap_sites.parent_site_code`` and ``ldap_sites.site_type`` are *always* NULL in
our collected data (they're populated by AdminService payloads in CMBP, but the
new collector intentionally only emits site-codes from LDAP and tags site systems
separately). We therefore re-derive site type / parent from
``adminservice_site_systems`` evidence:

  * **CAS** = site has ``SMS Site Server`` AND ``SMS Provider`` AND NO
    ``SMS Management Point``.
  * **Primary** = site has ``SMS Site Server`` AND ``SMS Provider`` AND
    ``SMS Management Point``.
  * **Secondary** = site has ``SMS Site Server`` AND ``SMS Management Point``
    AND NO ``SMS Provider``.

  * **CAS parent** = none (it's the root).
  * **Primary parent** = the CAS in the same hierarchy (heuristic: the only CAS
    in the data, since multi-CAS environments are vanishingly rare in practice).
    If there's no CAS, the Primary is its own root.
  * **Secondary parent** = the Primary in the same hierarchy. We use
    ``adminservice_admins.source_site_code`` for further evidence when multiple
    primaries are present. If unresolvable, the Secondary is its own root.
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
    "admins_replicated_to_edges": "(start_id VARCHAR, end_id VARCHAR)",
    "contains_edges": "(start_id VARCHAR, end_id VARCHAR, end_kind VARCHAR)",
    "role_assignment_edges": "(start_id VARCHAR, end_id VARCHAR, edge_kind VARCHAR)",
    "all_permissions_edges": "(start_id VARCHAR, end_id VARCHAR)",
    "same_host_as_edges": "(start_id VARCHAR, end_id VARCHAR)",
    "local_admin_required_edges": "(start_id VARCHAR, end_id VARCHAR)",
    "assign_all_permissions_edges": "(start_id VARCHAR, end_id VARCHAR, collection_source VARCHAR)",
    "mssql_sysadmin_edges": (
        "(start_id VARCHAR, end_id VARCHAR, edge_kind VARCHAR, "
        "login_name VARCHAR, server_id VARCHAR, database_id VARCHAR, site_code VARCHAR, "
        "node_kind VARCHAR)"
    ),
    "mssql_server_hierarchy_edges": (
        "(start_id VARCHAR, end_id VARCHAR, edge_kind VARCHAR)"
    ),
    "coerce_and_relay_edges": (
        "(start_id VARCHAR, end_id VARCHAR, edge_kind VARCHAR, victim_fqdn VARCHAR, target_fqdn VARCHAR)"
    ),
    "mssql_gettgs_edges": "(start_id VARCHAR, end_id VARCHAR, edge_kind VARCHAR)",
    "secret_policy_edges": "(start_id VARCHAR, end_id VARCHAR, edge_kind VARCHAR)",
    # ----- Phase 6 additions -----
    "has_member_edges":     "(start_id VARCHAR, end_id VARCHAR)",
    "has_client_edges":     "(start_id VARCHAR, end_id VARCHAR, collection_source VARCHAR)",
    "client_user_edges":    "(start_id VARCHAR, end_id VARCHAR, edge_kind VARCHAR)",
    "is_assigned_edges":    "(start_id VARCHAR, end_id VARCHAR, collection_source VARCHAR)",
    "is_mapped_to_edges":   "(start_id VARCHAR, end_id VARCHAR, collection_source VARCHAR)",
    "r_system_member_of_edges": "(start_id VARCHAR, end_id VARCHAR)",
    "r_user_member_of_edges":   "(start_id VARCHAR, end_id VARCHAR)",
    "registry_has_session_edges": "(start_id VARCHAR, end_id VARCHAR)",
    "has_stored_account_edges":   "(start_id VARCHAR, end_id VARCHAR)",
}


def _ensure_empty(con: duckdb.DuckDBPyConnection, schema: str, table: str) -> None:
    cols = _EMPTY_SCHEMAS.get(table, "(start_id VARCHAR, end_id VARCHAR)")
    con.execute(f"CREATE OR REPLACE TABLE {schema}.{table} {cols}")


# ---------------------------------------------------------------------------
# Targets union (Phase 1+).
# ---------------------------------------------------------------------------

def _build_targets(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Union every host-yielding source table into ``sccm.targets`` with provenance."""
    sources = []
    for table, source, host_col in [
        ("ldap_computers", "LDAP", "dns_host_name"),
        ("local_management_points", "Local-MP", "hostname"),
        ("local_distribution_points", "Local-DP", "hostname"),
        ("dns_management_points", "DNS", "hostname"),
        ("dhcp_pxe_dps", "DHCP", "hostname"),
        ("registry_sccm_components", "Registry", "hostname"),
        ("mssql_epa_flags", "MSSQL", "hostname"),
        ("mssql_logins", "MSSQL-Auth", "hostname"),
        ("adminservice_client_devices", "AdminService", "hostname"),
        ("wmi_clients", "WMI-Client", "hostname"),
        ("wmi_users_seen", "WMI-UsersSeen", "hostname"),
        ("wmi_sql_service_accounts", "WMI-SqlSvc", "hostname"),
        ("http_management_points", "HTTP-MP", "hostname"),
        ("http_smsproviders", "HTTP-SMSProvider", "hostname"),
        ("http_distribution_points", "HTTP-DP", "hostname"),
        ("smb_site_servers", "SMB-SiteServer", "hostname"),
        ("smb_distribution_points", "SMB-DP", "hostname"),
        ("smb_signing_status", "SMB-Signing", "hostname"),
    ]:
        if _table_exists(con, schema, table) and _column_exists(con, schema, table, host_col):
            sources.append(
                f"SELECT DISTINCT LOWER({host_col}) AS hostname, '{source}' AS source "
                f"FROM {schema}.{table} WHERE {host_col} IS NOT NULL AND {host_col} <> ''"
            )

    if not sources:
        con.execute(f"CREATE OR REPLACE TABLE {schema}.targets (hostname VARCHAR, source VARCHAR)")
        return

    union_sql = " UNION ALL ".join(sources)
    con.execute(f"CREATE OR REPLACE TABLE {schema}.targets AS {union_sql}")


# ---------------------------------------------------------------------------
# Site types + hierarchies (replaces the LDAP-only hierarchies builder).
# ---------------------------------------------------------------------------

def _build_site_types(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Derive (site_code, site_type, parent_site_code) from adminservice_site_systems.

    Heuristic (see module docstring): role mix tells us site type. CAS is detected
    as the only/main parent for Primaries; Secondaries hang off Primaries via
    naming convention fallback when no admin source-trace evidence is present.
    """
    if not _table_exists(con, schema, "ldap_sites"):
        _ensure_empty(con, schema, "site_types")
        return

    has_site_systems = _table_exists(con, schema, "adminservice_site_systems")

    has_smb_ss = _table_exists(con, schema, "smb_site_servers")
    has_smb_dp = _table_exists(con, schema, "smb_distribution_points")

    # Build the union of all site_codes — ldap_sites is authoritative when
    # present, adminservice_site_systems and smb_* fill in sites that
    # weren't enumerable via the System Management container (e.g. a
    # Secondary site that a low-priv user can only see via SMB shares).
    all_sites_parts = [
        f"SELECT DISTINCT site_code FROM {schema}.ldap_sites WHERE site_code IS NOT NULL"
    ]
    if has_site_systems:
        all_sites_parts.append(
            f"SELECT DISTINCT site_code FROM {schema}.adminservice_site_systems WHERE site_code IS NOT NULL"
        )
    if has_smb_ss:
        all_sites_parts.append(
            f"SELECT DISTINCT site_code FROM {schema}.smb_site_servers WHERE site_code IS NOT NULL AND site_code <> ''"
        )
    if has_smb_dp:
        all_sites_parts.append(
            f"SELECT DISTINCT site_code FROM {schema}.smb_distribution_points WHERE site_code IS NOT NULL AND site_code <> ''"
        )

    sql = f"""
    CREATE OR REPLACE TEMP TABLE _all_sites AS
    {' UNION '.join(all_sites_parts)};
    """
    con.execute(sql)

    if has_site_systems:
        # Roles per site code (Boolean flags) — primary source is AdminService
        # SMS_SCI_SysResUse; SMB enumeration only contributes the bare flag
        # ``has_site_server`` / ``has_dp`` (no MP / Provider / SQL signal).
        sql = f"""
        CREATE OR REPLACE TEMP TABLE _site_role_flags AS
        SELECT
            sc.site_code,
            BOOL_OR(LOWER(ss.role) LIKE '%sms site server%')        AS has_site_server,
            BOOL_OR(LOWER(ss.role) LIKE '%sms provider%')           AS has_provider,
            BOOL_OR(LOWER(ss.role) LIKE '%sms management point%')   AS has_mp,
            BOOL_OR(LOWER(ss.role) LIKE '%sms distribution point%') AS has_dp,
            BOOL_OR(LOWER(ss.role) LIKE '%sms sql server%')         AS has_sql
        FROM _all_sites sc
        LEFT JOIN {schema}.adminservice_site_systems ss
            ON LOWER(ss.site_code) = LOWER(sc.site_code)
        GROUP BY sc.site_code;
        """
        con.execute(sql)
    else:
        # No AdminService data — derive role flags from SMB tables when available.
        # SMB site servers don't tell us about Provider/MP/SQL roles, but they
        # do tell us "this site has a site server" which is the core signal
        # used to classify a site as non-trivial.
        ss_subquery = (
            f"BOOL_OR(LOWER(sc.site_code) IN (SELECT LOWER(site_code) FROM {schema}.smb_site_servers WHERE site_code IS NOT NULL AND site_code <> ''))"
            if has_smb_ss
            else "FALSE"
        )
        dp_subquery = (
            f"BOOL_OR(LOWER(sc.site_code) IN (SELECT LOWER(site_code) FROM {schema}.smb_distribution_points WHERE site_code IS NOT NULL AND site_code <> ''))"
            if has_smb_dp
            else "FALSE"
        )
        sql = f"""
        CREATE OR REPLACE TEMP TABLE _site_role_flags AS
        SELECT
            sc.site_code,
            {ss_subquery} AS has_site_server,
            FALSE         AS has_provider,
            FALSE         AS has_mp,
            {dp_subquery} AS has_dp,
            FALSE         AS has_sql
        FROM _all_sites sc
        GROUP BY sc.site_code;
        """
        con.execute(sql)

    # Classify and pick a parent. Parent picking is conservative:
    #   - CAS has no parent.
    #   - Primary's parent is the (unique) CAS in the data, or NULL if none exists
    #     (then Primary is its own root).
    #   - Secondary's parent is the (unique) Primary in the data, or NULL if none.
    #
    # When ``ldap_mp_site_classifications`` is available (mSSMSManagementPoint
    # capabilities XML parse) it OVERRIDES the role-flag heuristic, since the
    # MP-derived data is authoritative (CMBP's primary classification source).
    # When MP data classifies a Primary with parent=X, that's strong evidence
    # X is a CAS even when X's own MP isn't visible to the calling user; we
    # do a second-pass inference for that case.
    has_mp_class = _table_exists(con, schema, "ldap_mp_site_classifications")
    mp_join = (
        f"LEFT JOIN {schema}.ldap_mp_site_classifications mp ON UPPER(mp.site_code) = UPPER(c.site_code)"
        if has_mp_class
        else ""
    )
    mp_select = "mp.site_type AS mp_type, mp.parent_site_code AS mp_parent" if has_mp_class else "NULL AS mp_type, NULL AS mp_parent"

    # Build inferred CAS / Primary sets:
    #   inferred_cas = sites that appear as parent_site_code of any MP-classified Primary
    #   inferred_primary = sites that appear as parent_site_code of any MP-classified Secondary
    # These take precedence over the role-flag heuristic when present.
    if has_mp_class:
        inferred_cas_sql = (
            f"SELECT DISTINCT UPPER(mp.parent_site_code) AS code "
            f"FROM {schema}.ldap_mp_site_classifications mp "
            f"WHERE mp.site_type = 'Primary' AND mp.parent_site_code IS NOT NULL "
            f"  AND mp.parent_site_code <> ''"
        )
        inferred_primary_sql = (
            f"SELECT DISTINCT UPPER(mp.parent_site_code) AS code "
            f"FROM {schema}.ldap_mp_site_classifications mp "
            f"WHERE mp.site_type = 'Secondary' AND mp.parent_site_code IS NOT NULL "
            f"  AND mp.parent_site_code <> ''"
        )
    else:
        inferred_cas_sql = "SELECT NULL AS code WHERE FALSE"
        inferred_primary_sql = "SELECT NULL AS code WHERE FALSE"

    sql = f"""
    CREATE OR REPLACE TABLE {schema}.site_types AS
    WITH classified AS (
        SELECT
            c.site_code,
            CASE
                WHEN has_site_server AND has_provider AND NOT has_mp THEN 'CAS'
                WHEN has_site_server AND NOT has_provider AND has_mp THEN 'Secondary'
                WHEN has_site_server AND has_provider AND has_mp     THEN 'Primary'
                WHEN has_site_server                                 THEN 'Primary'
                ELSE 'Primary'
            END AS heuristic_type,
            {mp_select}
        FROM _site_role_flags c
        {mp_join}
    ),
    inferred_cas      AS ({inferred_cas_sql}),
    inferred_primary  AS ({inferred_primary_sql}),
    typed AS (
        SELECT
            c.site_code,
            CASE
                WHEN c.mp_type IS NOT NULL                                            THEN c.mp_type
                WHEN UPPER(c.site_code) IN (SELECT code FROM inferred_cas)            THEN 'CAS'
                WHEN UPPER(c.site_code) IN (SELECT code FROM inferred_primary)        THEN 'Primary'
                ELSE c.heuristic_type
            END AS site_type,
            c.mp_type, c.mp_parent
        FROM classified c
    ),
    cas_codes  AS (SELECT site_code AS code FROM typed WHERE site_type = 'CAS'),
    prim_codes AS (SELECT site_code AS code FROM typed WHERE site_type = 'Primary')
    SELECT
        t.site_code,
        t.site_type,
        CASE
            WHEN t.site_type = 'CAS'                                            THEN NULL
            WHEN t.mp_parent IS NOT NULL                                        THEN t.mp_parent
            WHEN t.site_type = 'Primary'                                        THEN (SELECT code FROM cas_codes LIMIT 1)
            WHEN t.site_type = 'Secondary'                                      THEN (SELECT code FROM prim_codes LIMIT 1)
            ELSE NULL
        END AS parent_site_code
    FROM typed t;
    """
    _safe_exec(con, sql, "site_types")


def _build_hierarchies(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Recursive walk: for each site, find its root via parent_site_code."""
    if not _table_exists(con, schema, "site_types"):
        _ensure_empty(con, schema, "hierarchies")
        return

    sql = f"""
    CREATE OR REPLACE TABLE {schema}.hierarchies AS
    WITH RECURSIVE walk(site_code, parent_site_code, path_root) AS (
        SELECT site_code, parent_site_code, site_code
            FROM {schema}.site_types
            WHERE parent_site_code IS NULL OR parent_site_code = ''
        UNION ALL
        SELECT s.site_code, s.parent_site_code, w.path_root
            FROM {schema}.site_types s
            JOIN walk w ON s.parent_site_code = w.site_code
    )
    SELECT path_root AS root_code, site_code AS member_code FROM walk;
    """
    _safe_exec(con, sql, "hierarchies")


# ---------------------------------------------------------------------------
# Derived-edge views.
# ---------------------------------------------------------------------------

def _build_admins_replicated_to(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Bidirectional CAS<->Primary, unidirectional Primary->Secondary."""
    if not _table_exists(con, schema, "site_types"):
        _ensure_empty(con, schema, "admins_replicated_to_edges")
        return

    sql = f"""
    CREATE OR REPLACE TABLE {schema}.admins_replicated_to_edges AS
    WITH s AS (SELECT site_code, parent_site_code, site_type FROM {schema}.site_types)
    -- CAS -> Primary
    SELECT cas.site_code AS start_id, prim.site_code AS end_id
        FROM s prim JOIN s cas
          ON prim.site_type = 'Primary' AND cas.site_type = 'CAS'
         AND prim.parent_site_code = cas.site_code
    UNION ALL
    -- Primary -> CAS
    SELECT prim.site_code AS start_id, cas.site_code AS end_id
        FROM s prim JOIN s cas
          ON prim.site_type = 'Primary' AND cas.site_type = 'CAS'
         AND prim.parent_site_code = cas.site_code
    UNION ALL
    -- Primary -> Secondary
    SELECT prim.site_code AS start_id, sec.site_code AS end_id
        FROM s prim JOIN s sec
          ON prim.site_type = 'Primary' AND sec.site_type = 'Secondary'
         AND sec.parent_site_code = prim.site_code
    ;
    """
    _safe_exec(con, sql, "admins_replicated_to_edges")


def _build_contains(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """SCCM_Contains: every non-secondary site -> every global object at root."""
    if not (_table_exists(con, schema, "site_types") and _table_exists(con, schema, "hierarchies")):
        _ensure_empty(con, schema, "contains_edges")
        return

    targets: list[str] = []
    for table, kind, id_expr in [
        ("adminservice_admins", "SCCM_AdminUser",
         "LOWER(t.logon_name) || '@' || h_obj.root_code"),
        ("adminservice_security_roles", "SCCM_SecurityRole",
         "t.role_id || '@' || h_obj.root_code"),
        ("adminservice_collections", "SCCM_Collection",
         "t.collection_id || '@' || h_obj.root_code"),
    ]:
        if _table_exists(con, schema, table):
            targets.append(
                f"SELECT DISTINCT s.site_code AS start_id, "
                f"{id_expr} AS end_id, '{kind}' AS end_kind "
                f"FROM {schema}.{table} t "
                f"JOIN {schema}.hierarchies h_obj ON LOWER(h_obj.member_code) = LOWER(t.site_code) "
                f"JOIN {schema}.hierarchies h_site ON h_site.root_code = h_obj.root_code "
                f"JOIN {schema}.site_types s ON s.site_code = h_site.member_code "
                f"WHERE s.site_type <> 'Secondary'"
            )

    if not targets:
        _ensure_empty(con, schema, "contains_edges")
        return

    sql = (
        f"CREATE OR REPLACE TABLE {schema}.contains_edges AS "
        + " UNION ALL ".join(f"SELECT * FROM ({t})" for t in targets)
    )
    _safe_exec(con, sql, "contains_edges")


def _build_role_assignment_edges(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Map admin -> client device for each role assignment.

    The full ROLE_EDGE_MAP from CMBP::ROLE_EDGE_MAP is encoded as a CASE ladder.
    Roles in ROLE_SKIP_SET (Read-Only Analyst, Remote Tools Operator, ...) yield
    no edge — they're informational-only assignments.

    Joins:
      adminservice_role_members (admin x role x scope_collection)
        x adminservice_collection_members (scope_collection x device)
        x adminservice_client_devices (device GUID)
    """
    needed = all(_table_exists(con, schema, t) for t in (
        "adminservice_role_members",
        "adminservice_collection_members",
        "adminservice_client_devices",
        "hierarchies",
    ))
    if not needed:
        _ensure_empty(con, schema, "role_assignment_edges")
        return

    # Edge-kind dispatch matches lib/post_processing.py::ROLE_EDGE_MAP.
    role_case = """
        CASE rm.role_id
            WHEN 'SMS0001R' THEN 'SCCM_FullAdministrator'
            WHEN 'SMS0006R' THEN 'SCCM_ComplianceSettingsManager'
            WHEN 'SMS0008R' THEN 'SCCM_ApplicationAuthor'
            WHEN 'SMS0009R' THEN 'SCCM_ApplicationAdministrator'
            WHEN 'SMS000AR' THEN 'SCCM_OSDManager'
            WHEN 'SMS000ER' THEN 'SCCM_OperationsAdministrator'
            WHEN 'SMS000FR' THEN 'SCCM_SecurityAdministrator'
            -- ROLE_SKIP_SET (no edge produced for these)
            WHEN 'SMS0002R' THEN NULL
            WHEN 'SMS0003R' THEN NULL
            WHEN 'SMS0004R' THEN NULL
            WHEN 'SMS0007R' THEN NULL
            WHEN 'SMS000BR' THEN NULL
            WHEN 'SMS000CR' THEN NULL
            WHEN 'SMS000GR' THEN NULL
            WHEN 'SMS000HR' THEN NULL
            ELSE 'SCCM_AssignSpecificPermissions'
        END
    """

    sql = f"""
    CREATE OR REPLACE TABLE {schema}.role_assignment_edges AS
    SELECT DISTINCT
        LOWER(rm.admin_logon_name) || '@' || h.root_code AS start_id,
        'GUID:' || cd.guid                              AS end_id,
        {role_case}                                      AS edge_kind
    FROM {schema}.adminservice_role_members rm
    JOIN {schema}.adminservice_collection_members cm
        ON LOWER(cm.site_code) = LOWER(rm.site_code)
       AND cm.collection_id    = rm.scope_collection_id
    JOIN {schema}.adminservice_client_devices cd
        ON cd.resource_id   = cm.resource_id
       AND LOWER(cd.site_code) = LOWER(cm.site_code)
    JOIN {schema}.hierarchies h
        ON LOWER(h.member_code) = LOWER(rm.site_code)
    WHERE {role_case} IS NOT NULL
      AND cd.guid IS NOT NULL AND cd.guid <> '';
    """
    _safe_exec(con, sql, "role_assignment_edges")


def _build_all_permissions(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """SCCM_AllPermissions: Full Administrator with both 'All Systems' and
    'All Users and User Groups' collections -> every site in the hierarchy.

    CMBP source: ``post_processing.py::_process_role_assignments_and_all_permissions``
    end-of-loop (lines 502-505). The ``adminservice_admins`` rows expose
    ``is_all_instances`` (bool) plus ``collection_names`` (array) which
    together identify the qualifying admins.
    """
    if not (
        _table_exists(con, schema, "adminservice_admins")
        and _table_exists(con, schema, "adminservice_role_members")
        and _table_exists(con, schema, "hierarchies")
    ):
        _ensure_empty(con, schema, "all_permissions_edges")
        return

    sql = f"""
    CREATE OR REPLACE TABLE {schema}.all_permissions_edges AS
    WITH full_admins AS (
        SELECT DISTINCT
            LOWER(a.logon_name) AS logon_name,
            a.site_code
        FROM {schema}.adminservice_admins a
        JOIN {schema}.adminservice_role_members rm
            ON  LOWER(rm.admin_logon_name) = LOWER(a.logon_name)
            AND LOWER(rm.site_code)        = LOWER(a.site_code)
            AND rm.role_id = 'SMS0001R'
        WHERE a.is_all_instances = TRUE
          AND a.collection_names::VARCHAR LIKE '%All Systems%'
          AND a.collection_names::VARCHAR LIKE '%All Users and User Groups%'
    )
    SELECT DISTINCT
        fa.logon_name || '@' || h_admin.root_code AS start_id,
        site_in_hierarchy.member_code              AS end_id
    FROM full_admins fa
    JOIN {schema}.hierarchies h_admin
        ON LOWER(h_admin.member_code) = LOWER(fa.site_code)
    JOIN {schema}.hierarchies site_in_hierarchy
        ON site_in_hierarchy.root_code = h_admin.root_code
    JOIN {schema}.site_types s
        ON s.site_code = site_in_hierarchy.member_code
       AND s.site_type <> 'Secondary'
    ;
    """
    _safe_exec(con, sql, "all_permissions_edges")


def _build_same_host_as(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Bidirectional SCCM_ClientDevice <-> Computer match by SID or hostname."""
    if not (
        _table_exists(con, schema, "adminservice_client_devices")
        and _table_exists(con, schema, "ldap_computers")
    ):
        _ensure_empty(con, schema, "same_host_as_edges")
        return

    sql = f"""
    CREATE OR REPLACE TABLE {schema}.same_host_as_edges AS
    WITH matches AS (
        SELECT DISTINCT 'GUID:' || cd.guid AS device_id, c.object_sid AS computer_id
        FROM {schema}.adminservice_client_devices cd
        JOIN {schema}.ldap_computers c
            ON  (cd.ad_object_sid IS NOT NULL AND cd.ad_object_sid <> '' AND LOWER(cd.ad_object_sid) = LOWER(c.object_sid))
            OR  (cd.machine_name  IS NOT NULL AND cd.machine_name <> ''
                 AND (LOWER(cd.machine_name) = LOWER(c.sam_account_name)
                      OR LOWER(cd.machine_name) || '$' = LOWER(c.sam_account_name)
                      OR LOWER(cd.machine_name) = LOWER(c.name)))
        WHERE cd.guid IS NOT NULL AND cd.guid <> ''
    )
    SELECT device_id   AS start_id, computer_id AS end_id FROM matches
    UNION ALL
    SELECT computer_id AS start_id, device_id   AS end_id FROM matches
    ;
    """
    _safe_exec(con, sql, "same_host_as_edges")


def _build_local_admin_required(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Site server -> co-located site systems for the same site_code.

    Models CMBP ``post_processing.py::_process_computer_nodes`` (lines 662-681).
    For each site, the (unique) site server gets a LocalAdminRequired edge to
    every other host carrying any ``@<site_code>`` role.

    Two source paths, unioned for low-priv runs:
      1. ``adminservice_site_systems`` (full-access only)
      2. ``smb_site_servers`` + ``smb_distribution_points`` (SMB-discovered)
    """
    has_admin = (
        _table_exists(con, schema, "adminservice_site_systems")
        and _table_exists(con, schema, "ldap_computers")
    )
    has_smb_ss = _table_exists(con, schema, "smb_site_servers")
    has_smb_dp = _table_exists(con, schema, "smb_distribution_points")

    if not (has_admin or has_smb_ss):
        _ensure_empty(con, schema, "local_admin_required_edges")
        return

    members_parts: list[str] = []
    servers_parts: list[str] = []

    if has_admin:
        members_parts.append(f"""
            SELECT
                LOWER(s.hostname) AS hostname,
                s.site_code      AS site_code,
                c.object_sid     AS computer_sid
            FROM {schema}.adminservice_site_systems s
            JOIN {schema}.ldap_computers c
                ON  LOWER(c.dns_host_name) = LOWER(s.hostname)
                OR  LOWER(c.sam_account_name) = LOWER(SPLIT_PART(s.hostname, '.', 1)) || '$'
                OR  LOWER(c.name)             = LOWER(SPLIT_PART(s.hostname, '.', 1))
        """)
        servers_parts.append(f"""
            SELECT DISTINCT
                LOWER(s.hostname) AS hostname,
                s.site_code      AS site_code,
                c.object_sid     AS computer_sid
            FROM {schema}.adminservice_site_systems s
            JOIN {schema}.ldap_computers c
                ON  LOWER(c.dns_host_name) = LOWER(s.hostname)
                OR  LOWER(c.sam_account_name) = LOWER(SPLIT_PART(s.hostname, '.', 1)) || '$'
                OR  LOWER(c.name)             = LOWER(SPLIT_PART(s.hostname, '.', 1))
            WHERE LOWER(s.role) = 'sms site server'
        """)

    if has_smb_ss:
        # smb_site_servers: hostname, role ('SMS Site Server'), site_code, computer_sid
        members_parts.append(f"""
            SELECT
                LOWER(hostname) AS hostname,
                site_code       AS site_code,
                computer_sid    AS computer_sid
            FROM {schema}.smb_site_servers
            WHERE computer_sid IS NOT NULL AND site_code IS NOT NULL
        """)
        servers_parts.append(f"""
            SELECT DISTINCT
                LOWER(hostname) AS hostname,
                site_code       AS site_code,
                computer_sid    AS computer_sid
            FROM {schema}.smb_site_servers
            WHERE computer_sid IS NOT NULL AND site_code IS NOT NULL
        """)

    if has_smb_dp:
        # smb_distribution_points contributes site members (DPs are site-system hosts)
        members_parts.append(f"""
            SELECT
                LOWER(hostname) AS hostname,
                site_code       AS site_code,
                computer_sid    AS computer_sid
            FROM {schema}.smb_distribution_points
            WHERE computer_sid IS NOT NULL AND site_code IS NOT NULL
        """)

    # Additional member sources: each table tells us a Computer carries some
    # @site_code role even when AdminService and SMB enumeration miss it.
    # CMBP gathers SCCMSiteSystemRoles from every collector and per-Computer
    # iterates them; we approximate that fan-out by treating each row as a
    # site member for the LocalAdminRequired SQL.
    if (
        _table_exists(con, schema, "dns_management_points")
        and _table_exists(con, schema, "ldap_computers")
    ):
        members_parts.append(f"""
            SELECT
                LOWER(d.hostname) AS hostname,
                d.site_code       AS site_code,
                c.object_sid      AS computer_sid
            FROM {schema}.dns_management_points d
            JOIN {schema}.ldap_computers c
                ON  LOWER(c.dns_host_name) = LOWER(d.hostname)
                OR  LOWER(c.sam_account_name) = LOWER(SPLIT_PART(d.hostname, '.', 1)) || '$'
                OR  LOWER(c.name)             = LOWER(SPLIT_PART(d.hostname, '.', 1))
            WHERE d.site_code IS NOT NULL AND d.site_code <> ''
              AND c.object_sid IS NOT NULL
        """)

    if (
        _table_exists(con, schema, "local_distribution_points")
        and _column_exists(con, schema, "local_distribution_points", "site_code")
        and _table_exists(con, schema, "ldap_computers")
    ):
        # local_distribution_points carries site_code only for DP-roled hosts;
        # other rows are pure log-parse adjuncts that we shouldn't fold in.
        members_parts.append(f"""
            SELECT
                LOWER(l.hostname) AS hostname,
                l.site_code       AS site_code,
                c.object_sid      AS computer_sid
            FROM {schema}.local_distribution_points l
            JOIN {schema}.ldap_computers c
                ON  LOWER(c.dns_host_name) = LOWER(l.hostname)
                OR  LOWER(c.sam_account_name) = LOWER(SPLIT_PART(l.hostname, '.', 1)) || '$'
                OR  LOWER(c.name)             = LOWER(SPLIT_PART(l.hostname, '.', 1))
            WHERE l.site_code IS NOT NULL AND l.site_code <> ''
              AND c.object_sid IS NOT NULL
        """)

    if (
        _table_exists(con, schema, "http_management_points")
        and _table_exists(con, schema, "ldap_computers")
    ):
        members_parts.append(f"""
            SELECT
                LOWER(h.hostname) AS hostname,
                h.site_code       AS site_code,
                c.object_sid      AS computer_sid
            FROM {schema}.http_management_points h
            JOIN {schema}.ldap_computers c
                ON  LOWER(c.dns_host_name) = LOWER(h.hostname)
                OR  LOWER(c.sam_account_name) = LOWER(SPLIT_PART(h.hostname, '.', 1)) || '$'
                OR  LOWER(c.name)             = LOWER(SPLIT_PART(h.hostname, '.', 1))
            WHERE h.site_code IS NOT NULL AND h.site_code <> ''
              AND c.object_sid IS NOT NULL
        """)

    members_union = " UNION ALL ".join(f"SELECT * FROM ({p})" for p in members_parts)
    servers_union = " UNION ALL ".join(f"SELECT * FROM ({p})" for p in servers_parts)

    sql = f"""
    CREATE OR REPLACE TABLE {schema}.local_admin_required_edges AS
    WITH site_servers AS (
        SELECT DISTINCT site_code, hostname, computer_sid
        FROM ({servers_union})
    ),
    site_members AS (
        SELECT DISTINCT site_code, hostname, computer_sid
        FROM ({members_union})
    )
    SELECT DISTINCT ss.computer_sid AS start_id, sm.computer_sid AS end_id
    FROM site_servers ss
    JOIN site_members sm
      ON ss.site_code  = sm.site_code
     AND ss.hostname  <> sm.hostname
    WHERE ss.computer_sid IS NOT NULL
      AND sm.computer_sid IS NOT NULL
      AND ss.computer_sid <> sm.computer_sid
    ;
    """
    _safe_exec(con, sql, "local_admin_required_edges")


def _build_assign_all_permissions(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """SCCM_AssignAllPermissions:
    SMS Provider computer -> every primary site in its hierarchy.

    Per-provider fan-out: when a Computer hosts the ``SMS Provider`` role
    for multiple sites (e.g. CAS and PS1 sharing a server), CMBP iterates
    over each provider-role separately and emits one edge to every primary
    site in the hierarchy per provider. We mirror this by emitting one row
    per (provider_site, target_primary_site, computer_sid) carrying the
    provider site as ``collection_source``. The output-stage dedup key on
    ``collectionSource`` keeps each provider variant as a distinct edge,
    matching CMBP's ``upsert_edge`` duplicate-retention semantics.

    The CMBP behaviour also adds ``MSSQL_Database -> primary site`` edges for
    ``CM_<site_code>`` databases, but those nodes don't yet exist in our
    extension's MSSQL chain (Phase 3a stubbed mssql_databases). For Phase 4 we
    cover the SMS-Provider variant only.
    """
    needed = (
        _table_exists(con, schema, "adminservice_site_systems")
        and _table_exists(con, schema, "ldap_computers")
        and _table_exists(con, schema, "hierarchies")
        and _table_exists(con, schema, "site_types")
    )
    if not needed:
        _ensure_empty(con, schema, "assign_all_permissions_edges")
        return

    has_derived_nodes = _table_exists(con, schema, "derived_nodes")

    db_clause = ""
    if has_derived_nodes:
        # Mirrors CMBP's post_processing.py lines 705-722: each MSSQL_Database
        # named ``CM_<site_code>`` gets an SCCM_AssignAllPermissions edge to
        # the corresponding primary site (must be Primary or CAS, not
        # Secondary). The DB node's site_code field carries the target site,
        # so we don't need to re-parse the name.
        db_clause = f"""
        UNION ALL
        SELECT DISTINCT
            dn.node_id                                  AS start_id,
            st.site_code                                AS end_id,
            'MSSQL_Database@' || dn.site_code           AS collection_source
        FROM {schema}.derived_nodes dn
        JOIN {schema}.site_types st
            ON UPPER(st.site_code) = UPPER(dn.site_code)
        WHERE dn.kind = 'MSSQL_Database'
          AND st.site_type <> 'Secondary'
          AND dn.node_id IS NOT NULL AND dn.node_id <> ''
        """

    sql = f"""
    CREATE OR REPLACE TABLE {schema}.assign_all_permissions_edges AS
    WITH provider_hosts AS (
        SELECT DISTINCT s.site_code, c.object_sid AS computer_sid
        FROM {schema}.adminservice_site_systems s
        JOIN {schema}.ldap_computers c
            ON  LOWER(c.dns_host_name) = LOWER(s.hostname)
            OR  LOWER(c.sam_account_name) = LOWER(SPLIT_PART(s.hostname, '.', 1)) || '$'
            OR  LOWER(c.name)             = LOWER(SPLIT_PART(s.hostname, '.', 1))
        WHERE LOWER(s.role) = 'sms provider'
    )
    SELECT DISTINCT
        ph.computer_sid                            AS start_id,
        st.site_code                               AS end_id,
        'AdminService-SMS_SCI_SysResUse@' || ph.site_code AS collection_source
    FROM provider_hosts ph
    JOIN {schema}.hierarchies hp
        ON LOWER(hp.member_code) = LOWER(ph.site_code)
    JOIN {schema}.hierarchies sh
        ON sh.root_code = hp.root_code
    JOIN {schema}.site_types st
        ON st.site_code = sh.member_code
    WHERE st.site_type <> 'Secondary'
      AND ph.computer_sid IS NOT NULL
    {db_clause}
    ;
    """
    _safe_exec(con, sql, "assign_all_permissions_edges")


def _build_mssql_sysadmin_edges(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Materialise the MSSQL sysadmin facts emitted by
    ``_process_computer_nodes`` -> ``_create_mssql_sysadmin_edges``.

    For each site, the **site DB** computer gets MSSQL infrastructure (server
    role / db / login / db user) emitted from each "sysadmin" computer (every
    Site Server and SMS Provider in the same site). Each row carries enough
    context for the consuming model to fan out the eight edges:

      MSSQL_HasLogin    : (sysadmin Computer)   -> MSSQL_Login
      MSSQL_Contains    : (MSSQL_Server)        -> MSSQL_Login
      MSSQL_MemberOf    : (MSSQL_Login)         -> MSSQL_ServerRole sysadmin
      MSSQL_IsMappedTo  : (MSSQL_Login)         -> MSSQL_DatabaseUser
      MSSQL_Contains    : (MSSQL_Database)      -> MSSQL_DatabaseUser
      MSSQL_MemberOf    : (MSSQL_DatabaseUser)  -> MSSQL_DatabaseRole db_owner
      MSSQL_HostFor     : (db Computer)         -> MSSQL_Server (site DB host)
      MSSQL_ExecuteOnHost (informational)       — emitted by db-Computer model

    Plus the **MSSQL_Login** and **MSSQL_DatabaseUser** *nodes* are emitted by
    the consuming derived model (since they don't exist as their own table).

    Each row is one (sysadmin_computer, db_computer, site_code) tuple. The
    consumer model fans out all derived nodes/edges from there.
    """
    needed = (
        _table_exists(con, schema, "adminservice_site_systems")
        and _table_exists(con, schema, "ldap_computers")
        and _table_exists(con, schema, "site_types")
    )
    if not needed:
        _ensure_empty(con, schema, "mssql_sysadmin_edges")
        return

    sql = f"""
    CREATE OR REPLACE TABLE {schema}.mssql_sysadmin_edges AS
    WITH ss_with_sid AS (
        SELECT
            LOWER(s.hostname) AS hostname,
            s.role,
            s.site_code,
            c.object_sid       AS computer_sid,
            c.sam_account_name AS sam,
            c.dns_host_name    AS fqdn,
            c.domain           AS domain
        FROM {schema}.adminservice_site_systems s
        JOIN {schema}.ldap_computers c
            ON  LOWER(c.dns_host_name) = LOWER(s.hostname)
            OR  LOWER(c.sam_account_name) = LOWER(SPLIT_PART(s.hostname, '.', 1)) || '$'
            OR  LOWER(c.name)             = LOWER(SPLIT_PART(s.hostname, '.', 1))
    ),
    site_dbs AS (
        SELECT DISTINCT site_code, hostname, computer_sid
        FROM ss_with_sid
        WHERE LOWER(role) = 'sms sql server'
    ),
    sysadmins AS (
        -- Every Site Server and SMS Provider at a primary/CAS site is a sysadmin candidate.
        SELECT DISTINCT s.site_code, s.hostname, s.computer_sid, s.sam, s.fqdn, s.domain
        FROM ss_with_sid s
        JOIN {schema}.site_types st ON st.site_code = s.site_code AND st.site_type <> 'Secondary'
        WHERE LOWER(s.role) IN ('sms site server', 'sms provider')
    )
    SELECT
        sa.computer_sid AS start_id,
        db.hostname || ':1433' || chr(92) || 'CM_' || sa.site_code AS end_id,  -- placeholder; consumer rewrites
        'MSSQL_Sysadmin' AS edge_kind,
        LOWER(SPLIT_PART(sa.domain, '.', 1)) || chr(92) || LOWER(REPLACE(sa.sam, '$', '')) AS login_name,
        db.hostname || ':1433' AS server_id,
        db.hostname || ':1433' || chr(92) || 'CM_' || sa.site_code AS database_id,
        sa.site_code AS site_code,
        'fanout' AS node_kind
    FROM sysadmins sa
    JOIN site_dbs db
        ON db.site_code = sa.site_code
       AND db.hostname <> sa.hostname
    WHERE sa.computer_sid IS NOT NULL
    ;
    """
    _safe_exec(con, sql, "mssql_sysadmin_edges")


def _build_mssql_server_hierarchy_edges(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Per-MSSQL_Server structural edges that CMBP emits unconditionally.

    For every MSSQL_Server node (one per host that responded to TDS prelogin
    on TCP/1433), CMBP emits:

      * MSSQL_HostFor       : (db Computer) -> MSSQL_Server
      * MSSQL_ExecuteOnHost : MSSQL_Server  -> (db Computer)

    And, for every server whose host has an associated SCCM site code (via
    AdminService SMS_SCI_SysResUse 'SMS SQL Server' role, regardless of whether
    the site is CAS / Primary / Secondary — the int siteType=1 Secondary case
    still gets the full hierarchy emitted because CMBP's check
    ``siteType == 'Secondary Site'`` is a string compare that never matches the
    int form), CMBP emits:

      * MSSQL_Contains      : MSSQL_Server      -> sysadmin@Server (ServerRole)
      * MSSQL_ControlServer : sysadmin@Server   -> MSSQL_Server
      * MSSQL_Contains      : MSSQL_Server      -> CM_<site> (Database)
      * MSSQL_Contains      : CM_<site>         -> db_owner@Server\\CM_<site>
      * MSSQL_ControlDB     : db_owner@Server\\CM_<site> -> CM_<site>

    Reference: ``ConfigManBearPig/python/lib/collectors/mssql_collector.py``
    lines 103-107 (HostFor / ExecuteOnHost) and 367-435 (per-site hierarchy).

    The sysadmin-fan-out (MSSQL_HasLogin / per-login MSSQL_Contains /
    MSSQL_MemberOf / MSSQL_IsMappedTo / MSSQL_Contains DB->User) is handled
    separately by ``_build_mssql_sysadmin_edges`` because it depends on
    cross-host (sysadmin-Computer x db-Computer) pairs from non-Secondary
    sites only.

    The synthesised MSSQL_Database / MSSQL_ServerRole / MSSQL_DatabaseRole
    nodes are emitted at collect time by ``derived_nodes`` in ``source.py``.
    """
    needed = (
        _table_exists(con, schema, "mssql_epa_flags")
        and _table_exists(con, schema, "ldap_computers")
    )
    if not needed:
        _ensure_empty(con, schema, "mssql_server_hierarchy_edges")
        return

    has_site_systems = _table_exists(con, schema, "adminservice_site_systems")

    # Resolve each MSSQL_Server to its Computer SID + (if any) site_code.
    # The site_code lookup uses the AdminService 'SMS SQL Server' role row
    # for that host. If AdminService isn't accessible (lowpriv), there's
    # no site_code, so only HostFor/ExecuteOnHost fire — but for lowpriv,
    # the ``mssql_epa_flags`` table is also empty (it's gated on
    # ``sccm_discovered_hosts()``), so this view yields zero rows total.
    if has_site_systems:
        site_join = f"""
        LEFT JOIN (
            SELECT DISTINCT LOWER(hostname) AS hostname, site_code
            FROM {schema}.adminservice_site_systems
            WHERE LOWER(role) = 'sms sql server'
              AND site_code IS NOT NULL
              AND site_code <> ''
        ) sql_site
            ON sql_site.hostname = LOWER(epa.hostname)
        """
        site_col = "sql_site.site_code"
    else:
        site_join = ""
        site_col = "NULL"

    sql = f"""
    CREATE OR REPLACE TABLE {schema}.mssql_server_hierarchy_edges AS
    WITH server_with_host AS (
        SELECT DISTINCT
            LOWER(epa.hostname) || ':1433' AS server_id,
            c.object_sid                    AS computer_sid,
            {site_col}                      AS site_code
        FROM {schema}.mssql_epa_flags epa
        JOIN {schema}.ldap_computers c
            ON  LOWER(c.dns_host_name) = LOWER(epa.hostname)
            OR  LOWER(c.sam_account_name) = LOWER(SPLIT_PART(epa.hostname, '.', 1)) || '$'
            OR  LOWER(c.name)             = LOWER(SPLIT_PART(epa.hostname, '.', 1))
        {site_join}
        WHERE c.object_sid IS NOT NULL AND c.object_sid <> ''
    )
    -- HostFor: Computer -> MSSQL_Server (always)
    SELECT computer_sid AS start_id, server_id AS end_id, 'MSSQL_HostFor' AS edge_kind
        FROM server_with_host
    UNION ALL
    -- ExecuteOnHost: MSSQL_Server -> Computer (always)
    SELECT server_id AS start_id, computer_sid AS end_id, 'MSSQL_ExecuteOnHost' AS edge_kind
        FROM server_with_host
    UNION ALL
    -- Contains: Server -> sysadmin role (only when site_code resolved)
    SELECT
        server_id AS start_id,
        'sysadmin@' || server_id AS end_id,
        'MSSQL_Contains' AS edge_kind
        FROM server_with_host WHERE site_code IS NOT NULL AND site_code <> ''
    UNION ALL
    -- ControlServer: sysadmin role -> Server
    SELECT
        'sysadmin@' || server_id AS start_id,
        server_id AS end_id,
        'MSSQL_ControlServer' AS edge_kind
        FROM server_with_host WHERE site_code IS NOT NULL AND site_code <> ''
    UNION ALL
    -- Contains: Server -> Database
    SELECT
        server_id AS start_id,
        server_id || chr(92) || 'CM_' || site_code AS end_id,
        'MSSQL_Contains' AS edge_kind
        FROM server_with_host WHERE site_code IS NOT NULL AND site_code <> ''
    UNION ALL
    -- Contains: Database -> db_owner role
    SELECT
        server_id || chr(92) || 'CM_' || site_code AS start_id,
        'db_owner@' || server_id || chr(92) || 'CM_' || site_code AS end_id,
        'MSSQL_Contains' AS edge_kind
        FROM server_with_host WHERE site_code IS NOT NULL AND site_code <> ''
    UNION ALL
    -- ControlDB: db_owner role -> Database
    SELECT
        'db_owner@' || server_id || chr(92) || 'CM_' || site_code AS start_id,
        server_id || chr(92) || 'CM_' || site_code AS end_id,
        'MSSQL_ControlDB' AS edge_kind
        FROM server_with_host WHERE site_code IS NOT NULL AND site_code <> ''
    ;
    """
    _safe_exec(con, sql, "mssql_server_hierarchy_edges")


def _build_coerce_and_relay_edges(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """CoerceAndRelay edges. Authenticated Users -> {AdminService site / MSSQL login / SMB target}.

    Three flavours:
      * SCCM_CoerceAndRelayToAdminService — per (CAS|Primary) site that has at
        least one SMS Provider with NTLM unrestricted; auth users -> site code.
      * MSSQL_CoerceAndRelayToMSSQL — per site DB host with EPA Off; auth users
        -> MSSQL_Login of each victim (site server / SMS provider / MP).
      * SCCM_CoerceAndRelayToSMB / SCCM_CoerceAndRelaytoSMB — per host where
        SMB signing is NOT required; auth users -> Computer SID.

    NTLM restriction is currently UNKNOWN for our collected data (the registry
    flag isn't yet captured). We treat NULL as "unrestricted" (CMBP fallback).
    """
    needed = (
        _table_exists(con, schema, "site_types")
        and _table_exists(con, schema, "ldap_computers")
    )
    if not needed:
        _ensure_empty(con, schema, "coerce_and_relay_edges")
        return

    has_site_systems = _table_exists(con, schema, "adminservice_site_systems")
    has_smb_signing = _table_exists(con, schema, "smb_signing_status")
    has_epa_flags = _table_exists(con, schema, "mssql_epa_flags")

    # Authenticated users id is "<DOMAIN>-S-1-5-11" (uppercased FQDN, e.g. MAYYHEM.COM).
    # We pick the first non-null domain from ldap_computers and uppercase it.
    auth_users_sql = f"""
        SELECT DISTINCT UPPER(domain) || '-S-1-5-11' AS auth_users_id
        FROM {schema}.ldap_computers
        WHERE domain IS NOT NULL AND domain <> ''
        LIMIT 1
    """

    flavors: list[str] = []

    # ---- AdminService flavour ------------------------------------------------
    if has_site_systems:
        flavors.append(f"""
        SELECT
            au.auth_users_id AS start_id,
            site.site_code   AS end_id,
            'CoerceAndRelayToAdminService' AS edge_kind,
            srv.fqdn AS victim_fqdn,
            prov.fqdn AS target_fqdn
        FROM ({auth_users_sql}) au
        JOIN {schema}.site_types site ON site.site_type <> 'Secondary'
        JOIN (
            SELECT DISTINCT s.site_code, LOWER(s.hostname) AS hostname,
                            c.dns_host_name AS fqdn
            FROM {schema}.adminservice_site_systems s
            JOIN {schema}.ldap_computers c
                ON LOWER(c.dns_host_name) = LOWER(s.hostname)
                OR LOWER(c.sam_account_name) = LOWER(SPLIT_PART(s.hostname, '.', 1)) || '$'
            WHERE LOWER(s.role) = 'sms provider'
        ) prov ON prov.site_code = site.site_code
        JOIN (
            SELECT DISTINCT s.site_code, LOWER(s.hostname) AS hostname,
                            c.dns_host_name AS fqdn
            FROM {schema}.adminservice_site_systems s
            JOIN {schema}.ldap_computers c
                ON LOWER(c.dns_host_name) = LOWER(s.hostname)
                OR LOWER(c.sam_account_name) = LOWER(SPLIT_PART(s.hostname, '.', 1)) || '$'
            WHERE LOWER(s.role) = 'sms site server'
        ) srv ON srv.site_code = site.site_code
        WHERE prov.hostname <> srv.hostname
        """)

    # ---- MSSQL flavour -------------------------------------------------------
    # We can produce coerce-MSSQL edges per-victim-Computer when the EPA flag on
    # the site DB is Off / null (CMBP heuristic). Lacking real MSSQL_Login
    # nodes from authenticated introspection, we point the edge at the site
    # DB Computer SID itself — Phase 6 will revisit when MSSQL_Login emission
    # becomes real. For now, the per-victim row is annotated with a synthetic
    # "login_name@server_id" string in target_fqdn so the consumer model can
    # synthesise the MSSQL_Login node id at convert time.
    if has_site_systems and has_epa_flags:
        flavors.append(f"""
        SELECT
            au.auth_users_id AS start_id,
            -- Synthetic MSSQL_Login id: domain + backslash + sam + @host:1433
            LOWER(SPLIT_PART(victim.domain, '.', 1)) || chr(92) ||
                LOWER(REPLACE(victim.sam, '$', '')) ||
                '@' || db.hostname || ':1433'             AS end_id,
            'CoerceAndRelayToMSSQL'                        AS edge_kind,
            victim.fqdn AS victim_fqdn,
            db.hostname AS target_fqdn
        FROM ({auth_users_sql}) au
        JOIN {schema}.site_types site ON site.site_type <> 'Secondary'
        JOIN (
            SELECT DISTINCT s.site_code, LOWER(s.hostname) AS hostname
            FROM {schema}.adminservice_site_systems s
            WHERE LOWER(s.role) = 'sms sql server'
        ) db ON db.site_code = site.site_code
        JOIN {schema}.mssql_epa_flags epa
            ON LOWER(epa.hostname) = db.hostname
        JOIN (
            -- Victim Computers: site servers, SMS providers, management points
            -- in the same site, joined to LDAP for SAM / domain / fqdn.
            SELECT DISTINCT s.site_code, LOWER(s.hostname) AS hostname,
                            c.sam_account_name AS sam,
                            c.dns_host_name AS fqdn,
                            c.domain        AS domain
            FROM {schema}.adminservice_site_systems s
            JOIN {schema}.ldap_computers c
                ON LOWER(c.dns_host_name) = LOWER(s.hostname)
                OR LOWER(c.sam_account_name) = LOWER(SPLIT_PART(s.hostname, '.', 1)) || '$'
            WHERE LOWER(s.role) IN ('sms site server', 'sms provider', 'sms management point')
        ) victim ON victim.site_code = site.site_code
        WHERE victim.hostname <> db.hostname
          AND (LOWER(epa.epa) = 'off' OR epa.epa IS NULL OR epa.epa = '' OR LOWER(epa.epa) = 'none')
        """)

    # ---- SMB flavour ---------------------------------------------------------
    if has_site_systems and has_smb_signing:
        flavors.append(f"""
        SELECT
            au.auth_users_id AS start_id,
            target.computer_sid AS end_id,
            'CoerceAndRelayToSMB' AS edge_kind,
            srv.fqdn AS victim_fqdn,
            target.fqdn AS target_fqdn
        FROM ({auth_users_sql}) au
        JOIN {schema}.site_types site ON site.site_type <> 'Secondary'
        JOIN (
            SELECT DISTINCT s.site_code, LOWER(s.hostname) AS hostname,
                            c.dns_host_name AS fqdn
            FROM {schema}.adminservice_site_systems s
            JOIN {schema}.ldap_computers c
                ON LOWER(c.dns_host_name) = LOWER(s.hostname)
                OR LOWER(c.sam_account_name) = LOWER(SPLIT_PART(s.hostname, '.', 1)) || '$'
            WHERE LOWER(s.role) = 'sms site server'
        ) srv ON srv.site_code = site.site_code
        JOIN (
            SELECT DISTINCT s.site_code,
                            LOWER(s.hostname)  AS hostname,
                            c.dns_host_name    AS fqdn,
                            c.object_sid       AS computer_sid
            FROM {schema}.adminservice_site_systems s
            JOIN {schema}.ldap_computers c
                ON LOWER(c.dns_host_name) = LOWER(s.hostname)
                OR LOWER(c.sam_account_name) = LOWER(SPLIT_PART(s.hostname, '.', 1)) || '$'
        ) target ON target.site_code = site.site_code
        JOIN {schema}.smb_signing_status sig ON LOWER(sig.hostname) = target.hostname
        WHERE target.hostname <> srv.hostname
          AND sig.signing_required = FALSE
          AND target.computer_sid IS NOT NULL
        """)
        # Note: CMBP source (lib/post_processing.py::_process_sccm_coerce_and_relay_to_smb)
        # only emits the correct ``CoerceAndRelayToSMB`` kind; the lowercase
        # ``CoerceAndRelaytoSMB`` typo seen in the cmbp_seed baseline is a
        # leftover seed_data declaration that no real edge ever populated
        # past 1. We therefore do NOT emit a typo'd duplicate.

    # ---- SMB-only fallback (low-priv runs without AdminService) -----------
    # When AdminService is unreachable but SMB enumeration produced a
    # ``smb_site_servers`` table, use it as the site-server source so
    # low-priv users still get CoerceAndRelayToSMB edges from each
    # SMB-discovered site to its non-signing-required co-located hosts.
    has_smb_ss = _table_exists(con, schema, "smb_site_servers")
    has_smb_dp = _table_exists(con, schema, "smb_distribution_points")
    if not has_site_systems and has_smb_signing and has_smb_ss:
        # Build a "victim site members" union from smb_site_servers + smb_distribution_points
        member_parts = [
            f"""SELECT DISTINCT site_code, LOWER(hostname) AS hostname,
                hostname AS fqdn, computer_sid
            FROM {schema}.smb_site_servers
            WHERE computer_sid IS NOT NULL""",
        ]
        if has_smb_dp:
            member_parts.append(f"""
            SELECT DISTINCT site_code, LOWER(hostname) AS hostname,
                hostname AS fqdn, computer_sid
            FROM {schema}.smb_distribution_points
            WHERE computer_sid IS NOT NULL""")
        members_union = " UNION ALL ".join(f"SELECT * FROM ({p})" for p in member_parts)

        flavors.append(f"""
        SELECT
            au.auth_users_id AS start_id,
            target.computer_sid AS end_id,
            'CoerceAndRelayToSMB' AS edge_kind,
            srv.fqdn AS victim_fqdn,
            target.fqdn AS target_fqdn
        FROM ({auth_users_sql}) au
        JOIN (
            SELECT DISTINCT site_code, LOWER(hostname) AS hostname,
                hostname AS fqdn
            FROM {schema}.smb_site_servers
        ) srv ON 1=1
        JOIN ({members_union}) target ON target.site_code = srv.site_code
        JOIN {schema}.smb_signing_status sig ON LOWER(sig.hostname) = target.hostname
        WHERE target.hostname <> srv.hostname
          AND sig.signing_required = FALSE
          AND target.computer_sid IS NOT NULL
        """)

    if not flavors:
        _ensure_empty(con, schema, "coerce_and_relay_edges")
        return

    union_sql = " UNION ALL ".join(f"SELECT * FROM ({f})" for f in flavors)
    sql = f"CREATE OR REPLACE TABLE {schema}.coerce_and_relay_edges AS {union_sql}"
    _safe_exec(con, sql, "coerce_and_relay_edges")


def _build_mssql_gettgs_edges(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """MSSQL_GetTGS, MSSQL_GetAdminTGS, MSSQL_ServiceAccountFor, HasSession.

    From CMBP ``post_processing.py::_add_mssql_get_tgs_edges`` (lines 813-864):
    every MSSQL_Server with a known service account SID gets:
      * MSSQL_ServiceAccountFor : (User of service account) -> MSSQL_Server
      * MSSQL_GetTGS            : (User of service account) -> every MSSQL_Login on that server
      * MSSQL_GetAdminTGS       : same, but only when the login is in sysadmin (SPN-bearing)
      * HasSession              : (Computer of SQL host) -> (User of service account)

    The MSSQL_Login nodes on which we depend come from the
    ``mssql_sysadmin_edges`` fan-out — for each (sysadmin computer, db host)
    row, we synthesise the login id ``<dom>\\<sam>@<host>:1433`` and emit an
    MSSQL_GetAdminTGS edge from the service account to it.

    Service account resolution: ``wmi_sql_service_accounts.service_account``
    looks like ``mayyhem\\sqlsccmsvc`` (DOMAIN\\sam). We resolve it to the AD
    user SID via ``ldap_users.sam_account_name``.
    """
    # Two source paths for service-account discovery:
    #   1. wmi_sql_service_accounts (Win32_Service via WMI). Requires the
    #      caller to have Win32_Service read rights on each SQL host —
    #      domainadmin gets this; lowpriv/roanalyst do NOT.
    #   2. adminservice_site_systems.service_account (SMS_SCI_SysResUse
    #      Props.PropertyName="SQL Server Service Logon Account" Value2).
    #      Requires only AdminService access to the SMS Provider —
    #      roanalyst HAS this; lowpriv does not.
    #
    # CMBP merges both paths (lib/collectors/wmi_collector.py:1492 +
    # lib/collectors/adminservice_collector.py:1340). We mirror that here:
    # UNION ALL the two sources and DISTINCT on (host, svc_sam) so the same
    # (host, svc_sam) pair from both sources doesn't double-fire.
    has_wmi = _table_exists(con, schema, "wmi_sql_service_accounts")
    has_adminservice = (
        _table_exists(con, schema, "adminservice_site_systems")
        and _column_exists(con, schema, "adminservice_site_systems", "service_account")
    )
    needed = (
        (has_wmi or has_adminservice)
        and _table_exists(con, schema, "ldap_users")
        and _table_exists(con, schema, "ldap_computers")
    )
    if not needed:
        _ensure_empty(con, schema, "mssql_gettgs_edges")
        return

    svc_source_parts: list[str] = []
    if has_wmi:
        svc_source_parts.append(f"""
            SELECT
                LOWER(w.hostname) AS host,
                w.service_account
            FROM {schema}.wmi_sql_service_accounts w
            WHERE w.service_account IS NOT NULL AND w.service_account <> ''
        """)
    if has_adminservice:
        svc_source_parts.append(f"""
            SELECT
                LOWER(s.hostname) AS host,
                s.service_account
            FROM {schema}.adminservice_site_systems s
            WHERE LOWER(s.role) = 'sms sql server'
              AND s.service_account IS NOT NULL AND s.service_account <> ''
        """)
    svc_union = " UNION ALL ".join(svc_source_parts)

    # Edge target shapes (matching CMBP):
    #   * MSSQL_ServiceAccountFor : svc -> MSSQL_Server (host:1433)
    #     CMBP: lib/collectors/mssql_collector.py:572 (collector path)
    #   * MSSQL_GetAdminTGS : svc -> MSSQL_Server (host:1433)
    #     CMBP: lib/collectors/mssql_collector.py:575 (collector path).
    #     Fires once per (svc, server) — NOT per login. One edge per
    #     reachable MSSQL_Server that has a MSSQLSvc SPN match in AD.
    #   * MSSQL_GetTGS : svc -> every MSSQL_Login on the server
    #     CMBP: lib/post_processing.py:849-852. Fires for ALL logins
    #     on the server (not just sysadmin).
    #   * HasSession : Computer (db host) -> svc User
    #     CMBP: lib/collectors/mssql_collector.py:583.
    #
    # We can compute these without a live MSSQL connection because
    # we have the service account from `adminservice_site_systems`
    # (CMBP fallback) AND we have the MSSQLSvc SPN visible on
    # `ldap_users.service_principal_names` (the user account that runs
    # the SQL service is registered with `MSSQLSvc/<host>`). If the SPN
    # is registered, the host is Kerberoastable — that's the
    # GetAdminTGS gate.
    sql = f"""
    CREATE OR REPLACE TABLE {schema}.mssql_gettgs_edges AS
    WITH raw_svc AS ({svc_union}),
    svc AS (
        SELECT DISTINCT
            r.host,
            r.service_account,
            -- Strip "DOMAIN\" prefix to get bare SAM. service_account looks like
            -- 'mayyhem\\sqlsccmsvc' on disk; we keep everything after the last '\'.
            LOWER(SPLIT_PART(r.service_account, chr(92), -1)) AS svc_sam,
            u.object_sid AS svc_user_sid,
            u.service_principal_names AS svc_spns,
            c.object_sid AS host_computer_sid
        FROM raw_svc r
        LEFT JOIN {schema}.ldap_users u
            ON LOWER(u.sam_account_name) = LOWER(SPLIT_PART(r.service_account, chr(92), -1))
        LEFT JOIN {schema}.ldap_computers c
            ON LOWER(c.dns_host_name) = LOWER(r.host)
        WHERE u.object_sid IS NOT NULL
    )
    -- MSSQL_ServiceAccountFor : User SID -> MSSQL_Server (host:1433)
    -- One edge per reachable host. CMBP: 1 per MSSQL_Server.
    SELECT
        svc.svc_user_sid AS start_id,
        svc.host || ':1433' AS end_id,
        'MSSQL_ServiceAccountFor' AS edge_kind
    FROM svc
    UNION ALL
    -- HasSession : Computer (db host) -> User (service account)
    SELECT
        svc.host_computer_sid AS start_id,
        svc.svc_user_sid     AS end_id,
        'HasSession'         AS edge_kind
    FROM svc
    WHERE svc.host_computer_sid IS NOT NULL
    UNION ALL
    -- MSSQL_GetAdminTGS : svc -> MSSQL_Server (host:1433).
    -- Fires once per (svc, server) where the svc account has a MSSQLSvc/<host>
    -- SPN registered in AD. CMBP: lib/collectors/mssql_collector.py:575.
    -- The SPN match is the Kerberoasting precondition — without an MSSQLSvc
    -- SPN the service account ticket isn't Kerberoastable, and the edge
    -- doesn't fire.
    SELECT
        svc.svc_user_sid AS start_id,
        svc.host || ':1433' AS end_id,
        'MSSQL_GetAdminTGS' AS edge_kind
    FROM svc
    WHERE svc.svc_spns IS NOT NULL
      AND CAST(svc.svc_spns AS VARCHAR) ILIKE '%MSSQLSvc/' || svc.host || '%'
    UNION ALL
    -- MSSQL_GetTGS : svc user -> every MSSQL_Login on the server (any role).
    -- CMBP: lib/post_processing.py:849-852. Iterates all logins on the
    -- server, not just sysadmin.
    SELECT
        svc.svc_user_sid AS start_id,
        msa.login_name || '@' || msa.server_id AS end_id,
        'MSSQL_GetTGS' AS edge_kind
    FROM svc
    JOIN {schema}.mssql_sysadmin_edges msa
        ON LOWER(SPLIT_PART(msa.server_id, ':', 1)) = svc.host
    ;
    """
    _safe_exec(con, sql, "mssql_gettgs_edges")


def _build_secret_policy_edges(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """SCCM_HasNetworkAccessAccount / HasStoredAccount / HasCollectionVar / HasTaskSequence.

    Each secret discovered by CRED-* attack flows is tagged with a
    ``discovered_in_site`` and a ``discovered_secret_type``. SCCM_ClientDevice
    nodes in that site each get an edge. None of CRED-2/3/5/6 are implemented
    yet, so the upstream tables are typically empty; the SQL produces zero
    rows gracefully.
    """
    # CMBP only emits these edges for nodes that carry both
    # ``discoveredSecretType`` AND ``discoveredInSite`` properties — i.e.
    # secrets that were *actually decrypted* by the CRED-* attack flows
    # (NAA decrypt, collection-variable decrypt, task-sequence decrypt).
    # The bare existence of an SMS_TaskSequencePackage / SMS_CollectionVariable
    # row is NOT enough: those are policy artefacts, not extracted secrets.
    # Phase 4 wired ``adminservice_task_sequences`` here as a placeholder, but
    # this caused a 20-edge over-emit on every device-with-task-sequence
    # cross-join. Phase 6 narrows the source list to the CRED-* output tables
    # only (still empty in the lab — CRED-* attack flows are stubs — so this
    # view stays at 0 rows until they're implemented).
    secret_tables = []
    for table, edge_kind in [
        ("local_naa_secrets",        "SCCM_HasNetworkAccessAccount"),
        ("http_naa_secrets",         "SCCM_HasNetworkAccessAccount"),
        ("http_collection_secrets",  "SCCM_HasStoredAccount"),
    ]:
        if _table_exists(con, schema, table):
            secret_tables.append((table, edge_kind))

    if not secret_tables or not _table_exists(con, schema, "adminservice_client_devices"):
        _ensure_empty(con, schema, "secret_policy_edges")
        return

    parts = []
    for table, edge_kind in secret_tables:
        # adminservice_collection_variables / adminservice_task_sequences are
        # the only "known-shape" tables we know exist with site_code already
        # in their schema; the others are stubs and may have no
        # ``discovered_in_site`` column.
        if not _column_exists(con, schema, table, "site_code"):
            continue
        # Synthesise a per-secret id: collection_variables get
        # ``CV:<collection_id>:<name>``, task_sequences get
        # ``TS:<package_id>``. NAA / stored accounts (when implemented) will
        # carry their own ``id`` field and will wire in here.
        if table == "adminservice_collection_variables":
            id_expr = "'CV:' || COALESCE(t.collection_id, '') || ':' || COALESCE(t.name, '')"
            site_expr = "t.site_code"
        elif table == "adminservice_task_sequences":
            id_expr = "'TS:' || COALESCE(CAST(t.package_id AS VARCHAR), '')"
            site_expr = "t.site_code"
        else:
            # NAA / stored-account stub schemas — best-effort with safe fallbacks.
            id_expr = "COALESCE(t.name, '')"
            site_expr = "t.site_code"

        parts.append(f"""
        SELECT DISTINCT
            'GUID:' || cd.guid AS start_id,
            {id_expr}          AS end_id,
            '{edge_kind}'      AS edge_kind
        FROM {schema}.{table} t
        JOIN {schema}.adminservice_client_devices cd
            ON LOWER(cd.site_code) = LOWER({site_expr})
        WHERE cd.guid IS NOT NULL AND cd.guid <> ''
          AND {id_expr} IS NOT NULL AND {id_expr} <> ''
        """)

    if not parts:
        _ensure_empty(con, schema, "secret_policy_edges")
        return

    union_sql = " UNION ALL ".join(f"SELECT * FROM ({p})" for p in parts)
    sql = f"CREATE OR REPLACE TABLE {schema}.secret_policy_edges AS {union_sql}"
    _safe_exec(con, sql, "secret_policy_edges")


# ---------------------------------------------------------------------------
# Phase 6 — gap-closure derived edge views.
# ---------------------------------------------------------------------------
# These views materialise the per-row edges that CMBP emits inline from its
# AdminService collector at collect time (see
# ``lib/collectors/adminservice_collector.py``):
#
#   * ``SCCM_HasMember``           collection -> client device
#   * ``SCCM_HasClient``           site       -> client device
#   * ``SCCM_HasADLastLogonUser``  device     -> user (last logon)
#   * ``SCCM_HasCurrentUser``      device     -> user (currently logged in)
#   * ``SCCM_HasPrimaryUser``      device     -> user (primary user)
#   * ``SCCM_IsAssigned``          admin      -> {role, collection}
#   * ``SCCM_IsMappedTo``          principal  -> admin user
#   * ``MemberOf`` extras          computer   -> security group via SMS_R_System
#
# All of these are simple JOINs over the AdminService raw tables already
# materialised by collect; we keep them in DuckDB for the same reasons as
# the Phase 4 derived views (testable, idempotent, degrades gracefully
# when upstream tables are absent).


def _build_has_member_edges(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """SCCM_HasMember: SCCM_Collection -> SCCM_ClientDevice.

    One edge per (collection, resource_id) row in
    ``adminservice_collection_members`` where the resource has a corresponding
    SCCM_ClientDevice row. The collection id carries the hierarchy root for
    the rewriting rule (Risk 1).
    """
    needed = (
        _table_exists(con, schema, "adminservice_collection_members")
        and _table_exists(con, schema, "adminservice_client_devices")
        and _table_exists(con, schema, "hierarchies")
    )
    if not needed:
        _ensure_empty(con, schema, "has_member_edges")
        return

    sql = f"""
    CREATE OR REPLACE TABLE {schema}.has_member_edges AS
    SELECT DISTINCT
        cm.collection_id || '@' || h.root_code AS start_id,
        'GUID:' || cd.guid                      AS end_id
    FROM {schema}.adminservice_collection_members cm
    JOIN {schema}.adminservice_client_devices cd
      ON cd.resource_id      = cm.resource_id
     AND LOWER(cd.site_code) = LOWER(cm.site_code)
    JOIN {schema}.hierarchies h
      ON LOWER(h.member_code) = LOWER(cm.site_code)
    WHERE cd.guid IS NOT NULL AND cd.guid <> ''
      AND cm.collection_id IS NOT NULL AND cm.collection_id <> '';
    """
    _safe_exec(con, sql, "has_member_edges")


def _build_has_client_edges(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """SCCM_HasClient: SCCM_Site -> SCCM_ClientDevice.

    CMBP emits this edge from TWO sources (matching their own ``upsert_edge``
    dedup semantics):

      1. ``_get_combined_device_resources``: ``assigned_site -> device``
         (the device's own reported SiteCode).
      2. ``_get_sms_r_system`` (per-provider, called once for every reachable
         SMS Provider): ``<provider_site_code> -> device``.

    With (1) the start is the device's ``assigned_site`` (typically the
    Primary site only). With (2) the start is each provider's site_code
    (CAS + Primary in a CAS-led hierarchy).

    We replicate this by emitting one edge per (site_code in the hierarchy
    of any SMS Provider, non-Secondary, device). This produces the same
    set as CMBP after dedup.
    """
    if not (
        _table_exists(con, schema, "adminservice_client_devices")
        and _table_exists(con, schema, "site_types")
    ):
        _ensure_empty(con, schema, "has_client_edges")
        return

    # CMBP emits SCCM_HasClient edges per discovery path. After the
    # post-processing `rename_node` merges device ids by ADDomainSID,
    # the JSON output contains:
    #   * one canonical edge per (provider_site, device) — typically
    #     ``(CAS, GUID:<sms>)`` and ``(<primary>, GUID:<sms>)``;
    #   * one duplicate per (assigned_site, device) when the same
    #     device was also discovered via a second path (LDAP-CmRcService
    #     SPN match) — the rename collapses both onto the same
    #     canonical key and the duplicate-retention semantic keeps the
    #     extra copy.
    #
    # We replicate this by emitting one unique row per (site, device)
    # tagged with ``AdminService`` as the source, plus one extra row
    # per device that appears in the LDAP-CmRcService path (the
    # duplicate, tagged with ``LDAP-CmRcService``). The output-stage
    # dedup keys on (start, end, kind, collection_source) so each row
    # produces a distinct edge in the JSON.
    sql = f"""
    CREATE OR REPLACE TABLE {schema}.has_client_edges AS
    WITH unique_paths AS (
        -- One canonical edge per (provider_site_in_hierarchy, device).
        -- The CAS+Primary cross-product reflects the multi-provider
        -- AdminService crawl ((PS1, dev) and (CAS, dev) both appear).
        SELECT s.site_code AS start_id,
               'GUID:' || cd.guid AS end_id,
               'AdminService' AS collection_source
        FROM {schema}.adminservice_client_devices cd
        CROSS JOIN {schema}.site_types s
        WHERE cd.source LIKE 'AdminService%'
          AND s.site_type IN ('CAS', 'Primary')
          AND cd.guid IS NOT NULL AND cd.guid <> ''
    ),
    cmrc_rows AS (
        -- LDAP-CmRcService rows reuse the AdminService GUID when one
        -- exists. Each row produces ONE duplicate edge (assigned_site,
        -- device) on top of the canonical AdminService edge.
        SELECT cd.site_code AS start_id,
               'GUID:' || cd.guid AS end_id,
               'LDAP-CmRcService' AS collection_source
        FROM {schema}.adminservice_client_devices cd
        WHERE cd.source = 'LDAP-CmRcService'
          AND cd.guid IS NOT NULL AND cd.guid <> ''
          AND cd.site_code IS NOT NULL AND cd.site_code <> ''
    )
    SELECT DISTINCT start_id, end_id, collection_source FROM unique_paths
    UNION ALL
    SELECT DISTINCT start_id, end_id, collection_source FROM cmrc_rows
    ;
    """
    _safe_exec(con, sql, "has_client_edges")


def _build_client_user_edges(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """SCCM_HasADLastLogonUser / SCCM_HasCurrentUser / SCCM_HasPrimaryUser.

    AdminService reports ``LastLogonUser`` / ``CurrentLogonUser`` /
    ``PrimaryUser`` per ``SMS_CombinedDeviceResources`` row. These are
    short ``DOMAIN\\sam`` strings; we resolve to a User object_sid via
    ``ldap_users.sam_account_name`` and emit a typed edge per populated
    column.
    """
    needed = (
        _table_exists(con, schema, "adminservice_client_devices")
        and _table_exists(con, schema, "ldap_users")
    )
    if not needed:
        _ensure_empty(con, schema, "client_user_edges")
        return

    # CMBP normalises ``DOMAIN\\user`` and bare ``user``.
    # We match on the bare sAMAccountName (case-insensitive) — this is what
    # CMBP's ADResolver.resolve_principal does after splitting the backslash.
    # ``LIST_EXTRACT(STRING_SPLIT(s, chr(92)), -1)`` returns the substring
    # after the LAST backslash (chr(92) = ``\``) — DuckDB list arithmetic
    # supports negative indexes. Robust to bare usernames (no backslash) and
    # to extra/double backslash variants.
    sql = f"""
    CREATE OR REPLACE TABLE {schema}.client_user_edges AS
    WITH device_users AS (
        SELECT 'GUID:' || cd.guid AS device_id,
               LOWER(LIST_EXTRACT(STRING_SPLIT(COALESCE(cd.last_logon_user, ''), chr(92)), -1)) AS last_user_sam,
               LOWER(LIST_EXTRACT(STRING_SPLIT(COALESCE(cd."current_user", ''), chr(92)), -1)) AS curr_user_sam,
               LOWER(LIST_EXTRACT(STRING_SPLIT(COALESCE(cd.primary_user,    ''), chr(92)), -1)) AS prim_user_sam
        FROM {schema}.adminservice_client_devices cd
        WHERE cd.guid IS NOT NULL AND cd.guid <> ''
    )
    SELECT du.device_id AS start_id, u.object_sid AS end_id, 'SCCM_HasADLastLogonUser' AS edge_kind
    FROM device_users du JOIN {schema}.ldap_users u
        ON LOWER(u.sam_account_name) = du.last_user_sam
    WHERE du.last_user_sam <> ''
    UNION ALL
    SELECT du.device_id AS start_id, u.object_sid AS end_id, 'SCCM_HasCurrentUser' AS edge_kind
    FROM device_users du JOIN {schema}.ldap_users u
        ON LOWER(u.sam_account_name) = du.curr_user_sam
    WHERE du.curr_user_sam <> ''
    UNION ALL
    SELECT du.device_id AS start_id, u.object_sid AS end_id, 'SCCM_HasPrimaryUser' AS edge_kind
    FROM device_users du JOIN {schema}.ldap_users u
        ON LOWER(u.sam_account_name) = du.prim_user_sam
    WHERE du.prim_user_sam <> ''
    ;
    """
    _safe_exec(con, sql, "client_user_edges")


def _build_is_assigned_edges(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """SCCM_IsAssigned: SCCM_AdminUser -> SCCM_SecurityRole / SCCM_Collection.

    Every (admin, role, scope_collection) tuple from
    ``adminservice_role_members`` produces:
      * one edge admin -> role
      * one edge admin -> collection (if scope_collection_id is non-empty)
    Both use hierarchy-rewritten ids.
    """
    needed = (
        _table_exists(con, schema, "adminservice_role_members")
        and _table_exists(con, schema, "hierarchies")
    )
    if not needed:
        _ensure_empty(con, schema, "is_assigned_edges")
        return

    # CMBP queries SMS_Admin once per SMS Provider (CAS + Primary
    # only — Secondary sites don't host an SMS Provider). Each
    # provider emits ``(admin@<provider>, role@<provider>)`` /
    # ``(admin@<provider>, coll@<provider>)`` edges. Post-processing
    # rewrites the provider-site suffix to the hierarchy root, so
    # ``admin@PS1 -> role@PS1`` becomes ``admin@CAS -> role@CAS``. The
    # rename collision retains the renamed edge as a duplicate.
    #
    # We replicate this by emitting one row per (admin, role/coll,
    # provider_site_code) where provider_site is CAS or a Primary in
    # the hierarchy. The output-stage dedup key on
    # ``collection_source`` keeps each provider variant as a distinct
    # JSON edge.
    needed_st = _table_exists(con, schema, "site_types")
    site_types_join = (
        f"JOIN {schema}.site_types st ON st.site_code = h.member_code AND st.site_type IN ('CAS', 'Primary')"
        if needed_st
        else ""
    )
    sql = f"""
    CREATE OR REPLACE TABLE {schema}.is_assigned_edges AS
    -- admin -> role, one row per CAS / Primary provider in the hierarchy.
    SELECT DISTINCT
        LOWER(rm.admin_logon_name) || '@' || h.root_code AS start_id,
        rm.role_id || '@' || h.root_code                  AS end_id,
        'AdminService-SMS_Admin@' || h.member_code        AS collection_source
    FROM {schema}.adminservice_role_members rm
    JOIN {schema}.hierarchies h
      ON h.root_code = (
          SELECT h2.root_code FROM {schema}.hierarchies h2
          WHERE LOWER(h2.member_code) = LOWER(rm.site_code) LIMIT 1
      )
    {site_types_join}
    WHERE rm.role_id IS NOT NULL AND rm.role_id <> ''
    UNION ALL
    -- admin -> collection, one row per CAS / Primary provider.
    SELECT DISTINCT
        LOWER(rm.admin_logon_name) || '@' || h.root_code AS start_id,
        rm.scope_collection_id || '@' || h.root_code      AS end_id,
        'AdminService-SMS_Admin@' || h.member_code        AS collection_source
    FROM {schema}.adminservice_role_members rm
    JOIN {schema}.hierarchies h
      ON h.root_code = (
          SELECT h2.root_code FROM {schema}.hierarchies h2
          WHERE LOWER(h2.member_code) = LOWER(rm.site_code) LIMIT 1
      )
    {site_types_join}
    WHERE rm.scope_collection_id IS NOT NULL
      AND rm.scope_collection_id <> ''
    ;
    """
    _safe_exec(con, sql, "is_assigned_edges")


def _build_is_mapped_to_edges(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """SCCM_IsMappedTo: AD User/Group -> SCCM_AdminUser when admin_sid matches.

    CMBP uses the ADResolver to look up admin_sid against either users or
    groups in AD. We mirror this by joining ``ldap_users`` first then
    ``ldap_groups`` (both should hit the same SID space).

    Per-provider fan-out: like SCCM_IsAssigned, CMBP queries SMS_Admin once
    per SMS Provider site (CAS + Primary). Each provider emits a fresh
    ``IsMappedTo`` edge for the same (admin_sid -> AdminUser) pair, and the
    post-processing rewrites collide on the hierarchy root id, but the
    rename-collision retains duplicates. Mirrored here by emitting one row
    per (start_sid, admin@root, provider_site_code) restricted to
    CAS / Primary providers — combined with ``output.py``'s widened
    ``(start, end, kind, collectionSource)`` dedup key, this closes the
    -3 IsMappedTo gap for full-access users.
    """
    needed = (
        _table_exists(con, schema, "adminservice_admins")
        and _table_exists(con, schema, "hierarchies")
    )
    if not needed:
        _ensure_empty(con, schema, "is_mapped_to_edges")
        return

    has_users = _table_exists(con, schema, "ldap_users")
    has_groups = _table_exists(con, schema, "ldap_groups")
    if not (has_users or has_groups):
        _ensure_empty(con, schema, "is_mapped_to_edges")
        return

    needed_st = _table_exists(con, schema, "site_types")
    site_types_join = (
        f"JOIN {schema}.site_types st ON st.site_code = h.member_code AND st.site_type IN ('CAS', 'Primary')"
        if needed_st
        else ""
    )

    parts: list[str] = []
    if has_users:
        parts.append(f"""
        SELECT DISTINCT
            u.object_sid                                       AS start_id,
            LOWER(a.logon_name) || '@' || h.root_code           AS end_id,
            'AdminService-SMS_Admin@' || h.member_code          AS collection_source
        FROM {schema}.adminservice_admins a
        JOIN {schema}.hierarchies h
          ON h.root_code = (
              SELECT h2.root_code FROM {schema}.hierarchies h2
              WHERE LOWER(h2.member_code) = LOWER(a.site_code) LIMIT 1
          )
        {site_types_join}
        JOIN {schema}.ldap_users u
          ON LOWER(u.object_sid) = LOWER(a.admin_sid)
        WHERE a.admin_sid IS NOT NULL AND a.admin_sid <> ''
        """)
    if has_groups:
        parts.append(f"""
        SELECT DISTINCT
            g.object_sid                                       AS start_id,
            LOWER(a.logon_name) || '@' || h.root_code           AS end_id,
            'AdminService-SMS_Admin@' || h.member_code          AS collection_source
        FROM {schema}.adminservice_admins a
        JOIN {schema}.hierarchies h
          ON h.root_code = (
              SELECT h2.root_code FROM {schema}.hierarchies h2
              WHERE LOWER(h2.member_code) = LOWER(a.site_code) LIMIT 1
          )
        {site_types_join}
        JOIN {schema}.ldap_groups g
          ON LOWER(g.object_sid) = LOWER(a.admin_sid)
        WHERE a.admin_sid IS NOT NULL AND a.admin_sid <> ''
        """)

    union_sql = " UNION ALL ".join(f"SELECT * FROM ({p})" for p in parts)
    sql = f"CREATE OR REPLACE TABLE {schema}.is_mapped_to_edges AS {union_sql}"
    _safe_exec(con, sql, "is_mapped_to_edges")


def _build_r_system_member_of_edges(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """MemberOf: Computer -> Group via SMS_R_System SecurityGroupName.

    Joins ``adminservice_r_system_security_groups`` against:
      * ``ldap_computers`` for the Computer object_sid (start_id)
      * ``ldap_groups``    for the Group object_sid    (end_id)

    Group names from SMS_R_System come back as ``DOMAIN\\GROUP``; we strip
    the prefix the same way AD ``CN=`` resolution does.
    """
    needed = (
        _table_exists(con, schema, "adminservice_r_system_security_groups")
        and _table_exists(con, schema, "ldap_computers")
        and _table_exists(con, schema, "ldap_groups")
    )
    if not needed:
        _ensure_empty(con, schema, "r_system_member_of_edges")
        return

    sql = f"""
    CREATE OR REPLACE TABLE {schema}.r_system_member_of_edges AS
    SELECT DISTINCT
        c.object_sid AS start_id,
        g.object_sid AS end_id
    FROM {schema}.adminservice_r_system_security_groups r
    JOIN {schema}.ldap_computers c
        ON LOWER(c.name) = LOWER(r.machine_name)
        OR LOWER(c.sam_account_name) = LOWER(r.machine_name) || '$'
        OR LOWER(c.dns_host_name) = LOWER(r.machine_name)
    JOIN {schema}.ldap_groups g
        ON LOWER(g.sam_account_name) = LOWER(LIST_EXTRACT(STRING_SPLIT(r.security_group_name, chr(92)), -1))
        OR LOWER(g.name)             = LOWER(LIST_EXTRACT(STRING_SPLIT(r.security_group_name, chr(92)), -1))
    WHERE c.object_sid IS NOT NULL AND c.object_sid <> ''
      AND g.object_sid IS NOT NULL AND g.object_sid <> ''
    ;
    """
    _safe_exec(con, sql, "r_system_member_of_edges")


def _build_registry_has_session_edges(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """HasSession: Computer -> User from registry-discovered current users
    and WMI CCM_UsersSeenOnSystem rows.

    CMBP emits these from ``registry_collector._read_current_user`` (line
    667) and ``wmi_collector`` per-user. We resolve the user name (typically
    ``DOMAIN\\sam`` or bare ``sam``) to ``ldap_users.object_sid`` and join
    against ``ldap_computers`` for the host SID.
    """
    parts: list[str] = []

    if (
        _table_exists(con, schema, "registry_current_users")
        and _table_exists(con, schema, "ldap_users")
        and _table_exists(con, schema, "ldap_computers")
    ):
        parts.append(f"""
        SELECT DISTINCT
            c.object_sid AS start_id,
            u.object_sid AS end_id
        FROM {schema}.registry_current_users r
        JOIN {schema}.ldap_users u
            ON LOWER(u.sam_account_name) = LOWER(LIST_EXTRACT(STRING_SPLIT(r.user_name, chr(92)), -1))
        JOIN {schema}.ldap_computers c
            ON LOWER(c.dns_host_name) = LOWER(r.hostname)
            OR LOWER(c.name) = LOWER(SPLIT_PART(r.hostname, '.', 1))
        WHERE u.object_sid IS NOT NULL AND u.object_sid <> ''
          AND c.object_sid IS NOT NULL AND c.object_sid <> ''
        """)

    if (
        _table_exists(con, schema, "wmi_users_seen")
        and _table_exists(con, schema, "ldap_users")
        and _table_exists(con, schema, "ldap_computers")
    ):
        parts.append(f"""
        SELECT DISTINCT
            c.object_sid AS start_id,
            u.object_sid AS end_id
        FROM {schema}.wmi_users_seen w
        JOIN {schema}.ldap_users u
            ON LOWER(u.sam_account_name) = LOWER(LIST_EXTRACT(STRING_SPLIT(w.user_name, chr(92)), -1))
        JOIN {schema}.ldap_computers c
            ON LOWER(c.dns_host_name) = LOWER(w.hostname)
            OR LOWER(c.name) = LOWER(SPLIT_PART(w.hostname, '.', 1))
        WHERE u.object_sid IS NOT NULL AND u.object_sid <> ''
          AND c.object_sid IS NOT NULL AND c.object_sid <> ''
        """)

    if not parts:
        _ensure_empty(con, schema, "registry_has_session_edges")
        return

    union_sql = " UNION ".join(f"SELECT * FROM ({p})" for p in parts)
    sql = f"CREATE OR REPLACE TABLE {schema}.registry_has_session_edges AS {union_sql}"
    _safe_exec(con, sql, "registry_has_session_edges")


def _build_has_stored_account_edges(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """SCCM_HasStoredAccount: SCCM_Site -> User from SMS_SCI_Reserved.

    CMBP's ``adminservice_collector._get_stored_accounts`` resolves the
    account_username (typically ``DOMAIN\\sam``) against AD and emits a
    ``SCCM_HasStoredAccount`` edge from the ``SCCM_Site`` (id = site_code)
    to the resolved User SID. We mirror by joining
    ``adminservice_reserved_accounts`` against ``ldap_users``.
    """
    if not (
        _table_exists(con, schema, "adminservice_reserved_accounts")
        and _table_exists(con, schema, "ldap_users")
    ):
        _ensure_empty(con, schema, "has_stored_account_edges")
        return

    # account_username may be "DOMAIN\sam", "sam", or in rare cases UPN
    # ("user@domain"). Resolve via sAMAccountName match (case-insensitive),
    # falling back to upn when present. CMBP's ``ad_resolver.resolve_principal``
    # uses the same precedence.
    sql = f"""
    CREATE OR REPLACE TABLE {schema}.has_stored_account_edges AS
    SELECT DISTINCT
        r.site_code  AS start_id,
        u.object_sid AS end_id
    FROM {schema}.adminservice_reserved_accounts r
    JOIN {schema}.ldap_users u
        ON LOWER(u.sam_account_name) =
           LOWER(LIST_EXTRACT(STRING_SPLIT(r.account_username, chr(92)), -1))
        OR LOWER(u.user_principal_name) = LOWER(r.account_username)
    WHERE u.object_sid IS NOT NULL AND u.object_sid <> ''
      AND r.site_code IS NOT NULL AND r.site_code <> ''
    ;
    """
    _safe_exec(con, sql, "has_stored_account_edges")


def _build_r_user_member_of_edges(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """MemberOf: User -> Group via SMS_R_User SecurityGroupName.

    Joins ``adminservice_r_user_security_groups`` against:
      * ``ldap_users``  for the User object_sid (start_id), preferring an
                        SID match on the SMS_R_User row's SID directly,
                        with fallbacks to UserPrincipalName /
                        UniqueUserName / sAMAccountName.
      * ``ldap_groups`` for the Group object_sid (end_id), matching on
                        the bare group name after stripping the
                        ``DOMAIN\\`` prefix.

    Mirrors CMBP's ``adminservice_collector._get_sms_r_user`` (lines
    757-870).
    """
    needed = (
        _table_exists(con, schema, "adminservice_r_user_security_groups")
        and _table_exists(con, schema, "ldap_users")
        and _table_exists(con, schema, "ldap_groups")
    )
    if not needed:
        _ensure_empty(con, schema, "r_user_member_of_edges")
        return

    sql = f"""
    CREATE OR REPLACE TABLE {schema}.r_user_member_of_edges AS
    SELECT DISTINCT
        u.object_sid AS start_id,
        g.object_sid AS end_id
    FROM {schema}.adminservice_r_user_security_groups r
    JOIN {schema}.ldap_users u
        ON LOWER(u.object_sid) = LOWER(r.user_sid)
        OR LOWER(u.sam_account_name) = LOWER(r.user_sam_account_name)
        OR LOWER(u.sam_account_name) = LOWER(LIST_EXTRACT(STRING_SPLIT(r.user_name, chr(92)), -1))
    JOIN {schema}.ldap_groups g
        ON LOWER(g.sam_account_name) = LOWER(LIST_EXTRACT(STRING_SPLIT(r.security_group_name, chr(92)), -1))
        OR LOWER(g.name)             = LOWER(LIST_EXTRACT(STRING_SPLIT(r.security_group_name, chr(92)), -1))
    WHERE u.object_sid IS NOT NULL AND u.object_sid <> ''
      AND g.object_sid IS NOT NULL AND g.object_sid <> ''
    ;
    """
    _safe_exec(con, sql, "r_user_member_of_edges")


# ---------------------------------------------------------------------------
# Public entrypoint.
# ---------------------------------------------------------------------------

def transforms(con: duckdb.DuckDBPyConnection, schema: str = "sccm") -> None:
    """Apply all preprocessing transformations to the DuckDB lookup database.

    Runs in dependency order: targets first (used by everything), site_types +
    hierarchies next (drives ID rewriting AND every derived edge), then the
    individual derived-edge tables.
    """
    con.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")

    _build_targets(con, schema)
    _build_site_types(con, schema)
    _build_hierarchies(con, schema)

    _build_admins_replicated_to(con, schema)
    _build_contains(con, schema)
    _build_role_assignment_edges(con, schema)
    _build_all_permissions(con, schema)
    _build_same_host_as(con, schema)
    _build_local_admin_required(con, schema)
    _build_assign_all_permissions(con, schema)
    _build_mssql_sysadmin_edges(con, schema)
    _build_mssql_server_hierarchy_edges(con, schema)
    _build_coerce_and_relay_edges(con, schema)
    _build_mssql_gettgs_edges(con, schema)
    _build_secret_policy_edges(con, schema)
    # Phase 6 gap-closure views — emit per-row edges that CMBP produces
    # inline in its AdminService collector.
    _build_has_member_edges(con, schema)
    _build_has_client_edges(con, schema)
    _build_client_user_edges(con, schema)
    _build_is_assigned_edges(con, schema)
    _build_is_mapped_to_edges(con, schema)
    _build_r_system_member_of_edges(con, schema)
    _build_r_user_member_of_edges(con, schema)
    _build_registry_has_session_edges(con, schema)
    _build_has_stored_account_edges(con, schema)
