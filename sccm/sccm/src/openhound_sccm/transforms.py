# src/openhound_sccm/transforms.py
"""DuckDB transforms for the SCCM collector's preproc phase.

Stage 1 builds the cross-cutting lookup tables (`principal_by_name`, site hierarchy
with `root_site_code`) and — added in later tasks — the coalesced `node_*` tables and
`graph_edges`. Each builder is defensive: a missing source table is logged and
skipped (early stages won't have collected everything).
"""
import logging

import duckdb

logger = logging.getLogger(__name__)


def _safe(con: duckdb.DuckDBPyConnection, label: str, sql: str) -> None:
    """Run one SQL statement; log and continue if a source table is missing."""
    try:
        con.execute(sql)
    except duckdb.CatalogException as err:
        # A missing source table is expected when not all collectors have run.
        logger.warning("transform %r skipped (missing source): %s", label, err)
    except duckdb.Error as err:
        logger.error("transform %r failed: %s", label, err)


def _ensure_columns(
    con: duckdb.DuckDBPyConnection,
    schema: str,
    table: str,
    coldefs: dict[str, str],
) -> None:
    """Add any missing columns (as NULL, typed) so a coalesce SELECT always binds.

    A coalesce SELECT references source columns inside expressions
    (e.g. ``_arr('sccm_site_system_roles')``, ``coalesce(sccm_infra, false)``).
    ``INSERT ... BY NAME`` only maps the *output* aliases, so every referenced
    source column must physically exist or the whole SELECT fails to compile and
    ``_safe`` drops the source. Two real-data reasons a column goes missing:

      * the source never emits it (e.g. ldap_cmrc_devices has no roles column), or
      * dlt drops a column that is all-NULL across the load.

    We pre-create the union of optional columns each coalesce references so the
    SELECTs bind regardless. Adding a column the SELECT doesn't read is harmless
    (``INSERT ... BY NAME`` ignores it); an already-present column keeps its real
    type (we only add when missing). No-op if the table doesn't exist — the
    following ``_safe`` INSERT logs that skip.
    """
    exists = con.execute(
        "SELECT 1 FROM information_schema.tables "
        "WHERE table_schema = ? AND table_name = ?",
        [schema, table],
    ).fetchone()
    if not exists:
        # Missing table is handled (and logged) by the _safe INSERT that follows.
        logger.debug("ensure_columns: table %s.%s absent; nothing to do", schema, table)
        return

    have = {
        row[0]
        for row in con.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = ? AND table_name = ?",
            [schema, table],
        ).fetchall()
    }
    for col, sqltype in coldefs.items():
        if col in have:
            continue
        # Column referenced by a coalesce SELECT but absent in this load — add as NULL.
        con.execute(f'ALTER TABLE {schema}.{table} ADD COLUMN "{col}" {sqltype}')
        logger.debug("ensure_columns: added %s.%s.%s (%s)", schema, table, col, sqltype)


def _principal_by_name(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Union every collected (name, SID) pair for offline name->SID resolution.

    Each source table is optional — a missing table is logged and skipped. The
    result is deduplicated with SIDs uppercased; names are stored in their
    original casing (callers must upper() both sides when joining on name).
    """
    con.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
    con.execute(f"CREATE OR REPLACE TABLE {schema}.principal_by_name (name VARCHAR, sid VARCHAR)")

    # Each entry is (label, SELECT statement yielding (name, sid) columns).
    sources = [
        ("principal_by_name<-adminservice_r_system",
         f"SELECT name, sid FROM {schema}.adminservice_r_system WHERE sid IS NOT NULL"),
        ("principal_by_name<-wmi_r_system",
         f"SELECT name, sid FROM {schema}.wmi_r_system WHERE sid IS NOT NULL"),
        ("principal_by_name<-adminservice_r_user",
         f"SELECT name, sid FROM {schema}.adminservice_r_user WHERE sid IS NOT NULL"),
        ("principal_by_name<-wmi_r_user",
         f"SELECT name, sid FROM {schema}.wmi_r_user WHERE sid IS NOT NULL"),
        # SMS_R_UserGroup carries each security group's own SID + its DOMAIN\name
        # (unique_usergroup_name), so the security_group_name memberships on r_system /
        # r_user rows resolve to a group SID here (offline) instead of a live AD lookup.
        ("principal_by_name<-adminservice_user_group",
         f"SELECT unique_usergroup_name AS name, sid FROM {schema}.adminservice_user_group WHERE sid IS NOT NULL"),
        ("principal_by_name<-wmi_user_group",
         f"SELECT unique_usergroup_name AS name, sid FROM {schema}.wmi_user_group WHERE sid IS NOT NULL"),
        ("principal_by_name<-adminservice_admins",
         f"SELECT logon_name AS name, admin_sid AS sid FROM {schema}.adminservice_admins WHERE admin_sid IS NOT NULL"),
        ("principal_by_name<-wmi_admins",
         f"SELECT logon_name AS name, admin_sid AS sid FROM {schema}.wmi_admins WHERE admin_sid IS NOT NULL"),
    ]

    for label, select_sql in sources:
        # Preserve the original name casing; only uppercase the SID for consistent lookups.
        _safe(
            con,
            label,
            f"INSERT INTO {schema}.principal_by_name "
            f"SELECT trim(name), upper(sid) FROM ({select_sql})",
        )

    # Replace the raw inserts with a deduplicated copy.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.principal_by_name AS "
        f"SELECT DISTINCT name, sid FROM {schema}.principal_by_name "
        f"WHERE name IS NOT NULL AND sid IS NOT NULL"
    )
    logger.info("principal_by_name built in schema %r", schema)


def _site_hierarchy(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Build site_code/parent_site_code/site_type, then stamp root_site_code.

    Root = the CAS (site_type=4) if present, else a parentless Primary
    (site_type=2), matching CMBP Get-HierarchyRoot (ps1:2620). Single-hierarchy
    assumption (README Assumptions): one root per graph.
    """
    con.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.site_hierarchy "
        f"(site_code VARCHAR, parent_site_code VARCHAR, site_type INTEGER)"
    )

    # Load from whichever site-definition sources were collected.
    _safe(
        con,
        "site_hierarchy<-adminservice",
        f"INSERT INTO {schema}.site_hierarchy "
        f"SELECT site_code, parent_site_code, TRY_CAST(site_type AS INTEGER) "
        f"FROM {schema}.adminservice_site_definitions",
    )
    _safe(
        con,
        "site_hierarchy<-wmi",
        f"INSERT INTO {schema}.site_hierarchy "
        f"SELECT site_code, parent_site_code, TRY_CAST(site_type AS INTEGER) "
        f"FROM {schema}.wmi_site_definitions",
    )

    # Collapse duplicate rows (same site_code from multiple sources).
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.site_hierarchy AS "
        f"SELECT site_code, "
        f"       any_value(parent_site_code) AS parent_site_code, "
        f"       max(site_type) AS site_type "
        f"FROM {schema}.site_hierarchy "
        f"WHERE site_code IS NOT NULL "
        f"GROUP BY site_code"
    )

    # Determine the root: CAS (type 4) takes priority; fall back to a parentless
    # Primary (type 2) for single-Primary hierarchies with no CAS.
    root = con.execute(
        f"SELECT site_code FROM {schema}.site_hierarchy WHERE site_type = 4 "
        f"UNION ALL "
        f"SELECT site_code FROM {schema}.site_hierarchy "
        f"WHERE site_type = 2 "
        f"  AND (parent_site_code IS NULL OR parent_site_code IN ('', 'None', 'Undetermined')) "
        f"LIMIT 1"
    ).fetchone()

    root_code = root[0] if root else None

    if root_code:
        logger.info("site_hierarchy root resolved to %r in schema %r", root_code, schema)
    else:
        logger.warning("site_hierarchy: no root site found in schema %r", schema)

    # Stamp every row with the resolved root.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.site_hierarchy AS "
        f"SELECT site_code, parent_site_code, site_type, ? AS root_site_code "
        f"FROM {schema}.site_hierarchy",
        [root_code],
    )


def _arr(col: str) -> str:
    """Return SQL that normalises a role column to VARCHAR[], whatever its shape.

    Across the collectors the same logical role list arrives in *four* physical
    shapes, so the result is always VARCHAR[] for uniform aggregation:

      * NULL                                   -> ``[]``
      * a VARCHAR holding JSON-array TEXT       -> parsed JSON elements
        (e.g. ``'["SMS Site Server@CAS","SMS Distribution Point@CAS"]'`` from the
        smb / remoteregistry collectors, which stringify a Python list)
      * a plain/comma-joined VARCHAR scalar     -> ``string_split(.,',')``
        (e.g. ``'SMS Management Point@PS1'`` from site_definitions_computers/http)
      * a native JSON array or VARCHAR[] list   -> ``CAST(. AS VARCHAR[])``
        (e.g. ``system_roles`` which dlt types as JSON)

    The JSON branch is gated on a leading ``[`` (after trimming) so only true
    array text takes it; ``TRY_CAST`` + ``coalesce`` mean malformed JSON degrades
    to ``[]`` rather than failing the whole INSERT. DuckDB's ``typeof()`` returns
    'VARCHAR' for scalars/JSON-text and 'JSON'/'VARCHAR[]' for the native shapes.
    """
    as_varchar = f"CAST({col} AS VARCHAR)"
    return (
        f"CASE "
        f"WHEN {col} IS NULL THEN CAST([] AS VARCHAR[]) "
        # VARCHAR that *contains* JSON-array text: parse it, not comma-split it.
        f"WHEN typeof({col}) = 'VARCHAR' AND ltrim({as_varchar}) LIKE '[%' "
        f"  THEN coalesce(CAST(TRY_CAST({as_varchar} AS JSON) AS VARCHAR[]), CAST([] AS VARCHAR[])) "
        # Plain/comma-joined VARCHAR scalar.
        f"WHEN typeof({col}) = 'VARCHAR' THEN string_split({as_varchar}, ',') "
        # Native JSON array or VARCHAR[] list.
        f"ELSE CAST({col} AS VARCHAR[]) "
        f"END"
    )


def _node_computer(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Build node_computer: one row per SID from every computer-bearing source.

    The full set of sources and which columns they contribute is documented in
    the Stage 1 plan "Computer property provenance" table. Missing source tables
    are skipped silently via _safe(). The final GROUP BY collapses all rows for
    the same SID with array-union for role/resource lists, bool_or for flags, and
    any_value for scalars.
    """
    # Start with an empty staging table whose column names match the SELECT aliases
    # used in every INSERT below. INSERT … BY NAME matches on column name, not
    # position, so every source SELECT only needs to name the columns it provides —
    # all others default to the types defined here (NULL / false / []).
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_computer ("
        "sid VARCHAR, "
        "name VARCHAR, "
        "dnshostname VARCHAR, "
        "sam_account_name VARCHAR, "
        "resource_id_str VARCHAR, "          # '<rid>@<site>' or NULL; aggregated later
        "roles VARCHAR[], "                  # normalised per-row list; array-union later
        "sccm_infra BOOLEAN, "
        "sms_unique_identifier VARCHAR, "
        "smb_signing_required BOOLEAN, "
        "sccm_has_client_remote_control_spn BOOLEAN, "
        "network_boot_server BOOLEAN, "
        "disable_loopback_check BOOLEAN, "
        "restrict_receiving_ntlm_traffic VARCHAR, "
        "sccm_client_certificate_required BOOLEAN, "
        "sccm_hosts_content_library BOOLEAN, "
        "sccm_is_pxe_support_enabled BOOLEAN"
        ")"
    )

    # Pre-create the optional columns every source SELECT below references, so a
    # source that lacks one (never-emitted, or dlt-dropped because all-NULL) still
    # binds instead of dropping the whole source. Keys (sid/object_sid) are not
    # listed — a source without its key is meaningless. See _ensure_columns.
    _optional = {
        "name": "VARCHAR",
        "dns_host_name": "VARCHAR",
        "sam_account_name": "VARCHAR",
        "sccm_site_system_roles": "VARCHAR",
        "sccm_infra": "BOOLEAN",
        "smb_signing_required": "BOOLEAN",
        "sccm_hosts_content_library": "BOOLEAN",
        "sccm_is_pxe_support_enabled": "BOOLEAN",
        "disable_loopback_check": "BOOLEAN",
        "restrict_receiving_ntlm_traffic": "VARCHAR",
        "client_cert_required": "BOOLEAN",
        "system_roles": "VARCHAR",
        "resource_id": "BIGINT",
        "source_site_code": "VARCHAR",
        "obsolete": "BOOLEAN",
        "sms_unique_identifier": "VARCHAR",
    }
    for _src in (
        "adminservice_r_system", "wmi_r_system",
        "ldap_cmrc_devices", "ldap_network_boot_servers",
        "smb_computers", "remoteregistry_computers",
        "adminservice_site_definitions_computers", "wmi_site_definitions_computers",
        "http_management_points", "http_distribution_points", "http_smsproviders",
    ):
        _ensure_columns(con, schema, _src, _optional)

    # Each INSERT selects exactly the columns the source has, with NULL / false / []
    # for the rest. INSERT … BY NAME pairs source column names to staging column names
    # regardless of select-list order.

    # --- adminservice_r_system: sid, system_roles, resource_id@source_site_code, sms_unique_identifier ---
    _safe(
        con,
        "node_computer<-adminservice_r_system",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(sid) AS sid, name, "
        f"NULL AS dnshostname, NULL AS sam_account_name, "
        f"CASE WHEN resource_id IS NULL THEN NULL "
        f"     ELSE CAST(resource_id AS VARCHAR) || '@' || CAST(source_site_code AS VARCHAR) END AS resource_id_str, "
        f"{_arr('system_roles')} AS roles, "
        f"false AS sccm_infra, sms_unique_identifier, "
        f"NULL AS smb_signing_required, "
        f"false AS sccm_has_client_remote_control_spn, "
        f"false AS network_boot_server, "
        f"NULL AS disable_loopback_check, "
        f"NULL AS restrict_receiving_ntlm_traffic, "
        f"NULL AS sccm_client_certificate_required, "
        f"NULL AS sccm_hosts_content_library, "
        f"NULL AS sccm_is_pxe_support_enabled "
        f"FROM {schema}.adminservice_r_system "
        f"WHERE sid IS NOT NULL AND NOT coalesce(obsolete, false)",
    )

    # --- wmi_r_system: same shape as adminservice_r_system ---
    _safe(
        con,
        "node_computer<-wmi_r_system",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(sid) AS sid, name, "
        f"NULL AS dnshostname, NULL AS sam_account_name, "
        f"CASE WHEN resource_id IS NULL THEN NULL "
        f"     ELSE CAST(resource_id AS VARCHAR) || '@' || CAST(source_site_code AS VARCHAR) END AS resource_id_str, "
        f"{_arr('system_roles')} AS roles, "
        f"false AS sccm_infra, sms_unique_identifier, "
        f"NULL AS smb_signing_required, "
        f"false AS sccm_has_client_remote_control_spn, "
        f"false AS network_boot_server, "
        f"NULL AS disable_loopback_check, "
        f"NULL AS restrict_receiving_ntlm_traffic, "
        f"NULL AS sccm_client_certificate_required, "
        f"NULL AS sccm_hosts_content_library, "
        f"NULL AS sccm_is_pxe_support_enabled "
        f"FROM {schema}.wmi_r_system "
        f"WHERE sid IS NOT NULL AND NOT coalesce(obsolete, false)",
    )

    # --- ldap_cmrc_devices: object_sid; synthesize sccm_has_client_remote_control_spn=TRUE ---
    _safe(
        con,
        "node_computer<-ldap_cmrc_devices",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(object_sid) AS sid, name, "
        f"dns_host_name AS dnshostname, sam_account_name, "
        f"NULL AS resource_id_str, "
        f"{_arr('sccm_site_system_roles')} AS roles, "
        f"coalesce(sccm_infra, false) AS sccm_infra, "
        f"NULL AS sms_unique_identifier, "
        f"NULL AS smb_signing_required, "
        f"true AS sccm_has_client_remote_control_spn, "  # membership = has CMRC SPN
        f"false AS network_boot_server, "
        f"NULL AS disable_loopback_check, "
        f"NULL AS restrict_receiving_ntlm_traffic, "
        f"NULL AS sccm_client_certificate_required, "
        f"NULL AS sccm_hosts_content_library, "
        f"NULL AS sccm_is_pxe_support_enabled "
        f"FROM {schema}.ldap_cmrc_devices "
        f"WHERE object_sid IS NOT NULL",
    )

    # --- ldap_network_boot_servers: synthesize network_boot_server=TRUE ---
    _safe(
        con,
        "node_computer<-ldap_network_boot_servers",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(object_sid) AS sid, name, "
        f"dns_host_name AS dnshostname, sam_account_name, "
        f"NULL AS resource_id_str, "
        f"{_arr('sccm_site_system_roles')} AS roles, "
        f"coalesce(sccm_infra, false) AS sccm_infra, "
        f"NULL AS sms_unique_identifier, "
        f"NULL AS smb_signing_required, "
        f"false AS sccm_has_client_remote_control_spn, "
        f"true AS network_boot_server, "                 # LDAP-discovered NBS membership
        f"NULL AS disable_loopback_check, "
        f"NULL AS restrict_receiving_ntlm_traffic, "
        f"NULL AS sccm_client_certificate_required, "
        f"NULL AS sccm_hosts_content_library, "
        f"NULL AS sccm_is_pxe_support_enabled "
        f"FROM {schema}.ldap_network_boot_servers "
        f"WHERE object_sid IS NOT NULL",
    )

    # --- smb_computers: smb_signing_required; sccm_hosts_content_library; sccm_is_pxe_support_enabled ---
    # sam_account_name is not emitted by the SMB collector — use NULL so the LDAP sources win via any_value.
    _safe(
        con,
        "node_computer<-smb_computers",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(object_sid) AS sid, name, "
        f"dns_host_name AS dnshostname, NULL AS sam_account_name, "
        f"NULL AS resource_id_str, "
        f"{_arr('sccm_site_system_roles')} AS roles, "
        f"coalesce(sccm_infra, false) AS sccm_infra, "
        f"NULL AS sms_unique_identifier, "
        f"smb_signing_required, "
        f"false AS sccm_has_client_remote_control_spn, "
        f"false AS network_boot_server, "
        f"NULL AS disable_loopback_check, "
        f"NULL AS restrict_receiving_ntlm_traffic, "
        f"NULL AS sccm_client_certificate_required, "
        f"sccm_hosts_content_library, "
        f"sccm_is_pxe_support_enabled "
        f"FROM {schema}.smb_computers "
        f"WHERE object_sid IS NOT NULL",
    )

    # --- remoteregistry_computers: disable_loopback_check; restrict_receiving_ntlm_traffic (string) ---
    # sam_account_name is not emitted by the RemoteRegistry collector — use NULL.
    _safe(
        con,
        "node_computer<-remoteregistry_computers",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(object_sid) AS sid, name, "
        f"dns_host_name AS dnshostname, NULL AS sam_account_name, "
        f"NULL AS resource_id_str, "
        f"{_arr('sccm_site_system_roles')} AS roles, "
        f"coalesce(sccm_infra, false) AS sccm_infra, "
        f"NULL AS sms_unique_identifier, "
        f"smb_signing_required, "
        f"false AS sccm_has_client_remote_control_spn, "
        f"false AS network_boot_server, "
        f"disable_loopback_check, "
        f"CAST(restrict_receiving_ntlm_traffic AS VARCHAR) AS restrict_receiving_ntlm_traffic, "
        f"NULL AS sccm_client_certificate_required, "
        f"NULL AS sccm_hosts_content_library, "
        f"NULL AS sccm_is_pxe_support_enabled "
        f"FROM {schema}.remoteregistry_computers "
        f"WHERE object_sid IS NOT NULL",
    )

    # --- adminservice_site_definitions_computers: object_sid; sccm_site_system_roles ---
    _safe(
        con,
        "node_computer<-adminservice_site_definitions_computers",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(object_sid) AS sid, name, "
        f"dns_host_name AS dnshostname, NULL AS sam_account_name, "
        f"NULL AS resource_id_str, "
        f"{_arr('sccm_site_system_roles')} AS roles, "
        f"coalesce(sccm_infra, false) AS sccm_infra, "
        f"NULL AS sms_unique_identifier, "
        f"NULL AS smb_signing_required, "
        f"false AS sccm_has_client_remote_control_spn, "
        f"false AS network_boot_server, "
        f"NULL AS disable_loopback_check, "
        f"NULL AS restrict_receiving_ntlm_traffic, "
        f"NULL AS sccm_client_certificate_required, "
        f"NULL AS sccm_hosts_content_library, "
        f"NULL AS sccm_is_pxe_support_enabled "
        f"FROM {schema}.adminservice_site_definitions_computers "
        f"WHERE object_sid IS NOT NULL",
    )

    # --- wmi_site_definitions_computers: same shape as adminservice_site_definitions_computers ---
    _safe(
        con,
        "node_computer<-wmi_site_definitions_computers",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(object_sid) AS sid, name, "
        f"dns_host_name AS dnshostname, NULL AS sam_account_name, "
        f"NULL AS resource_id_str, "
        f"{_arr('sccm_site_system_roles')} AS roles, "
        f"coalesce(sccm_infra, false) AS sccm_infra, "
        f"NULL AS sms_unique_identifier, "
        f"NULL AS smb_signing_required, "
        f"false AS sccm_has_client_remote_control_spn, "
        f"false AS network_boot_server, "
        f"NULL AS disable_loopback_check, "
        f"NULL AS restrict_receiving_ntlm_traffic, "
        f"NULL AS sccm_client_certificate_required, "
        f"NULL AS sccm_hosts_content_library, "
        f"NULL AS sccm_is_pxe_support_enabled "
        f"FROM {schema}.wmi_site_definitions_computers "
        f"WHERE object_sid IS NOT NULL",
    )

    # --- http_management_points: client_cert_required -> sccm_client_certificate_required ---
    _safe(
        con,
        "node_computer<-http_management_points",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(object_sid) AS sid, name, "
        f"dns_host_name AS dnshostname, sam_account_name, "
        f"NULL AS resource_id_str, "
        f"{_arr('sccm_site_system_roles')} AS roles, "
        f"coalesce(sccm_infra, false) AS sccm_infra, "
        f"NULL AS sms_unique_identifier, "
        f"NULL AS smb_signing_required, "
        f"false AS sccm_has_client_remote_control_spn, "
        f"false AS network_boot_server, "
        f"NULL AS disable_loopback_check, "
        f"NULL AS restrict_receiving_ntlm_traffic, "
        f"client_cert_required AS sccm_client_certificate_required, "
        f"NULL AS sccm_hosts_content_library, "
        f"NULL AS sccm_is_pxe_support_enabled "
        f"FROM {schema}.http_management_points "
        f"WHERE object_sid IS NOT NULL",
    )

    # --- http_distribution_points: client_cert_required -> sccm_client_certificate_required ---
    _safe(
        con,
        "node_computer<-http_distribution_points",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(object_sid) AS sid, name, "
        f"dns_host_name AS dnshostname, sam_account_name, "
        f"NULL AS resource_id_str, "
        f"{_arr('sccm_site_system_roles')} AS roles, "
        f"coalesce(sccm_infra, false) AS sccm_infra, "
        f"NULL AS sms_unique_identifier, "
        f"NULL AS smb_signing_required, "
        f"false AS sccm_has_client_remote_control_spn, "
        f"false AS network_boot_server, "
        f"NULL AS disable_loopback_check, "
        f"NULL AS restrict_receiving_ntlm_traffic, "
        f"client_cert_required AS sccm_client_certificate_required, "
        f"NULL AS sccm_hosts_content_library, "
        f"NULL AS sccm_is_pxe_support_enabled "
        f"FROM {schema}.http_distribution_points "
        f"WHERE object_sid IS NOT NULL",
    )

    # --- http_smsproviders: client_cert_required -> sccm_client_certificate_required ---
    _safe(
        con,
        "node_computer<-http_smsproviders",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(object_sid) AS sid, name, "
        f"dns_host_name AS dnshostname, sam_account_name, "
        f"NULL AS resource_id_str, "
        f"{_arr('sccm_site_system_roles')} AS roles, "
        f"coalesce(sccm_infra, false) AS sccm_infra, "
        f"NULL AS sms_unique_identifier, "
        f"NULL AS smb_signing_required, "
        f"false AS sccm_has_client_remote_control_spn, "
        f"false AS network_boot_server, "
        f"NULL AS disable_loopback_check, "
        f"NULL AS restrict_receiving_ntlm_traffic, "
        f"client_cert_required AS sccm_client_certificate_required, "
        f"NULL AS sccm_hosts_content_library, "
        f"NULL AS sccm_is_pxe_support_enabled "
        f"FROM {schema}.http_smsproviders "
        f"WHERE object_sid IS NOT NULL",
    )

    # Collapse all staging rows into one row per SID. Role lists are array-unioned;
    # boolean flags use bool_or (true wins); scalars use any_value (first non-null wins).
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_computer AS "
        f"SELECT "
        f"  sid, "
        f"  any_value(name) AS name, "
        f"  any_value(dnshostname) AS dnshostname, "
        f"  any_value(sam_account_name) AS sam_account_name, "
        f"  list_distinct(list_filter(flatten(list(roles)), x -> x IS NOT NULL AND trim(x) != '')) AS site_system_roles, "
        f"  coalesce(list_distinct(array_agg(resource_id_str) FILTER (WHERE resource_id_str IS NOT NULL)), CAST([] AS VARCHAR[])) AS resource_ids, "
        f"  bool_or(sccm_infra) AS sccm_infra, "
        f"  any_value(sms_unique_identifier) AS sms_unique_identifier, "
        f"  bool_or(smb_signing_required) AS smb_signing_required, "
        f"  bool_or(sccm_has_client_remote_control_spn) AS sccm_has_client_remote_control_spn, "
        f"  bool_or(network_boot_server) AS network_boot_server, "
        f"  bool_or(disable_loopback_check) AS disable_loopback_check, "
        f"  any_value(restrict_receiving_ntlm_traffic) AS restrict_receiving_ntlm_traffic, "
        f"  bool_or(sccm_client_certificate_required) AS sccm_client_certificate_required, "
        f"  bool_or(sccm_hosts_content_library) AS sccm_hosts_content_library, "
        f"  bool_or(sccm_is_pxe_support_enabled) AS sccm_is_pxe_support_enabled "
        f"FROM {schema}.node_computer "
        f"GROUP BY sid"
    )
    logger.info("node_computer built in schema %r", schema)


def _node_user(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Build node_user: one row per SID from every user-bearing source.

    Sources and the columns they contribute:

    * adminservice_r_user / wmi_r_user  — sid, name, resource_id@source_site_code
    * remoteregistry_users              — object_sid (clean snake_case per Task-3 fix)
    * adminservice_admins / wmi_admins  — admin_sid where is_group=false → sccm_infra=true
    * adminservice_reserved_accounts / wmi_reserved_accounts
                                        — object_sid, site_code → stored_in_sccm_site

    The final GROUP BY collapses all rows for the same uppercased SID with
    array-union for resource_ids, bool_or for sccm_infra, and any_value for
    scalars (name, stored_in_sccm_site).
    """
    # Staging table holds one raw row per source record before collapsing.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_user ("
        "sid VARCHAR, "
        "name VARCHAR, "
        "resource_id_str VARCHAR, "     # '<rid>@<site>' or NULL; aggregated below
        "sccm_infra BOOLEAN, "
        "stored_in_sccm_site VARCHAR"   # site_code where the account is stored (reserved)
        ")"
    )

    # Pre-create optional columns so a source missing one still binds. See _ensure_columns.
    _optional = {
        "name": "VARCHAR",
        "resource_id": "BIGINT",
        "source_site_code": "VARCHAR",
        "sam_account_name": "VARCHAR",
        "logon_name": "VARCHAR",
        "is_group": "BOOLEAN",
        "site_code": "VARCHAR",
    }
    for _src in (
        "adminservice_r_user", "wmi_r_user", "remoteregistry_users",
        "adminservice_admins", "wmi_admins",
        "adminservice_reserved_accounts", "wmi_reserved_accounts",
    ):
        _ensure_columns(con, schema, _src, _optional)

    # --- adminservice_r_user: sid, name, resource_id@source_site_code ---
    _safe(
        con,
        "node_user<-adminservice_r_user",
        f"INSERT INTO {schema}.node_user BY NAME "
        f"SELECT upper(sid) AS sid, name, "
        f"CASE WHEN resource_id IS NULL THEN NULL "
        f"     ELSE CAST(resource_id AS VARCHAR) || '@' || CAST(source_site_code AS VARCHAR) END AS resource_id_str, "
        f"false AS sccm_infra, "
        f"NULL AS stored_in_sccm_site "
        f"FROM {schema}.adminservice_r_user "
        f"WHERE sid IS NOT NULL",
    )

    # --- wmi_r_user: same shape as adminservice_r_user ---
    _safe(
        con,
        "node_user<-wmi_r_user",
        f"INSERT INTO {schema}.node_user BY NAME "
        f"SELECT upper(sid) AS sid, name, "
        f"CASE WHEN resource_id IS NULL THEN NULL "
        f"     ELSE CAST(resource_id AS VARCHAR) || '@' || CAST(source_site_code AS VARCHAR) END AS resource_id_str, "
        f"false AS sccm_infra, "
        f"NULL AS stored_in_sccm_site "
        f"FROM {schema}.wmi_r_user "
        f"WHERE sid IS NOT NULL",
    )

    # --- remoteregistry_users: object_sid (clean snake_case); no resource_id ---
    _safe(
        con,
        "node_user<-remoteregistry_users",
        f"INSERT INTO {schema}.node_user BY NAME "
        f"SELECT upper(object_sid) AS sid, sam_account_name AS name, "
        f"NULL AS resource_id_str, "
        f"false AS sccm_infra, "
        f"NULL AS stored_in_sccm_site "
        f"FROM {schema}.remoteregistry_users "
        f"WHERE object_sid IS NOT NULL",
    )

    # --- adminservice_admins (users only): admin_sid, logon_name → sccm_infra=true ---
    _safe(
        con,
        "node_user<-adminservice_admins",
        f"INSERT INTO {schema}.node_user BY NAME "
        f"SELECT upper(admin_sid) AS sid, logon_name AS name, "
        f"NULL AS resource_id_str, "
        f"true AS sccm_infra, "
        f"NULL AS stored_in_sccm_site "
        f"FROM {schema}.adminservice_admins "
        f"WHERE admin_sid IS NOT NULL AND NOT coalesce(is_group, false)",
    )

    # --- wmi_admins (users only): same shape as adminservice_admins ---
    _safe(
        con,
        "node_user<-wmi_admins",
        f"INSERT INTO {schema}.node_user BY NAME "
        f"SELECT upper(admin_sid) AS sid, logon_name AS name, "
        f"NULL AS resource_id_str, "
        f"true AS sccm_infra, "
        f"NULL AS stored_in_sccm_site "
        f"FROM {schema}.wmi_admins "
        f"WHERE admin_sid IS NOT NULL AND NOT coalesce(is_group, false)",
    )

    # --- adminservice_reserved_accounts: object_sid, site_code → stored_in_sccm_site ---
    # The account name column in reserved_accounts is 'name' (verified clean snake_case).
    _safe(
        con,
        "node_user<-adminservice_reserved_accounts",
        f"INSERT INTO {schema}.node_user BY NAME "
        f"SELECT upper(object_sid) AS sid, name, "
        f"NULL AS resource_id_str, "
        f"false AS sccm_infra, "
        f"site_code AS stored_in_sccm_site "
        f"FROM {schema}.adminservice_reserved_accounts "
        f"WHERE object_sid IS NOT NULL",
    )

    # --- wmi_reserved_accounts: same shape as adminservice_reserved_accounts ---
    _safe(
        con,
        "node_user<-wmi_reserved_accounts",
        f"INSERT INTO {schema}.node_user BY NAME "
        f"SELECT upper(object_sid) AS sid, name, "
        f"NULL AS resource_id_str, "
        f"false AS sccm_infra, "
        f"site_code AS stored_in_sccm_site "
        f"FROM {schema}.wmi_reserved_accounts "
        f"WHERE object_sid IS NOT NULL",
    )

    # Collapse all staging rows into one row per SID.
    # resource_ids: array-union the non-null '<rid>@<site>' strings.
    # sccm_infra:   bool_or (true wins if any source set it true).
    # stored_in_sccm_site / name: any_value (first non-null wins; scalar per CMBP).
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_user AS "
        f"SELECT "
        f"  sid, "
        f"  any_value(name) AS name, "
        f"  coalesce(list_distinct(array_agg(resource_id_str) FILTER (WHERE resource_id_str IS NOT NULL)), CAST([] AS VARCHAR[])) AS resource_ids, "
        f"  bool_or(sccm_infra) AS sccm_infra, "
        f"  any_value(stored_in_sccm_site) AS stored_in_sccm_site "
        f"FROM {schema}.node_user "
        f"GROUP BY sid"
    )
    logger.info("node_user built in schema %r", schema)


def _node_group(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Build node_group: one row per SID from every group-bearing source.

    Groups arrive in two ways:
      1. Name-only: security_group_name lists on r_system / r_user rows.
         The group name is resolved to a SID via a case-insensitive join on
         principal_by_name (both sides uppercased, because principal_by_name
         stores names in original case while the list values may differ).
         r_user rows also carry a resource_id that we propagate as a
         sccm_resource_ids hint (per CMBP; the value is the parent user's
         ResourceID).
      2. Direct SID: admins / wmi_admins rows where is_group=True. These
         carry sccm_infra=True.

    A fallback_domain_sid is derived where possible — the domain SID of the
    r_system / r_user row that produced the group name — so that builtin
    group SIDs (S-1-5-32-*) can be qualified per the locked identity rule.

    The final GROUP BY deduplicates on upper(sid): sccm_infra uses bool_or
    (True wins), sccm_resource_ids are array-unioned, name and
    fallback_domain_sid use any_value (first non-null wins).
    """
    # Staging table: one raw row per source record before collapsing.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_group ("
        "sid VARCHAR, "
        "name VARCHAR, "
        "sccm_infra BOOLEAN, "
        "resource_id_str VARCHAR, "     # '<rid>@<site>' from the parent user row; NULL otherwise
        "fallback_domain_sid VARCHAR"   # domain SID of the co-occurring host/user; NULL when unknown
        ")"
    )

    # --- From r_system: unnest security_group_name, resolve to SID via principal_by_name.
    # The fallback_domain_sid is the domain SID of the r_system host (strip the RID via regex).
    # dlt loads security_group_name as a JSON column (e.g. '["mayyhem\\Domain Users"]'), not a
    # native list, so we route it through _arr() (JSON/scalar/list -> VARCHAR[]) before UNNEST;
    # a raw `unnest(json_col)` raises "UNNEST requires a single list as input".
    # DuckDB lateral unnest: `unnest(<expr>) AS t(gname)` — the column is `t.gname` in all refs.
    _safe(
        con,
        "node_group<-adminservice_r_system",
        f"INSERT INTO {schema}.node_group BY NAME "
        f"SELECT pbn.sid AS sid, t.gname AS name, "
        f"false AS sccm_infra, "
        f"NULL AS resource_id_str, "
        f"regexp_extract(upper(r.sid), '^(S-1-5-21(?:-\\d+){{3}})-\\d+$', 1) AS fallback_domain_sid "
        f"FROM {schema}.adminservice_r_system r, "
        f"unnest({_arr('r.security_group_name')}) AS t(gname) "
        f"JOIN {schema}.principal_by_name pbn "
        f"  ON upper(trim(t.gname)) = upper(pbn.name) "
        f"WHERE r.sid IS NOT NULL AND NOT coalesce(r.obsolete, false) "
        f"  AND t.gname IS NOT NULL AND trim(t.gname) != ''",
    )

    # --- From wmi_r_system: same shape as adminservice_r_system ---
    _safe(
        con,
        "node_group<-wmi_r_system",
        f"INSERT INTO {schema}.node_group BY NAME "
        f"SELECT pbn.sid AS sid, t.gname AS name, "
        f"false AS sccm_infra, "
        f"NULL AS resource_id_str, "
        f"regexp_extract(upper(r.sid), '^(S-1-5-21(?:-\\d+){{3}})-\\d+$', 1) AS fallback_domain_sid "
        f"FROM {schema}.wmi_r_system r, "
        f"unnest({_arr('r.security_group_name')}) AS t(gname) "
        f"JOIN {schema}.principal_by_name pbn "
        f"  ON upper(trim(t.gname)) = upper(pbn.name) "
        f"WHERE r.sid IS NOT NULL AND NOT coalesce(r.obsolete, false) "
        f"  AND t.gname IS NOT NULL AND trim(t.gname) != ''",
    )

    # --- From r_user: unnest security_group_name; carry parent resource_id as sccm_resource_ids.
    # Per CMBP: the value is the parent user's ResourceID (resource_id@source_site_code).
    _safe(
        con,
        "node_group<-adminservice_r_user",
        f"INSERT INTO {schema}.node_group BY NAME "
        f"SELECT pbn.sid AS sid, t.gname AS name, "
        f"false AS sccm_infra, "
        f"CASE WHEN r.resource_id IS NULL THEN NULL "
        f"     ELSE CAST(r.resource_id AS VARCHAR) || '@' || CAST(r.source_site_code AS VARCHAR) END AS resource_id_str, "
        f"regexp_extract(upper(r.sid), '^(S-1-5-21(?:-\\d+){{3}})-\\d+$', 1) AS fallback_domain_sid "
        f"FROM {schema}.adminservice_r_user r, "
        f"unnest({_arr('r.security_group_name')}) AS t(gname) "
        f"JOIN {schema}.principal_by_name pbn "
        f"  ON upper(trim(t.gname)) = upper(pbn.name) "
        f"WHERE r.sid IS NOT NULL "
        f"  AND t.gname IS NOT NULL AND trim(t.gname) != ''",
    )

    # --- From wmi_r_user: same shape as adminservice_r_user ---
    _safe(
        con,
        "node_group<-wmi_r_user",
        f"INSERT INTO {schema}.node_group BY NAME "
        f"SELECT pbn.sid AS sid, t.gname AS name, "
        f"false AS sccm_infra, "
        f"CASE WHEN r.resource_id IS NULL THEN NULL "
        f"     ELSE CAST(r.resource_id AS VARCHAR) || '@' || CAST(r.source_site_code AS VARCHAR) END AS resource_id_str, "
        f"regexp_extract(upper(r.sid), '^(S-1-5-21(?:-\\d+){{3}})-\\d+$', 1) AS fallback_domain_sid "
        f"FROM {schema}.wmi_r_user r, "
        f"unnest({_arr('r.security_group_name')}) AS t(gname) "
        f"JOIN {schema}.principal_by_name pbn "
        f"  ON upper(trim(t.gname)) = upper(pbn.name) "
        f"WHERE r.sid IS NOT NULL "
        f"  AND t.gname IS NOT NULL AND trim(t.gname) != ''",
    )

    # --- From adminservice_admins: direct group SID where is_group=True; sccm_infra=True ---
    _safe(
        con,
        "node_group<-adminservice_admins",
        f"INSERT INTO {schema}.node_group BY NAME "
        f"SELECT upper(admin_sid) AS sid, logon_name AS name, "
        f"true AS sccm_infra, "
        f"NULL AS resource_id_str, "
        f"NULL AS fallback_domain_sid "
        f"FROM {schema}.adminservice_admins "
        f"WHERE admin_sid IS NOT NULL AND coalesce(is_group, false)",
    )

    # --- From wmi_admins: same shape as adminservice_admins ---
    _safe(
        con,
        "node_group<-wmi_admins",
        f"INSERT INTO {schema}.node_group BY NAME "
        f"SELECT upper(admin_sid) AS sid, logon_name AS name, "
        f"true AS sccm_infra, "
        f"NULL AS resource_id_str, "
        f"NULL AS fallback_domain_sid "
        f"FROM {schema}.wmi_admins "
        f"WHERE admin_sid IS NOT NULL AND coalesce(is_group, false)",
    )

    # Collapse all staging rows into one row per SID (uppercased).
    # sccm_infra: bool_or (True wins if any source set it True).
    # sccm_resource_ids: array-union the non-null '<rid>@<site>' strings.
    # name / fallback_domain_sid: any_value (first non-null wins).
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_group AS "
        f"SELECT "
        f"  upper(sid) AS sid, "
        f"  any_value(name) AS name, "
        f"  bool_or(sccm_infra) AS sccm_infra, "
        f"  coalesce(list_distinct(array_agg(resource_id_str) FILTER (WHERE resource_id_str IS NOT NULL)), CAST([] AS VARCHAR[])) AS sccm_resource_ids, "
        f"  any_value(fallback_domain_sid) AS fallback_domain_sid "
        f"FROM {schema}.node_group "
        f"WHERE sid IS NOT NULL "
        f"GROUP BY upper(sid)"
    )
    logger.info("node_group built in schema %r", schema)


def _node_site(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Build node_site: one row per site_code, coalesced from all site sources.

    Sources and the columns they contribute:

    * adminservice_sites / wmi_sites         — site_code, site_name, server_name,
                                               reporting_site_code (= parent), type (= site_type),
                                               version, build_number, install_dir
    * adminservice_site_definitions / wmi_site_definitions
                                             — site_code, parent_site_code, site_guid,
                                               sql_server_name, sql_database_name, site_type
    * ldap_sites                             — site_code, site_guid, parent_site_code

    After collapsing duplicates with GROUP BY upper(site_code), the result is
    LEFT JOINed to site_hierarchy (built by _site_hierarchy) to stamp each row
    with root_site_code. site_hierarchy must already exist when this runs.
    """
    # Staging table — one raw row per source record before collapsing.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_site ("
        "site_code VARCHAR, "
        "site_name VARCHAR, "
        "server_name VARCHAR, "
        "parent_site_code VARCHAR, "
        "site_type INTEGER, "
        "site_guid VARCHAR, "
        "sql_server_name VARCHAR, "
        "sql_database_name VARCHAR, "
        "version VARCHAR, "
        "build_number VARCHAR, "
        "install_dir VARCHAR"
        ")"
    )

    # Pre-create the optional columns the site-source SELECTs reference, so a
    # source missing one (never-emitted, or dlt-dropped because all-NULL) still
    # binds instead of a binder error dropping the whole source. Real
    # adminservice_site_definitions, for instance, often lacks site_guid. site_code
    # is the key/filter — a source without it is meaningless, so it is not listed.
    # See _ensure_columns (same pattern as _node_computer / _node_user).
    _optional = {
        "site_name": "VARCHAR",
        "server_name": "VARCHAR",
        "reporting_site_code": "VARCHAR",   # adminservice_sites/wmi_sites -> parent_site_code
        "type": "INTEGER",                  # adminservice_sites/wmi_sites -> site_type
        "version": "VARCHAR",
        "build_number": "VARCHAR",
        "install_dir": "VARCHAR",
        "parent_site_code": "VARCHAR",      # site_definitions / ldap_sites
        "site_type": "INTEGER",             # site_definitions
        "site_guid": "VARCHAR",             # site_definitions / ldap_sites
        "sql_server_name": "VARCHAR",       # site_definitions
        "sql_database_name": "VARCHAR",     # site_definitions
    }
    for _src in (
        "adminservice_sites", "wmi_sites",
        "adminservice_site_definitions", "wmi_site_definitions",
        "ldap_sites",
    ):
        _ensure_columns(con, schema, _src, _optional)

    # --- adminservice_sites: site_code, site_name, server_name, reporting_site_code → parent, type → site_type ---
    _safe(
        con,
        "node_site<-adminservice_sites",
        f"INSERT INTO {schema}.node_site BY NAME "
        f"SELECT site_code, site_name, server_name, "
        f"reporting_site_code AS parent_site_code, "
        f"TRY_CAST(type AS INTEGER) AS site_type, "
        f"NULL AS site_guid, NULL AS sql_server_name, NULL AS sql_database_name, "
        f"version, build_number, install_dir "
        f"FROM {schema}.adminservice_sites WHERE site_code IS NOT NULL",
    )

    # --- wmi_sites: same shape as adminservice_sites ---
    _safe(
        con,
        "node_site<-wmi_sites",
        f"INSERT INTO {schema}.node_site BY NAME "
        f"SELECT site_code, site_name, server_name, "
        f"reporting_site_code AS parent_site_code, "
        f"TRY_CAST(type AS INTEGER) AS site_type, "
        f"NULL AS site_guid, NULL AS sql_server_name, NULL AS sql_database_name, "
        f"version, build_number, install_dir "
        f"FROM {schema}.wmi_sites WHERE site_code IS NOT NULL",
    )

    # --- adminservice_site_definitions: parent_site_code, site_guid, sql_*, site_type ---
    _safe(
        con,
        "node_site<-adminservice_site_definitions",
        f"INSERT INTO {schema}.node_site BY NAME "
        f"SELECT site_code, NULL AS site_name, NULL AS server_name, "
        f"parent_site_code, TRY_CAST(site_type AS INTEGER) AS site_type, "
        f"site_guid, sql_server_name, sql_database_name, "
        f"NULL AS version, NULL AS build_number, NULL AS install_dir "
        f"FROM {schema}.adminservice_site_definitions WHERE site_code IS NOT NULL",
    )

    # --- wmi_site_definitions: same shape as adminservice_site_definitions ---
    _safe(
        con,
        "node_site<-wmi_site_definitions",
        f"INSERT INTO {schema}.node_site BY NAME "
        f"SELECT site_code, NULL AS site_name, NULL AS server_name, "
        f"parent_site_code, TRY_CAST(site_type AS INTEGER) AS site_type, "
        f"site_guid, sql_server_name, sql_database_name, "
        f"NULL AS version, NULL AS build_number, NULL AS install_dir "
        f"FROM {schema}.wmi_site_definitions WHERE site_code IS NOT NULL",
    )

    # --- ldap_sites: site_code, site_guid, parent_site_code ---
    _safe(
        con,
        "node_site<-ldap_sites",
        f"INSERT INTO {schema}.node_site BY NAME "
        f"SELECT site_code, NULL AS site_name, NULL AS server_name, "
        f"parent_site_code, NULL AS site_type, "
        f"site_guid, NULL AS sql_server_name, NULL AS sql_database_name, "
        f"NULL AS version, NULL AS build_number, NULL AS install_dir "
        f"FROM {schema}.ldap_sites WHERE site_code IS NOT NULL",
    )

    # Collapse all staging rows into one row per site_code (uppercased).
    # Scalars use any_value (first non-null wins); site_type uses max to prefer
    # the highest-authority value (e.g. CAS=4 wins over an older Secondary=1 row).
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_site AS "
        f"SELECT "
        f"  upper(site_code) AS site_code, "
        f"  any_value(site_name) AS site_name, "
        f"  any_value(server_name) AS server_name, "
        f"  any_value(parent_site_code) AS parent_site_code, "
        f"  max(site_type) AS site_type, "
        f"  any_value(site_guid) AS site_guid, "
        f"  any_value(sql_server_name) AS sql_server_name, "
        f"  any_value(sql_database_name) AS sql_database_name, "
        f"  any_value(version) AS version, "
        f"  any_value(build_number) AS build_number, "
        f"  any_value(install_dir) AS install_dir "
        f"FROM {schema}.node_site "
        f"WHERE site_code IS NOT NULL "
        f"GROUP BY upper(site_code)"
    )

    # Stamp each row with root_site_code from the site_hierarchy table.
    # LEFT JOIN so sites missing from site_hierarchy still appear (root = NULL).
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_site AS "
        f"SELECT ns.*, sh.root_site_code "
        f"FROM {schema}.node_site ns "
        f"LEFT JOIN {schema}.site_hierarchy sh USING (site_code)"
    )
    logger.info("node_site built in schema %r", schema)


def _graph_edges(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Build graph_edges(start_id, end_id, kind) from a self-join of site_hierarchy.

    The CMBP type matrix (ps1:1604-1624) defines which site-type pairs get edges
    and how many:

    * CAS (4) <-> Primary (2): TWO rows (bidirectional — both directions)
    * Primary (2) -> Secondary (1): ONE row (parent -> child only)

    No other site-type pair receives a replication edge. Endpoints are site codes.

    site_hierarchy must already exist when this runs (it is built by _site_hierarchy).
    Both exception branches create an empty graph_edges table so convert can always
    read the table even when no site data was collected or an unexpected error occurs.
    """
    from .kinds.edges import SCCM_ADMINS_REPLICATED_TO

    try:
        con.execute(
            f"CREATE OR REPLACE TABLE {schema}.graph_edges AS "
            # CAS(4) <- Primary(2): Primary reports to CAS — emit Primary->CAS direction.
            f"SELECT "
            f"  child.site_code AS start_id, "
            f"  parent.site_code AS end_id, "
            f"  '{SCCM_ADMINS_REPLICATED_TO}' AS kind "
            f"FROM {schema}.site_hierarchy child "
            f"JOIN {schema}.site_hierarchy parent "
            f"  ON child.parent_site_code = parent.site_code "
            f"WHERE child.site_type = 2 AND parent.site_type = 4 "
            f"UNION ALL "
            # CAS(4) -> Primary(2): reverse direction to complete the bidirectional pair.
            f"SELECT "
            f"  parent.site_code AS start_id, "
            f"  child.site_code AS end_id, "
            f"  '{SCCM_ADMINS_REPLICATED_TO}' AS kind "
            f"FROM {schema}.site_hierarchy child "
            f"JOIN {schema}.site_hierarchy parent "
            f"  ON child.parent_site_code = parent.site_code "
            f"WHERE child.site_type = 2 AND parent.site_type = 4 "
            f"UNION ALL "
            # Primary(2) -> Secondary(1): one-way, parent->child only.
            f"SELECT "
            f"  parent.site_code AS start_id, "
            f"  child.site_code AS end_id, "
            f"  '{SCCM_ADMINS_REPLICATED_TO}' AS kind "
            f"FROM {schema}.site_hierarchy child "
            f"JOIN {schema}.site_hierarchy parent "
            f"  ON child.parent_site_code = parent.site_code "
            f"WHERE child.site_type = 1 AND parent.site_type = 2"
        )
        row_count = con.execute(f"SELECT count(*) FROM {schema}.graph_edges").fetchone()[0]
        logger.info("graph_edges built in schema %r: %d replication edge(s)", schema, row_count)
    except duckdb.CatalogException as err:
        # site_hierarchy not yet built (e.g. no site sources collected); leave graph_edges empty.
        logger.warning("graph_edges skipped (missing site_hierarchy): %s", err)
        con.execute(
            f"CREATE OR REPLACE TABLE {schema}.graph_edges "
            f"(start_id VARCHAR, end_id VARCHAR, kind VARCHAR)"
        )
    except duckdb.Error as err:
        # Unexpected DuckDB error (not a missing table); create an empty table so
        # convert can always read graph_edges without a separate existence check.
        logger.error("graph_edges failed: %s", err)
        con.execute(
            f"CREATE OR REPLACE TABLE {schema}.graph_edges "
            f"(start_id VARCHAR, end_id VARCHAR, kind VARCHAR)"
        )


def transforms(con: duckdb.DuckDBPyConnection, schema: str = "sccm") -> None:
    """Top-level transform entrypoint (registered via @app.preproc(transformer=transforms))."""
    con.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
    _principal_by_name(con, schema)
    _site_hierarchy(con, schema)
    _node_computer(con, schema)
    _node_user(con, schema)
    _node_group(con, schema)
    _node_site(con, schema)
    # _graph_edges must run last — it reads site_hierarchy (built by _site_hierarchy above).
    _graph_edges(con, schema)
