# src/openhound_sccm/transforms.py
"""DuckDB transforms for the SCCM collector's preproc phase.

Stage 1 builds the cross-cutting lookup tables (`principal_by_name`, site hierarchy
with `root_site_code`) and — added in later tasks — the coalesced `node_*` tables and
`graph_edges`. Each builder is defensive: a missing source table is logged and
skipped (early stages won't have collected everything).
"""
import logging
import re

import duckdb

logger = logging.getLogger(__name__)


def _safe(con: duckdb.DuckDBPyConnection, label: str, sql: str) -> None:
    """Run one SQL statement; log and continue if a source table is missing.

    WMI/AdminService fallback-mirror logic: the collector produces EITHER
    wmi_<X> OR adminservice_<X> tables for each data type — whichever
    transport was available. A CatalogException for wmi_<X> when
    adminservice_<X> exists (or vice versa) is a normal, expected miss;
    we log it at DEBUG to keep the log clean during routine operation.
    Any other missing-table error still logs at WARNING.
    """
    try:
        con.execute(sql)
    except duckdb.CatalogException as err:
        # Parse the missing table name from the DuckDB error message.
        # Example: "Catalog Error: Table with name wmi_r_system does not exist!"
        _match = re.search(r'with name "?([A-Za-z0-9_]+)"?', str(err))
        _missing = _match.group(1) if _match else None

        _log_as_debug = False
        if _missing:
            # Determine the sibling table name by swapping the wmi_/adminservice_ prefix.
            if _missing.startswith("wmi_"):
                _sibling = "adminservice_" + _missing[len("wmi_"):]
            elif _missing.startswith("adminservice_"):
                _sibling = "wmi_" + _missing[len("adminservice_"):]
            else:
                _sibling = None

            if _sibling:
                try:
                    # Extract the schema from the failing sql (e.g. 'schema.missing_table').
                    _schema_match = re.search(
                        rf'([A-Za-z0-9_]+)\.{re.escape(_missing)}',
                        sql,
                    )
                    _schema = _schema_match.group(1) if _schema_match else None

                    if _schema:
                        # Check sibling in the same schema.
                        _found = con.execute(
                            "SELECT 1 FROM information_schema.tables "
                            "WHERE table_schema = ? AND table_name = ?",
                            [_schema, _sibling],
                        ).fetchone()
                    else:
                        # Schema extraction failed; fall back to schema-agnostic query.
                        _found = con.execute(
                            "SELECT 1 FROM information_schema.tables WHERE table_name = ?",
                            [_sibling],
                        ).fetchone()

                    if _found:
                        # The sibling (other transport) table exists; this is an expected
                        # fallback miss — no need to warn.
                        _log_as_debug = True
                except duckdb.Error:
                    # Unable to query information_schema; default to WARNING (safe).
                    pass

        if _log_as_debug:
            logger.debug(
                "transform %r skipped (expected fallback miss — sibling table present): %s",
                label, err,
            )
        else:
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
        # DOMAIN\user / UPN name forms from r_user so device primary/current user and SQL service
        # account fields (which carry these forms) resolve to a SID via principal_by_name.
        ("principal_by_name<-adminservice_r_user_unique",
         f"SELECT unique_user_name AS name, sid FROM {schema}.adminservice_r_user WHERE sid IS NOT NULL AND unique_user_name IS NOT NULL"),
        ("principal_by_name<-wmi_r_user_unique",
         f"SELECT unique_user_name AS name, sid FROM {schema}.wmi_r_user WHERE sid IS NOT NULL AND unique_user_name IS NOT NULL"),
        ("principal_by_name<-adminservice_r_user_full",
         f"SELECT full_user_name AS name, sid FROM {schema}.adminservice_r_user WHERE sid IS NOT NULL AND full_user_name IS NOT NULL"),
        ("principal_by_name<-wmi_r_user_full",
         f"SELECT full_user_name AS name, sid FROM {schema}.wmi_r_user WHERE sid IS NOT NULL AND full_user_name IS NOT NULL"),
        ("principal_by_name<-adminservice_r_user_upn",
         f"SELECT user_principal_name AS name, sid FROM {schema}.adminservice_r_user WHERE sid IS NOT NULL AND user_principal_name IS NOT NULL"),
        ("principal_by_name<-wmi_r_user_upn",
         f"SELECT user_principal_name AS name, sid FROM {schema}.wmi_r_user WHERE sid IS NOT NULL AND user_principal_name IS NOT NULL"),
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
        "distinguished_name VARCHAR, "
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
        "distinguished_name": "VARCHAR",
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
        f"NULL AS dnshostname, NULL AS sam_account_name, NULL AS distinguished_name, "
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
        f"NULL AS dnshostname, NULL AS sam_account_name, NULL AS distinguished_name, "
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
    # Note: ldap_cmrc_devices does have distinguished_name (from entry.entry_dn via ad.py),
    # but we prefer smb_computers / remoteregistry_computers as primary sources to keep
    # the any_value coalesce consistent. NULL here; those arms fill it in.
    _safe(
        con,
        "node_computer<-ldap_cmrc_devices",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(object_sid) AS sid, name, "
        f"dns_host_name AS dnshostname, sam_account_name, NULL AS distinguished_name, "
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
        f"dns_host_name AS dnshostname, sam_account_name, NULL AS distinguished_name, "
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
    # smb_computers spreads **ad_object which includes distinguished_name (primary source).
    # sam_account_name is not emitted by the SMB collector — use NULL so the LDAP sources win via any_value.
    _safe(
        con,
        "node_computer<-smb_computers",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(object_sid) AS sid, name, "
        f"dns_host_name AS dnshostname, NULL AS sam_account_name, distinguished_name, "
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
    # remoteregistry_computers also spreads **ad_object, providing distinguished_name.
    # sam_account_name is not emitted by the RemoteRegistry collector — use NULL.
    _safe(
        con,
        "node_computer<-remoteregistry_computers",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(object_sid) AS sid, name, "
        f"dns_host_name AS dnshostname, NULL AS sam_account_name, distinguished_name, "
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
    # This source also spreads **ad_object, providing distinguished_name.
    _safe(
        con,
        "node_computer<-adminservice_site_definitions_computers",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(object_sid) AS sid, name, "
        f"dns_host_name AS dnshostname, NULL AS sam_account_name, distinguished_name, "
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
        f"dns_host_name AS dnshostname, NULL AS sam_account_name, distinguished_name, "
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
        f"dns_host_name AS dnshostname, sam_account_name, NULL AS distinguished_name, "
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
        f"dns_host_name AS dnshostname, sam_account_name, NULL AS distinguished_name, "
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
        f"dns_host_name AS dnshostname, sam_account_name, NULL AS distinguished_name, "
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
        f"  any_value(distinguished_name) AS distinguished_name, "
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
        "stored_in_sccm_site VARCHAR, "   # site_code where the account is stored (reserved)
        "distinguished_name VARCHAR, "
        "user_principal_name VARCHAR"
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
        "distinguished_name": "VARCHAR",
        "user_principal_name": "VARCHAR",
    }
    for _src in (
        "adminservice_r_user", "wmi_r_user", "remoteregistry_users",
        "adminservice_admins", "wmi_admins",
        "adminservice_reserved_accounts", "wmi_reserved_accounts",
    ):
        _ensure_columns(con, schema, _src, _optional)

    # --- adminservice_r_user: sid, name, resource_id@source_site_code, AD attributes ---
    # RUSER_COLUMNS includes DistinguishedName and UserPrincipalName (dlt snake-cases them).
    _safe(
        con,
        "node_user<-adminservice_r_user",
        f"INSERT INTO {schema}.node_user BY NAME "
        f"SELECT upper(sid) AS sid, name, "
        f"CASE WHEN resource_id IS NULL THEN NULL "
        f"     ELSE CAST(resource_id AS VARCHAR) || '@' || CAST(source_site_code AS VARCHAR) END AS resource_id_str, "
        f"false AS sccm_infra, "
        f"NULL AS stored_in_sccm_site, "
        f"distinguished_name, "
        f"user_principal_name "
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
        f"NULL AS stored_in_sccm_site, "
        f"distinguished_name, "
        f"user_principal_name "
        f"FROM {schema}.wmi_r_user "
        f"WHERE sid IS NOT NULL",
    )

    # --- remoteregistry_users: object_sid (clean snake_case); no resource_id or AD attrs ---
    _safe(
        con,
        "node_user<-remoteregistry_users",
        f"INSERT INTO {schema}.node_user BY NAME "
        f"SELECT upper(object_sid) AS sid, sam_account_name AS name, "
        f"NULL AS resource_id_str, "
        f"false AS sccm_infra, "
        f"NULL AS stored_in_sccm_site, "
        f"NULL AS distinguished_name, "
        f"NULL AS user_principal_name "
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
        f"NULL AS stored_in_sccm_site, "
        f"NULL AS distinguished_name, "
        f"NULL AS user_principal_name "
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
        f"NULL AS stored_in_sccm_site, "
        f"NULL AS distinguished_name, "
        f"NULL AS user_principal_name "
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
        f"site_code AS stored_in_sccm_site, "
        f"NULL AS distinguished_name, "
        f"NULL AS user_principal_name "
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
        f"site_code AS stored_in_sccm_site, "
        f"NULL AS distinguished_name, "
        f"NULL AS user_principal_name "
        f"FROM {schema}.wmi_reserved_accounts "
        f"WHERE object_sid IS NOT NULL",
    )

    # Collapse all staging rows into one row per SID.
    # resource_ids: array-union the non-null '<rid>@<site>' strings.
    # sccm_infra:   bool_or (true wins if any source set it true).
    # name / stored_in_sccm_site / distinguished_name / user_principal_name:
    #   any_value (first non-null wins; scalar per CMBP).
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_user AS "
        f"SELECT "
        f"  sid, "
        f"  any_value(name) AS name, "
        f"  coalesce(list_distinct(array_agg(resource_id_str) FILTER (WHERE resource_id_str IS NOT NULL)), CAST([] AS VARCHAR[])) AS resource_ids, "
        f"  bool_or(sccm_infra) AS sccm_infra, "
        f"  any_value(stored_in_sccm_site) AS stored_in_sccm_site, "
        f"  any_value(distinguished_name) AS distinguished_name, "
        f"  any_value(user_principal_name) AS user_principal_name "
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
    * ldap_sites                             — site_code, site_guid, parent_site_code,
                                               distinguished_name, source_forest
    * adminservice_site_systems / wmi_site_systems (correlated subquery)
                                             — sql_service_account_name (any non-null
                                               sql_server_service_logon_account per site_code)

    After collapsing duplicates with GROUP BY upper(site_code), the result is
    LEFT JOINed to site_hierarchy (built by _site_hierarchy) to stamp each row
    with root_site_code and sql_service_account_name. site_hierarchy must already
    exist when this runs. admin_users and stored_accounts list columns are added
    later by _enrich_site_lists.
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
        "install_dir VARCHAR, "
        "distinguished_name VARCHAR, "
        "source_forest VARCHAR, "
        "sql_server_fqdn VARCHAR, "       # SMS_SCI_SiteDefinition Props "SQLServerFQDN"
        "sql_service_port VARCHAR"        # SMS_SCI_SiteDefinition Props "SQLServicePort"
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
        "distinguished_name": "VARCHAR",    # ldap_sites (mSSMSSite DN)
        "source_forest": "VARCHAR",         # ldap_sites (mSSMSSourceForest)
        "sql_server_fqdn": "VARCHAR",       # site_definitions (Props SQLServerFQDN)
        "sql_service_port": "VARCHAR",      # site_definitions (Props SQLServicePort)
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
        f"NULL AS version, NULL AS build_number, NULL AS install_dir, "
        f"sql_server_fqdn, CAST(sql_service_port AS VARCHAR) AS sql_service_port "
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
        f"NULL AS version, NULL AS build_number, NULL AS install_dir, "
        f"sql_server_fqdn, CAST(sql_service_port AS VARCHAR) AS sql_service_port "
        f"FROM {schema}.wmi_site_definitions WHERE site_code IS NOT NULL",
    )

    # --- ldap_sites: site_code, site_guid, parent_site_code, distinguished_name, source_forest ---
    _safe(
        con,
        "node_site<-ldap_sites",
        f"INSERT INTO {schema}.node_site BY NAME "
        f"SELECT site_code, NULL AS site_name, NULL AS server_name, "
        f"parent_site_code, NULL AS site_type, "
        f"site_guid, NULL AS sql_server_name, NULL AS sql_database_name, "
        f"NULL AS version, NULL AS build_number, NULL AS install_dir, "
        f"distinguished_name, source_forest "
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
        f"  any_value(install_dir) AS install_dir, "
        f"  any_value(distinguished_name) AS distinguished_name, "
        f"  any_value(source_forest) AS source_forest, "
        f"  any_value(sql_server_fqdn) AS sql_server_fqdn, "
        f"  any_value(sql_service_port) AS sql_service_port "
        f"FROM {schema}.node_site "
        f"WHERE site_code IS NOT NULL "
        f"GROUP BY upper(site_code)"
    )

    # Aggregate sql_server_service_logon_account per site_code from both
    # site_systems sources into a temp table so the final JOIN can reference a
    # single table regardless of which sources are present (CMBP ps1:225 area).
    con.execute(
        "CREATE OR REPLACE TEMP TABLE _site_sql_acct (site_code VARCHAR, acct VARCHAR)"
    )
    for _ss in ("adminservice_site_systems", "wmi_site_systems"):
        _ensure_columns(con, schema, _ss, {
            "site_code": "VARCHAR",
            "sql_server_service_logon_account": "VARCHAR",
        })
        _safe(
            con,
            f"_site_sql_acct<-{_ss}",
            f"INSERT INTO _site_sql_acct "
            f"SELECT upper(site_code), any_value(sql_server_service_logon_account) "
            f"FROM {schema}.{_ss} "
            f"WHERE site_code IS NOT NULL AND sql_server_service_logon_account IS NOT NULL "
            f"GROUP BY upper(site_code)",
        )

    # Resolve the site-server and SQL-server computer SIDs/FQDNs per site (CMBP
    # ps1:7052-7063). The privileged collector already resolved each server to an AD
    # object at collect time and tagged it with its role ("SMS Site Server@<site>" /
    # "SMS SQL Server@<site>") in *_site_definitions_computers, so we read object_sid
    # and dns_host_name straight from there instead of re-resolving. CMBP names these
    # properties "*DomainSID" but stores the full computer SID, not the domain prefix —
    # we mirror that. The site code is parsed back out of the role string.
    con.execute(
        "CREATE OR REPLACE TEMP TABLE _site_def_computers "
        "(role_kind VARCHAR, site_code VARCHAR, object_sid VARCHAR, dns_host_name VARCHAR)"
    )
    for _sdc in ("adminservice_site_definitions_computers", "wmi_site_definitions_computers"):
        _ensure_columns(con, schema, _sdc, {
            "object_sid": "VARCHAR",
            "dns_host_name": "VARCHAR",
            "sccm_site_system_roles": "VARCHAR",
        })
        _safe(
            con,
            f"_site_def_computers<-{_sdc}",
            f"INSERT INTO _site_def_computers "
            f"SELECT CASE WHEN sccm_site_system_roles LIKE 'SMS Site Server@%' THEN 'SITE' "
            f"            WHEN sccm_site_system_roles LIKE 'SMS SQL Server@%' THEN 'SQL' END AS role_kind, "
            f"  upper(split_part(sccm_site_system_roles, '@', 2)) AS site_code, "
            f"  upper(object_sid) AS object_sid, dns_host_name "
            f"FROM {schema}.{_sdc} "
            f"WHERE object_sid IS NOT NULL "
            f"  AND (sccm_site_system_roles LIKE 'SMS Site Server@%' "
            f"       OR sccm_site_system_roles LIKE 'SMS SQL Server@%')",
        )

    # Stamp each row with root_site_code from site_hierarchy, sql_service_account_name
    # from the aggregated temp table (CMBP ps1:225 area), and the site-server/SQL-server
    # SIDs + FQDNs (CMBP ps1:7052-7065). The SQL service-account SID is resolved by
    # name through principal_by_name (CMBP ps1:3040). All LEFT JOINs so a site missing
    # any of these still appears.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_site AS "
        f"SELECT ns.*, sh.root_site_code, ssa.acct AS sql_service_account_name, "
        f"  site_srv.object_sid AS site_server_domain_sid, "
        f"  site_srv.dns_host_name AS site_server_fqdn, "
        f"  sql_srv.object_sid AS sql_server_domain_sid, "
        f"  (SELECT pbn.sid FROM {schema}.principal_by_name pbn "
        f"   WHERE upper(pbn.name) = upper(ssa.acct) LIMIT 1) AS sql_service_account_domain_sid "
        f"FROM {schema}.node_site ns "
        f"LEFT JOIN {schema}.site_hierarchy sh USING (site_code) "
        f"LEFT JOIN (SELECT site_code, any_value(acct) AS acct FROM _site_sql_acct GROUP BY site_code) ssa "
        f"  USING (site_code) "
        f"LEFT JOIN (SELECT site_code, any_value(object_sid) AS object_sid, "
        f"                  any_value(dns_host_name) AS dns_host_name "
        f"           FROM _site_def_computers WHERE role_kind = 'SITE' GROUP BY site_code) site_srv "
        f"  USING (site_code) "
        f"LEFT JOIN (SELECT site_code, any_value(object_sid) AS object_sid "
        f"           FROM _site_def_computers WHERE role_kind = 'SQL' GROUP BY site_code) sql_srv "
        f"  USING (site_code)"
    )
    logger.info("node_site built in schema %r", schema)


def _root_code(con: duckdb.DuckDBPyConnection, schema: str) -> str | None:
    """Return the single hierarchy root_site_code (built by _site_hierarchy).

    Used to mint SCCM-native ids at final coalesce time. Later tasks (B2, B3,
    E2) all call this helper — define it once here. Returns None if no site
    data was collected (site_hierarchy missing or empty).
    """
    try:
        row = con.execute(f"SELECT any_value(root_site_code) FROM {schema}.site_hierarchy").fetchone()
        return row[0] if row else None
    except duckdb.CatalogException:
        # site_hierarchy not yet built; caller handles None gracefully.
        logger.warning("_root_code: site_hierarchy missing; SCCM-native ids will lack a root scope")
        return None


def _read_disable_possible(con: duckdb.DuckDBPyConnection, schema: str) -> bool:
    """Read the persisted disable_possible_edges flag (collection_settings, written at
    collect time). True only if the flag is set; False if the table is absent (older
    collection) or the flag is false/NULL. Gates the possible-client rows (E2) and,
    later, Stage 6 relay edges."""
    try:
        row = con.execute(
            f"SELECT bool_or(disable_possible_edges) FROM {schema}.collection_settings"
        ).fetchone()
        val = bool(row[0]) if row and row[0] is not None else False
    except duckdb.CatalogException:
        # Older collection without the settings table -> default to emitting possible rows.
        logger.info("collection_settings absent; possible edges/nodes enabled by default")
        val = False
    logger.info("disable_possible_edges = %s", val)
    return val


def _node_collection(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Build node_collection: one row per collection_id, coalesced from all collection sources.

    Sources and the columns they contribute:

    * adminservice_collections — collection_id, name, collection_type, member_count, is_built_in,
                                 source_site_code, last_change_time, last_member_change_time
    * wmi_collections          — same shape

    The final GROUP BY collapses duplicates (same collection from multiple sources) with
    any_value for scalars, max for numeric aggregates, and bool_or for booleans. Each row
    is stamped with the hierarchy root_site_code from _root_code (via site_hierarchy).
    """
    # Staging table — one raw row per source record before collapsing.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_collection ("
        "collection_id VARCHAR, name VARCHAR, collection_type INTEGER, member_count BIGINT, "
        "comment VARCHAR, is_built_in BOOLEAN, limit_to_collection_id VARCHAR, "
        "limit_to_collection_name VARCHAR, collection_variables_count BIGINT, "
        "source_site_code VARCHAR, last_change_time VARCHAR, last_member_change_time VARCHAR)"
    )

    # Pre-create optional columns so a source missing one (never-emitted, or
    # dlt-dropped because all-NULL) still binds via INSERT … BY NAME. See _ensure_columns.
    _optional = {
        "name": "VARCHAR",
        "collection_type": "INTEGER",
        "member_count": "BIGINT",
        "comment": "VARCHAR",
        "is_built_in": "BOOLEAN",
        "limit_to_collection_id": "VARCHAR",
        "limit_to_collection_name": "VARCHAR",
        "collection_variables_count": "BIGINT",
        "source_site_code": "VARCHAR",
        "last_change_time": "VARCHAR",
        "last_member_change_time": "VARCHAR",
    }
    for _src in ("adminservice_collections", "wmi_collections"):
        _ensure_columns(con, schema, _src, _optional)
        _safe(
            con,
            f"node_collection<-{_src}",
            f"INSERT INTO {schema}.node_collection BY NAME "
            f"SELECT upper(collection_id) AS collection_id, name, "
            f"TRY_CAST(collection_type AS INTEGER) AS collection_type, "
            f"TRY_CAST(member_count AS BIGINT) AS member_count, comment, "
            f"is_built_in, limit_to_collection_id, limit_to_collection_name, "
            f"TRY_CAST(collection_variables_count AS BIGINT) AS collection_variables_count, "
            f"source_site_code, last_change_time, last_member_change_time "
            f"FROM {schema}.{_src} WHERE collection_id IS NOT NULL",
        )

    # Collapse all staging rows into one row per collection_id, then stamp with root.
    root = _root_code(con, schema)
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_collection AS "
        f"SELECT collection_id, "
        f"any_value(name) AS name, "
        f"max(collection_type) AS collection_type, "
        f"max(member_count) AS member_count, "
        f"any_value(comment) AS comment, "
        f"bool_or(is_built_in) AS is_built_in, "
        f"any_value(limit_to_collection_id) AS limit_to_collection_id, "
        f"any_value(limit_to_collection_name) AS limit_to_collection_name, "
        f"max(collection_variables_count) AS collection_variables_count, "
        f"any_value(source_site_code) AS source_site_code, "
        f"any_value(last_change_time) AS last_change_time, "
        f"any_value(last_member_change_time) AS last_member_change_time, "
        f"? AS root_site_code "
        f"FROM {schema}.node_collection "
        f"GROUP BY collection_id",
        [root],
    )
    logger.info("node_collection built in schema %r", schema)


def _enrich_collection_members(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Add node_collection.members: the raw ResourceID@SiteCode keys per collection
    (CMBP ps1:7605), faithful — built-in/unresolved members included. From the raw
    collection_members tables, NOT from graph_edges (Stage 3 Decision #6)."""
    con.execute("CREATE OR REPLACE TEMP TABLE _cmembers (collection_id VARCHAR, member_key VARCHAR)")
    for _src in ("adminservice_collection_members", "wmi_collection_members"):
        _ensure_columns(con, schema, _src, {"collection_id": "VARCHAR", "resource_id": "BIGINT", "site_code": "VARCHAR"})
        _safe(con, f"_cmembers<-{_src}",
              f"INSERT INTO _cmembers SELECT upper(collection_id), "
              f"CAST(resource_id AS VARCHAR) || '@' || CAST(site_code AS VARCHAR) "
              f"FROM {schema}.{_src} WHERE collection_id IS NOT NULL AND resource_id IS NOT NULL")
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_collection AS "
        f"SELECT c.*, coalesce(m.members, CAST([] AS VARCHAR[])) AS members "
        f"FROM {schema}.node_collection c "
        f"LEFT JOIN (SELECT collection_id, list_distinct(array_agg(member_key)) AS members "
        f"           FROM _cmembers GROUP BY collection_id) m ON m.collection_id = c.collection_id")
    logger.info("node_collection.members enriched in schema %r", schema)


def _enrich_role_members(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Add node_security_role.members: the admin node ids assigned to each role
    (CMBP ps1:7854/7880). Resolved from raw admins (roles id list + role_names
    fallback via role_by_name when roles is empty), NOT from graph_edges (Decision #6).

    Each member id is upper(logon_name)@root, matching the SCCM_AdminUser node id.
    """
    root = _root_code(con, schema) or ""
    # Inline the @root suffix so the INSERT SQL needs no parameters (matches _safe convention).
    suffix = f" || '@{root}'" if root else ""
    con.execute("CREATE OR REPLACE TEMP TABLE _rmembers (role_id VARCHAR, admin_id VARCHAR)")
    for _src in ("adminservice_admins", "wmi_admins"):
        _ensure_columns(con, schema, _src, {"logon_name": "VARCHAR", "roles": "VARCHAR", "role_names": "VARCHAR"})

        # Arm 1: role id list — unnest the roles JSON/CSV array via _arr().
        _safe(con, f"_rmembers_roles<-{_src}",
              f"INSERT INTO _rmembers SELECT upper(trim(t.rid)), upper(a.logon_name){suffix} "
              f"FROM {schema}.{_src} a, unnest({_arr('a.roles')}) AS t(rid) "
              f"WHERE a.logon_name IS NOT NULL AND trim(t.rid) != ''")

        # Arm 2: role_names fallback — ONLY when roles is empty; resolve name -> id via role_by_name.
        _safe(con, f"_rmembers_names<-{_src}",
              f"INSERT INTO _rmembers SELECT rbn.role_id, upper(a.logon_name){suffix} "
              f"FROM {schema}.{_src} a, unnest({_arr('a.role_names')}) AS t(rn) "
              f"JOIN {schema}.role_by_name rbn ON upper(trim(t.rn)) = rbn.name "
              f"WHERE a.logon_name IS NOT NULL AND trim(t.rn) != '' AND len({_arr('a.roles')}) = 0")

    # Attach the aggregated member lists to node_security_role.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_security_role AS "
        f"SELECT r.*, coalesce(m.members, CAST([] AS VARCHAR[])) AS members "
        f"FROM {schema}.node_security_role r "
        f"LEFT JOIN (SELECT role_id, list_distinct(array_agg(admin_id)) AS members "
        f"           FROM _rmembers GROUP BY role_id) m ON m.role_id = r.role_id")
    logger.info("node_security_role.members enriched in schema %r", schema)


def _enrich_admin_assignments(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Add node_admin_user.collection_ids / role_ids / member_of (CMBP ps1:7775/7783/7848).

    role_ids = raw admin.roles list; member_of = resolved role node ids (roles list
    primary, role_names fallback when roles is empty); collection_ids = collection node
    ids resolved from collection_names via collection_by_name. Built from raw admins
    rows + name lookups, NOT from graph_edges (Decision #6).
    """
    root = _root_code(con, schema) or ""
    suffix = f" || '@{root}'" if root else ""
    con.execute("CREATE OR REPLACE TEMP TABLE _aassign (logon_key VARCHAR, kind VARCHAR, val VARCHAR)")
    for _src in ("adminservice_admins", "wmi_admins"):
        _ensure_columns(con, schema, _src, {"logon_name": "VARCHAR", "roles": "VARCHAR",
                                            "role_names": "VARCHAR", "collection_names": "VARCHAR"})

        # Arm 1: role_ids — raw role id from the roles JSON/CSV array.
        _safe(con, f"_aassign_roleid<-{_src}",
              f"INSERT INTO _aassign SELECT upper(a.logon_name), 'role_id', upper(trim(t.rid)) "
              f"FROM {schema}.{_src} a, unnest({_arr('a.roles')}) AS t(rid) "
              f"WHERE a.logon_name IS NOT NULL AND trim(t.rid) != ''")

        # Arm 2: member_of — role node id from the roles list (upper(role_id)@root).
        _safe(con, f"_aassign_memberof_id<-{_src}",
              f"INSERT INTO _aassign SELECT upper(a.logon_name), 'member_of', upper(trim(t.rid)){suffix} "
              f"FROM {schema}.{_src} a, unnest({_arr('a.roles')}) AS t(rid) "
              f"WHERE a.logon_name IS NOT NULL AND trim(t.rid) != ''")

        # Arm 3: member_of fallback — role_names -> role_by_name -> role node id,
        # only when the roles list is empty (no direct ids available).
        _safe(con, f"_aassign_memberof_name<-{_src}",
              f"INSERT INTO _aassign SELECT upper(a.logon_name), 'member_of', rbn.role_id{suffix} "
              f"FROM {schema}.{_src} a, unnest({_arr('a.role_names')}) AS t(rn) "
              f"JOIN {schema}.role_by_name rbn ON upper(trim(t.rn)) = rbn.name "
              f"WHERE a.logon_name IS NOT NULL AND trim(t.rn) != '' AND len({_arr('a.roles')}) = 0")

        # Arm 4: collection_ids — collection_names -> collection_by_name -> collection node id.
        _safe(con, f"_aassign_coll<-{_src}",
              f"INSERT INTO _aassign SELECT upper(a.logon_name), 'collection_id', cbn.collection_id{suffix} "
              f"FROM {schema}.{_src} a, unnest({_arr('a.collection_names')}) AS t(cn) "
              f"JOIN {schema}.collection_by_name cbn ON upper(trim(t.cn)) = cbn.name "
              f"WHERE a.logon_name IS NOT NULL AND trim(t.cn) != ''")

    # Correlated-subquery aggregation: attach all three list columns to node_admin_user.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_admin_user AS SELECT a.*, "
        f"coalesce((SELECT list_distinct(array_agg(val)) FROM _aassign x "
        f"          WHERE x.logon_key = upper(a.logon_name) AND x.kind = 'collection_id'), "
        f"         CAST([] AS VARCHAR[])) AS collection_ids, "
        f"coalesce((SELECT list_distinct(array_agg(val)) FROM _aassign x "
        f"          WHERE x.logon_key = upper(a.logon_name) AND x.kind = 'role_id'), "
        f"         CAST([] AS VARCHAR[])) AS role_ids, "
        f"coalesce((SELECT list_distinct(array_agg(val)) FROM _aassign x "
        f"          WHERE x.logon_key = upper(a.logon_name) AND x.kind = 'member_of'), "
        f"         CAST([] AS VARCHAR[])) AS member_of "
        f"FROM {schema}.node_admin_user a")
    logger.info("node_admin_user assignment lists enriched in schema %r", schema)


def _enrich_client_device(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Add resolved *_sid fields and collection_ids/collection_names to node_client_device.

    SID resolution (CMBP ps1:7227/7232/7245/7248): each name-only user field on the
    device row (primary_user_name, current_logon_user_name, ad_last_logon_user_name,
    last_mp_server_name) is looked up in principal_by_name via a correlated subquery.

    Collection lists (CMBP ps1:7228-7229): built from collection_members JOIN collections
    keyed on the device's resource_id_str (<resource_id>@<site>).
    """
    root = _root_code(con, schema) or ""
    suffix = f" || '@{root}'" if root else ""

    # Gather all collection memberships per device resource_id into a temp table.
    con.execute("CREATE OR REPLACE TEMP TABLE _devcoll (rid_key VARCHAR, coll_id VARCHAR, coll_name VARCHAR)")
    for _cm in ("adminservice_collection_members", "wmi_collection_members"):
        _ensure_columns(con, schema, _cm, {"collection_id": "VARCHAR", "resource_id": "BIGINT", "site_code": "VARCHAR"})
        for _c in ("adminservice_collections", "wmi_collections"):
            _ensure_columns(con, schema, _c, {"collection_id": "VARCHAR", "name": "VARCHAR"})
            _safe(con, f"_devcoll<-{_cm}+{_c}",
                  f"INSERT INTO _devcoll "
                  f"SELECT CAST(cm.resource_id AS VARCHAR) || '@' || CAST(cm.site_code AS VARCHAR), "
                  f"upper(cm.collection_id){suffix}, c.name "
                  f"FROM {schema}.{_cm} cm JOIN {schema}.{_c} c ON upper(c.collection_id) = upper(cm.collection_id) "
                  f"WHERE cm.resource_id IS NOT NULL AND cm.collection_id IS NOT NULL")

    # Rebuild node_client_device with SID columns and collection list columns appended.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_client_device AS SELECT d.*, "
        f"(SELECT pbn.sid FROM {schema}.principal_by_name pbn "
        f" WHERE upper(pbn.name) = upper(trim(d.primary_user_name)) LIMIT 1) AS primary_user_sid, "
        f"(SELECT pbn.sid FROM {schema}.principal_by_name pbn "
        f" WHERE upper(pbn.name) = upper(trim(d.current_logon_user_name)) LIMIT 1) AS current_logon_user_sid, "
        f"(SELECT pbn.sid FROM {schema}.principal_by_name pbn "
        f" WHERE upper(pbn.name) = upper(trim(d.ad_last_logon_user_name)) LIMIT 1) AS ad_last_logon_user_sid, "
        f"(SELECT pbn.sid FROM {schema}.principal_by_name pbn "
        f" WHERE upper(pbn.name) = upper(trim(d.last_mp_server_name)) LIMIT 1) AS last_reported_mp_server_sid, "
        f"coalesce((SELECT list_distinct(array_agg(coll_id)) FROM _devcoll x WHERE x.rid_key = d.resource_id_str), "
        f"         CAST([] AS VARCHAR[])) AS collection_ids, "
        f"coalesce((SELECT list_distinct(array_agg(coll_name)) FROM _devcoll x WHERE x.rid_key = d.resource_id_str), "
        f"         CAST([] AS VARCHAR[])) AS collection_names "
        f"FROM {schema}.node_client_device d"
    )
    logger.info("node_client_device resolved SIDs + collection lists enriched in schema %r", schema)


def _enrich_site_lists(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Add node_site.admin_users and node_site.stored_accounts list columns.

    admin_users (CMBP ps1:1724): all SCCM admin logon names uppercased and scoped
    to the hierarchy root (e.g. "DOMAIN\\USER@CAS"). Every admin in the single
    hierarchy is contained by every non-secondary site, so the same list appears
    on every site row.

    stored_accounts (CMBP ps1:7141): the object_sid values from the reserved-
    accounts table scoped to that specific site_code (uppercased).
    """
    root = _root_code(con, schema) or ""
    suffix = f" || '@{root}'" if root else ""

    # Collect all admin logon names into a temp table; upper() for consistency.
    con.execute("CREATE OR REPLACE TEMP TABLE _alladmins (admin_id VARCHAR)")
    for _src in ("adminservice_admins", "wmi_admins"):
        _ensure_columns(con, schema, _src, {"logon_name": "VARCHAR"})
        _safe(
            con,
            f"_alladmins<-{_src}",
            f"INSERT INTO _alladmins "
            f"SELECT DISTINCT upper(logon_name){suffix} "
            f"FROM {schema}.{_src} WHERE logon_name IS NOT NULL",
        )

    # Collect all reserved-account SIDs per site_code into a temp table.
    con.execute("CREATE OR REPLACE TEMP TABLE _stored (site_code VARCHAR, sid VARCHAR)")
    for _src in ("adminservice_reserved_accounts", "wmi_reserved_accounts"):
        _ensure_columns(con, schema, _src, {"site_code": "VARCHAR", "object_sid": "VARCHAR"})
        _safe(
            con,
            f"_stored<-{_src}",
            f"INSERT INTO _stored "
            f"SELECT upper(site_code), upper(object_sid) "
            f"FROM {schema}.{_src} "
            f"WHERE site_code IS NOT NULL AND object_sid IS NOT NULL",
        )

    # Rebuild node_site with both list columns appended. The admin_users subquery
    # has no site_code filter — all admins are contained by the single hierarchy.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_site AS "
        f"SELECT s.*, "
        f"coalesce("
        f"  (SELECT list_distinct(array_agg(admin_id)) FROM _alladmins), "
        f"  CAST([] AS VARCHAR[])"
        f") AS admin_users, "
        f"coalesce("
        f"  (SELECT list_distinct(array_agg(st.sid)) FROM _stored st WHERE st.site_code = s.site_code), "
        f"  CAST([] AS VARCHAR[])"
        f") AS stored_accounts "
        f"FROM {schema}.node_site s"
    )
    logger.info("node_site.admin_users + stored_accounts enriched in schema %r", schema)


def _node_security_role(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """One row per role_id, coalesced from adminservice/wmi security_roles.

    Audit fields (site_code, created_by, created_date, last_modified_by,
    last_modified_date) come from ROLE_COLUMNS in the source tables. site_code
    is aliased from source_site (ROLE_COLUMNS.SourceSite -> dlt snake-case).
    """
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_security_role ("
        "role_id VARCHAR, role_name VARCHAR, role_description VARCHAR, is_built_in BOOLEAN, "
        "is_sec_admin_role BOOLEAN, copied_from_id VARCHAR, number_of_admins BIGINT, operations VARCHAR[], "
        "site_code VARCHAR, created_by VARCHAR, created_date VARCHAR, "
        "last_modified_by VARCHAR, last_modified_date VARCHAR)"
    )
    _optional = {
        "role_name": "VARCHAR",
        "role_description": "VARCHAR",
        "is_built_in": "BOOLEAN",
        "is_sec_admin_role": "BOOLEAN",
        "copied_from_id": "VARCHAR",
        "number_of_admins": "BIGINT",
        "operations": "VARCHAR",
        # Audit fields (ROLE_COLUMNS; may be absent if dlt dropped all-NULL columns).
        "source_site": "VARCHAR",
        "created_by": "VARCHAR",
        "created_date": "VARCHAR",
        "last_modified_by": "VARCHAR",
        "last_modified_date": "VARCHAR",
    }
    for _src in ("adminservice_security_roles", "wmi_security_roles"):
        _ensure_columns(con, schema, _src, _optional)
        _safe(
            con,
            f"node_security_role<-{_src}",
            f"INSERT INTO {schema}.node_security_role BY NAME "
            f"SELECT upper(role_id) AS role_id, role_name, role_description, is_built_in, "
            f"is_sec_admin_role, copied_from_id, TRY_CAST(number_of_admins AS BIGINT) AS number_of_admins, "
            f"{_arr('operations')} AS operations, "
            f"source_site AS site_code, created_by, created_date, last_modified_by, last_modified_date "
            f"FROM {schema}.{_src} WHERE role_id IS NOT NULL",
        )

    # Collapse all staging rows into one row per role_id (already uppercased above), then stamp with root.
    root = _root_code(con, schema)
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_security_role AS "
        f"SELECT role_id, "
        f"any_value(role_name) AS role_name, "
        f"any_value(role_description) AS role_description, "
        f"bool_or(is_built_in) AS is_built_in, "
        f"bool_or(is_sec_admin_role) AS is_sec_admin_role, "
        f"any_value(copied_from_id) AS copied_from_id, "
        f"max(number_of_admins) AS number_of_admins, "
        f"list_distinct(list_filter(flatten(list(operations)), x -> x IS NOT NULL AND trim(x) != '')) AS operations, "
        f"any_value(site_code) AS site_code, "
        f"any_value(created_by) AS created_by, "
        f"any_value(created_date) AS created_date, "
        f"any_value(last_modified_by) AS last_modified_by, "
        f"any_value(last_modified_date) AS last_modified_date, "
        f"? AS root_site_code "
        f"FROM {schema}.node_security_role "
        f"GROUP BY role_id",
        [root],
    )
    logger.info("node_security_role built in schema %r", schema)


def _node_admin_user(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """One row per upper(logon_name), coalesced from adminservice/wmi admins.

    Scalar audit fields (display_name, source_site_code, created_by, created_date,
    last_modified_by, last_modified_date) come from ADMIN_COLUMNS in the source tables.
    source_site_code is aliased from source_site (ADMIN_COLUMNS.SourceSite -> dlt snake-case).
    logon_name stored original-case; dedup key is upper(logon_name).
    """
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_admin_user ("
        "logon_name VARCHAR, admin_id VARCHAR, admin_sid VARCHAR, display_name VARCHAR, "
        "distinguished_name VARCHAR, is_group BOOLEAN, account_type INTEGER, "
        "source_site_code VARCHAR, created_by VARCHAR, created_date VARCHAR, "
        "last_modified_by VARCHAR, last_modified_date VARCHAR)"
    )
    _optional = {
        "admin_id": "VARCHAR",
        "admin_sid": "VARCHAR",
        "display_name": "VARCHAR",
        "distinguished_name": "VARCHAR",
        "is_group": "BOOLEAN",
        "account_type": "INTEGER",
        # Audit fields (ADMIN_COLUMNS; may be absent if dlt dropped all-NULL columns).
        "source_site": "VARCHAR",
        "created_by": "VARCHAR",
        "created_date": "VARCHAR",
        "last_modified_by": "VARCHAR",
        "last_modified_date": "VARCHAR",
    }
    for _src in ("adminservice_admins", "wmi_admins"):
        _ensure_columns(con, schema, _src, _optional)
        _safe(con, f"node_admin_user<-{_src}",
              f"INSERT INTO {schema}.node_admin_user BY NAME "
              f"SELECT logon_name, CAST(admin_id AS VARCHAR) AS admin_id, upper(admin_sid) AS admin_sid, "
              f"display_name, distinguished_name, is_group, TRY_CAST(account_type AS INTEGER) AS account_type, "
              f"source_site AS source_site_code, created_by, created_date, last_modified_by, last_modified_date "
              f"FROM {schema}.{_src} WHERE logon_name IS NOT NULL")
    root = _root_code(con, schema)
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_admin_user AS SELECT "
        f"any_value(logon_name) AS logon_name, any_value(admin_id) AS admin_id, "
        f"any_value(admin_sid) AS admin_sid, any_value(display_name) AS display_name, "
        f"any_value(distinguished_name) AS distinguished_name, bool_or(is_group) AS is_group, "
        f"max(account_type) AS account_type, "
        f"any_value(source_site_code) AS source_site_code, "
        f"any_value(created_by) AS created_by, "
        f"any_value(created_date) AS created_date, "
        f"any_value(last_modified_by) AS last_modified_by, "
        f"any_value(last_modified_date) AS last_modified_date, "
        f"? AS root_site_code "
        f"FROM {schema}.node_admin_user GROUP BY upper(logon_name)", [root])
    logger.info("node_admin_user built in schema %r", schema)


def _node_client_device(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """One row per smsid from adminservice/wmi client_devices (real clients only:
    is_client AND NOT is_obsolete). possible/ad_domain_sid are placeholders for the
    possible-client rows added in Task E2.

    Telemetry scalars added in Stage 3 C4 (CMBP parity):
      ad_last_logon_time, ad_last_logon_user_domain, source_site_code (from brief)
      last_active_time, last_online_time, last_offline_time (reclassified PORT-NOW by matrix)
    SID resolution and collection lists are added by _enrich_client_device.
    """
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_client_device ("
        "smsid VARCHAR, name VARCHAR, site_code VARCHAR, resource_id_str VARCHAR, "
        "device_os VARCHAR, device_os_build VARCHAR, is_virtual_machine BOOLEAN, co_managed BOOLEAN, "
        "aad_device_id VARCHAR, aad_tenant_id VARCHAR, last_mp_server_name VARCHAR, "
        "primary_user_name VARCHAR, current_logon_user_name VARCHAR, ad_last_logon_user_name VARCHAR, "
        "ad_last_logon_time VARCHAR, ad_last_logon_user_domain VARCHAR, source_site_code VARCHAR, "
        "last_active_time VARCHAR, last_online_time VARCHAR, last_offline_time VARCHAR, "
        "possible BOOLEAN, ad_domain_sid VARCHAR)"
    )
    _optional = {
        "name": "VARCHAR", "site_code": "VARCHAR", "resource_id": "BIGINT",
        "device_os": "VARCHAR", "device_os_build": "VARCHAR", "is_virtual_machine": "BOOLEAN",
        "co_managed": "BOOLEAN", "aad_device_id": "VARCHAR", "aad_tenant_id": "VARCHAR",
        "last_mp_server_name": "VARCHAR", "primary_user": "VARCHAR",
        "current_logon_user": "VARCHAR", "user_name": "VARCHAR",
        "is_client": "BOOLEAN", "is_obsolete": "BOOLEAN",
        # Telemetry scalars (Stage 3 C4).
        "ad_last_logon_time": "VARCHAR", "user_domain_name": "VARCHAR",
        "source_site_code": "VARCHAR",
        # dlt snake-cases ADLastLogonTime -> a_d_last_logon_time (collector fixes this
        # back to ad_last_logon_time); CNLastOnlineTime -> c_n_last_online_time;
        # CNLastOfflineTime -> c_n_last_offline_time; LastActiveTime -> last_active_time.
        "last_active_time": "VARCHAR",
        "c_n_last_online_time": "VARCHAR",
        "c_n_last_offline_time": "VARCHAR",
    }
    for _src in ("adminservice_client_devices", "wmi_client_devices"):
        _ensure_columns(con, schema, _src, _optional)
        _safe(con, f"node_client_device<-{_src}",
              f"INSERT INTO {schema}.node_client_device BY NAME "
              f"SELECT upper(smsid) AS smsid, name, site_code, "
              f"CASE WHEN resource_id IS NULL THEN NULL "
              f"     ELSE CAST(resource_id AS VARCHAR) || '@' || CAST(site_code AS VARCHAR) END AS resource_id_str, "
              f"device_os, device_os_build, is_virtual_machine, co_managed, aad_device_id, aad_tenant_id, "
              f"last_mp_server_name, primary_user AS primary_user_name, "
              f"current_logon_user AS current_logon_user_name, user_name AS ad_last_logon_user_name, "
              f"ad_last_logon_time, user_domain_name AS ad_last_logon_user_domain, source_site_code, "
              f"last_active_time, c_n_last_online_time AS last_online_time, "
              f"c_n_last_offline_time AS last_offline_time, "
              f"false AS possible, NULL AS ad_domain_sid "
              f"FROM {schema}.{_src} "
              f"WHERE smsid IS NOT NULL AND coalesce(is_client, false) AND NOT coalesce(is_obsolete, false)")
    root = _root_code(con, schema)
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_client_device AS SELECT smsid, "
        f"any_value(name) AS name, any_value(site_code) AS site_code, "
        f"any_value(resource_id_str) AS resource_id_str, any_value(device_os) AS device_os, "
        f"any_value(device_os_build) AS device_os_build, bool_or(is_virtual_machine) AS is_virtual_machine, "
        f"bool_or(co_managed) AS co_managed, any_value(aad_device_id) AS aad_device_id, "
        f"any_value(aad_tenant_id) AS aad_tenant_id, any_value(last_mp_server_name) AS last_mp_server_name, "
        f"any_value(primary_user_name) AS primary_user_name, "
        f"any_value(current_logon_user_name) AS current_logon_user_name, "
        f"any_value(ad_last_logon_user_name) AS ad_last_logon_user_name, "
        f"any_value(ad_last_logon_time) AS ad_last_logon_time, "
        f"any_value(ad_last_logon_user_domain) AS ad_last_logon_user_domain, "
        f"any_value(source_site_code) AS source_site_code, "
        f"any_value(last_active_time) AS last_active_time, "
        f"any_value(last_online_time) AS last_online_time, "
        f"any_value(last_offline_time) AS last_offline_time, "
        f"bool_or(possible) AS possible, any_value(ad_domain_sid) AS ad_domain_sid, ? AS root_site_code "
        f"FROM {schema}.node_client_device GROUP BY smsid", [root])
    logger.info("node_client_device built in schema %r", schema)


def _node_client_device_possible(
    con: duckdb.DuckDBPyConnection, schema: str, disable_possible: bool
) -> None:
    """Append inferred possible-client SCCM_ClientDevice rows from ldap_cmrc_devices
    (CMBP ps1:3272, fixed to a deterministic id). id = upper(object_sid)@root — its own
    namespace, so it never merges with the Computer node (raw SID) and Stage 4 SameHostAs
    can later dedup it against a real client via ad_domain_sid. Gated by
    --disable-possible-edges and on a present root_site_code."""
    if disable_possible:
        # --disable-possible-edges was set at collection time; skip all possible-client rows.
        logger.info("possible-client nodes disabled (--disable-possible-edges); skipping")
        return
    root = _root_code(con, schema)
    if not root:
        # Without a hierarchy root the id would collapse to the bare SID and collide
        # with the Computer node; a possible-client only makes sense inside a hierarchy.
        logger.warning("no root_site_code resolved; skipping possible-client nodes")
        return
    _ensure_columns(con, schema, "ldap_cmrc_devices", {"object_sid": "VARCHAR", "name": "VARCHAR"})
    # root is a 3-character alphanumeric site code so inlining it as a literal is safe.
    _safe(con, "node_client_device_possible<-ldap_cmrc_devices",
          f"INSERT INTO {schema}.node_client_device BY NAME "
          f"SELECT upper(object_sid) || '@{root}' AS smsid, name, '{root}' AS site_code, "
          f"true AS possible, upper(object_sid) AS ad_domain_sid, '{root}' AS root_site_code "
          f"FROM {schema}.ldap_cmrc_devices WHERE object_sid IS NOT NULL")
    logger.info("node_client_device_possible built in schema %r", schema)


def _resource_to_sid(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Build resource_key '<resource_id>@<site>' -> SID lookup.

    Covers r_system (computers), r_user (users), and user_group (groups). The
    r_system source filters out obsolete rows; the others do not carry that flag.
    SIDs are uppercased for consistent joins. Used by Stage 2 edge builders that
    receive resource_id fields and need to resolve them to a SID.
    """
    con.execute(f"CREATE OR REPLACE TABLE {schema}.resource_to_sid (resource_key VARCHAR, sid VARCHAR)")

    # r_system sources: filter obsolete rows
    for _src in ("adminservice_r_system", "wmi_r_system"):
        _ensure_columns(con, schema, _src, {"resource_id": "BIGINT", "source_site_code": "VARCHAR", "sid": "VARCHAR", "obsolete": "BOOLEAN"})
        _safe(con, f"resource_to_sid<-{_src}",
              f"INSERT INTO {schema}.resource_to_sid "
              f"SELECT CAST(resource_id AS VARCHAR)||'@'||CAST(source_site_code AS VARCHAR), upper(sid) "
              f"FROM {schema}.{_src} WHERE resource_id IS NOT NULL AND sid IS NOT NULL AND NOT coalesce(obsolete, false)")

    # r_user sources: no obsolete flag
    for _src in ("adminservice_r_user", "wmi_r_user"):
        _ensure_columns(con, schema, _src, {"resource_id": "BIGINT", "source_site_code": "VARCHAR", "sid": "VARCHAR"})
        _safe(con, f"resource_to_sid<-{_src}",
              f"INSERT INTO {schema}.resource_to_sid "
              f"SELECT CAST(resource_id AS VARCHAR)||'@'||CAST(source_site_code AS VARCHAR), upper(sid) "
              f"FROM {schema}.{_src} WHERE resource_id IS NOT NULL AND sid IS NOT NULL")

    # user_group sources: no obsolete flag
    for _src in ("adminservice_user_group", "wmi_user_group"):
        _ensure_columns(con, schema, _src, {"resource_id": "BIGINT", "source_site_code": "VARCHAR", "sid": "VARCHAR"})
        _safe(con, f"resource_to_sid<-{_src}",
              f"INSERT INTO {schema}.resource_to_sid "
              f"SELECT CAST(resource_id AS VARCHAR)||'@'||CAST(source_site_code AS VARCHAR), upper(sid) "
              f"FROM {schema}.{_src} WHERE resource_id IS NOT NULL AND sid IS NOT NULL")

    con.execute(f"CREATE OR REPLACE TABLE {schema}.resource_to_sid AS "
                f"SELECT DISTINCT resource_key, sid FROM {schema}.resource_to_sid "
                f"WHERE resource_key IS NOT NULL AND sid IS NOT NULL")
    logger.info("resource_to_sid built in schema %r", schema)


def _device_by_resourceid(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Build resource_key '<resource_id>@<site>' -> smsid lookup from real clients only.

    Only rows where is_client=True and is_obsolete=False are included, matching
    the same filter used when building node_client_device. smsid is uppercased
    for consistent joins. Used by Stage 2 edge builders that carry a resource_id
    and need to reach the smsid of the corresponding client device.
    """
    con.execute(f"CREATE OR REPLACE TABLE {schema}.device_by_resourceid (resource_key VARCHAR, smsid VARCHAR)")

    for _src in ("adminservice_client_devices", "wmi_client_devices"):
        _ensure_columns(con, schema, _src, {"resource_id": "BIGINT", "site_code": "VARCHAR", "is_client": "BOOLEAN", "is_obsolete": "BOOLEAN"})
        _safe(con, f"device_by_resourceid<-{_src}",
              f"INSERT INTO {schema}.device_by_resourceid "
              f"SELECT CAST(resource_id AS VARCHAR)||'@'||CAST(site_code AS VARCHAR), upper(smsid) "
              f"FROM {schema}.{_src} WHERE resource_id IS NOT NULL AND smsid IS NOT NULL "
              f"AND coalesce(is_client, false) AND NOT coalesce(is_obsolete, false)")

    con.execute(f"CREATE OR REPLACE TABLE {schema}.device_by_resourceid AS "
                f"SELECT DISTINCT resource_key, smsid FROM {schema}.device_by_resourceid "
                f"WHERE resource_key IS NOT NULL AND smsid IS NOT NULL")
    logger.info("device_by_resourceid built in schema %r", schema)


def _collection_by_name(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Build upper(trim(name)) -> upper(collection_id) lookup.

    Collection names are not guaranteed unique — if duplicates exist after
    dedup, the edge builders that join on name will produce multiple edges
    (fan-out), which is the correct CMBP behaviour (IsAssigned). Duplicates
    are logged at INFO so operators can spot misconfigured environments.
    """
    con.execute(f"CREATE OR REPLACE TABLE {schema}.collection_by_name (name VARCHAR, collection_id VARCHAR)")

    for _src in ("adminservice_collections", "wmi_collections"):
        _ensure_columns(con, schema, _src, {"name": "VARCHAR"})
        _safe(con, f"collection_by_name<-{_src}",
              f"INSERT INTO {schema}.collection_by_name "
              f"SELECT upper(trim(name)), upper(collection_id) "
              f"FROM {schema}.{_src} WHERE name IS NOT NULL AND collection_id IS NOT NULL")

    con.execute(f"CREATE OR REPLACE TABLE {schema}.collection_by_name AS "
                f"SELECT DISTINCT name, collection_id FROM {schema}.collection_by_name")

    dupes = con.execute(
        f"SELECT count(*) FROM (SELECT name FROM {schema}.collection_by_name GROUP BY name HAVING count(*) > 1)"
    ).fetchone()[0]
    if dupes:
        # Multiple collection_ids share the same name — edge builders will fan out (correct per CMBP).
        logger.info("collection_by_name: %d collection name(s) map to multiple ids (IsAssigned will fan out)", dupes)
    else:
        logger.debug("collection_by_name: all names unique")


def _role_by_name(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Build upper(trim(role_name)) -> upper(role_id) lookup.

    Role names are expected to be unique, but the table is deduplicated the
    same way as collection_by_name for safety.
    """
    con.execute(f"CREATE OR REPLACE TABLE {schema}.role_by_name (name VARCHAR, role_id VARCHAR)")

    for _src in ("adminservice_security_roles", "wmi_security_roles"):
        _ensure_columns(con, schema, _src, {"role_name": "VARCHAR"})
        _safe(con, f"role_by_name<-{_src}",
              f"INSERT INTO {schema}.role_by_name "
              f"SELECT upper(trim(role_name)), upper(role_id) "
              f"FROM {schema}.{_src} WHERE role_name IS NOT NULL AND role_id IS NOT NULL")

    con.execute(f"CREATE OR REPLACE TABLE {schema}.role_by_name AS "
                f"SELECT DISTINCT name, role_id FROM {schema}.role_by_name")
    logger.info("role_by_name built in schema %r", schema)


def _graph_edges_init(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Create the empty graph_edges table that every edge builder INSERTs into.
    Always runs (even with no site/edge data) so convert can read the table."""
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.graph_edges "
        f"(start_id VARCHAR, end_id VARCHAR, kind VARCHAR, collection_source VARCHAR[])"
    )


def _edge_replication(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Append SCCM_AdminsReplicatedTo edges from the site_hierarchy self-join
    (CMBP ps1:1604-1624): CAS(4)<->Primary(2) bidirectional; Primary(2)->Secondary(1)
    one-way. _safe() skips+logs if site_hierarchy is missing."""
    from .kinds.edges import SCCM_ADMINS_REPLICATED_TO
    _safe(
        con, "edge_replication",
        f"INSERT INTO {schema}.graph_edges BY NAME "
        f"SELECT child.site_code AS start_id, parent.site_code AS end_id, "
        f"'{SCCM_ADMINS_REPLICATED_TO}' AS kind, ['SCCM_Invoke-PostProcessing'] AS collection_source "
        f"FROM {schema}.site_hierarchy child JOIN {schema}.site_hierarchy parent "
        f"  ON child.parent_site_code = parent.site_code "
        f"WHERE child.site_type = 2 AND parent.site_type = 4 "
        f"UNION ALL "
        f"SELECT parent.site_code, child.site_code, '{SCCM_ADMINS_REPLICATED_TO}', ['SCCM_Invoke-PostProcessing'] "
        f"FROM {schema}.site_hierarchy child JOIN {schema}.site_hierarchy parent "
        f"  ON child.parent_site_code = parent.site_code "
        f"WHERE child.site_type = 2 AND parent.site_type = 4 "
        f"UNION ALL "
        f"SELECT parent.site_code, child.site_code, '{SCCM_ADMINS_REPLICATED_TO}', ['SCCM_Invoke-PostProcessing'] "
        f"FROM {schema}.site_hierarchy child JOIN {schema}.site_hierarchy parent "
        f"  ON child.parent_site_code = parent.site_code "
        f"WHERE child.site_type = 1 AND parent.site_type = 2"
    )


def _edge_has_member(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Append SCCM_HasMember edges: Collection -> member (CMBP ps1:7617-7647).

    Device member -> ClientDevice smsid (via device_by_resourceid); user/group
    member -> SID (via resource_to_sid). coalesce prefers the device lookup so
    device members point at the ClientDevice node rather than the Computer node,
    matching CMBP behaviour. Built-in pseudo-resources are skipped.

    Collection start id is upper(collection_id)@root (matches the SCCMCollection
    node id built in _node_collection). Because _safe() does not accept SQL params,
    the root literal is inlined into the SQL string — site codes are 3 alphanumerics
    so this is safe.
    """
    from .kinds.edges import SCCM_HAS_MEMBER
    root_lit = _root_code(con, schema) or ""
    start_expr = (f"upper(cm.collection_id) || '@{root_lit}'" if root_lit
                  else "upper(cm.collection_id)")
    _src_tags = {
        "adminservice_collection_members": "AdminService-SMS_FullCollectionMembership",
        "wmi_collection_members": "WMI-SMS_FullCollectionMembership",
    }
    for _src in ("adminservice_collection_members", "wmi_collection_members"):
        _ensure_columns(con, schema, _src, {"collection_id": "VARCHAR", "resource_id": "BIGINT", "site_code": "VARCHAR"})
        _tag = _src_tags[_src]
        _safe(con, f"edge_has_member<-{_src}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT {start_expr} AS start_id, coalesce(d.smsid, r.sid) AS end_id, "
              f"'{SCCM_HAS_MEMBER}' AS kind, ['{_tag}'] AS collection_source "
              f"FROM {schema}.{_src} cm "
              f"LEFT JOIN {schema}.device_by_resourceid d "
              f"  ON d.resource_key = CAST(cm.resource_id AS VARCHAR) || '@' || CAST(cm.site_code AS VARCHAR) "
              f"LEFT JOIN {schema}.resource_to_sid r "
              f"  ON r.resource_key = CAST(cm.resource_id AS VARCHAR) || '@' || CAST(cm.site_code AS VARCHAR) "
              f"WHERE cm.collection_id IS NOT NULL "
              f"  AND coalesce(d.smsid, r.sid) IS NOT NULL "
              f"  AND CAST(cm.resource_id AS VARCHAR) NOT IN ('2046820352', '2046820353') "
              f"  AND CAST(cm.resource_id AS VARCHAR) NOT LIKE '203004%'")


def _edge_is_mapped_to(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """AD principal -> SCCM_AdminUser (CMBP ps1:7789-7807). start = upper(admin_sid)
    if present, else logon_name resolved via principal_by_name; end = upper(logon_name)@root."""
    from .kinds.edges import SCCM_IS_MAPPED_TO
    root_lit = _root_code(con, schema) or ""
    end_expr = (f"upper(a.logon_name) || '@{root_lit}'" if root_lit else "upper(a.logon_name)")
    _src_tags = {
        "adminservice_admins": "AdminService-SMS_Admin",
        "wmi_admins": "WMI-SMS_Admin",
    }
    for _src in ("adminservice_admins", "wmi_admins"):
        _ensure_columns(con, schema, _src, {"admin_sid": "VARCHAR", "logon_name": "VARCHAR"})
        _tag = _src_tags[_src]
        _safe(con, f"edge_is_mapped_to<-{_src}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT coalesce(upper(a.admin_sid), pbn.sid) AS start_id, {end_expr} AS end_id, "
              f"'{SCCM_IS_MAPPED_TO}' AS kind, ['{_tag}'] AS collection_source "
              f"FROM {schema}.{_src} a "
              f"LEFT JOIN {schema}.principal_by_name pbn ON upper(trim(a.logon_name)) = upper(pbn.name) "
              f"WHERE a.logon_name IS NOT NULL AND coalesce(upper(a.admin_sid), pbn.sid) IS NOT NULL")


def _edge_is_assigned(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """AdminUser -> Collection / SecurityRole (CMBP ps1:7819/7841/7867).

    Three arms per admin source:
      1. Collection by name: split collection_names (comma-separated), join collection_by_name.
      2. Role by id list: unnest the roles JSON/CSV array via _arr(), one edge per role id.
      3. Role by name fallback: ONLY when roles is empty — split role_names, join role_by_name.

    start/end ids are upper(...)@root to match the AdminUser / Collection / SecurityRole node ids.
    """
    from .kinds.edges import SCCM_IS_ASSIGNED
    root_lit = _root_code(con, schema) or ""

    def _id(col: str) -> str:
        # Build <upper(col)>@root inline (no SQL params — _safe takes none).
        return f"upper({col}) || '@{root_lit}'" if root_lit else f"upper({col})"

    start_expr = _id("a.logon_name")
    _src_tags = {
        "adminservice_admins": "AdminService-SMS_Admin",
        "wmi_admins": "WMI-SMS_Admin",
    }
    for _src in ("adminservice_admins", "wmi_admins"):
        _ensure_columns(con, schema, _src,
                        {"logon_name": "VARCHAR", "collection_names": "VARCHAR",
                         "role_names": "VARCHAR", "roles": "VARCHAR"})
        _tag = _src_tags[_src]

        # --- Arm 1: AdminUser -> Collection (by name) ---
        # collection_names arrives as JSON-array text (e.g. '["All Systems","All Users"]')
        # from the AdminService collector, so route it through _arr() to parse the JSON
        # before unnesting. string_split would shred the brackets/quotes into garbage.
        _safe(con, f"edge_is_assigned_collection<-{_src}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT {start_expr} AS start_id, {_id('cbn.collection_id')} AS end_id, "
              f"'{SCCM_IS_ASSIGNED}' AS kind, ['{_tag}'] AS collection_source "
              f"FROM {schema}.{_src} a, unnest({_arr('a.collection_names')}) AS t(cname) "
              f"JOIN {schema}.collection_by_name cbn ON upper(trim(t.cname)) = cbn.name "
              f"WHERE a.logon_name IS NOT NULL AND a.collection_names IS NOT NULL AND trim(t.cname) != ''")

        # --- Arm 2: AdminUser -> SecurityRole (role-id list) ---
        _safe(con, f"edge_is_assigned_role_id<-{_src}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT {start_expr} AS start_id, {_id('t.rid')} AS end_id, "
              f"'{SCCM_IS_ASSIGNED}' AS kind, ['{_tag}'] AS collection_source "
              f"FROM {schema}.{_src} a, unnest({_arr('a.roles')}) AS t(rid) "
              f"WHERE a.logon_name IS NOT NULL AND t.rid IS NOT NULL AND trim(t.rid) != ''")

        # --- Arm 3: AdminUser -> SecurityRole (name fallback, only when roles list is empty) ---
        # role_names arrives as JSON-array text for the same reason as collection_names.
        _safe(con, f"edge_is_assigned_role_name<-{_src}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT {start_expr} AS start_id, {_id('rbn.role_id')} AS end_id, "
              f"'{SCCM_IS_ASSIGNED}' AS kind, ['{_tag}'] AS collection_source "
              f"FROM {schema}.{_src} a, unnest({_arr('a.role_names')}) AS t(rname) "
              f"JOIN {schema}.role_by_name rbn ON upper(trim(t.rname)) = rbn.name "
              f"WHERE a.logon_name IS NOT NULL AND a.role_names IS NOT NULL AND trim(t.rname) != '' "
              f"  AND len({_arr('a.roles')}) = 0")


def _edge_has_user(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Append ClientDevice -> User edges for the three device user fields (CMBP ps1:7266/7275/7298).

    Each name-only field on node_client_device is resolved to a SID via a
    case-insensitive join on principal_by_name. Devices whose field is NULL or
    empty, or whose value does not resolve to a SID, are silently dropped (the
    JOIN filters them out), matching CMBP behaviour.
    """
    from .kinds.edges import (
        SCCM_HAS_PRIMARY_USER, SCCM_HAS_CURRENT_USER, SCCM_HAS_AD_LAST_LOGON_USER,
    )
    for col, kind in (
        ("primary_user_name", SCCM_HAS_PRIMARY_USER),
        ("current_logon_user_name", SCCM_HAS_CURRENT_USER),
        ("ad_last_logon_user_name", SCCM_HAS_AD_LAST_LOGON_USER),
    ):
        _safe(con, f"edge_has_user<-{kind}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT cd.smsid AS start_id, pbn.sid AS end_id, '{kind}' AS kind, "
              f"['AdminService-ClientDevices'] AS collection_source "
              f"FROM {schema}.node_client_device cd "
              f"JOIN {schema}.principal_by_name pbn ON upper(trim(cd.{col})) = upper(pbn.name) "
              f"WHERE cd.smsid IS NOT NULL AND cd.{col} IS NOT NULL AND trim(cd.{col}) != ''")


def _edge_member_of(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Computer/User -> Group (CMBP ps1:7375/7470). Reuses the security_group_name
    unnest+resolve from _node_group; principal->group only (group->group nesting comes
    from a merged SharpHound collection, per the 2026-06-23 decision)."""
    from .kinds.edges import MEMBER_OF
    # (source_table, apply_obsolete_filter, collection_source_tag)
    _src_tags = {
        "adminservice_r_system": "AdminService-SMS_R_System",
        "wmi_r_system": "WMI-SMS_R_System",
        "adminservice_r_user": "AdminService-SMS_R_User",
        "wmi_r_user": "WMI-SMS_R_User",
    }
    sources = (
        ("adminservice_r_system", True),
        ("wmi_r_system", True),
        ("adminservice_r_user", False),
        ("wmi_r_user", False),
    )
    for _src, drop_obsolete in sources:
        _ensure_columns(con, schema, _src, {"sid": "VARCHAR", "security_group_name": "VARCHAR", "obsolete": "BOOLEAN"})
        # Only r_system rows need the obsolete filter; r_user has no such column.
        obsolete_clause = " AND NOT coalesce(r.obsolete, false)" if drop_obsolete else ""
        _tag = _src_tags[_src]
        _safe(con, f"edge_member_of<-{_src}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT upper(r.sid) AS start_id, pbn.sid AS end_id, '{MEMBER_OF}' AS kind, "
              f"['{_tag}'] AS collection_source "
              f"FROM {schema}.{_src} r, unnest({_arr('r.security_group_name')}) AS t(gname) "
              f"JOIN {schema}.principal_by_name pbn ON upper(trim(t.gname)) = upper(pbn.name) "
              f"WHERE r.sid IS NOT NULL AND t.gname IS NOT NULL AND trim(t.gname) != ''{obsolete_clause}")


def _edge_has_session(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Computer -> User sessions (CMBP ps1:5029 + ps1:8007). Two sources:
    (1) RemoteRegistry logged-on user; (2) the MSSQL service account on the site DB
    server (domain accounts only). HasSession is traversable (allow-list)."""
    from .kinds.edges import HAS_SESSION

    # (1) RemoteRegistry: host_object_sid -> the logged-on user's object_sid.
    _safe(con, "edge_has_session<-remoteregistry_users",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT upper(host_object_sid) AS start_id, upper(object_sid) AS end_id, "
          f"'{HAS_SESSION}' AS kind, ['RemoteRegistry-CurrentUser'] AS collection_source "
          f"FROM {schema}.remoteregistry_users "
          f"WHERE host_object_sid IS NOT NULL AND object_sid IS NOT NULL")

    # (2) MSSQL service account: SQL host computer -> service-account user.
    # network_os_path is like '\\SQL01.lab' -> strip leading backslashes, take the host
    # label before the first dot, lowercase; match node_computer by dnshostname or name.
    host_expr = "lower(split_part(ltrim(ss.network_os_path, '\\'), '.', 1))"
    _src_tags = {
        "adminservice_site_systems": "AdminService-SMS_SCI_SysResUse",
        "wmi_site_systems": "WMI-SMS_SCI_SysResUse",
    }
    for _src in ("adminservice_site_systems", "wmi_site_systems"):
        _ensure_columns(con, schema, _src, {"network_os_path": "VARCHAR", "sql_server_service_logon_account": "VARCHAR"})
        _tag = _src_tags[_src]
        # Skip local accounts: anything without a backslash (no DOMAIN\ prefix),
        # plus the NT AUTHORITY\ virtual accounts that do contain a backslash.
        _safe(con, f"edge_has_session<-{_src}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT nc.sid AS start_id, pbn.sid AS end_id, '{HAS_SESSION}' AS kind, "
              f"['{_tag}'] AS collection_source "
              f"FROM {schema}.{_src} ss "
              f"JOIN {schema}.node_computer nc "
              f"  ON lower(split_part(nc.dnshostname, '.', 1)) = {host_expr} "
              f"  OR lower(nc.name) = {host_expr} "
              f"JOIN {schema}.principal_by_name pbn "
              f"  ON upper(trim(ss.sql_server_service_logon_account)) = upper(pbn.name) "
              f"WHERE ss.network_os_path IS NOT NULL "
              f"  AND ss.sql_server_service_logon_account IS NOT NULL "
              f"  AND contains(ss.sql_server_service_logon_account, '\\') "
              f"  AND upper(ss.sql_server_service_logon_account) NOT LIKE 'NT AUTHORITY\\%' "
              f"  AND upper(ss.sql_server_service_logon_account) NOT IN ('LOCALSYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE')")


def _edge_has_stored_account(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Site -> stored User/Group account (CMBP ps1:7147). start = site_code (the
    SCCM_Site node id); end = the reserved account's AD object_sid (resolved at
    collection). The User/Group node property stored_in_sccm_site is set in Stage 1."""
    from .kinds.edges import SCCM_HAS_STORED_ACCOUNT
    _src_tags = {
        "adminservice_reserved_accounts": "AdminService-SMS_SCI_Reserved",
        "wmi_reserved_accounts": "WMI-SMS_SCI_Reserved",
    }
    for _src in ("adminservice_reserved_accounts", "wmi_reserved_accounts"):
        _ensure_columns(con, schema, _src, {"site_code": "VARCHAR", "object_sid": "VARCHAR"})
        _tag = _src_tags[_src]
        _safe(con, f"edge_has_stored_account<-{_src}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT site_code AS start_id, upper(object_sid) AS end_id, "
              f"'{SCCM_HAS_STORED_ACCOUNT}' AS kind, ['{_tag}'] AS collection_source "
              f"FROM {schema}.{_src} WHERE site_code IS NOT NULL AND object_sid IS NOT NULL")


# Well-known security-role id -> the client-device edge kind it grants (CMBP ps1:1751-1797).
_ROLE_EDGE_KIND = {
    "SMS0001R": "SCCM_FullAdministrator",
    "SMS0008R": "SCCM_ApplicationAuthor",
    "SMS0009R": "SCCM_ApplicationAdministrator",
    "SMS0006R": "SCCM_ComplianceSettingsManager",
    "SMS000AR": "SCCM_OSDManager",
    "SMS000ER": "SCCM_OperationsAdministrator",
    "SMS000FR": "SCCM_SecurityAdministrator",
}
# Built-in roles CMBP knows but creates no client-device edge for (CMBP ps1:1803-1818).
# Built-in roles CMBP knows but creates no client-device edge for (full built-in list
# at CMBP ps1:1803-1810). NOTE the deliberate divergence: CMBP's runtime -notin array
# (ps1:1811-1818) omits SMS0003R (Remote Tools Operator) — a CMBP oversight that makes it
# spuriously log a "custom role" warning for that built-in. We include SMS0003R here (all 8
# built-ins) so the custom-role skip warning fires only for genuinely custom roles.
_ROLE_KNOWN_NO_EDGE = ("SMS0002R", "SMS0003R", "SMS0004R", "SMS0007R", "SMS000BR", "SMS000CR", "SMS000GR", "SMS000HR")


def _edge_contains(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Site -> Collection/SecurityRole/AdminUser (CMBP ps1:1659-1690). Every
    non-secondary site (site_type != 1) in the single hierarchy contains every
    global object (all are @root). collection_source = SCCM_Invoke-PostProcessing."""
    from .kinds.edges import SCCM_CONTAINS
    nonsec = (f"(SELECT site_code FROM {schema}.site_hierarchy "
              f"WHERE coalesce(site_type, 0) != 1 AND site_code IS NOT NULL)")
    cs = "['SCCM_Invoke-PostProcessing']"
    # -- Every non-secondary site contains every collection, security role, and admin user
    # -- in the hierarchy (all @root).
    _safe(con, "edge_contains",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT site.site_code AS start_id, collection.collection_id || '@' || collection.root_site_code AS end_id, "
          f"'{SCCM_CONTAINS}' AS kind, {cs} AS collection_source "
          f"FROM {nonsec} site JOIN {schema}.node_collection collection ON collection.root_site_code IS NOT NULL "
          f"UNION ALL "
          f"SELECT site.site_code, role.role_id || '@' || role.root_site_code, '{SCCM_CONTAINS}', {cs} "
          f"FROM {nonsec} site JOIN {schema}.node_security_role role ON role.root_site_code IS NOT NULL "
          f"UNION ALL "
          f"SELECT site.site_code, upper(admin.logon_name) || '@' || admin.root_site_code, '{SCCM_CONTAINS}', {cs} "
          f"FROM {nonsec} site JOIN {schema}.node_admin_user admin ON admin.root_site_code IS NOT NULL")


def _edge_rbac_role_grants(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """The 7 RBAC role edges (AdminUser -> ClientDevice), reconstructed from graph_edges
    (CMBP ps1:1714-1827). Path: IsAssigned(admin->role) JOIN IsAssigned(admin->Device-collection)
    JOIN HasMember(collection->clientdevice). The role's well-known id picks the edge kind.
    Custom (non-built-in) roles assigned to admins are counted and logged (CMBP ps1:1820)."""
    role_map = ", ".join(f"('{rid}','{kind}')" for rid, kind in _ROLE_EDGE_KIND.items())
    # -- Walk graph_edges: an admin --IsAssigned--> a security role, and the SAME admin
    # -- --IsAssigned--> a Device-type collection, whose members --HasMember--> client devices.
    # -- The role's well-known id selects the edge kind.
    _safe(con, "edge_rbac_role_grants",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT admin_to_role.start_id AS start_id, collection_to_device.end_id AS end_id, role_edge_kind.edge_kind AS kind, "
          f"['SCCM_Invoke-PostProcessing'] AS collection_source "
          f"FROM {schema}.graph_edges admin_to_role "
          f"JOIN {schema}.node_security_role role "
          f"  ON role.role_id || '@' || role.root_site_code = admin_to_role.end_id "
          f"JOIN (VALUES {role_map}) AS role_edge_kind(role_id, edge_kind) ON upper(role.role_id) = role_edge_kind.role_id "
          f"JOIN {schema}.graph_edges admin_to_collection "
          f"  ON admin_to_collection.start_id = admin_to_role.start_id AND admin_to_collection.kind = 'SCCM_IsAssigned' "
          f"JOIN {schema}.node_collection device_collection "
          f"  ON device_collection.collection_id || '@' || device_collection.root_site_code = admin_to_collection.end_id AND device_collection.collection_type = 2 "
          f"JOIN {schema}.graph_edges collection_to_device "
          f"  ON collection_to_device.start_id = admin_to_collection.end_id AND collection_to_device.kind = 'SCCM_HasMember' "
          f"JOIN {schema}.node_client_device client_device ON client_device.smsid = collection_to_device.end_id "
          f"WHERE admin_to_role.kind = 'SCCM_IsAssigned'")
    # Diagnostic: count custom roles assigned to admins that produce no device edge (CMBP warns per role).
    skip_list = ", ".join(f"'{r}'" for r in (*_ROLE_EDGE_KIND, *_ROLE_KNOWN_NO_EDGE))
    try:
        cnt = con.execute(
            f"SELECT count(DISTINCT role.role_id) FROM {schema}.graph_edges admin_to_role "
            f"JOIN {schema}.node_security_role role ON role.role_id || '@' || role.root_site_code = admin_to_role.end_id "
            f"WHERE admin_to_role.kind = 'SCCM_IsAssigned' AND upper(role.role_id) NOT IN ({skip_list})"
        ).fetchone()[0]
    except duckdb.Error as err:
        logger.warning("edge_rbac_role_grants: custom-role audit query failed: %s", err)
        cnt = 0
    if cnt:
        logger.warning("edge_rbac_role_grants: %d custom security role(s) assigned to admins have no "
                       "traversable client-device edge (matches CMBP skip behaviour)", cnt)
    else:
        logger.debug("edge_rbac_role_grants: no custom roles to skip")


def _edge_all_permissions(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """AdminUser -> Site SCCM_AllPermissions (CMBP ps1:1730-1837): Full Administrator
    (SMS0001R) AND assigned BOTH SMS00001 (All Systems) and SMS00004 (All Users and User
    Groups) -> every non-secondary site. Detection by well-known collection id (Decision #2;
    CMBP matched display name 'All Systems'/'All Users and User Groups')."""
    from .kinds.edges import SCCM_ALL_PERMISSIONS
    nonsec = (f"(SELECT site_code FROM {schema}.site_hierarchy "
              f"WHERE coalesce(site_type, 0) != 1 AND site_code IS NOT NULL)")
    # -- An admin --IsAssigned--> the Full Administrator role (SMS0001R) AND
    # -- --IsAssigned--> BOTH the All Systems (SMS00001) and All Users and User Groups
    # -- (SMS00004) collections -> grant SCCM_AllPermissions to every non-secondary site.
    _safe(con, "edge_all_permissions",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT admin_to_full_admin_role.start_id AS start_id, site.site_code AS end_id, "
          f"'{SCCM_ALL_PERMISSIONS}' AS kind, ['SCCM_Invoke-PostProcessing'] AS collection_source "
          f"FROM {schema}.graph_edges admin_to_full_admin_role "
          f"JOIN {schema}.node_security_role full_admin_role "
          f"  ON full_admin_role.role_id || '@' || full_admin_role.root_site_code = admin_to_full_admin_role.end_id AND upper(full_admin_role.role_id) = 'SMS0001R' "
          f"JOIN {schema}.graph_edges admin_to_all_systems ON admin_to_all_systems.start_id = admin_to_full_admin_role.start_id AND admin_to_all_systems.kind = 'SCCM_IsAssigned' "
          f"JOIN {schema}.node_collection all_systems_collection "
          f"  ON all_systems_collection.collection_id || '@' || all_systems_collection.root_site_code = admin_to_all_systems.end_id AND upper(all_systems_collection.collection_id) = 'SMS00001' "
          f"JOIN {schema}.graph_edges admin_to_all_users ON admin_to_all_users.start_id = admin_to_full_admin_role.start_id AND admin_to_all_users.kind = 'SCCM_IsAssigned' "
          f"JOIN {schema}.node_collection all_users_collection "
          f"  ON all_users_collection.collection_id || '@' || all_users_collection.root_site_code = admin_to_all_users.end_id AND upper(all_users_collection.collection_id) = 'SMS00004' "
          f"CROSS JOIN {nonsec} site "
          f"WHERE admin_to_full_admin_role.kind = 'SCCM_IsAssigned'")


def _edge_assign_all_permissions(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Computer(SMS Provider) -> Site SCCM_AssignAllPermissions (CMBP ps1:1932-1940).

    Any computer whose site_system_roles contains an 'SMS Provider' entry gets an
    SCCM_AssignAllPermissions edge to every non-secondary site in the single hierarchy.
    start = computer SID (the Computer node id); end = non-secondary site_code.
    """
    from .kinds.edges import SCCM_ASSIGN_ALL_PERMISSIONS
    nonsec = (f"(SELECT site_code FROM {schema}.site_hierarchy "
              f"WHERE coalesce(site_type, 0) != 1 AND site_code IS NOT NULL)")
    # -- Any computer whose site_system_roles include 'SMS Provider' ->
    # -- SCCM_AssignAllPermissions to every non-secondary site.
    _safe(con, "edge_assign_all_permissions",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT computer.sid AS start_id, site.site_code AS end_id, "
          f"'{SCCM_ASSIGN_ALL_PERMISSIONS}' AS kind, ['SCCM_Invoke-PostProcessing'] AS collection_source "
          f"FROM {schema}.node_computer computer "
          f"CROSS JOIN {nonsec} site "
          f"WHERE computer.sid IS NOT NULL "
          f"  AND len(list_filter(computer.site_system_roles, x -> x LIKE '%SMS Provider%')) > 0")


def _graph_edges_dedup(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Collapse duplicate (start_id, end_id, kind) rows into one row per unique triple.

    Duplicates arise when both the adminservice and wmi sources contribute the same
    edge, or when name fan-out (collection_by_name, role_by_name) matches the same
    id twice. CMBP's Upsert-Edge dedupes at insert time; we do it once here after all
    edge builders have run.

    collection_source tags from all duplicate rows are merged into one distinct list
    (same array-union idiom as site_system_roles in _node_computer).
    """
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.graph_edges AS "
        f"SELECT start_id, end_id, kind, "
        f"  coalesce(list_distinct(flatten(list(collection_source))), CAST([] AS VARCHAR[])) AS collection_source "
        f"FROM {schema}.graph_edges "
        f"GROUP BY start_id, end_id, kind"
    )
    logger.info("graph_edges deduplicated in schema %r", schema)


def _edge_has_client(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Append SCCM_HasClient edges: Site -> ClientDevice (CMBP ps1:7257/7394).
    start = device.site_code (the site that owns the client), end = smsid.
    Possible-client rows (added in Task E2) carry site_code='root' so they also
    get a HasClient edge automatically once E2 runs. _safe() skips+logs if
    node_client_device is missing."""
    from .kinds.edges import SCCM_HAS_CLIENT
    _safe(
        con, "edge_has_client",
        f"INSERT INTO {schema}.graph_edges BY NAME "
        f"SELECT site_code AS start_id, smsid AS end_id, '{SCCM_HAS_CLIENT}' AS kind, "
        f"CASE WHEN coalesce(possible, false) THEN ['LDAP-CmRcService'] "
        f"     ELSE ['AdminService-ClientDevices'] END AS collection_source "
        f"FROM {schema}.node_client_device "
        f"WHERE site_code IS NOT NULL AND smsid IS NOT NULL"
    )


def _node_backfill(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Synthesise bare nodes for edge END endpoints that resolved to a SID/smsid with no
    node (graph-integrity decision 2026-06-23). Kind is inferred from the edge position
    (BACKFILL_END_KIND); ambiguous ends get 'Base'. Logs a warning count. Runs LAST."""
    from .graph import BACKFILL_END_KIND

    con.execute(
        f"CREATE OR REPLACE TEMP TABLE _existing_ids AS "
        f"SELECT sid AS id FROM {schema}.node_computer WHERE sid IS NOT NULL "
        f"UNION SELECT sid FROM {schema}.node_user WHERE sid IS NOT NULL "
        f"UNION SELECT sid FROM {schema}.node_group WHERE sid IS NOT NULL "
        f"UNION SELECT smsid FROM {schema}.node_client_device WHERE smsid IS NOT NULL"
    )
    map_values = ", ".join(f"('{k}', '{v}')" for k, v in BACKFILL_END_KIND.items())
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_backfill AS "
        f"SELECT DISTINCT ge.end_id AS id, m.kind AS kind "
        f"FROM {schema}.graph_edges ge "
        f"JOIN (VALUES {map_values}) AS m(edge_kind, kind) ON ge.kind = m.edge_kind "
        f"WHERE ge.end_id IS NOT NULL "
        f"  AND ge.end_id NOT IN (SELECT id FROM _existing_ids)"
    )
    cnt = con.execute(f"SELECT count(*) FROM {schema}.node_backfill").fetchone()[0]
    if cnt:
        logger.warning(
            "node_backfill: synthesised %d stub node(s) for edge endpoints with no node",
            cnt,
        )
    else:
        logger.debug("node_backfill: every edge endpoint has a node")


def transforms(con: duckdb.DuckDBPyConnection, schema: str = "sccm") -> None:
    """Top-level transform entrypoint (registered via @app.preproc(transformer=transforms))."""
    con.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
    _principal_by_name(con, schema)
    _site_hierarchy(con, schema)
    _node_computer(con, schema)
    _node_user(con, schema)
    _node_group(con, schema)
    _node_site(con, schema)
    _node_collection(con, schema)
    _node_security_role(con, schema)
    _node_admin_user(con, schema)
    _node_client_device(con, schema)
    disable_possible = _read_disable_possible(con, schema)
    _node_client_device_possible(con, schema, disable_possible)
    # Stage 2 lookup tables: name/id -> id maps that edge builders join against.
    # These read from the raw source tables (not the node_* coalesces) and must
    # run after all _node_* builders (which may add columns via _ensure_columns)
    # and before _graph_edges_init so edge builders can reference them.
    _resource_to_sid(con, schema)
    _device_by_resourceid(con, schema)
    _collection_by_name(con, schema)
    _role_by_name(con, schema)
    # Relationship-list enrichment: add denormalised list columns to node_* tables.
    # These run after all _node_* builders and lookup tables but before edge builders,
    # so edge builders see the fully-enriched node tables.
    _enrich_collection_members(con, schema)
    _enrich_role_members(con, schema)
    _enrich_admin_assignments(con, schema)
    _enrich_client_device(con, schema)
    _enrich_site_lists(con, schema)
    # _graph_edges_init must run before all edge builders; _edge_replication and future
    # edge builders all INSERT into the table created here.
    _graph_edges_init(con, schema)
    _edge_replication(con, schema)
    _edge_has_client(con, schema)
    _edge_has_member(con, schema)
    _edge_is_mapped_to(con, schema)
    _edge_is_assigned(con, schema)
    _edge_has_user(con, schema)
    _edge_member_of(con, schema)
    _edge_has_session(con, schema)
    _edge_has_stored_account(con, schema)
    _edge_contains(con, schema)
    _edge_rbac_role_grants(con, schema)
    _edge_all_permissions(con, schema)
    _edge_assign_all_permissions(con, schema)
    # Dedup after all edge builders: both adminservice and wmi sources can contribute the
    # same edge, and name fan-out (collection_by_name, role_by_name) can match the same
    # id twice. CMBP's Upsert-Edge dedupes at insert time; we do it once here.
    _graph_edges_dedup(con, schema)
    # node_backfill runs LAST: synthesises bare stub nodes for edge END endpoints
    # that resolved to a SID/smsid not present in any node_* table (graph-integrity
    # decision 2026-06-23). All node_* and graph_edges tables exist by this point.
    _node_backfill(con, schema)
