"""Lookup helpers for the OpenHound SCCM extension.

Exposes cached DuckDB queries used by `BaseAsset.as_node`/`edges` during the convert
phase. Methods are cached with `@lru_cache` so repeated lookups (e.g. resolving a
hierarchy root for every collection node) hit DuckDB only once.

Tables read here are produced by `transforms.py` during preproc and registered in
`main.py::preproc`. If a table is missing (e.g. preproc was skipped or a phase didn't
run) the underlying DuckDB call raises; callers should guard with try/except where
that's a real possibility.
"""

from __future__ import annotations

import logging
from functools import lru_cache

from duckdb import DuckDBPyConnection
from openhound.core.lookup import LookupManager

from . import log_context  # noqa: F401 — installs VERBOSE level on Logger
from .log_context import cached_with_log

logger = logging.getLogger(__name__)


class SCCMLookup(LookupManager):
    """DuckDB-backed lookup for SCCM convert-time queries.

    The schema is implicitly the source name (`sccm`) — every table loaded by preproc
    lives under it, so all methods reference `{self.schema}.<table>`.
    """

    def __init__(self, client: DuckDBPyConnection, schema: str = "sccm") -> None:
        super().__init__(client, schema)

    # -----------------------------------------------------------------
    # Hierarchy resolution (post-processing step 1 + step 3)
    # -----------------------------------------------------------------

    @lru_cache
    def hierarchy_root(self, site_code: str | None) -> str | None:
        """Return the root site code for the hierarchy containing `site_code`.

        Falls back to `site_code` itself when the hierarchies table doesn't have a
        match (e.g. for the root site, or when LDAP-only collection ran).
        """
        if not site_code:
            return None
        try:
            res = self._find_single_object(
                f"SELECT root_code FROM {self.schema}.hierarchies WHERE member_code = ?",
                [site_code],
            )
        except Exception:
            return site_code
        return res or site_code

    @lru_cache
    def sites_in_hierarchy(self, root_code: str) -> tuple[str, ...]:
        """Return the tuple of site codes in the hierarchy rooted at `root_code`."""
        try:
            rows = self._find_all_objects(
                f"SELECT member_code FROM {self.schema}.hierarchies WHERE root_code = ?",
                [root_code],
            )
        except Exception:
            return ()
        return tuple(r[0] for r in rows if r and r[0])

    # -----------------------------------------------------------------
    # AD principal resolution
    # -----------------------------------------------------------------

    @cached_with_log("Computer SID")
    def computer_by_sid(self, sid: str) -> str | None:
        """Return the canonical id of a Computer node by SID."""
        try:
            return self._find_single_object(
                f"SELECT object_sid FROM {self.schema}.ldap_computers WHERE object_sid = ?",
                [sid],
            )
        except Exception:
            return None

    @cached_with_log("Computer name")
    def computer_by_name(self, name: str) -> str | None:
        """Return the SID of a Computer node by its sAMAccountName or short hostname."""
        if not name:
            return None
        # Strip trailing `$` if present
        bare = name.rstrip("$")
        try:
            return self._find_single_object(
                f"SELECT object_sid FROM {self.schema}.ldap_computers "
                f"WHERE LOWER(sam_account_name) IN (LOWER(?), LOWER(? || '$')) OR LOWER(name) = LOWER(?)",
                [bare, bare, bare],
            )
        except Exception:
            return None

    @cached_with_log("Computer hostname")
    def computer_sid_by_hostname(self, hostname: str) -> str | None:
        """Resolve a hostname (FQDN or short name) to a Computer SID.

        Used by SCCM_Site to populate siteServerDomainSID / SQLServerDomainSID
        — equivalent to PowerShell ``Resolve-PrincipalInDomain`` against the
        server name reported by ``SMS_Site.ServerName`` / ``SMS_SCI_SiteDefinition.SQLServerName``.
        Matches against ``dns_host_name`` (FQDN), the short hostname (NetBIOS),
        the ``name`` field, and the ``sam_account_name`` minus the trailing ``$``.
        """
        if not hostname:
            return None
        host_low = hostname.lower()
        short = host_low.split(".", 1)[0]
        try:
            return self._find_single_object(
                f"""
                SELECT object_sid FROM {self.schema}.ldap_computers
                WHERE LOWER(dns_host_name) = ?
                   OR LOWER(SPLIT_PART(COALESCE(dns_host_name, ''), '.', 1)) = ?
                   OR LOWER(name) = ?
                   OR LOWER(sam_account_name) = ? || '$'
                LIMIT 1
                """,
                [host_low, short, short, short],
            )
        except Exception:
            return None

    @cached_with_log("Principal SAM")
    def principal_sid_by_account_name(self, account: str) -> str | None:
        """Resolve a service-account string (``DOMAIN\\sam`` or bare ``sam``)
        to an AD SID. Reads the precomputed ``sccm.ad_principals`` view
        (built by ``transforms._build_ad_principals``) — a single indexed
        scan that prefers users over computers via ``ORDER BY kind``.
        Used by SCCM_Site for SQLServiceAccountDomainSID.
        """
        if not account:
            return None
        # Strip a DOMAIN\ prefix and trailing $ (gMSA / machine-account form).
        bare = account.split("\\", 1)[-1].strip().lower().rstrip("$")
        if not bare:
            return None
        if "\\" in account:
            logger.verbose("Detected DOMAIN\\username format for '%s'; resolving username '%s'", account, bare)
        try:
            # ``ad_principals`` stores ``sam_account_bare`` with trailing $
            # already stripped for computer rows, so a single equality matches
            # both `mssqlsvc` (user) and `cas-pss` (computer, originally
            # `cas-pss$`). ``ORDER BY kind`` is alphabetical and puts
            # 'computer' before 'user' — we want the opposite, so we negate.
            return self._find_single_object(
                f"SELECT object_sid FROM {self.schema}.ad_principals "
                f"WHERE sam_account_bare = ? "
                f"ORDER BY CASE WHEN kind = 'user' THEN 0 ELSE 1 END "
                f"LIMIT 1",
                [bare],
            )
        except Exception:
            return None

    @cached_with_log("User SAM")
    def user_by_sam(self, sam: str) -> str | None:
        try:
            return self._find_single_object(
                f"SELECT object_sid FROM {self.schema}.ldap_users WHERE LOWER(sam_account_name) = LOWER(?)",
                [sam],
            )
        except Exception:
            return None

    @cached_with_log("Group SID")
    def group_by_sid(self, sid: str) -> str | None:
        try:
            return self._find_single_object(
                f"SELECT object_sid FROM {self.schema}.ldap_groups WHERE object_sid = ?",
                [sid],
            )
        except Exception:
            return None

    @cached_with_log("Principal DN")
    def principal_id_by_dn(self, dn: str) -> str | None:
        """Resolve an AD distinguishedName to its objectSid by checking users,
        computers, then groups in turn.

        Used by ``GroupMembership.edges`` to convert a ``member`` DN into an SID
        that the framework's ``EdgePath(match_by="id")`` schema accepts. Returns
        ``None`` for foreign/unmatched DNs (the edge is silently dropped).
        """
        if not dn:
            return None
        for table in ("ldap_users", "ldap_computers", "ldap_groups"):
            try:
                row = self._find_single_object(
                    f"SELECT object_sid FROM {self.schema}.{table} "
                    f"WHERE LOWER(distinguished_name) = LOWER(?)",
                    [dn],
                )
            except Exception:
                row = None
            if row:
                return row
        return None

    # -----------------------------------------------------------------
    # SCCM artefact resolution
    # -----------------------------------------------------------------

    @lru_cache
    def client_device_by_sid(self, sid: str) -> str | None:
        try:
            return self._find_single_object(
                f"SELECT 'GUID:' || guid FROM {self.schema}.adminservice_client_devices WHERE LOWER(ad_object_sid) = LOWER(?)",
                [sid],
            )
        except Exception:
            return None

    @lru_cache
    def client_device_by_name(self, name: str) -> str | None:
        try:
            return self._find_single_object(
                f"SELECT 'GUID:' || guid FROM {self.schema}.adminservice_client_devices WHERE LOWER(machine_name) = LOWER(?)",
                [name],
            )
        except Exception:
            return None

    @lru_cache
    def admin_user_collection_ids(self, collection_names: tuple[str, ...], site_code: str) -> tuple[str, ...]:
        """Resolve a tuple of collection names to ``<collection_id>@<site_code>``
        node IDs matching the per-site SCCM_Collection node IDs.

        Each SMS Provider reports collections tagged with its own site
        code, so an admin discovered via the PS1-PSS provider references
        ``SMS00001@PS1``, while the same admin discovered via the
        CAS-PSS provider references ``SMS00001@CAS``. Mirrors CMBP's
        ``collectionIDs`` resolution (ConfigManBearPig.ps1 lines
        7819-7833) with the PS1 per-provider fan-out preserved.
        """
        if not collection_names or not site_code:
            return ()
        names_lower = [n.lower() for n in collection_names if n]
        if not names_lower:
            return ()
        placeholders = ", ".join("?" for _ in names_lower)
        try:
            rows = self._find_all_objects(
                f"SELECT DISTINCT collection_id FROM {self.schema}.adminservice_collections "
                f"WHERE LOWER(name) IN ({placeholders})",
                names_lower,
            )
        except Exception:
            return ()
        return tuple(sorted(f"{r[0]}@{site_code}" for r in rows if r and r[0]))

    @lru_cache
    def admin_user_role_ids(self, role_names: tuple[str, ...], site_code: str) -> tuple[str, ...]:
        """Resolve a tuple of role names to ``<role_id>@<site_code>``
        node IDs matching the per-site SCCM_SecurityRole node IDs.

        Each SMS Provider reports roles tagged with its own site code,
        so an admin discovered via PS1-PSS references ``SMS0001R@PS1``
        while the same admin via CAS-PSS references ``SMS0001R@CAS``.
        Mirrors CMBP's ``securityRoles`` resolution
        (ConfigManBearPig.ps1 lines 7864-7888) with the PS1 per-provider
        fan-out preserved.
        """
        if not role_names or not site_code:
            return ()
        names_lower = [n.lower() for n in role_names if n]
        if not names_lower:
            return ()
        placeholders = ", ".join("?" for _ in names_lower)
        try:
            rows = self._find_all_objects(
                f"SELECT DISTINCT role_id FROM {self.schema}.adminservice_security_roles "
                f"WHERE LOWER(role_name) IN ({placeholders})",
                names_lower,
            )
        except Exception:
            return ()
        return tuple(sorted(f"{r[0]}@{site_code}" for r in rows if r and r[0]))

    # -----------------------------------------------------------------
    # MSSQL EPA flag (used by post-processing coerce edges)
    # -----------------------------------------------------------------

    @lru_cache
    def epa_for_host(self, hostname: str) -> str | None:
        """Return the EPA flag (e.g. 'Off', 'Allowed', 'Required') for an MSSQL host, or None."""
        try:
            return self._find_single_object(
                f"SELECT epa FROM {self.schema}.mssql_epa_flags WHERE LOWER(hostname) = LOWER(?)",
                [hostname],
            )
        except Exception:
            return None

    # -----------------------------------------------------------------
    # SMB signing (used by post-processing coerce edges)
    # -----------------------------------------------------------------

    @lru_cache
    def smb_signing_for_host(self, hostname: str) -> str | None:
        try:
            return self._find_single_object(
                f"SELECT signing FROM {self.schema}.smb_signing_status WHERE LOWER(hostname) = LOWER(?)",
                [hostname],
            )
        except Exception:
            return None

    # -----------------------------------------------------------------
    # Computer / SCCM-infra anchor lookups
    # -----------------------------------------------------------------

    @lru_cache
    def site_system_roles_for_site(self, site_code: str) -> tuple[str, ...]:
        """Return ``'hostname: RoleName@site_code'`` tuples for every site system
        serving ``site_code``. PS1 format (CMBP mirrors it).

        Ordering matches the AdminService row order (typically SMS SQL Server,
        SMS Component Server, SMS Site System, then the rest) — PS1 emits in
        insertion order and BH queries can be sensitive to position-based
        comparison. We preserve that by NOT applying a SQL ORDER BY.
        """
        if not site_code:
            return ()
        try:
            rows = self._find_all_objects(
                f"SELECT hostname || ': ' || role || '@' || site_code "
                f"FROM {self.schema}.adminservice_site_systems "
                f"WHERE LOWER(site_code) = LOWER(?) "
                f"AND role IS NOT NULL AND role <> '' "
                f"AND hostname IS NOT NULL AND hostname <> ''",
                [site_code],
            )
        except Exception:
            return ()
        # Dedup while preserving insertion order.
        seen: set[str] = set()
        out: list[str] = []
        for r in rows:
            if not (r and r[0]):
                continue
            if r[0] in seen:
                continue
            seen.add(r[0])
            out.append(r[0])
        return tuple(out)

    @lru_cache
    def extra_collection_sources_for_site(self, site_code: str) -> tuple[str, ...]:
        """Return the additional ``collectionSource`` tags a SCCM_Site picks up
        from non-AdminService phases (local SMS authority, RemoteRegistry,
        SMS_SCI_Reserved). PS1 lists these alongside the LDAP / AdminService
        tags; OH discovers them in independent resources, so we re-derive at
        convert time via lookups against the DuckDB schema.

        Also folds in ``AdminService-SMS_Sites`` and
        ``AdminService-SMS_SCI_SiteDefinition`` whenever the site has rows
        in the corresponding AdminService tables — this restores the
        provenance tagging that the in-line ``ldap_sites`` fold-in used to
        do, now that the LDAP collector emits LDAP-only rows.
        """
        if not site_code:
            return ()
        out: list[str] = []
        for table, tag in (
            ("local_management_points",   "Local-SMS_Authority"),
            ("local_distribution_points", "Local-SMS_Authority"),
            ("registry_sccm_components",  "RemoteRegistry"),
            ("registry_sccm_databases",   "RemoteRegistry"),
            ("adminservice_sites",        "AdminService-SMS_Sites"),
            ("adminservice_site_definitions", "AdminService-SMS_SCI_SiteDefinition"),
            ("adminservice_reserved_accounts", "AdminService-SMS_SCI_Reserved"),
        ):
            try:
                row = self._find_single_object(
                    f"SELECT 1 FROM {self.schema}.{table} WHERE LOWER(site_code) = LOWER(?) LIMIT 1",
                    [site_code],
                )
            except Exception:
                row = None
            if row and tag not in out:
                out.append(tag)
        return tuple(out)

    @lru_cache
    def admin_enrichment_for_site(self, site_code: str) -> tuple[
        str | None, str | None, str | None, str | None, str | None,
        str | None, str | None, str | None,
    ]:
        """Convert-time enrichment for a SCCM_Site row.

        The Phase 1 ``ldap_sites`` collector emits LDAP-only fields (it no
        longer reaches into AdminService — that happens in Phase 7), so the
        rich CMBP-equivalent property surface for SCCM_Site is reconstructed
        here by joining the AdminService DLT tables.

        Returns a positional tuple (lru_cache requires a hashable return):

            (display_name, site_server_name, sql_server_name,
             sql_database_name, sql_service_account_name, version,
             site_type, parent_site_code, install_dir)

        Any field absent from AdminService is returned as ``None``. The
        SCCMSite model uses these as fallbacks for its own ``None`` slots.
        """
        if not site_code:
            return (None, None, None, None, None, None, None, None, None)

        display_name: str | None = None
        site_server_name: str | None = None
        version: str | None = None
        site_type: str | None = None
        parent_site_code: str | None = None
        install_dir: str | None = None
        # SMS_Site: display name, site server, version, type, parent,
        # install directory.
        try:
            row = self._find_all_objects(
                f"SELECT site_name, server_name, version, site_type, "
                f"reporting_site_code, install_dir "
                f"FROM {self.schema}.adminservice_sites "
                f"WHERE LOWER(site_code) = LOWER(?) LIMIT 1",
                [site_code],
            )
        except Exception:
            row = []
        if row:
            r = row[0]
            display_name = (r[0] or None) if r and len(r) > 0 else None
            site_server_name = (r[1] or None) if r and len(r) > 1 else None
            version = (str(r[2]) if r[2] not in (None, "") else None) if r and len(r) > 2 else None
            t = r[3] if r and len(r) > 3 else None
            # SMS_Site.Type: 1=Secondary, 2=Primary, 4=CAS (CMBP/PS1 long form)
            if t == 1:
                site_type = "Secondary Site"
            elif t == 2:
                site_type = "Primary Site"
            elif t == 4:
                site_type = "Central Administration Site"
            parent_raw = (r[4] or None) if r and len(r) > 4 else None
            if parent_raw and parent_raw != site_code:
                parent_site_code = parent_raw
            install_dir = (r[5] or None) if r and len(r) > 5 else None

        # SMS_SCI_SiteDefinition: SQL server/db, and a more reliable SiteName.
        sql_server_name: str | None = None
        sql_database_name: str | None = None
        try:
            row = self._find_all_objects(
                f"SELECT site_name, sql_server_name, sql_database_name "
                f"FROM {self.schema}.adminservice_site_definitions "
                f"WHERE LOWER(site_code) = LOWER(?) LIMIT 1",
                [site_code],
            )
        except Exception:
            row = []
        if row:
            r = row[0]
            sd_site_name = (r[0] or None) if r and len(r) > 0 else None
            if sd_site_name:
                display_name = sd_site_name  # CMBP prefers SMS_SCI_SiteDefinition.SiteName
            sql_server_name = (r[1] or None) if r and len(r) > 1 else None
            sql_database_name = (r[2] or None) if r and len(r) > 2 else None

        # SMS_SCI_SysResUse: SQL service account (the role whose name contains
        # "sql server"). adminservice_site_systems holds one row per role per host.
        sql_service_account_name: str | None = None
        try:
            row = self._find_all_objects(
                f"SELECT service_account FROM {self.schema}.adminservice_site_systems "
                f"WHERE LOWER(site_code) = LOWER(?) "
                f"AND LOWER(role) LIKE '%sql server%' "
                f"AND service_account IS NOT NULL AND service_account <> '' "
                f"LIMIT 1",
                [site_code],
            )
        except Exception:
            row = []
        if row and row[0] and row[0][0]:
            sql_service_account_name = row[0][0]

        return (
            display_name,
            site_server_name,
            sql_server_name,
            sql_database_name,
            sql_service_account_name,
            version,
            site_type,
            parent_site_code,
            install_dir,
        )

    @lru_cache
    def admin_user_logon_names_for_site(self, site_code: str) -> tuple[str, ...]:
        """Return the tuple of admin logon names (``DOMAIN\\sam``) for admins
        attached to ``site_code``. Populates SCCM_Site.adminUsers.
        """
        if not site_code:
            return ()
        try:
            rows = self._find_all_objects(
                f"SELECT DISTINCT logon_name FROM {self.schema}.adminservice_admins "
                f"WHERE LOWER(site_code) = LOWER(?) AND logon_name IS NOT NULL AND logon_name <> ''",
                [site_code],
            )
        except Exception:
            return ()
        return tuple(sorted(r[0] for r in rows if r and r[0]))

    @lru_cache
    def stored_account_labels_for_site(self, site_code: str) -> tuple[str, ...]:
        """Return PS1-style ``' (<sid>)'`` labels for SMS_SCI_Reserved
        accounts attached to ``site_code``.

        PS1 emits a leading space + parenthesized SID — its sam_account_name
        slot ends up empty because the upstream collection doesn't carry it
        through. We match PS1's literal format (leading-space + parens) so
        BloodHound queries against ``s.storedAccounts`` work identically.
        """
        if not site_code:
            return ()
        try:
            rows = self._find_all_objects(
                f"""
                SELECT DISTINCT ' (' || u.object_sid || ')'
                FROM {self.schema}.adminservice_reserved_accounts r
                JOIN {self.schema}.ldap_users u
                    ON LOWER(u.sam_account_name) =
                       LOWER(LIST_EXTRACT(STRING_SPLIT(r.account_username, chr(92)), -1))
                    OR LOWER(u.user_principal_name) = LOWER(r.account_username)
                WHERE LOWER(r.site_code) = LOWER(?)
                  AND r.account_username IS NOT NULL AND r.account_username <> ''
                  AND u.object_sid IS NOT NULL
                """,
                [site_code],
            )
        except Exception:
            return ()
        return tuple(sorted(r[0] for r in rows if r and r[0]))

    @lru_cache
    def computer_site_system_roles(self, sid: str, hostname: str | None = None) -> tuple[str, ...]:
        """Return the tuple of ``RoleName@SiteCode`` strings for a Computer.

        Mirrors CMBP's ``SCCMSiteSystemRoles`` property: each row in
        ``adminservice_site_systems`` for this host contributes one entry of
        the form ``"<role>@<site_code>"``. Matched by SID where available,
        falling back to FQDN / short-hostname comparison since
        ``adminservice_site_systems.hostname`` may not be SID-resolved.
        """
        if not sid and not hostname:
            return ()
        host_low = hostname.lower() if hostname else None
        host_short = host_low.split(".", 1)[0] if host_low else None
        sid_low = sid.lower() if sid else None
        # ``sccm.host_site_system_roles`` (built by transforms._build_host_site_system_roles)
        # holds one row per (host, role@site) with SID resolved in-line. The
        # lookup reduces to a single indexed scan.
        try:
            rows = self._find_all_objects(
                f"SELECT role_at_site FROM {self.schema}.host_site_system_roles "
                f"WHERE (? IS NOT NULL AND object_sid = ?) "
                f"   OR (? IS NOT NULL AND hostname_low = ?) "
                f"   OR (? IS NOT NULL AND hostname_short = ?)",
                [sid_low, sid_low, host_low, host_low, host_short, host_short],
            )
        except Exception:
            return ()
        # Preserve insertion order (AdminService row order) — match PS1.
        seen: set[str] = set()
        out: list[str] = []
        for r in rows:
            if r and r[0] and r[0] not in seen:
                seen.add(r[0])
                out.append(r[0])
        return tuple(out)

    @lru_cache
    def computer_is_in_r_system_groups(self, sid: str) -> bool:
        """Return True if the Computer SID has any rows in
        ``adminservice_r_system_security_groups`` via the LDAP-name join.

        Used to suppress LDAP-derived Computer->Group MemberOf edges when
        the SMS_R_System path is already covering the same membership
        (and CMBP emits only the SMS_R_System variant).
        """
        if not sid:
            return False
        try:
            return bool(self._find_single_object(
                f"""
                SELECT 1
                FROM {self.schema}.adminservice_r_system_security_groups r
                JOIN {self.schema}.ldap_computers c
                  ON LOWER(c.name) = LOWER(r.machine_name)
                  OR LOWER(c.sam_account_name) = LOWER(r.machine_name) || '$'
                WHERE LOWER(c.object_sid) = LOWER(?)
                LIMIT 1
                """,
                [sid],
            ))
        except Exception:
            return False

    @lru_cache
    def user_is_sccm_infra(self, sid: str) -> bool:
        """Return True if a User SID appears in SMS_R_User
        (``adminservice_r_user_security_groups``).

        Used by the output-stage prune as a User anchor so AdminService-
        discovered users keep their MemberOf edges through the
        SCCM-anchor BFS.
        """
        if not sid:
            return False
        try:
            return bool(self._find_single_object(
                f"SELECT 1 FROM {self.schema}.adminservice_r_user_security_groups WHERE LOWER(user_sid) = LOWER(?) LIMIT 1",
                [sid],
            ))
        except Exception:
            return False

    @lru_cache
    def adminservice_membership_available(self) -> bool:
        """Return True if AdminService SMS_R_System / SMS_R_User membership
        tables are populated. Used to decide whether to suppress LDAP-derived
        Group->Group MemberOf edges (CMBP never queries LDAP ``member`` so
        when AdminService gives us authoritative membership data we should
        drop the LDAP variants entirely)."""
        for table in (
            "adminservice_r_system_security_groups",
            "adminservice_r_user_security_groups",
        ):
            try:
                row = self._find_single_object(
                    f"SELECT 1 FROM {self.schema}.{table} LIMIT 1",
                    [],
                )
            except Exception:
                continue
            if row:
                return True
        return False

    @lru_cache
    def is_group_sid(self, sid: str) -> bool:
        """Return True if the given SID resolves to an AD Group in ``ldap_groups``."""
        if not sid:
            return False
        try:
            return bool(self._find_single_object(
                f"SELECT 1 FROM {self.schema}.ldap_groups WHERE LOWER(object_sid) = LOWER(?) LIMIT 1",
                [sid],
            ))
        except Exception:
            return False

    @lru_cache
    def has_system_management_acl(self, sid: str) -> bool:
        """Return True if *sid* appears in ``ldap_system_management_acl`` —
        i.e. holds an applicable ACE (GenericAll) on the System Management
        container. Used by Computer / User / Group models to add the
        ``LDAP-GenericAllSystemManagement`` collectionSource tag.
        """
        if not sid:
            return False
        try:
            return bool(self._find_single_object(
                f"SELECT 1 FROM {self.schema}.ldap_system_management_acl WHERE principal_sid = ? LIMIT 1",
                [sid],
            ))
        except Exception:
            return False

    @lru_cache
    def computer_is_sccm_infra(self, sid: str, hostname: str | None = None) -> bool:
        """Return True if a Computer SID / hostname appears in any
        SCCM-infrastructure source table.

        Reads the precomputed ``sccm.computer_sccm_infra`` view built by
        ``transforms._build_computer_sccm_infra`` — one indexed query instead
        of the historic 7-table per-call probe. Used by the output-stage
        prune as an extra Computer anchor so SCCM site servers / DPs / MPs /
        SMS providers survive the LDAP-superset filter even when no
        SCCM_AdminUser node is emitted.
        """
        if not sid and not hostname:
            return False
        host_low = hostname.lower() if hostname else None
        host_short = host_low.split(".", 1)[0] if host_low else None
        sid_low = sid.lower() if sid else None
        try:
            return bool(self._find_single_object(
                f"SELECT 1 FROM {self.schema}.computer_sccm_infra "
                f"WHERE (? IS NOT NULL AND hostname_low = ?) "
                f"   OR (? IS NOT NULL AND hostname_short = ?) "
                f"   OR (? IS NOT NULL AND object_sid = ?) "
                f"LIMIT 1",
                [host_low, host_low, host_short, host_short, sid_low, sid_low],
            ))
        except Exception:
            return False
