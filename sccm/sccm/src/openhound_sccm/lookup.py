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

from functools import lru_cache

from duckdb import DuckDBPyConnection
from openhound.core.lookup import LookupManager


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

    @lru_cache
    def computer_by_sid(self, sid: str) -> str | None:
        """Return the canonical id of a Computer node by SID."""
        try:
            return self._find_single_object(
                f"SELECT object_sid FROM {self.schema}.ldap_computers WHERE object_sid = ?",
                [sid],
            )
        except Exception:
            return None

    @lru_cache
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

    @lru_cache
    def user_by_sam(self, sam: str) -> str | None:
        try:
            return self._find_single_object(
                f"SELECT object_sid FROM {self.schema}.ldap_users WHERE LOWER(sam_account_name) = LOWER(?)",
                [sam],
            )
        except Exception:
            return None

    @lru_cache
    def group_by_sid(self, sid: str) -> str | None:
        try:
            return self._find_single_object(
                f"SELECT object_sid FROM {self.schema}.ldap_groups WHERE object_sid = ?",
                [sid],
            )
        except Exception:
            return None

    @lru_cache
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
    def computer_is_sccm_infra(self, sid: str, hostname: str | None = None) -> bool:
        """Return True if a Computer SID / hostname appears in any
        SCCM-infrastructure source table.

        Used by the output-stage prune as an extra Computer anchor so
        SCCM site servers / distribution points / management points /
        SMS providers survive the LDAP-superset filter even when no
        SCCM_AdminUser node is emitted (i.e. low-priv runs that never
        reached the AdminService SMS_Admin endpoint).
        """
        if not sid and not hostname:
            return False
        # Use a single UNION ALL probe so this is one round-trip per SID.
        sid_pred = "1=0" if not sid else "LOWER(? ) = LOWER(?)"  # constant-true placeholder; we use parameter binding
        params: list[str] = []
        # Build conditional SQL based on what's available. We always check
        # by hostname when given; SID matching is done where the source
        # table populates ``computer_sid`` directly.
        clauses: list[str] = []
        if hostname:
            host_low = hostname.lower()
            host_short = host_low.split(".")[0]
            for table in (
                "smb_site_servers",
                "smb_distribution_points",
                "http_management_points",
                "http_smsproviders",
                "http_distribution_points",
            ):
                try:
                    if not self._find_single_object(
                        f"SELECT 1 FROM {self.schema}.{table} WHERE LOWER(hostname) = ? OR LOWER(SPLIT_PART(hostname, '.', 1)) = ? LIMIT 1",
                        [host_low, host_short],
                    ):
                        continue
                    return True
                except Exception:
                    continue
        if sid:
            try:
                if self._find_single_object(
                    f"SELECT 1 FROM {self.schema}.ldap_sms_providers WHERE LOWER(object_sid) = LOWER(?) LIMIT 1",
                    [sid],
                ):
                    return True
            except Exception:
                pass
        # Computers that appear in SMS_R_System (AdminService) are also
        # SCCM-discovered — they're enumerated by SCCM's site discovery and
        # carry security-group memberships (used by SMS_R_System MemberOf
        # path). Without this anchor, Computers like the DC that have
        # security-group memberships from SMS_R_System but no Site System
        # role would not be anchored, and their MemberOf -> Group edges
        # would be pruned out (because forward_only BFS only fires when
        # the start Computer is already an anchor).
        if hostname:
            host_low = hostname.lower()
            host_short = host_low.split(".", 1)[0]
            try:
                if self._find_single_object(
                    f"SELECT 1 FROM {self.schema}.adminservice_r_system_security_groups WHERE LOWER(machine_name) = ? LIMIT 1",
                    [host_short],
                ):
                    return True
            except Exception:
                pass
        return False
