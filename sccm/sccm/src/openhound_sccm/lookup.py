"""Lookup helpers for the OpenHound SCCM extension.

Exposes cached DuckDB queries used by `BaseAsset.as_node`/`edges` during the convert
phase. Methods are cached with `@lru_cache` so repeated lookups (e.g. resolving a
hierarchy root for every collection node) hit DuckDB only once.

Tables read here are produced by `transforms.py` during preproc and registered in
`main.py::preproc`. If a table is missing (e.g. preproc was skipped or a phase didn't
run) the underlying DuckDB call raises; callers should guard with try/except where
that's a real possibility.
"""

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
    # Site system roles (populated from LDAP mSSMSManagementPoint)
    # -----------------------------------------------------------------

    @lru_cache
    def computer_site_system_roles(self, object_sid: str | None, dns_host_name: str | None) -> tuple[str, ...]:
        """Return site system roles for a computer as 'RoleName@SiteCode' strings.

        Matches against computer_site_system_roles by FQDN and short name so that
        'mp.contoso.com' matches a hostname stored as either form.
        Returns empty tuple when the table is absent or no roles are found.
        """
        # object_sid is a cache-key discriminator only — it is not used in the
        # query, but including it prevents false hits when two computers from
        # different domains share the same short hostname.
        if not dns_host_name:
            return ()
        hostname_lower = dns_host_name.lower()
        short = hostname_lower.split(".")[0]
        try:
            rows = self._find_all_objects(
                f"""SELECT DISTINCT role
                    FROM {self.schema}.computer_site_system_roles
                    WHERE LOWER(hostname) = ?
                       OR LOWER(SPLIT_PART(hostname, '.', 1)) = ?""",
                [hostname_lower, short],
            )
        except Exception:
            return ()
        return tuple(r[0] for r in rows if r and r[0])
