"""DuckDB lookup helpers for the MSSQL convert phase.

``MSSQLLookup`` is injected into ``convert`` as ``ctx.lookup`` and as
``self._lookup`` on every model/asset. It exposes cached point/list reads over
the raw + derived tables that ``transforms.py`` built in ``preproc``, so the
convert stage can resolve a permission's target principal, a role's nested
members, a server's effective high-privilege principals, fixed-role implied
permissions, and linked-server flags — none of which a model can derive from its
own raw row alone.

Caching: the base :class:`LookupManager` has none. Point lookups
(``server_principal`` / ``database_principal`` / ``effective_high_priv`` /
``effective_high_priv_summary``) are backed by per-table dicts built lazily on
first use and memoized on the instance, so a convert that touches every principal
does one scan per derived table rather than one query per lookup. List lookups
(``role_members`` / ``fixed_role_permissions`` / ``linked_server_flags``) are
memoized with :func:`functools.lru_cache`. ``table_rows`` streams a whole table
for the convert-reads-DuckDB pipeline and is intentionally uncached.

The ``schema`` keyword MUST keep its default (``"mssql"``): the framework
constructs the lookup as ``MSSQLLookup(client)`` with the client only.
"""
from __future__ import annotations

import logging
from collections.abc import Iterator
from functools import lru_cache
from typing import Optional

import duckdb
from duckdb import DuckDBPyConnection
from openhound.core.lookup import LookupManager

logger = logging.getLogger(__name__)


class MSSQLLookup(LookupManager):
    def __init__(self, client: DuckDBPyConnection, schema: str = "mssql") -> None:
        super().__init__(client, schema)
        self.schema = schema
        self.client = client
        # Lazily-built per-table indexes (None = not yet built). Keyed for point
        # lookups so a full convert does one scan per table, not one query per row.
        self._server_principals_idx: Optional[dict[tuple[str, int], dict]] = None
        self._database_principals_idx: Optional[dict[tuple[str, str, int], dict]] = None
        self._high_priv_idx: Optional[dict[tuple[str, int], dict]] = None
        self._high_priv_summary_idx: Optional[dict[str, dict]] = None

    # ------------------------------------------------------------------
    # Whole-table streaming (convert-reads-DuckDB pipeline)
    # ------------------------------------------------------------------
    def table_rows(self, table: str) -> Iterator[dict]:
        """Yield each row of ``{schema}.{table}`` as a column-named dict.

        Works for both raw and derived tables. Uses an independent cursor so this
        streaming scan never clobbers the active result of other ``self._lookup``
        queries sharing the connection. A missing/unreadable table logs and yields
        nothing so a not-yet-built table can't crash convert.
        """
        try:
            cur = self.client.cursor()
            cur.execute(f"SELECT * FROM {self.schema}.{table}")
        except duckdb.Error as err:
            logger.warning("MSSQLLookup.table_rows(%r) failed: %s", table, err)
            return
        cols = [c[0] for c in cur.description]
        while True:
            batch = cur.fetchmany(2000)
            if not batch:
                break
            for row in batch:
                yield dict(zip(cols, row))

    # ------------------------------------------------------------------
    # Principal resolution (point lookups, dict-backed)
    # ------------------------------------------------------------------
    def server_principal(self, server_oid: str, principal_id: int) -> Optional[dict]:
        """Resolve a server principal by (server_oid, principal_id).

        Returns the ``server_principal_map`` row (object_identifier, name,
        type_description, is_fixed_role, security_identifier,
        is_active_directory_principal) or ``None`` when unknown — e.g. a
        permission's ``TargetPrincipalID`` that names a dropped principal.
        """
        if self._server_principals_idx is None:
            self._server_principals_idx = {
                (r.get("server_oid"), _int(r.get("principal_id"))): r
                for r in self.table_rows("server_principal_map")
            }
            logger.debug("MSSQLLookup: cached %d server_principal_map row(s)",
                         len(self._server_principals_idx))
        return self._server_principals_idx.get((server_oid, _int(principal_id)))

    def database_principal(self, server_oid: str, database: str, principal_id: int) -> Optional[dict]:
        """Resolve a database principal by (server_oid, database, principal_id).

        Returns the ``database_principal_map`` row, or ``None`` when unknown.
        """
        if self._database_principals_idx is None:
            self._database_principals_idx = {
                (r.get("server_oid"), r.get("database"), _int(r.get("principal_id"))): r
                for r in self.table_rows("database_principal_map")
            }
            logger.debug("MSSQLLookup: cached %d database_principal_map row(s)",
                         len(self._database_principals_idx))
        return self._database_principals_idx.get((server_oid, database, _int(principal_id)))

    # ------------------------------------------------------------------
    # Role membership (list lookups)
    # ------------------------------------------------------------------
    @lru_cache(maxsize=None)
    def role_members(self, role_oid: str) -> list[dict]:
        """Every principal that is a (nested) member of *role_oid* at server level.

        Reads ``server_role_closure`` (member_oid -> role_oid, transitive). Each
        returned row carries the member's object identifier + principal id. Empty
        list when the role has no members / is unknown.
        """
        return self._find_all_dicts(
            f"SELECT member_oid, member_principal_id, role_oid, role_name "
            f"FROM {self.schema}.server_role_closure WHERE role_oid = ?",
            [role_oid],
        )

    @lru_cache(maxsize=None)
    def db_role_members(self, role_oid: str) -> list[dict]:
        """Every principal that is a (nested) member of *role_oid* at database level.

        Reads ``database_role_closure``. Empty list when unknown.
        """
        return self._find_all_dicts(
            f"SELECT member_oid, member_principal_id, role_oid, role_name, database "
            f"FROM {self.schema}.database_role_closure WHERE role_oid = ?",
            [role_oid],
        )

    # ------------------------------------------------------------------
    # Effective high-privilege (server node props + Kerberoasting edges)
    # ------------------------------------------------------------------
    def effective_high_priv(self, server_oid: str) -> dict:
        """Return the server's effective-high-privilege summary.

        The ``effective_high_priv_summary`` one-row-per-server table: the four
        ``domainPrincipalsWith*`` arrays + ``isAnyDomainPrincipalSysadmin``. Feeds
        the server node props and the GetAdminTGS edge. Returns an empty-but-shaped
        dict when the server has no summary row (no high-priv domain principals).
        """
        if self._high_priv_summary_idx is None:
            self._high_priv_summary_idx = {
                r.get("server_oid"): r
                for r in self.table_rows("effective_high_priv_summary")
            }
            logger.debug("MSSQLLookup: cached %d effective_high_priv_summary row(s)",
                         len(self._high_priv_summary_idx))
        row = self._high_priv_summary_idx.get(server_oid)
        if row is not None:
            return row
        # No summary row for this server: return the empty shape so callers can
        # read the arrays/boolean without a key check.
        return {
            "server_oid": server_oid,
            "domainPrincipalsWithSysadmin": [],
            "domainPrincipalsWithControlServer": [],
            "domainPrincipalsWithSecurityadmin": [],
            "domainPrincipalsWithImpersonateAnyLogin": [],
            "isAnyDomainPrincipalSysadmin": False,
        }

    def high_priv_principals(self, server_oid: str) -> list[dict]:
        """Every principal with at least one effective high-privilege on *server_oid*.

        Reads the per-principal ``effective_high_priv`` table (object_identifier,
        name, sid, is_domain, has_sysadmin/securityadmin/control_server/
        impersonate_any_login). Used where convert needs the per-principal flags
        (e.g. the enabled-domain-login CONNECT filter for GetTGS).
        """
        if self._high_priv_idx is None:
            self._high_priv_idx = {}
            for r in self.table_rows("effective_high_priv"):
                self._high_priv_idx.setdefault(r.get("server_oid"), []).append(r)
            logger.debug("MSSQLLookup: cached effective_high_priv for %d server(s)",
                         len(self._high_priv_idx))
        return self._high_priv_idx.get(server_oid, [])

    # ------------------------------------------------------------------
    # Fixed-role implied permissions
    # ------------------------------------------------------------------
    @lru_cache(maxsize=None)
    def fixed_role_permissions(self, server_oid: str, database: Optional[str] = None) -> list[dict]:
        """Implicit permissions conferred by fixed roles.

        With *database* ``None`` returns the server-level rows
        (``server_fixed_role_permissions``: principal_id, object_identifier, name,
        permission). With a *database* name returns that database's rows
        (``database_fixed_role_permissions``). Empty list when none.
        """
        if database is None:
            return self._find_all_dicts(
                f"SELECT principal_id, object_identifier, name, permission "
                f"FROM {self.schema}.server_fixed_role_permissions WHERE server_oid = ?",
                [server_oid],
            )
        return self._find_all_dicts(
            f"SELECT database, principal_id, object_identifier, name, permission "
            f"FROM {self.schema}.database_fixed_role_permissions "
            f"WHERE server_oid = ? AND database = ?",
            [server_oid, database],
        )

    # ------------------------------------------------------------------
    # Linked servers
    # ------------------------------------------------------------------
    @lru_cache(maxsize=None)
    def linked_server_flags(self, server_oid: str) -> list[dict]:
        """Every linked-server-login-mapping row for *server_oid*.

        Reads ``linked_server_flags`` (resolved_target, local/remote login,
        remote-privilege flags, is_linked_as_admin). One row per login mapping —
        preserving the distinct LocalLogin per link so the LinkedTo edge count
        isn't collapsed by JSON dedup downstream.
        """
        return self._find_all_dicts(
            f"SELECT * FROM {self.schema}.linked_server_flags WHERE server_oid = ?",
            [server_oid],
        )

    # ------------------------------------------------------------------
    # Internal helper
    # ------------------------------------------------------------------
    def _find_all_dicts(self, sql: str, params: list) -> list[dict]:
        """Run *sql* with *params* and return rows as column-named dicts.

        Logs and returns ``[]`` on a missing table / query error so a
        not-yet-built derived table can't crash convert.
        """
        try:
            cur = self.client.cursor()
            cur.execute(sql, params)
        except duckdb.Error as err:
            logger.warning("MSSQLLookup query failed (%s): %s", sql.split("FROM", 1)[-1].strip()[:60], err)
            return []
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def _int(value) -> Optional[int]:
    """Coerce a key value to int for stable dict keying (None stays None)."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


__all__ = ["MSSQLLookup"]
