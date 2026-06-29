"""``server_principals`` raw row -> ``MSSQL_Login`` OR ``MSSQL_ServerRole`` node.

Branches on ``type_desc`` exactly like Go ``createServerPrincipalNode``:
``SERVER_ROLE`` -> ``MSSQL_ServerRole``; everything else (SQL_LOGIN, WINDOWS_LOGIN,
WINDOWS_GROUP, CERTIFICATE_MAPPED_LOGIN, ...) -> ``MSSQL_Login``. Property sets
differ per branch (see the two NodeProperties dataclasses in graph.py), and
optional keys are emitted only when present (Go's conditional ``props[...] =``).

Enrichment from the preproc DuckDB via ``self._lookup``:

* the converted ``security_identifier`` (S-1-5-... form) + ``is_active_directory_principal``
  come from the ``server_principal_map`` derived table (``transforms`` did the hex
  -> S-1 conversion and the AD test).
* ``memberOfRoles`` / ``members`` (direct, + implicit ``public``) and
  ``explicitPermissions`` (+ fixed-role predefined) come from the raw role-member /
  permission tables via :mod:`models.members`.
* ``databaseUsers`` (login -> ["user@db", ...]) comes from the database-user <->
  server-login link map in :mod:`models.members`.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from openhound.core.asset import BaseAsset, NodeDef
from pydantic import ConfigDict

from .. import ids
from ..graph import LoginProperties, MSSQLNode, ServerRoleProperties
from ..kinds import nodes as nk
from ..main import app
from . import _common, members

logger = logging.getLogger(__name__)


@app.asset(
    node=NodeDef(
        kind=nk.LOGIN,
        description="A SQL Server server-level login (SQL/Windows login or Windows group).",
        icon=nk.ICONS[nk.LOGIN]["name"],
        properties=LoginProperties,
        color=nk.ICONS[nk.LOGIN]["color"],
    ),
    edges=[],
    description="MSSQL_Login / MSSQL_ServerRole node from the raw server_principals table.",
)
class MSSQLServerPrincipal(BaseAsset):
    """One raw ``server_principals`` row -> one Login or ServerRole node.

    A single asset emits both kinds (Go uses one ``createServerPrincipalNode`` that
    switches on ``type_desc``). The ``MSSQL_ServerRole`` node kind is registered via
    :class:`MSSQLServerRoleAsset` below so the catalog/docs carry both kinds.
    Field names are dlt's snake_case of the SERVER_PRINCIPALS query columns.
    """

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    principal_id: Optional[Any] = None
    name: Optional[str] = None
    type_desc: Optional[str] = None
    is_disabled: Optional[Any] = None
    is_fixed_role: Optional[Any] = None
    create_date: Optional[Any] = None
    modify_date: Optional[Any] = None
    default_database_name: Optional[str] = None
    sid: Optional[str] = None
    owning_principal_id: Optional[Any] = None

    @property
    def as_node(self) -> MSSQLNode | None:
        """Build the Login or ServerRole node (collector.go createServerPrincipalNode)."""
        server_oid = _common.server_oid_for(self._lookup)
        if not server_oid:
            logger.warning("MSSQLServerPrincipal: no server context; dropping %r", self.name)
            return None
        name = self.name or ""
        principal_id = _common.as_int(self.principal_id, default=0)
        oid = ids.principal_oid(name, server_oid)
        type_desc = self.type_desc or ""
        sql_server_name = _common.sql_server_name_for(self._lookup)

        if type_desc == "SERVER_ROLE":
            return self._build_role(name, principal_id, oid, server_oid, sql_server_name)
        return self._build_login(name, principal_id, oid, server_oid, type_desc, sql_server_name)

    @property
    def edges(self):
        """Login/role edges (MemberOf, permission edges, ...) are Stages 6/7."""
        return iter(())

    # ------------------------------------------------------------------
    def _build_role(self, name, principal_id, oid, server_oid, sql_server_name) -> MSSQLNode:
        """SERVER_ROLE branch -> MSSQL_ServerRole."""
        props = ServerRoleProperties(
            name=name,
            displayname=name,
            environmentid=server_oid,
            principalId=principal_id,
            createDate=_common.rfc3339(self.create_date),
            modifyDate=_common.rfc3339(self.modify_date),
            SQLServer=sql_server_name,
            isFixedRole=_common.as_bool(self.is_fixed_role),
        )
        role_members = members.server_role_members(self._lookup, principal_id)
        if role_members:
            props.members = role_members
        member_of = members.server_member_of(self._lookup, principal_id, "SERVER_ROLE")
        if member_of:
            props.memberOfRoles = member_of
        perms = members.server_explicit_permissions(
            self._lookup, principal_id, name, _common.as_bool(self.is_fixed_role)
        )
        if perms:
            props.explicitPermissions = perms
        return MSSQLNode(
            kinds=[nk.SERVER_ROLE], properties=props,
            object_identifier=oid, icon=nk.ICONS[nk.SERVER_ROLE],
        )

    def _build_login(self, name, principal_id, oid, server_oid, type_desc, sql_server_name) -> MSSQLNode:
        """Default branch -> MSSQL_Login (SQL/Windows login, Windows group, ...)."""
        props = LoginProperties(
            name=name,
            displayname=name,
            environmentid=server_oid,
            principalId=principal_id,
            createDate=_common.rfc3339(self.create_date),
            modifyDate=_common.rfc3339(self.modify_date),
            SQLServer=sql_server_name,
            type=type_desc,
            disabled=_common.as_bool(self.is_disabled),
            defaultDatabase=self.default_database_name or "",
        )

        # AD enrichment from server_principal_map (converted SID + AD flag).
        mapped = self._lookup.server_principal(server_oid, principal_id) or {}
        is_ad = _common.as_bool(mapped.get("is_active_directory_principal"))
        props.isActiveDirectoryPrincipal = is_ad
        sid = mapped.get("security_identifier") or ""
        if sid:
            # Go: activeDirectorySID set whenever a SID is present.
            props.activeDirectorySID = sid
            # activeDirectoryPrincipal set only for AD principals (Go: == name).
            if is_ad:
                props.activeDirectoryPrincipal = name

        # databaseUsers[] (login OID -> ["user@db", ...]).
        db_users = members.login_database_users(self._lookup, oid)
        if db_users:
            props.databaseUsers = db_users

        member_of = members.server_member_of(self._lookup, principal_id, type_desc)
        if member_of:
            props.memberOfRoles = member_of
        perms = members.server_explicit_permissions(
            self._lookup, principal_id, name, _common.as_bool(self.is_fixed_role)
        )
        if perms:
            props.explicitPermissions = perms

        return MSSQLNode(
            kinds=[nk.LOGIN], properties=props,
            object_identifier=oid, icon=nk.ICONS[nk.LOGIN],
        )


# The MSSQL_ServerRole node kind is emitted by MSSQLServerPrincipal (it switches on
# type_desc). This zero-row asset exists only to register the ServerRole NodeDef in
# the catalog/docs — it is NOT added to NODE_SPECS (no separate table feeds it).
@app.asset(
    node=NodeDef(
        kind=nk.SERVER_ROLE,
        description="A SQL Server server-level role (fixed or user-defined).",
        icon=nk.ICONS[nk.SERVER_ROLE]["name"],
        properties=ServerRoleProperties,
        color=nk.ICONS[nk.SERVER_ROLE]["color"],
    ),
    edges=[],
    description="MSSQL_ServerRole node (emitted by MSSQLServerPrincipal on SERVER_ROLE).",
)
class MSSQLServerRoleAsset(BaseAsset):
    """Documentation-only registration of the MSSQL_ServerRole kind."""

    model_config = ConfigDict(extra="allow")

    @property
    def as_node(self):
        return None

    @property
    def edges(self):
        return iter(())


__all__ = ["MSSQLServerPrincipal", "MSSQLServerRoleAsset"]
