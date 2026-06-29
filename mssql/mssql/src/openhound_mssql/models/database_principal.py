"""``database_principals`` raw row -> ``MSSQL_DatabaseUser`` / ``MSSQL_DatabaseRole``
/ ``MSSQL_ApplicationRole`` node (collector.go createDatabasePrincipalNode).

Branches on ``type_desc``: ``DATABASE_ROLE`` -> DatabaseRole; ``APPLICATION_ROLE``
-> ApplicationRole; everything else (SQL_USER, WINDOWS_USER, ...) -> DatabaseUser.
``defaultSchema`` is set for all three when present (Go sets it before the switch);
the per-kind properties (``isFixedRole`` + ``members`` for roles, ``type`` +
``serverLogin`` for users) match the Go conditional emission.

The node ``name`` carries the Go ``Name@DatabaseName`` form; the node ``id`` is the
database-principal ObjectIdentifier ``Name@<serverOID>\\<db>``. Memberships /
members / explicit permissions come from the raw per-database tables via
:mod:`models.members`; ``serverLogin`` comes from the database-user <-> server-login
link map.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from openhound.core.asset import BaseAsset, NodeDef
from pydantic import ConfigDict

from .. import ids
from ..graph import (
    ApplicationRoleProperties,
    DatabaseRoleProperties,
    DatabaseUserProperties,
    MSSQLNode,
)
from ..kinds import nodes as nk
from ..main import app
from . import _common, members

logger = logging.getLogger(__name__)


@app.asset(
    node=NodeDef(
        kind=nk.DATABASE_USER,
        description="A SQL Server database-level user (mapped login or contained user).",
        icon=nk.ICONS[nk.DATABASE_USER]["name"],
        properties=DatabaseUserProperties,
        color=nk.ICONS[nk.DATABASE_USER]["color"],
    ),
    edges=[],
    description="MSSQL_DatabaseUser / DatabaseRole / ApplicationRole from database_principals.",
)
class MSSQLDatabasePrincipal(BaseAsset):
    """One raw ``database_principals`` row -> one DatabaseUser/Role/AppRole node.

    Field names are dlt's snake_case of the DATABASE_PRINCIPALS query columns plus
    the ``database`` tag the collect stage adds per database.
    """

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    principal_id: Optional[Any] = None
    name: Optional[str] = None
    type_desc: Optional[str] = None
    create_date: Optional[Any] = None
    modify_date: Optional[Any] = None
    is_fixed_role: Optional[Any] = None
    owning_principal_id: Optional[Any] = None
    default_schema_name: Optional[str] = None
    sid: Optional[str] = None
    database: Optional[str] = None

    @property
    def as_node(self) -> MSSQLNode | None:
        """Build the DatabaseUser/Role/AppRole node (createDatabasePrincipalNode)."""
        server_oid = _common.server_oid_for(self._lookup)
        db_name = self.database or ""
        name = self.name or ""
        if not server_oid or not name:
            logger.warning("MSSQLDatabasePrincipal: dropping row (server_oid=%r, name=%r)",
                           server_oid, name)
            return None
        principal_id = _common.as_int(self.principal_id, default=0)
        oid = ids.db_principal_oid(name, server_oid, db_name)
        type_desc = self.type_desc or ""
        sql_server_name = _common.sql_server_name_for(self._lookup)
        # Go node name: "Name@DatabaseName".
        display_name = f"{name}@{db_name}"

        member_of = members.database_member_of(self._lookup, db_name, principal_id, type_desc)
        perms = members.database_explicit_permissions(self._lookup, db_name, principal_id)
        default_schema = self.default_schema_name or ""

        if type_desc == "DATABASE_ROLE":
            props = DatabaseRoleProperties(
                name=display_name, displayname=display_name, environmentid=server_oid,
                principalId=principal_id,
                createDate=_common.rfc3339(self.create_date),
                modifyDate=_common.rfc3339(self.modify_date),
                database=db_name, SQLServer=sql_server_name,
                isFixedRole=_common.as_bool(self.is_fixed_role),
            )
            if default_schema:
                props.defaultSchema = default_schema
            role_members = members.database_role_members(self._lookup, db_name, principal_id)
            if role_members:
                props.members = role_members
            if member_of:
                props.memberOfRoles = member_of
            if perms:
                props.explicitPermissions = perms
            kind, icon = nk.DATABASE_ROLE, nk.ICONS[nk.DATABASE_ROLE]

        elif type_desc == "APPLICATION_ROLE":
            props = ApplicationRoleProperties(
                name=display_name, displayname=display_name, environmentid=server_oid,
                principalId=principal_id,
                createDate=_common.rfc3339(self.create_date),
                modifyDate=_common.rfc3339(self.modify_date),
                database=db_name, SQLServer=sql_server_name,
            )
            if default_schema:
                props.defaultSchema = default_schema
            if member_of:
                props.memberOfRoles = member_of
            if perms:
                props.explicitPermissions = perms
            kind, icon = nk.APPLICATION_ROLE, nk.ICONS[nk.APPLICATION_ROLE]

        else:
            # Database users (SQL_USER, WINDOWS_USER, ...).
            props = DatabaseUserProperties(
                name=display_name, displayname=display_name, environmentid=server_oid,
                principalId=principal_id,
                createDate=_common.rfc3339(self.create_date),
                modifyDate=_common.rfc3339(self.modify_date),
                database=db_name, SQLServer=sql_server_name,
                type=type_desc,
            )
            if default_schema:
                props.defaultSchema = default_schema
            # serverLogin: only when this user maps to a server login (Go: if != nil).
            server_login = members.db_user_server_login(self._lookup, db_name, principal_id)
            if server_login:
                props.serverLogin = server_login
            if member_of:
                props.memberOfRoles = member_of
            if perms:
                props.explicitPermissions = perms
            kind, icon = nk.DATABASE_USER, nk.ICONS[nk.DATABASE_USER]

        return MSSQLNode(
            kinds=[kind], properties=props, object_identifier=oid, icon=icon,
        )

    @property
    def edges(self):
        """DB-principal edges (MemberOf, permission edges, ...) are Stages 6/7."""
        return iter(())


# Documentation-only registrations for the DatabaseRole / ApplicationRole kinds
# (both are emitted by MSSQLDatabasePrincipal switching on type_desc, so they are
# NOT added to NODE_SPECS — no separate table feeds them).
@app.asset(
    node=NodeDef(
        kind=nk.DATABASE_ROLE,
        description="A SQL Server database-level role (fixed or user-defined).",
        icon=nk.ICONS[nk.DATABASE_ROLE]["name"],
        properties=DatabaseRoleProperties,
        color=nk.ICONS[nk.DATABASE_ROLE]["color"],
    ),
    edges=[],
    description="MSSQL_DatabaseRole node (emitted by MSSQLDatabasePrincipal).",
)
class MSSQLDatabaseRoleAsset(BaseAsset):
    """Documentation-only registration of the MSSQL_DatabaseRole kind."""

    model_config = ConfigDict(extra="allow")

    @property
    def as_node(self):
        return None

    @property
    def edges(self):
        return iter(())


@app.asset(
    node=NodeDef(
        kind=nk.APPLICATION_ROLE,
        description="A SQL Server database application role.",
        icon=nk.ICONS[nk.APPLICATION_ROLE]["name"],
        properties=ApplicationRoleProperties,
        color=nk.ICONS[nk.APPLICATION_ROLE]["color"],
    ),
    edges=[],
    description="MSSQL_ApplicationRole node (emitted by MSSQLDatabasePrincipal).",
)
class MSSQLApplicationRoleAsset(BaseAsset):
    """Documentation-only registration of the MSSQL_ApplicationRole kind."""

    model_config = ConfigDict(extra="allow")

    @property
    def as_node(self):
        return None

    @property
    def edges(self):
        return iter(())


__all__ = [
    "MSSQLDatabasePrincipal",
    "MSSQLDatabaseRoleAsset",
    "MSSQLApplicationRoleAsset",
]
