"""``databases`` raw row -> ``MSSQL_Database`` node (collector.go createDatabaseNode).

One node per online database. All the always-present properties come straight off
the raw row; the owner properties (``ownerLoginName`` / ``ownerPrincipalID`` /
``OwnerObjectIdentifier``) and ``collationName`` are emitted only when present
(Go's conditional ``props[...] =``). The owner principal id + object identifier
are resolved by matching the database's owner login name against the server
principals (Go collectDatabases does the same match), via :mod:`models.members`.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from openhound.core.asset import BaseAsset, NodeDef
from pydantic import ConfigDict

from .. import ids
from ..graph import DatabaseProperties, MSSQLNode
from ..kinds import nodes as nk
from ..main import app
from . import _common, members

logger = logging.getLogger(__name__)


@app.asset(
    node=NodeDef(
        kind=nk.DATABASE,
        description="A SQL Server database.",
        icon=nk.ICONS[nk.DATABASE]["name"],
        properties=DatabaseProperties,
        color=nk.ICONS[nk.DATABASE]["color"],
    ),
    edges=[],
    description="MSSQL_Database node from the raw databases table.",
)
class MSSQLDatabase(BaseAsset):
    """One raw ``databases`` row -> one ``MSSQL_Database`` node.

    Field names are dlt's snake_case of the DATABASES query columns.
    """

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    database_id: Optional[Any] = None
    name: Optional[str] = None
    owner_name: Optional[str] = None        # SUSER_SNAME(owner_sid) -> ownerLoginName
    owner_sid: Optional[str] = None
    create_date: Optional[Any] = None
    compatibility_level: Optional[Any] = None
    collation_name: Optional[str] = None
    is_read_only: Optional[Any] = None
    is_trustworthy_on: Optional[Any] = None  # -> isTrustworthy
    is_encrypted: Optional[Any] = None

    @property
    def as_node(self) -> MSSQLNode | None:
        """Build the MSSQL_Database node (collector.go createDatabaseNode)."""
        server_oid = _common.server_oid_for(self._lookup)
        db_name = self.name or ""
        if not server_oid or not db_name:
            logger.warning("MSSQLDatabase: dropping row (server_oid=%r, name=%r)", server_oid, db_name)
            return None
        oid = ids.database_oid(server_oid, db_name)
        sql_server_name = _common.sql_server_name_for(self._lookup)

        props = DatabaseProperties(
            name=db_name,
            displayname=db_name,
            environmentid=server_oid,
            databaseId=_common.as_int(self.database_id, default=0),
            createDate=_common.rfc3339(self.create_date),
            compatibilityLevel=_common.as_int(self.compatibility_level, default=0),
            isReadOnly=_common.as_bool(self.is_read_only),
            isTrustworthy=_common.as_bool(self.is_trustworthy_on),
            isEncrypted=_common.as_bool(self.is_encrypted),
            SQLServer=sql_server_name,
            SQLServerID=server_oid,
        )

        # Owner login name (Go: if != "").
        owner_name = self.owner_name or ""
        if owner_name:
            props.ownerLoginName = owner_name
            # Resolve the owner login to its server principal for the id/OID props.
            owner = members.server_principal_by_name(self._lookup, owner_name)
            if owner is not None:
                # ownerPrincipalID is the principal_id rendered as a string (Go
                # fmt.Sprintf("%d", ...)); only set when non-zero.
                pid = owner["principal_id"]
                if pid:
                    props.ownerPrincipalID = str(pid)
                if owner["object_identifier"]:
                    props.OwnerObjectIdentifier = owner["object_identifier"]
            else:
                # Owner login not among the readable server principals (e.g. perms).
                logger.debug("MSSQLDatabase: owner %r of %s not found in server principals",
                             owner_name, db_name)

        # collationName (Go: if != "").
        if self.collation_name:
            props.collationName = self.collation_name

        return MSSQLNode(
            kinds=[nk.DATABASE], properties=props,
            object_identifier=oid, icon=nk.ICONS[nk.DATABASE],
        )

    @property
    def edges(self):
        """Database edges (Owns, Contains, ...) are Stages 6/7."""
        return iter(())


__all__ = ["MSSQLDatabase"]
