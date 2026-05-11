"""MSSQL_DatabaseUser node model.

Reads from the ``mssql_database_users`` DLT table. Yields one
MSSQL_DatabaseUser node per (login, database) mapping. The node id is
``<DOMAIN>\\<sam>$@<HOSTNAME>:<port>\\<DBNAME>``.

CMBP semantics: a login is a server-level principal; a database-user is
its representation inside a specific database (created by
``CREATE USER ... FOR LOGIN``). Phase 3a populates this when authenticated
queries succeed; cross-cutting edges (MSSQL_IsMappedTo Login->DatabaseUser,
MSSQL_MemberOf DatabaseUser->DatabaseRole) come from SQL views in Phase 4.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar, Optional

from dlt.common.libs.pydantic import DltConfig
from openhound.core.asset import BaseAsset, NodeDef
from pydantic import ConfigDict

from openhound_sccm.graph import SCCMNode, SCCMNodeProperties
from openhound_sccm.kinds import nodes as nk
from openhound_sccm.main import app


@dataclass
class MSSQLDatabaseUserProperties(SCCMNodeProperties):
    """Properties carried on every MSSQL_DatabaseUser node."""

    userName: Optional[str] = field(default=None, metadata={"description": "DOMAIN\\sam$ form (matches login)"})
    database: Optional[str] = field(default=None, metadata={"description": "Database name this user lives in"})
    SQLServer: Optional[str] = field(default=None, metadata={"description": "MSSQL server FQDN"})
    Type: str = field(default="MSSQL_DatabaseUser", metadata={"description": "Marker matching CMBP property"})


@app.asset(
    description="MSSQL Database User node",
    node=NodeDef(
        kind=nk.MSSQL_DATABASE_USER,
        description="Database-scoped user (CREATE USER ... FOR LOGIN)",
        icon="user",
        properties=MSSQLDatabaseUserProperties,
    ),
    edges=[],
)
class MSSQLDatabaseUser(BaseAsset):
    """MSSQL_DatabaseUser asset — one row per (login,database) from ``mssql_database_users``."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    hostname: str
    database_name: str
    user_name: str
    port: Optional[int] = 1433
    domain: Optional[str] = None
    source: Optional[str] = "MSSQL-Auth"

    @property
    def as_node(self) -> SCCMNode:
        port = self.port or 1433
        host = (self.hostname or "").lower()
        node_id = f"{self.user_name}@{host}:{port}\\{self.database_name}"
        return SCCMNode(
            kinds=[nk.MSSQL_DATABASE_USER],
            properties=MSSQLDatabaseUserProperties(
                node_id=node_id,
                name=node_id,
                displayname=self.user_name,
                environmentid=self.domain or "",
                userName=self.user_name,
                database=self.database_name,
                SQLServer=host,
                collectionSource=[self.source] if self.source else None,
                Type="MSSQL_DatabaseUser",
            ),
        )

    @property
    def edges(self):
        return iter(())
