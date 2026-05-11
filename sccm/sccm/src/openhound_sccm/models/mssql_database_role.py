"""MSSQL_DatabaseRole node model.

Reads from the ``mssql_database_roles`` DLT table. Yields one
MSSQL_DatabaseRole node per database-level role (db_owner, db_datareader,
db_datawriter, etc.) on a given (server, database) pair. The node id is
``<rolename>@<HOSTNAME>:<port>\\<DBNAME>`` (e.g.
``db_owner@cas-db:1433\\CM_CAS``).

CMBP synthesises a ``db_owner`` role node for every MSSQL_Database it
discovers because the role-membership graph hangs off the role node.
Phase 3a populates this table from authenticated
``database_role_members`` queries; cross-cutting edges (MSSQL_Contains
Database->DatabaseRole, MSSQL_ControlDB DatabaseRole->Database,
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
class MSSQLDatabaseRoleProperties(SCCMNodeProperties):
    """Properties carried on every MSSQL_DatabaseRole node."""

    isFixedRole: Optional[bool] = field(default=None, metadata={"description": "Whether this is a built-in fixed role"})
    database: Optional[str] = field(default=None, metadata={"description": "Database name this role lives in"})
    SQLServer: Optional[str] = field(default=None, metadata={"description": "MSSQL server FQDN"})
    Type: str = field(default="MSSQL_DatabaseRole", metadata={"description": "Marker matching CMBP property"})


@app.asset(
    description="MSSQL Database Role node",
    node=NodeDef(
        kind=nk.MSSQL_DATABASE_ROLE,
        description="Database-scoped role (db_owner, db_datareader, etc.)",
        icon="shield",
        properties=MSSQLDatabaseRoleProperties,
    ),
    edges=[],
)
class MSSQLDatabaseRole(BaseAsset):
    """MSSQL_DatabaseRole asset — one row per (db,role) from ``mssql_database_roles``."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    hostname: str
    database_name: str
    role_name: str
    port: Optional[int] = 1433
    is_fixed_role: Optional[bool] = None
    domain: Optional[str] = None
    source: Optional[str] = "MSSQL-Auth"

    @property
    def as_node(self) -> SCCMNode:
        port = self.port or 1433
        host = (self.hostname or "").lower()
        node_id = f"{self.role_name}@{host}:{port}\\{self.database_name}"
        return SCCMNode(
            kinds=[nk.MSSQL_DATABASE_ROLE],
            properties=MSSQLDatabaseRoleProperties(
                node_id=node_id,
                name=node_id,
                displayname=self.role_name,
                environmentid=self.domain or "",
                isFixedRole=self.is_fixed_role,
                database=self.database_name,
                SQLServer=host,
                collectionSource=[self.source] if self.source else None,
                Type="MSSQL_DatabaseRole",
            ),
        )

    @property
    def edges(self):
        return iter(())
