"""MSSQL_ServerRole node model.

Reads from the ``mssql_server_roles`` DLT table. Yields one
MSSQL_ServerRole node per server-level role (sysadmin, dbcreator,
securityadmin, etc.) on a given server. The node id is
``<rolename>@<HOSTNAME>:<port>`` (e.g. ``sysadmin@cas-db:1433``).

CMBP also synthesises a ``sysadmin`` role node for every MSSQL_Server it
discovers, because the role membership graph (``MSSQL_MemberOf``,
``MSSQL_ControlServer``) hangs off the role node. Phase 3a populates this
table from authenticated ``server_role_members`` queries; the same role
materialises whenever a Phase 4 SQL view inserts a synthetic row.
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
class MSSQLServerRoleProperties(SCCMNodeProperties):
    """Properties carried on every MSSQL_ServerRole node."""

    isFixedRole: Optional[bool] = field(default=None, metadata={"description": "Whether this is a built-in fixed role"})
    SQLServer: Optional[str] = field(default=None, metadata={"description": "MSSQL server FQDN"})
    Type: str = field(default="MSSQL_ServerRole", metadata={"description": "Marker matching CMBP property"})


@app.asset(
    description="MSSQL Server Role node",
    node=NodeDef(
        kind=nk.MSSQL_SERVER_ROLE,
        description="Server-scoped role (sysadmin, dbcreator, securityadmin, etc.)",
        icon="shield",
        properties=MSSQLServerRoleProperties,
    ),
    edges=[],
)
class MSSQLServerRole(BaseAsset):
    """MSSQL_ServerRole asset — one row per server role from ``mssql_server_roles``."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    hostname: str
    role_name: str
    port: Optional[int] = 1433
    is_fixed_role: Optional[bool] = None
    domain: Optional[str] = None
    source: Optional[str] = "MSSQL-Auth"

    @property
    def as_node(self) -> SCCMNode:
        port = self.port or 1433
        host = (self.hostname or "").lower()
        node_id = f"{self.role_name}@{host}:{port}"
        return SCCMNode(
            kinds=[nk.MSSQL_SERVER_ROLE],
            properties=MSSQLServerRoleProperties(
                node_id=node_id,
                name=node_id,
                displayname=self.role_name,
                environmentid=self.domain or "",
                isFixedRole=self.is_fixed_role,
                SQLServer=host,
                collectionSource=[self.source] if self.source else None,
                Type="MSSQL_ServerRole",
            ),
        )

    @property
    def edges(self):
        return iter(())
