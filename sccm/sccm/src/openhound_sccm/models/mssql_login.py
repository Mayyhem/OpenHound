"""MSSQL_Login node model.

Reads from the ``mssql_logins`` DLT table. Yields one MSSQL_Login node per
SQL login on a given server. The node id is the CMBP-canonical form
``<DOMAIN>\\<sam>$@<HOSTNAME>:<port>`` (e.g. ``MAYYHEM\\CAS-PSS$@cas-db:1433``).

Each row corresponds to one ``server_principals`` entry visible to the
authenticated user. Phase 3a only populates this table when impacket-mssql
can connect with the configured credentials (typical for domainadmin against
a CAS site DB); for low-priv users the table will be empty and zero
MSSQL_Login nodes will be emitted.

Cross-cutting edges (MSSQL_HasLogin Computer->Login, MSSQL_MemberOf
Login->ServerRole) live in ``models/derived/`` and come from SQL views
in Phase 4.
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
class MSSQLLoginProperties(SCCMNodeProperties):
    """Properties carried on every MSSQL_Login node."""

    loginName: Optional[str] = field(default=None, metadata={"description": "DOMAIN\\sam$ form of the login"})
    loginType: Optional[str] = field(default=None, metadata={"description": "WINDOWS_LOGIN / SQL_LOGIN / WINDOWS_GROUP"})
    isDisabled: Optional[bool] = field(default=None, metadata={"description": "Whether the login is disabled"})
    isLocked: Optional[bool] = field(default=None, metadata={"description": "Whether the login is locked"})
    server: Optional[str] = field(default=None, metadata={"description": "MSSQL server FQDN this login is on"})
    Type: str = field(default="MSSQL_Login", metadata={"description": "Marker matching CMBP property"})


@app.asset(
    description="MSSQL Login node",
    node=NodeDef(
        kind=nk.MSSQL_LOGIN,
        description="Microsoft SQL Server login (server-level principal)",
        icon="key",
        properties=MSSQLLoginProperties,
    ),
    edges=[],
)
class MSSQLLogin(BaseAsset):
    """MSSQL_Login asset — one row per server login from ``mssql_logins``."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    hostname: str
    login_name: str
    port: Optional[int] = 1433
    login_type: Optional[str] = None
    is_disabled: Optional[bool] = None
    is_locked: Optional[bool] = None
    sid: Optional[str] = None
    domain: Optional[str] = None
    source: Optional[str] = "MSSQL-Auth"

    @property
    def as_node(self) -> SCCMNode:
        port = self.port or 1433
        host = (self.hostname or "").lower()
        node_id = f"{self.login_name}@{host}:{port}"
        return SCCMNode(
            kinds=[nk.MSSQL_LOGIN],
            properties=MSSQLLoginProperties(
                node_id=node_id,
                name=node_id,
                displayname=self.login_name,
                environmentid=self.domain or "",
                loginName=self.login_name,
                loginType=self.login_type,
                isDisabled=self.is_disabled,
                isLocked=self.is_locked,
                server=host,
                collectionSource=[self.source] if self.source else None,
                Type="MSSQL_Login",
            ),
        )

    @property
    def edges(self):
        return iter(())
