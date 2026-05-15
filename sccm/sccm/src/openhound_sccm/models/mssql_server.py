"""MSSQL_Server node model.

Reads from the ``mssql_epa_flags`` DLT table. Yields one MSSQL_Server node per
host:port that responded to a TDS PRELOGIN probe on TCP/1433. The node id is
``<HOSTNAME>:1433`` (lower-cased). The CMBP collector also produces this kind
through both the registry path (``RemoteRegistry-MultisiteComponentServers``)
and the TDS path (``MSSQL-TDS``); we use the EPA-flag table here because TDS
prelogin is the authoritative one-row-per-listening-server source.

Cross-cutting edges (MSSQL_HostFor, MSSQL_Contains, MSSQL_HasLogin, etc.)
live in ``models/derived/`` and are computed in Phase 4 from SQL views; this
model only emits the node itself.
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
class MSSQLServerProperties(SCCMNodeProperties):
    """Properties carried on every MSSQL_Server node."""

    port: Optional[int] = field(default=1433, metadata={"description": "TCP port (always 1433 for default instance)"})
    SQLServicePort: Optional[int] = field(default=1433, metadata={"description": "Mirrors CMBP property name"})
    hostFQDN: Optional[str] = field(default=None, metadata={"description": "Fully qualified host name"})
    mssqlExtendedProtectionForAuthentication: Optional[bool] = field(
        default=None, metadata={"description": "EPA enabled? Drives CoerceAndRelayToMSSQL post-processing"}
    )
    mssqlEPAValue: Optional[int] = field(
        default=None, metadata={"description": "Raw EPA value 0=Off, 1=Allowed, 2=Required"}
    )
    SCCMInfra: Optional[bool] = field(default=True, metadata={"description": "Marker that this is SCCM infrastructure"})
    Type: str = field(default="MSSQL_Server", metadata={"description": "Marker matching CMBP property"})


@app.asset(
    description="MSSQL Server node",
    node=NodeDef(
        kind=nk.MSSQL_SERVER,
        description="Microsoft SQL Server instance discovered via TDS PRELOGIN on TCP/1433",
        icon="database",
        properties=MSSQLServerProperties,
    ),
    edges=[],
)
class MSSQLServer(BaseAsset):
    """MSSQL_Server asset — one row per (hostname, port) from ``mssql_epa_flags``."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    # Raw fields from mssql_epa_flags JSONL
    hostname: str
    port: Optional[int] = 1433
    epa: Optional[str] = None
    epa_value: Optional[int] = None
    epa_enabled: Optional[bool] = None
    fqdn: Optional[str] = None
    domain: Optional[str] = None
    source: Optional[str] = "MSSQL-TDS"

    @property
    def as_node(self) -> SCCMNode:
        port = self.port or 1433
        host = (self.hostname or "").lower()
        node_id = f"{host}:{port}"
        display = self.fqdn or host
        return SCCMNode(
            kinds=[nk.MSSQL_SERVER],
            properties=MSSQLServerProperties(
                node_id=node_id,
                name=f"{display}:{port}",
                displayname=f"{display}:{port}",
                environmentid=self.domain or None,
                dNSHostName=self.fqdn or host,
                hostFQDN=self.fqdn or host,
                port=port,
                SQLServicePort=port,
                mssqlExtendedProtectionForAuthentication=self.epa_enabled,
                mssqlEPAValue=self.epa_value,
                SCCMInfra=True,
                collectionSource=[self.source] if self.source else None,
                Type="MSSQL_Server",
            ),
        )

    @property
    def edges(self):
        return iter(())
