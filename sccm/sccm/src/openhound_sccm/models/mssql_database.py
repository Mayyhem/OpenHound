"""MSSQL_Database node model.

Reads from the ``mssql_databases`` DLT table. Yields one MSSQL_Database node
per database visible to the authenticated user on a given server. The node
id is ``<HOSTNAME>:<port>\\<DBNAME>`` (e.g. ``cas-db:1433\\CM_CAS``).

For SCCM environments the load-bearing database is ``CM_<sitecode>`` (the
site database). Phase 3a populates this table when impacket-mssql can
authenticate; otherwise the resource yields zero rows.

Cross-cutting edges (MSSQL_Contains Server->Database, MSSQL_Contains
Database->DatabaseRole, etc.) live in ``models/derived/`` and come from
SQL views in Phase 4.
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
class MSSQLDatabaseProperties(SCCMNodeProperties):
    """Properties carried on every MSSQL_Database node."""

    database: Optional[str] = field(default=None, metadata={"description": "Database name"})
    isTrustworthy: Optional[bool] = field(default=None, metadata={"description": "TRUSTWORTHY flag"})
    SQLServer: Optional[str] = field(default=None, metadata={"description": "MSSQL server FQDN this DB is on"})
    SCCMInfra: Optional[bool] = field(default=None, metadata={"description": "Marker that this is SCCM infrastructure"})
    Type: str = field(default="MSSQL_Database", metadata={"description": "Marker matching CMBP property"})


@app.asset(
    description="MSSQL Database node",
    node=NodeDef(
        kind=nk.MSSQL_DATABASE,
        description="Microsoft SQL Server database (e.g. CM_<sitecode> for SCCM site DB)",
        icon="database",
        properties=MSSQLDatabaseProperties,
    ),
    edges=[],
)
class MSSQLDatabase(BaseAsset):
    """MSSQL_Database asset — one row per database from ``mssql_databases``."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    hostname: str
    database_name: str
    port: Optional[int] = 1433
    is_trustworthy: Optional[bool] = None
    site_code: Optional[str] = None
    domain: Optional[str] = None
    source: Optional[str] = "MSSQL-Auth"

    @property
    def as_node(self) -> SCCMNode:
        port = self.port or 1433
        host = (self.hostname or "").lower()
        node_id = f"{host}:{port}\\{self.database_name}"
        return SCCMNode(
            kinds=[nk.MSSQL_DATABASE],
            properties=MSSQLDatabaseProperties(
                node_id=node_id,
                name=self.database_name,
                displayname=self.database_name,
                environmentid=self.domain or "",
                database=self.database_name,
                isTrustworthy=self.is_trustworthy,
                SQLServer=host,
                siteCode=self.site_code,
                SCCMInfra=bool(self.database_name and self.database_name.startswith("CM_")),
                collectionSource=[self.source] if self.source else None,
                Type="MSSQL_Database",
            ),
        )

    @property
    def edges(self):
        return iter(())
