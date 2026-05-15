"""MSSQL_DatabaseRole node-kind schema registration.

Schema-only placeholder. Real MSSQL_DatabaseRole nodes are emitted at
convert time by ``models/derived/derived_node.DerivedNode`` from the
``mssql_sysadmin_edges`` inference fan-out (sourced from
``adminservice_site_systems`` + ``ldap_computers`` — no SQL queries).
This file exists solely to register the kind's icon, description and
properties schema with OpenHound's ``ASSET_REGISTRY`` for OpenGraph
documentation and BloodHound display.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar, Optional

from dlt.common.libs.pydantic import DltConfig
from openhound.core.asset import BaseAsset, NodeDef
from pydantic import ConfigDict

from openhound_sccm.graph import SCCMNodeProperties
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
    """Schema-only registration; emission happens via DerivedNode."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    @property
    def as_node(self):
        return None

    @property
    def edges(self):
        return iter(())
