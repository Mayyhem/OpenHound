"""MSSQL_ServerRole node-kind schema registration.

Schema-only placeholder. Real MSSQL_ServerRole nodes are emitted at
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
    """Schema-only registration; emission happens via DerivedNode."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    @property
    def as_node(self):
        return None

    @property
    def edges(self):
        return iter(())
