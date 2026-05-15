"""MSSQL_Login node-kind schema registration.

Schema-only placeholder. Real MSSQL_Login nodes are emitted at convert
time by ``models/derived/derived_node.DerivedNode`` from the
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
    """Schema-only registration; emission happens via DerivedNode."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    @property
    def as_node(self):
        return None

    @property
    def edges(self):
        return iter(())
