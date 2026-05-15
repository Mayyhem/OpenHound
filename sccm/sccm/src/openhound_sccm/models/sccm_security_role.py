"""SCCM_SecurityRole node model.

Reads from the ``adminservice_security_roles`` DLT table (one row per
``SMS_Role`` entry returned by the AdminService REST API). Yields one
``SCCM_SecurityRole`` node per row.

Same hierarchy-root id rewriting as SCCMCollection / SCCMAdminUser (Risk 1).
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
class SCCMSecurityRoleProperties(SCCMNodeProperties):
    """Properties carried on every SCCM_SecurityRole node."""

    roleID: Optional[str] = field(default=None, metadata={"description": "RoleID from SMS_Role"})
    roleName: Optional[str] = field(default=None, metadata={"description": "RoleName from SMS_Role"})
    description: Optional[str] = field(default=None, metadata={"description": "RoleDescription from SMS_Role (alias kept for backwards compatibility)"})
    roleDescription: Optional[str] = field(default=None, metadata={"description": "RoleDescription from SMS_Role (PS1 canonical name)"})
    SCCMInfra: Optional[bool] = field(default=True, metadata={"description": "Marker that this is SCCM infrastructure"})
    Type: str = field(default="SCCM_SecurityRole", metadata={"description": "Marker matching CMBP property"})
    domain: Optional[str] = field(default=None, metadata={"description": "AD domain"})


@app.asset(
    description="SCCM security role node",
    node=NodeDef(
        kind=nk.SCCM_SECURITY_ROLE,
        description="SCCM security role discovered via the AdminService SMS_Role endpoint",
        icon="user-tag",
        properties=SCCMSecurityRoleProperties,
    ),
    edges=[],
)
class SCCMSecurityRole(BaseAsset):
    """SCCM_SecurityRole asset - one row per SMS_Role entry from ``adminservice_security_roles``."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    role_id: str
    site_code: str
    role_name: Optional[str] = None
    description: Optional[str] = None
    domain: Optional[str] = None
    source: Optional[str] = "AdminService-SMS_Role"

    @property
    def as_node(self) -> SCCMNode:
        root_site_code = (
            self._lookup.hierarchy_root(self.site_code) if self.site_code else None
        ) or self.site_code or ""

        node_id = f"{self.role_id}@{root_site_code}"
        # PS1 emits ``name`` = bare role_name (no @site suffix). Match that
        # so BloodHound queries against ``r.name = 'Full Administrator'`` work.
        display = self.role_name or node_id

        return SCCMNode(
            kinds=[nk.SCCM_SECURITY_ROLE],
            properties=SCCMSecurityRoleProperties(
                node_id=node_id,
                name=display,
                displayname=display,
                environmentid=self.domain or None,
                roleID=self.role_id,
                roleName=self.role_name,
                description=self.description,
                roleDescription=self.description,
                siteCode=self.site_code,
                rootSiteCode=root_site_code,
                SCCMInfra=True,
                collectionSource=[self.source] if self.source else None,
                Type="SCCM_SecurityRole",
            ),
        )

    @property
    def edges(self):
        return iter(())
