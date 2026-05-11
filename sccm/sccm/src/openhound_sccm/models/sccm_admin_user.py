"""SCCM_AdminUser node model.

Reads from the ``adminservice_admins`` DLT table (one row per
``SMS_Admin`` entry returned by the AdminService REST API on each SMS
Provider). Yields one ``SCCM_AdminUser`` node per row.

ID rewriting (Risk 1)
---------------------
CMBP's post-processing step 3 rewrites every Collection / AdminUser /
SecurityRole id from ``<x>@<SITECODE>`` to ``<x>@<ROOTSITECODE>`` so child
sites don't fragment principals across the hierarchy. This rewrite must
happen at node-emission time (not as a post-pass), otherwise the derived
edges produced by Phase 4 SQL views can refer to ids that no longer exist.

We resolve the root site code via ``self._lookup.hierarchy_root(site_code)``
in ``as_node`` below. The lookup is injected by OpenHound's convert phase
(see ``opengraph.source.apply_context`` in the framework). Falls back to
the raw site code when no hierarchies row is present (LDAP-only collections,
or for hosts without a CAS upstream).
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
class SCCMAdminUserProperties(SCCMNodeProperties):
    """Properties carried on every SCCM_AdminUser node."""

    logonName: Optional[str] = field(default=None, metadata={"description": "DOMAIN\\user form of the SCCM admin"})
    displayName: Optional[str] = field(default=None, metadata={"description": "Optional display name from SMS_Admin"})
    adminSid: Optional[str] = field(default=None, metadata={"description": "AdminSid as reported by SMS_Admin"})
    adminId: Optional[int] = field(default=None, metadata={"description": "AdminID integer from SMS_Admin"})
    isGroup: Optional[bool] = field(default=None, metadata={"description": "True when AccountType==1 (group)"})
    isAllInstances: Optional[bool] = field(default=None, metadata={"description": "True when CategoryNames includes 'All Systems'/'All'"})
    sourceSiteCode: Optional[str] = field(default=None, metadata={"description": "SourceSite reported by SMS_Admin (where the admin was created)"})
    SCCMInfra: Optional[bool] = field(default=True, metadata={"description": "Marker that this is SCCM infrastructure"})
    Type: str = field(default="SCCM_AdminUser", metadata={"description": "Marker matching CMBP property"})
    roleNames: Optional[list[str]] = field(default=None, metadata={"description": "RoleNames flattened from SMS_Admin"})
    collectionNames: Optional[list[str]] = field(default=None, metadata={"description": "CollectionNames flattened from SMS_Admin"})
    domain: Optional[str] = field(default=None, metadata={"description": "AD domain"})


@app.asset(
    description="SCCM admin user / group node",
    node=NodeDef(
        kind=nk.SCCM_ADMIN_USER,
        description="SCCM admin user discovered via the AdminService SMS_Admin endpoint",
        icon="user-shield",
        properties=SCCMAdminUserProperties,
    ),
    edges=[],
)
class SCCMAdminUser(BaseAsset):
    """SCCM_AdminUser asset - one row per SMS_Admin entry from ``adminservice_admins``."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    logon_name: str
    site_code: str
    admin_id: Optional[int] = None
    admin_sid: Optional[str] = None
    display_name: Optional[str] = None
    is_group: Optional[bool] = None
    is_all_instances: Optional[bool] = None
    source_site_code: Optional[str] = None
    role_names: Optional[list[str]] = None
    collection_names: Optional[list[str]] = None
    domain: Optional[str] = None
    source: Optional[str] = "AdminService-SMS_Admin"

    @property
    def as_node(self) -> SCCMNode:
        # Resolve the hierarchy root so ids are stable across CAS/Primary
        # boundaries. See module docstring (Risk 1).
        lookup = getattr(self, "_lookup", None)
        root_site_code = (
            lookup.hierarchy_root(self.site_code) if lookup and self.site_code else self.site_code
        ) or self.site_code or ""

        logon_lower = (self.logon_name or "").lower().strip()
        node_id = f"{logon_lower}@{root_site_code}"
        display = f"{self.logon_name}@{root_site_code}"

        return SCCMNode(
            kinds=[nk.SCCM_ADMIN_USER],
            properties=SCCMAdminUserProperties(
                node_id=node_id,
                name=display,
                displayname=display,
                environmentid=self.domain or "",
                logonName=self.logon_name,
                displayName=self.display_name,
                adminSid=self.admin_sid,
                adminId=self.admin_id,
                isGroup=self.is_group,
                isAllInstances=self.is_all_instances,
                siteCode=self.site_code,
                rootSiteCode=root_site_code,
                sourceSiteCode=self.source_site_code,
                SCCMInfra=True,
                collectionSource=[self.source] if self.source else None,
                Type="SCCM_AdminUser",
                roleNames=self.role_names,
                collectionNames=self.collection_names,
                domain=self.domain,
            ),
        )

    @property
    def edges(self):
        # SCCM_IsAssigned (admin->role, admin->collection), SCCM_IsMappedTo
        # (User/Group->admin), and SCCM_FullAdministrator (admin->client) all
        # live in models/derived/* and come from SQL views in Phase 4.
        return iter(())
