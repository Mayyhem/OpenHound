"""SCCM_ClientDevice node model.

Reads from the ``adminservice_client_devices`` DLT table (one row per
``SMS_R_System`` resource returned by the AdminService REST API).
Yields one ``SCCM_ClientDevice`` node per row.

Unlike Collections / AdminUsers / SecurityRoles, client devices are NOT
site-scoped in the global id sense - they are physical hosts that exist
once across the hierarchy regardless of which site reports them. The id
is therefore ``GUID:<resource_guid>`` and no hierarchy rewrite is applied.
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
class SCCMClientDeviceProperties(SCCMNodeProperties):
    """Properties carried on every SCCM_ClientDevice node."""

    resourceID: Optional[int] = field(default=None, metadata={"description": "ResourceID from SMS_R_System"})
    machineName: Optional[str] = field(default=None, metadata={"description": "Name reported by SMS_R_System"})
    smsGUID: Optional[str] = field(default=None, metadata={"description": "SMSUniqueIdentifier (preserves CMBP property)"})
    isClient: Optional[bool] = field(default=None, metadata={"description": "Whether the resource is an active client"})
    clientVersion: Optional[str] = field(default=None, metadata={"description": "Reported ClientVersion"})
    ADDomainSID: Optional[str] = field(default=None, metadata={"description": "AD computer SID matched via ad_object_sid"})
    SCCMInfra: Optional[bool] = field(default=True, metadata={"description": "Marker that this is SCCM infrastructure"})
    Type: str = field(default="SCCM_ClientDevice", metadata={"description": "Marker matching CMBP property"})
    domain: Optional[str] = field(default=None, metadata={"description": "AD domain"})


@app.asset(
    description="SCCM client device node",
    node=NodeDef(
        kind=nk.SCCM_CLIENT_DEVICE,
        description="SCCM client device discovered via the AdminService SMS_R_System / SMS_CombinedDeviceResources endpoint",
        icon="laptop",
        properties=SCCMClientDeviceProperties,
    ),
    edges=[],
)
class SCCMClientDevice(BaseAsset):
    """SCCM_ClientDevice asset - one row per client from ``adminservice_client_devices``."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    guid: str
    site_code: str
    machine_name: Optional[str] = None
    resource_id: Optional[int] = None
    is_client: Optional[bool] = None
    client_version: Optional[str] = None
    ad_object_sid: Optional[str] = None
    last_logon_user: Optional[str] = None
    primary_user: Optional[str] = None
    current_user: Optional[str] = None
    domain: Optional[str] = None
    source: Optional[str] = "AdminService-SMS_CombinedDeviceResources"

    @property
    def as_node(self) -> SCCMNode:
        node_id = f"GUID:{self.guid}"
        display = (
            f"{(self.machine_name or '').upper()}@{self.site_code}"
            if self.machine_name
            else node_id
        )

        return SCCMNode(
            kinds=[nk.SCCM_CLIENT_DEVICE],
            properties=SCCMClientDeviceProperties(
                node_id=node_id,
                name=display,
                displayname=display,
                environmentid=self.domain or "",
                resourceID=self.resource_id,
                machineName=self.machine_name,
                smsGUID=self.guid,
                isClient=self.is_client,
                clientVersion=self.client_version,
                ADDomainSID=self.ad_object_sid,
                siteCode=self.site_code,
                SCCMInfra=True,
                collectionSource=[self.source] if self.source else None,
                Type="SCCM_ClientDevice",
                domain=self.domain,
            ),
        )

    @property
    def edges(self):
        # Cross-cutting edges (SCCM_HasClient site->device, SameHostAs
        # device<->computer, SCCM_HasCurrentUser, etc.) live in
        # models/derived/* and come from SQL views in Phase 4.
        return iter(())
