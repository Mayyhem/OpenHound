"""Computer node model.

Reads from the ``ldap_computers`` DLT table. Yields one Computer node per AD
computer account, with kinds=[Computer, Base] to match ConfigManBearPig output.

Edges emitted from this model are limited to relationships that derive *only*
from a single computer's own attributes. Cross-cutting edges
(LocalAdminRequired, CoerceAndRelay*, SameHostAs, etc.) live in
``models/derived/`` and consume materialised SQL views.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar, Optional

from dlt.common.libs.pydantic import DltConfig
from openhound.core.asset import BaseAsset, NodeDef
from pydantic import ConfigDict

from openhound_sccm.graph import SCCMNode, SCCMNodeProperties
from openhound_sccm.kinds import nodes as nk
from openhound_sccm.log_context import trace_node_with_properties
from openhound_sccm.main import app


@dataclass
class ComputerProperties(SCCMNodeProperties):
    """Properties carried on every Computer node.

    Field names match the camelCase used by ConfigManBearPig's output so the
    values appear in the shape BloodHound expects and the test runner's wildcard 
    patterns (e.g. ``dNSHostName: cas-pss.$Domain``) match unchanged.
    """

    # From Active Directory
    CN: Optional[str] = field(default=None, metadata={"description": "Common name (last RDN of distinguishedName)"})
    dNSHostName: Optional[str] = field(default=None, metadata={"description": "dNSHostName"})
    domain: Optional[str] = field(default=None, metadata={"description": "AD domain"})
    enabled: Optional[bool] = field(default=None, metadata={"description": "Whether the AD account is enabled"})
    objectClass: Optional[list[str]] = field(default=None, metadata={"description": "AD objectClass list"})
    operatingSystem: Optional[str] = field(default=None, metadata={"description": "Operating system from AD"})
    operatingSystemVersion: Optional[str] = field(default=None, metadata={"description": "OS version from AD"})
    samAccountName: Optional[str] = field(default=None, metadata={"description": "sAMAccountName"})
    servicePrincipalName: Optional[list[str]] = field(default=None, metadata={"description": "AD SPNs"})

    # Derived from multiple sources
    disableLoopbackCheck: Optional[str] = field(default=None, metadata={"description": "LSA DisableLoopbackCheck setting ('Enabled' / 'Disabled')"})
    isDomainPrincipal: Optional[bool] = field(default=None, metadata={"description": "Whether this principal is sourced from AD"})
    networkBootServer: Optional[bool] = field(default=None, metadata={"description": "Whether this computer is a PXE-enabled DP"})
    restrictReceivingNtlmTraffic: Optional[str] = field(default=None, metadata={"description": "LSA MSV1_0 RestrictReceivingNtlmTraffic setting ('Off' / 'Deny_All' / 'Deny_Inbound_Explicit')"})
    SCCMHasClientRemoteControlSPN: Optional[bool] = field(default=None, metadata={"description": "True when the computer has the CmRcService SPN registered"})
    SCCMInfra: Optional[bool] = field(default=None, metadata={"description": "True when this Computer hosts an SCCM site system / DP / MP / SMS Provider role"})
    SCCMSiteSystemRoles: Optional[list[str]] = field(default=None, metadata={"description": "List of 'RoleName@SiteCode' entries from SMS_SCI_SysResUse"})
    SCCMClientCertificateRequired: Optional[bool] = field(default=None, metadata={"description": "True when the management point's SMSTRC endpoint returned 403 (client certificate required)"})
    SCCMHostsContentLibrary: Optional[bool] = field(default=None, metadata={"description": "True when the host exposes the SCCMContentLib$ SMB share (Distribution Point indicator)"})
    SCCMIsPXESupportEnabled: Optional[bool] = field(default=None, metadata={"description": "True when the host is configured as a PXE-enabled DP"})
    SCCMResourceIDs: Optional[list[str]] = field(default=None, metadata={"description": "List of ResourceID@SiteCode strings for the device's SMS_R_System resources"})
    SCCMClientDeviceIdentifier: Optional[str] = field(default=None, metadata={"description": "GUID:<smsGuid> of the matched SCCM_ClientDevice, when the computer is also an SCCM client"})
    SMBSigningRequired: Optional[bool] = field(default=None, metadata={"description": "Whether the host requires SMB signing"})


@app.asset(
    description="AD Computer node",
    node=NodeDef(
        kind=nk.COMPUTER,
        description="Active Directory computer account discovered via LDAP",
        icon="desktop",
        properties=ComputerProperties,
    ),
    edges=[],
)


class Computer(BaseAsset):
    """Computer asset — one row per AD computer account from ``ldap_computers``."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    # Raw fields from ldap_computers JSONL
    object_sid: str
    sam_account_name: Optional[str] = None
    name: Optional[str] = None
    distinguished_name: Optional[str] = None
    dns_host_name: Optional[str] = None
    operating_system: Optional[str] = None
    operating_system_version: Optional[str] = None
    enabled: Optional[bool] = None
    service_principal_names: Optional[list[str]] = None
    member_of_dns: Optional[list[str]] = None
    primary_group_id: Optional[int] = None
    source: Optional[str] = "LDAP"
    domain: Optional[str] = None

    @property
    def as_node(self) -> SCCMNode:
        display = self.name or (self.sam_account_name or "").rstrip("$") or self.object_sid
        roles = self._lookup.computer_site_system_roles(self.object_sid, self.dns_host_name)
        sccm_site_system_roles = list(roles) if roles else None
  
        props = ComputerProperties(
            node_id=self.object_sid,
            name=display,
            displayname=display,
            distinguishedName=self.distinguished_name,
            dNSHostName=self.dns_host_name,
            domain=self.domain,
            enabled=self.enabled,
            isDomainPrincipal=True,
            SCCMSiteSystemRoles=sccm_site_system_roles,
        )
        trace_node_with_properties(nk.COMPUTER, self.object_sid, display, props)
        return SCCMNode(kinds=[nk.COMPUTER, nk.BASE], properties=props)

    @property
    def edges(self):
        return iter(())
