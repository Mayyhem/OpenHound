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
from openhound.core.models.entries_dataclass import Edge
from pydantic import ConfigDict

from openhound_sccm.graph import SCCMNode, SCCMNodeProperties
from openhound_sccm.kinds import nodes as nk
from openhound_sccm.main import app


@dataclass
class ComputerProperties(SCCMNodeProperties):
    """Properties carried on every Computer node.

    Field names match the camelCase used by ConfigManBearPig's output so the
    test runner's wildcard patterns (e.g. ``dNSHostName: cas-pss.$Domain``)
    match unchanged.
    """

    objectGuid: Optional[str] = field(default=None, metadata={"description": "AD objectGUID"})
    operatingSystem: Optional[str] = field(default=None, metadata={"description": "Operating system from AD"})
    operatingSystemVersion: Optional[str] = field(default=None, metadata={"description": "OS version from AD"})
    servicePrincipalName: Optional[list[str]] = field(default=None, metadata={"description": "AD SPNs"})
    networkBootServer: Optional[bool] = field(default=None, metadata={"description": "Whether this computer is a PXE-enabled DP"})
    Type: Optional[str] = field(default="Computer", metadata={"description": "Marker matching CMBP property"})
    domain: Optional[str] = field(default=None, metadata={"description": "AD domain (NetBIOS or DNS)"})
    SCCMInfra: Optional[bool] = field(default=None, metadata={"description": "True when this Computer hosts an SCCM site system / DP / MP / SMS Provider role"})


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
    object_guid: Optional[str] = None
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
        # Look up SCCM-infra role membership at convert time so the
        # output-stage prune can keep this Computer when there's no
        # SCCM_AdminUser node (e.g. low-priv runs). The lookup probes
        # smb_site_servers / smb_distribution_points / http_*_points /
        # ldap_sms_providers and returns True if any row matches.
        sccm_infra: Optional[bool] = None
        lookup = getattr(self, "_lookup", None)
        if lookup is not None and hasattr(lookup, "computer_is_sccm_infra"):
            try:
                sccm_infra = lookup.computer_is_sccm_infra(self.object_sid, self.dns_host_name) or None
            except Exception:
                sccm_infra = None
        return SCCMNode(
            kinds=[nk.COMPUTER, nk.BASE],
            properties=ComputerProperties(
                node_id=self.object_sid,
                name=display,
                displayname=display,
                environmentid=self.domain or "",
                samAccountName=self.sam_account_name,
                dNSHostName=self.dns_host_name,
                distinguishedName=self.distinguished_name,
                objectGuid=self.object_guid,
                operatingSystem=self.operating_system,
                operatingSystemVersion=self.operating_system_version,
                enabled=self.enabled,
                servicePrincipalName=self.service_principal_names,
                isDomainPrincipal=True,
                collectionSource=[self.source] if self.source else None,
                Type="Computer",
                domain=self.domain,
                SCCMInfra=sccm_infra,
            ),
        )

    @property
    def edges(self):
        # Computer-only edges (none right now; MemberOf comes from group_membership.py;
        # cross-cutting edges live in models/derived/).
        return iter(())
