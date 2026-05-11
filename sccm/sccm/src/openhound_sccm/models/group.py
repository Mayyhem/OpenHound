"""Group node model.

Reads from the ``ldap_groups`` DLT table. Yields one Group node per AD group,
with kinds=[Group, Base] to match ConfigManBearPig output.

Edges emitted from this model are limited to relationships that derive *only*
from a single group's own attributes. The actual ``MemberOf`` edges are emitted
from ``models/group_membership.py`` which consumes the
``ldap_group_memberships`` transformer table.
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
class GroupProperties(SCCMNodeProperties):
    """Properties carried on every Group node.

    Field names match the camelCase used by ConfigManBearPig's output so the
    test runner's wildcard patterns match unchanged.
    """

    objectGuid: Optional[str] = field(default=None, metadata={"description": "AD objectGUID"})
    groupType: Optional[int] = field(default=None, metadata={"description": "AD groupType bitmask"})
    Type: Optional[str] = field(default="Group", metadata={"description": "Marker matching CMBP property"})
    domain: Optional[str] = field(default=None, metadata={"description": "AD domain (NetBIOS or DNS)"})


@app.asset(
    description="AD Group node",
    node=NodeDef(
        kind=nk.GROUP,
        description="Active Directory group discovered via LDAP",
        icon="users",
        properties=GroupProperties,
    ),
    edges=[],
)
class Group(BaseAsset):
    """Group asset — one row per AD group from ``ldap_groups``."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    # Raw fields from ldap_groups JSONL
    object_sid: str
    object_guid: Optional[str] = None
    sam_account_name: Optional[str] = None
    name: Optional[str] = None
    distinguished_name: Optional[str] = None
    group_type: Optional[int] = None
    member: Optional[list[str]] = None
    domain: Optional[str] = None

    @property
    def as_node(self) -> SCCMNode:
        display = self.name or self.sam_account_name or self.object_sid
        return SCCMNode(
            kinds=[nk.GROUP, nk.BASE],
            properties=GroupProperties(
                node_id=self.object_sid,
                name=display,
                displayname=display,
                environmentid=self.domain or "",
                samAccountName=self.sam_account_name,
                distinguishedName=self.distinguished_name,
                objectGuid=self.object_guid,
                groupType=self.group_type,
                isDomainPrincipal=True,
                collectionSource=["LDAP"],
                Type="Group",
                domain=self.domain,
            ),
        )

    @property
    def edges(self):
        # Group-only edges (none right now; MemberOf edges come from
        # models/group_membership.py; cross-cutting edges live in models/derived/).
        return iter(())
