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

    Attributes:
        objectGuid: AD objectGUID.
        groupType: AD groupType bitmask.
        Type: Marker matching CMBP property (always "Group").
        domain: AD domain (NetBIOS or DNS).
    """

    objectGuid: Optional[str] = field(default=None, metadata={"description": "AD objectGUID"})
    groupType: Optional[int] = field(default=None, metadata={"description": "AD groupType bitmask"})
    Type: Optional[str] = field(default="Group", metadata={"description": "Marker matching CMBP property"})
    # PS1-style PascalCase AD properties (see Computer model).
    Domain: Optional[str] = field(default=None, metadata={"description": "AD domain (PS1 PascalCase form)"})
    SamAccountName: Optional[str] = field(default=None, metadata={"description": "sAMAccountName (PS1 PascalCase form)"})
    Enabled: Optional[bool] = field(default=None, metadata={"description": "Whether the AD group is enabled (PS1 PascalCase form; groups don't really have UAC bit but PS1 emits ``Enabled=True``)"})
    IsDomainPrincipal: Optional[bool] = field(default=None, metadata={"description": "Whether this principal is sourced from AD (PS1 PascalCase form)"})
    SCCMResourceIDs: Optional[list[str]] = field(default=None, metadata={"description": "List of ResourceID@SiteCode of users assigned to this group (per-site SMS_R_User fan-out)"})


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
        # SCCMResourceIDs for groups — PS1 emits the ResourceID@SiteCode
        # entries of users whose ``SecurityGroupName`` references this
        # group (so the group's "members" appear in BloodHound queries
        # built against PS1's output). Pulled by matching the group's
        # SamAccountName against ``security_group_name`` in
        # ``adminservice_r_user_security_groups`` (which stores it as
        # ``"<DOMAIN>\<SAM>"``).
        sccm_resource_ids: Optional[list[str]] = None
        try:
            lookup = getattr(self, "_lookup", None)
            if lookup is not None and self.sam_account_name:
                client = lookup.client
                schema = lookup.schema
                needle = f"%\\{self.sam_account_name}"
                rows = client.execute(
                    f"SELECT DISTINCT resource_id, site_code "
                    f"FROM {schema}.adminservice_r_user_security_groups "
                    f"WHERE LOWER(security_group_name) LIKE LOWER(?) "
                    f"  AND resource_id IS NOT NULL AND site_code IS NOT NULL "
                    f"ORDER BY site_code, resource_id",
                    [needle],
                ).fetchall()
                if rows:
                    sccm_resource_ids = [f"{rid}@{sc}" for rid, sc in rows]
        except Exception:
            pass

        return SCCMNode(
            kinds=[nk.GROUP, nk.BASE],
            properties=GroupProperties(
                node_id=self.object_sid,
                name=display,
                displayname=display,
                environmentid=self.domain or None,
                distinguishedName=self.distinguished_name,
                objectGuid=self.object_guid,
                groupType=self.group_type,
                collectionSource=["LDAP"],
                Type="Group",
                # PS1-style PascalCase AD-property casing.
                Domain=self.domain,
                SamAccountName=self.sam_account_name,
                Enabled=True,
                IsDomainPrincipal=True,
                SCCMResourceIDs=sccm_resource_ids,
            ),
        )

    @property
    def edges(self):
        # Group-only edges (none right now; MemberOf edges come from
        # models/group_membership.py; cross-cutting edges live in models/derived/).
        return iter(())
