"""User node model.

Reads from the ``ldap_users`` DLT table. Yields one User node per AD user
account, with kinds=[User, Base] to match ConfigManBearPig output.

Edges emitted from this model are limited to relationships that derive *only*
from a single user's own attributes. Cross-cutting edges (MemberOf,
HasSession, etc.) live in ``models/group_membership.py`` and ``models/derived/``
and consume materialised SQL views.
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
class UserProperties(SCCMNodeProperties):
    """Properties carried on every User node.

    Field names match the camelCase used by ConfigManBearPig's output so the
    test runner's wildcard patterns match unchanged.

    Attributes:
        userPrincipalName: AD userPrincipalName.
        objectGuid: AD objectGUID.
        servicePrincipalName: AD SPNs.
        Type: Marker matching CMBP property (always "User").
        domain: AD domain (NetBIOS or DNS).
        SCCMInfra: True when this User appears in SMS_R_User (i.e. AdminService discovered them).
    """

    UserPrincipalName: Optional[str] = field(default=None, metadata={"description": "AD userPrincipalName (PS1 PascalCase form)"})
    objectGuid: Optional[str] = field(default=None, metadata={"description": "AD objectGUID"})
    servicePrincipalName: Optional[list[str]] = field(default=None, metadata={"description": "AD SPNs"})
    Type: Optional[str] = field(default="User", metadata={"description": "Marker matching CMBP property"})
    SCCMInfra: Optional[bool] = field(default=None, metadata={"description": "True when this User appears in SMS_R_User (i.e. AdminService discovered them)"})
    # PS1-style PascalCase AD properties (see Computer model for rationale).
    Domain: Optional[str] = field(default=None, metadata={"description": "AD domain (PS1 PascalCase form)"})
    SamAccountName: Optional[str] = field(default=None, metadata={"description": "sAMAccountName (PS1 PascalCase form)"})
    Enabled: Optional[bool] = field(default=None, metadata={"description": "Whether the AD account is enabled (PS1 PascalCase form)"})
    IsDomainPrincipal: Optional[bool] = field(default=None, metadata={"description": "Whether this principal is sourced from AD (PS1 PascalCase form)"})
    SCCMResourceIDs: Optional[list[str]] = field(default=None, metadata={"description": "List of ResourceID@SiteCode entries for the user (SMS_R_User per-site fan-out)"})
    storedInSCCMSite: Optional[str] = field(default=None, metadata={"description": "SCCM_Site id where this user is a stored NAA / SMS_SCI_Reserved account"})


@app.asset(
    description="AD User node",
    node=NodeDef(
        kind=nk.USER,
        description="Active Directory user account discovered via LDAP",
        icon="user",
        properties=UserProperties,
    ),
    edges=[],
)
class User(BaseAsset):
    """User asset — one row per AD user account from ``ldap_users``."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    # Raw fields from ldap_users JSONL
    object_sid: str
    object_guid: Optional[str] = None
    sam_account_name: Optional[str] = None
    user_principal_name: Optional[str] = None
    name: Optional[str] = None
    display_name: Optional[str] = None
    distinguished_name: Optional[str] = None
    enabled: Optional[bool] = None
    member_of_dns: Optional[list[str]] = None
    primary_group_id: Optional[int] = None
    service_principal_names: Optional[list[str]] = None
    domain: Optional[str] = None

    @property
    def as_node(self) -> SCCMNode:
        display = self.display_name or self.sam_account_name or self.object_sid
        # Tag SCCMInfra=True when this User appears in
        # adminservice_r_user_security_groups (i.e. SMS_R_User found
        # them). Drives the output-stage prune so AdminService-known
        # users keep their MemberOf edges even when no other anchor
        # path pulls them in.
        sccm_infra = self._lookup.user_is_sccm_infra(self.object_sid) or None

        # SCCMResourceIDs — list of ResourceID@SiteCode for this user
        # across every SMS Provider that surfaced them. Pulled from
        # ``adminservice_r_user_security_groups`` (a many-row table —
        # one row per group membership per site, so we DISTINCT on the
        # (resource_id, site_code) pair).
        sccm_resource_ids: Optional[list[str]] = None
        # storedInSCCMSite — when this user has a row in
        # ``adminservice_reserved_accounts`` (i.e. is a stored NAA /
        # SMS_SCI_Reserved account), PS1 sets this to the SCCM_Site id
        # the account is stored at.
        stored_in_site: Optional[str] = None
        try:
            client = self._lookup.client
            schema = self._lookup.schema
            rows = client.execute(
                f"SELECT DISTINCT resource_id, site_code "
                f"FROM {schema}.adminservice_r_user_security_groups "
                f"WHERE user_sid = ? "
                f"  AND resource_id IS NOT NULL AND site_code IS NOT NULL "
                f"ORDER BY site_code, resource_id",
                [self.object_sid],
            ).fetchall()
            if rows:
                sccm_resource_ids = [f"{rid}@{sc}" for rid, sc in rows]
        except Exception:
            pass
        # ``account_username`` in adminservice_reserved_accounts is
        # ``DOMAIN\sam`` form. Match against the user's
        # ``<domain prefix>\<sam>`` reconstruction.
        if self.sam_account_name and self.domain:
            domain_prefix = self.domain.split(".", 1)[0].lower()
            account_needle = f"{domain_prefix}\\{self.sam_account_name}".lower()
            try:
                row = client.execute(
                    f"SELECT site_code FROM {schema}.adminservice_reserved_accounts "
                    f"WHERE LOWER(account_username) = ? "
                    f"LIMIT 1",
                    [account_needle],
                ).fetchone()
                if row and row[0]:
                    stored_in_site = row[0]
            except Exception:
                pass
        # collectionSource — LDAP plus any extras from
        # ldap_system_management_acl when this user holds GenericAll on
        # the System Management container (PS1: ConfigManBearPig.ps1:3502).
        collection_sources: list[str] = ["LDAP"]
        if self._lookup.has_system_management_acl(self.object_sid):
            collection_sources.append("LDAP-GenericAllSystemManagement")

        props = UserProperties(
            node_id=self.object_sid,
            name=display,
            displayname=display,
            environmentid=self.domain or None,
            distinguishedName=self.distinguished_name,
            objectGuid=self.object_guid,
            servicePrincipalName=self.service_principal_names,
            collectionSource=collection_sources,
            Type="User",
            # PS1-style PascalCase AD-property casing.
            Domain=self.domain,
            SamAccountName=self.sam_account_name,
            Enabled=self.enabled,
            IsDomainPrincipal=True,
            UserPrincipalName=self.user_principal_name,
            SCCMResourceIDs=sccm_resource_ids,
            storedInSCCMSite=stored_in_site,
            SCCMInfra=sccm_infra,
        )
        trace_node_with_properties(nk.USER, self.object_sid, display, props)
        return SCCMNode(kinds=[nk.USER, nk.BASE], properties=props)

    @property
    def edges(self):
        # User-only edges (none right now; MemberOf comes from group_membership.py;
        # cross-cutting edges live in models/derived/).
        return iter(())
