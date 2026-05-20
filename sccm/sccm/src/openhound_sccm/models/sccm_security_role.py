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
from openhound_sccm.log_context import trace_node
from openhound_sccm.main import app


@dataclass
class SCCMSecurityRoleProperties(SCCMNodeProperties):
    """Properties carried on every SCCM_SecurityRole node."""

    roleID: Optional[str] = field(default=None, metadata={"description": "RoleID from SMS_Role"})
    roleName: Optional[str] = field(default=None, metadata={"description": "RoleName from SMS_Role"})
    description: Optional[str] = field(default=None, metadata={"description": "RoleDescription from SMS_Role (alias kept for backwards compatibility)"})
    roleDescription: Optional[str] = field(default=None, metadata={"description": "RoleDescription from SMS_Role (PS1 canonical name)"})
    copiedFromID: Optional[str] = field(default=None, metadata={"description": "Parent role ID when this role was cloned from a built-in"})
    createdBy: Optional[str] = field(default=None, metadata={"description": "DOMAIN\\sam of the admin who created the role"})
    createdDate: Optional[str] = field(default=None, metadata={"description": "ISO timestamp the role was created"})
    lastModifiedBy: Optional[str] = field(default=None, metadata={"description": "DOMAIN\\sam of the admin who last modified the role"})
    lastModifiedDate: Optional[str] = field(default=None, metadata={"description": "ISO timestamp of the last role modification"})
    members: Optional[list[str]] = field(default=None, metadata={"description": "List of SCCM_AdminUser node ids assigned this role (PS1 form)"})
    isBuiltIn: Optional[bool] = field(default=None, metadata={"description": "True for roles shipped by SCCM (id starts with 'SMS'), absent for customer-defined roles"})
    isSecAdminRole: Optional[bool] = field(default=None, metadata={"description": "True for the Full Administrator role specifically"})
    numberOfAdmins: Optional[int] = field(default=None, metadata={"description": "Count of SCCM admins assigned this role"})
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
    copied_from_id: Optional[str] = None
    created_by: Optional[str] = None
    created_date: Optional[str] = None
    last_modified_by: Optional[str] = None
    last_modified_date: Optional[str] = None
    domain: Optional[str] = None
    source: Optional[str] = "AdminService-SMS_Role"

    @property
    def as_node(self) -> SCCMNode:
        # PS1 polls every SMS Provider and tags each role with that
        # provider's site code, so the same SR id shows up as <id>@CAS and
        # <id>@PS1 as two distinct nodes. Keep that split by using the raw
        # site_code in the node id; rootSiteCode still resolves to the
        # hierarchy root.
        site_for_id = self.site_code or ""
        root_site_code = (
            self._lookup.hierarchy_root(self.site_code) if self.site_code else None
        ) or self.site_code or ""

        node_id = f"{self.role_id}@{site_for_id}"
        trace_node(nk.SCCM_SECURITY_ROLE, node_id, self.role_name)
        # PS1 emits ``name`` = bare role_name (no @site suffix). Match that
        # so BloodHound queries against ``r.name = 'Full Administrator'`` work.
        display = self.role_name or node_id

        # ``members`` — list of SCCM_AdminUser node ids assigned this
        # role. ``adminservice_admins.role_names`` is stored as a JSON
        # string list (DLT serialises nested lists that way), so we
        # parse it with ``json_extract`` + ``json_array_length`` and
        # match each element against the role name. Each match becomes
        # a ``<logonName_lower>@<site>`` AdminUser id.
        members: Optional[list[str]] = None
        if self.role_name:
            try:
                client = self._lookup.client
                schema = self._lookup.schema
                rows = client.execute(
                    f"SELECT DISTINCT LOWER(logon_name), site_code "
                    f"FROM {schema}.adminservice_admins, "
                    f"     UNNEST(CAST(role_names AS VARCHAR[])) AS t(role_name) "
                    f"WHERE role_name = ? AND site_code = ? "
                    f"ORDER BY 1",
                    [self.role_name, self.site_code],
                ).fetchall()
                if rows:
                    members = [f"{ln}@{sc}" for ln, sc in rows]
            except Exception:
                # CAST may fail if role_names is already a list or stored
                # in a different shape; fall back to a JSON-string LIKE
                # match. Brittle but adequate for unusual schemas.
                try:
                    needle = f'"{self.role_name}"'
                    rows = client.execute(
                        f"SELECT DISTINCT LOWER(logon_name), site_code "
                        f"FROM {schema}.adminservice_admins "
                        f"WHERE CAST(role_names AS VARCHAR) LIKE '%' || ? || '%' "
                        f"  AND site_code = ? "
                        f"ORDER BY 1",
                        [needle, self.site_code],
                    ).fetchall()
                    if rows:
                        members = [f"{ln}@{sc}" for ln, sc in rows]
                except Exception:
                    pass

        # ``isBuiltIn`` — PS1 only emits ``True`` for roles whose ID
        # starts with ``"SMS"`` (those are the SCCM-shipped defaults
        # like ``SMS0001R`` Full Administrator). Custom roles get a
        # site-code-prefixed id (``PS100001``) and leave the property
        # absent in PS1's output. ``isSecAdminRole`` is PS1's
        # explicit flag for the Full Administrator role (id ``SMS0001R``).
        # ``numberOfAdmins`` is the count of members; emit as ``None``
        # rather than ``0`` to match PS1's "no admins" representation.
        is_built_in: Optional[bool] = (
            True if (self.role_id or "").upper().startswith("SMS") else None
        )
        is_sec_admin_role: Optional[bool] = (
            True if (self.role_id or "").upper() == "SMS0001R" else None
        )
        number_of_admins: Optional[int] = len(members) if members else None

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
                copiedFromID=self.copied_from_id or None,
                createdBy=self.created_by or None,
                createdDate=self.created_date or None,
                lastModifiedBy=self.last_modified_by or None,
                lastModifiedDate=self.last_modified_date or None,
                members=members,
                isBuiltIn=is_built_in,
                isSecAdminRole=is_sec_admin_role,
                numberOfAdmins=number_of_admins,
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
