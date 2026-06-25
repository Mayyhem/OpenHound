"""Base OpenGraph node/edge dataclasses + shared helpers for the SCCM collector.

Concrete node models (models/*.py) build these in their `as_node`. `SCCMNode`
supplies the `id` directly (we already know the SID / site code), unlike the
framework's UUID-deriving base. `domain_environment_id` derives the AD-domain SID
used as `environmentid` for Base AD nodes (spec §2 "Root/environment node").
"""
import re
from dataclasses import dataclass, field

from openhound.core.models.entries_dataclass import EdgeProperties, Node, NodeProperties

# A domain SID is the `S-1-5-21-X-Y-Z` prefix; an account SID appends `-RID`.
_DOMAIN_SID = re.compile(r"^(S-1-5-21(?:-\d+){3})-\d+$")


def domain_environment_id(sid: str, fallback_domain_sid: str | None = None) -> str | None:
    """Return the AD-domain SID to use as `environmentid` for a Base AD node.

    - Normal account SID `S-1-5-21-X-Y-Z-RID` -> `S-1-5-21-X-Y-Z`.
    - Well-known/builtin SID (no `S-1-5-21` domain part, e.g. `S-1-5-32-544`,
      `S-1-5-11`) -> `fallback_domain_sid` (the domain SID known from the record
      that produced this principal; SharpHound-style per-domain qualification).
    - `None` if neither applies; caller drops the node and logs.
    """
    if not sid:
        return None
    m = _DOMAIN_SID.match(sid.upper())
    if m:
        return m.group(1)
    return fallback_domain_sid


# Edge kind -> the kind to give a synthesised stub when the edge's END id has no node.
# Only edges whose end is a user/group SID (or a device smsid) appear here; ambiguous
# ends (user OR group) get "Base". See Stage 2 graph-integrity decision (2026-06-23).
BACKFILL_END_KIND: dict[str, str] = {
    "SCCM_HasPrimaryUser": "User",
    "SCCM_HasCurrentUser": "User",
    "SCCM_HasADLastLogonUser": "User",
    "HasSession": "User",
    "MemberOf": "Group",
    "SCCM_HasMember": "Base",
    "SCCM_HasStoredAccount": "Base",
}


@dataclass
class SCCMEdgeProperties(EdgeProperties):
    collection_source: list[str] = field(default_factory=list, kw_only=True)


@dataclass
class SCCMNode(Node):
    """Concrete SCCM node: `id` is supplied directly (no UUID derivation)."""
    id: str = ""

    def __post_init__(self):
        # id is set by the caller; nothing to derive. (Node declares this abstract.)
        return


@dataclass
class ComputerProperties(NodeProperties):
    collection_source: list[str] = field(default_factory=list, kw_only=True)
    sccm_site_system_roles: list[str] = field(default_factory=list, kw_only=True)
    sccm_infra: bool = field(default=False, kw_only=True)
    sccm_resource_ids: list[str] = field(default_factory=list, kw_only=True)
    sccm_client_device_identifier: str | None = field(default=None, kw_only=True)
    dnshostname: str | None = field(default=None, kw_only=True)
    sam_account_name: str | None = field(default=None, kw_only=True)
    distinguished_name: str | None = field(default=None, kw_only=True)
    smb_signing_required: bool | None = field(default=None, kw_only=True)
    sccm_has_client_remote_control_spn: bool = field(default=False, kw_only=True)
    network_boot_server: bool = field(default=False, kw_only=True)
    disable_loopback_check: bool | None = field(default=None, kw_only=True)
    restrict_receiving_ntlm_traffic: str | None = field(default=None, kw_only=True)
    sccm_client_certificate_required: bool | None = field(default=None, kw_only=True)
    sccm_hosts_content_library: bool | None = field(default=None, kw_only=True)
    sccm_is_pxe_support_enabled: bool | None = field(default=None, kw_only=True)


@dataclass
class UserProperties(NodeProperties):
    collection_source: list[str] = field(default_factory=list, kw_only=True)
    sccm_resource_ids: list[str] = field(default_factory=list, kw_only=True)
    sccm_infra: bool = field(default=False, kw_only=True)
    stored_in_sccm_site: str | None = field(default=None, kw_only=True)
    distinguished_name: str | None = field(default=None, kw_only=True)
    user_principal_name: str | None = field(default=None, kw_only=True)


@dataclass
class GroupProperties(NodeProperties):
    collection_source: list[str] = field(default_factory=list, kw_only=True)
    sccm_infra: bool = field(default=False, kw_only=True)
    sccm_resource_ids: list[str] = field(default_factory=list, kw_only=True)


@dataclass
class SCCMSiteProperties(NodeProperties):
    collection_source: list[str] = field(default_factory=list, kw_only=True)
    site_code: str | None = field(default=None, kw_only=True)
    parent_site_code: str | None = field(default=None, kw_only=True)
    root_site_code: str | None = field(default=None, kw_only=True)
    site_type: str | None = field(default=None, kw_only=True)
    site_guid: str | None = field(default=None, kw_only=True)
    site_server_name: str | None = field(default=None, kw_only=True)
    sql_server_name: str | None = field(default=None, kw_only=True)
    sql_database_name: str | None = field(default=None, kw_only=True)
    version: str | None = field(default=None, kw_only=True)
    build_number: str | None = field(default=None, kw_only=True)
    install_dir: str | None = field(default=None, kw_only=True)
    # Stage 3 C5 additions — CMBP parity.
    sql_service_account_name: str | None = field(default=None, kw_only=True)
    distinguished_name: str | None = field(default=None, kw_only=True)
    source_forest: str | None = field(default=None, kw_only=True)
    admin_users: list[str] = field(default_factory=list, kw_only=True)
    stored_accounts: list[str] = field(default_factory=list, kw_only=True)
    sccm_infra: bool = field(default=True, kw_only=True)


@dataclass
class SCCMCollectionProperties(NodeProperties):
    collection_source: list[str] = field(default_factory=list, kw_only=True)
    sccm_collection_id: str | None = field(default=None, kw_only=True)
    sccm_collection_type: str | None = field(default=None, kw_only=True)   # "Other"/"User"/"Device"
    member_count: int | None = field(default=None, kw_only=True)
    comment: str | None = field(default=None, kw_only=True)
    is_built_in: bool | None = field(default=None, kw_only=True)
    limit_to_collection_id: str | None = field(default=None, kw_only=True)
    limit_to_collection_name: str | None = field(default=None, kw_only=True)
    collection_variables_count: int | None = field(default=None, kw_only=True)
    root_site_code: str | None = field(default=None, kw_only=True)
    source_site_code: str | None = field(default=None, kw_only=True)
    last_change_time: str | None = field(default=None, kw_only=True)
    last_member_change_time: str | None = field(default=None, kw_only=True)
    members: list[str] = field(default_factory=list, kw_only=True)
    sccm_infra: bool = field(default=True, kw_only=True)


@dataclass
class SCCMAdminUserProperties(NodeProperties):
    collection_source: list[str] = field(default_factory=list, kw_only=True)
    sccm_admin_id: str | None = field(default=None, kw_only=True)
    admin_sid: str | None = field(default=None, kw_only=True)
    distinguished_name: str | None = field(default=None, kw_only=True)
    is_group: bool | None = field(default=None, kw_only=True)
    account_type: int | None = field(default=None, kw_only=True)
    root_site_code: str | None = field(default=None, kw_only=True)
    # Audit fields from ADMIN_COLUMNS (CMBP parity, Stage 3 C3).
    display_name: str | None = field(default=None, kw_only=True)
    source_site_code: str | None = field(default=None, kw_only=True)
    created_by: str | None = field(default=None, kw_only=True)
    created_date: str | None = field(default=None, kw_only=True)
    last_modified_by: str | None = field(default=None, kw_only=True)
    last_modified_date: str | None = field(default=None, kw_only=True)
    # Assignment lists: raw role ids, resolved role node ids, resolved collection node ids.
    collection_ids: list[str] = field(default_factory=list, kw_only=True)
    role_ids: list[str] = field(default_factory=list, kw_only=True)
    member_of: list[str] = field(default_factory=list, kw_only=True)
    sccm_infra: bool = field(default=True, kw_only=True)


@dataclass
class SCCMSecurityRoleProperties(NodeProperties):
    collection_source: list[str] = field(default_factory=list, kw_only=True)
    sccm_role_id: str | None = field(default=None, kw_only=True)
    sccm_role_name: str | None = field(default=None, kw_only=True)
    role_description: str | None = field(default=None, kw_only=True)
    is_built_in: bool | None = field(default=None, kw_only=True)
    is_sec_admin_role: bool | None = field(default=None, kw_only=True)
    copied_from_id: str | None = field(default=None, kw_only=True)
    number_of_admins: int | None = field(default=None, kw_only=True)
    operations: list[str] = field(default_factory=list, kw_only=True)
    root_site_code: str | None = field(default=None, kw_only=True)
    # Audit fields from ROLE_COLUMNS (CMBP parity, Stage 3 C2).
    site_code: str | None = field(default=None, kw_only=True)
    created_by: str | None = field(default=None, kw_only=True)
    created_date: str | None = field(default=None, kw_only=True)
    last_modified_by: str | None = field(default=None, kw_only=True)
    last_modified_date: str | None = field(default=None, kw_only=True)
    # Members: upper(logon_name)@root for each admin assigned to this role.
    members: list[str] = field(default_factory=list, kw_only=True)
    sccm_infra: bool = field(default=True, kw_only=True)


@dataclass
class SCCMClientDeviceProperties(NodeProperties):
    collection_source: list[str] = field(default_factory=list, kw_only=True)
    smsid: str | None = field(default=None, kw_only=True)
    sccm_resource_id: str | None = field(default=None, kw_only=True)
    site_code: str | None = field(default=None, kw_only=True)
    device_os: str | None = field(default=None, kw_only=True)
    device_os_build: str | None = field(default=None, kw_only=True)
    is_virtual_machine: bool | None = field(default=None, kw_only=True)
    co_managed: bool | None = field(default=None, kw_only=True)
    aad_device_id: str | None = field(default=None, kw_only=True)
    aad_tenant_id: str | None = field(default=None, kw_only=True)
    last_reported_mp_server_name: str | None = field(default=None, kw_only=True)
    primary_user: str | None = field(default=None, kw_only=True)
    current_logon_user: str | None = field(default=None, kw_only=True)
    ad_last_logon_user: str | None = field(default=None, kw_only=True)
    root_site_code: str | None = field(default=None, kw_only=True)
    possible: bool = field(default=False, kw_only=True)
    sccm_ad_domain_sid: str | None = field(default=None, kw_only=True)
    # Telemetry scalars — Stage 3 C4 (CMBP parity).
    ad_last_logon_time: str | None = field(default=None, kw_only=True)
    ad_last_logon_user_domain: str | None = field(default=None, kw_only=True)
    source_site_code: str | None = field(default=None, kw_only=True)
    last_active_time: str | None = field(default=None, kw_only=True)
    last_online_time: str | None = field(default=None, kw_only=True)
    last_offline_time: str | None = field(default=None, kw_only=True)
    # Resolved SID fields — Stage 3 C4 (CMBP ps1:7227/7232/7245/7248).
    primary_user_sid: str | None = field(default=None, kw_only=True)
    current_logon_user_sid: str | None = field(default=None, kw_only=True)
    ad_last_logon_user_sid: str | None = field(default=None, kw_only=True)
    last_reported_mp_server_sid: str | None = field(default=None, kw_only=True)
    # Collection membership lists — Stage 3 C4 (CMBP ps1:7228-7229).
    collection_ids: list[str] = field(default_factory=list, kw_only=True)
    collection_names: list[str] = field(default_factory=list, kw_only=True)
    sccm_infra: bool = field(default=False, kw_only=True)
