"""Base OpenGraph node/edge dataclasses + shared helpers for the SCCM collector.

Concrete node models (models/*.py) build these in their `as_node`. `SCCMNode`
supplies the `id` directly (we already know the SID / site code), unlike the
framework's UUID-deriving base. `domain_environment_id` derives the AD-domain SID
used as `environmentid` for Base AD nodes (spec §2 "Root/environment node").
"""
import re
from dataclasses import dataclass, field

from openhound.core.models.entries_dataclass import Node, NodeProperties

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
    sccm_infra: bool = field(default=True, kw_only=True)
