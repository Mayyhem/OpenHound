# src/openhound_sccm/models/sccm_client_device.py
"""SCCMClientDevice: converts a node_client_device coalesced row into an SCCMNode.

Each row in node_client_device represents one real SCCM-managed client device
(AdminService or WMI source; is_client=True AND NOT is_obsolete), keyed by
upper(smsid). The `possible` and `ad_domain_sid` columns exist on the row now
but are placeholder values (False/NULL); inferred "possible-client" rows are
added in Task E2.
"""
import logging

from openhound.core.asset import BaseAsset
from pydantic import ConfigDict

from ..graph import SCCMNode, SCCMClientDeviceProperties
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)


class SCCMClientDevice(BaseAsset):
    """One coalesced client device row -> one OpenGraph SCCM_ClientDevice node.

    Fields map directly to the node_client_device columns produced by
    transforms._node_client_device(). Extra columns from the DB are silently
    ignored (extra="ignore") so schema drift doesn't crash convert.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    smsid: str | None = None
    name: str | None = None
    site_code: str | None = None
    resource_id_str: str | None = None
    device_os: str | None = None
    device_os_build: str | None = None
    is_virtual_machine: bool | None = None
    co_managed: bool | None = None
    aad_device_id: str | None = None
    aad_tenant_id: str | None = None
    last_mp_server_name: str | None = None
    primary_user_name: str | None = None
    current_logon_user_name: str | None = None
    ad_last_logon_user_name: str | None = None
    root_site_code: str | None = None
    possible: bool = False
    ad_domain_sid: str | None = None

    @property
    def as_node(self) -> SCCMNode | None:
        """Build the SCCMNode, or return None if the row has no usable smsid."""
        sid = (self.smsid or "").upper() or None
        if not sid:
            logger.warning("SCCMClientDevice: dropping row with no smsid")
            return None

        root = self.root_site_code or ""
        display = f"{self.name}@{self.site_code}" if (self.name and self.site_code) else (self.name or sid)

        return SCCMNode(
            id=sid,
            kinds=[nk.SCCM_CLIENT_DEVICE],
            properties=SCCMClientDeviceProperties(
                name=self.name or sid,
                displayname=display,
                environmentid=root or sid,
                smsid=sid,
                sccm_resource_id=self.resource_id_str,
                site_code=self.site_code,
                device_os=self.device_os,
                device_os_build=self.device_os_build,
                is_virtual_machine=self.is_virtual_machine,
                co_managed=self.co_managed,
                aad_device_id=self.aad_device_id,
                aad_tenant_id=self.aad_tenant_id,
                last_reported_mp_server_name=self.last_mp_server_name,
                primary_user=self.primary_user_name,
                current_logon_user=self.current_logon_user_name,
                ad_last_logon_user=self.ad_last_logon_user_name,
                root_site_code=self.root_site_code,
                possible=self.possible,
                sccm_ad_domain_sid=self.ad_domain_sid,
            ),
        )

    @property
    def edges(self):
        """Client device edges are built in later tasks (D1: HasPrimaryUser, etc.)."""
        return iter(())
