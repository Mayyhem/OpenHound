# src/openhound_sccm/models/computer.py
"""ComputerNode: converts a node_computer coalesced row into an SCCMNode.

Each row in the node_computer preproc table represents one unique computer
(keyed by SID). This model reads those rows, resolves the AD domain SID for
the environmentid, and emits a Computer+Base node with all SCCM-specific
properties populated.
"""
import logging

from openhound.core.asset import BaseAsset
from pydantic import ConfigDict

from ..graph import ComputerProperties, SCCMNode, domain_environment_id
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)


class ComputerNode(BaseAsset):
    """One coalesced computer row -> one OpenGraph Computer+Base node.

    Fields map directly to the node_computer columns produced by
    transforms._node_computer(). Extra columns from the DB are silently
    ignored (extra="ignore") so schema drift doesn't crash convert.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    sid: str | None = None
    name: str | None = None
    dnshostname: str | None = None
    sam_account_name: str | None = None
    site_system_roles: list[str] = []
    resource_ids: list[str] = []
    sccm_infra: bool = False
    sms_unique_identifier: str | None = None
    smb_signing_required: bool | None = None
    sccm_has_client_remote_control_spn: bool = False
    network_boot_server: bool = False
    disable_loopback_check: bool | None = None
    restrict_receiving_ntlm_traffic: str | None = None
    sccm_client_certificate_required: bool | None = None
    sccm_hosts_content_library: bool | None = None
    sccm_is_pxe_support_enabled: bool | None = None

    @property
    def as_node(self) -> SCCMNode | None:
        """Build the SCCMNode, or return None if the row has no usable SID."""
        sid = (self.sid or "").upper() or None
        if not sid:
            # No SID means we have no merge key; drop the row.
            logger.warning(
                "ComputerNode: dropping row with no SID (name=%r)", self.name
            )
            return None

        env = domain_environment_id(sid)
        if env is None:
            # Non-domain SID with no fallback available (builtin or well-known);
            # these are filtered out at the node_computer coalesce level in practice
            # but we guard here too.
            logger.warning(
                "ComputerNode: dropping SID %r — not a domain SID and no fallback "
                "domain SID available",
                sid,
            )
            return None

        display = self.name or self.dnshostname or sid

        return SCCMNode(
            id=sid,
            kinds=[nk.COMPUTER, nk.BASE],
            properties=ComputerProperties(
                name=self.name or display,
                displayname=display,
                environmentid=env,
                collection_source=[],
                sccm_site_system_roles=self.site_system_roles,
                sccm_infra=self.sccm_infra,
                sccm_resource_ids=self.resource_ids,
                sccm_client_device_identifier=self.sms_unique_identifier,
                smb_signing_required=self.smb_signing_required,
                sccm_has_client_remote_control_spn=self.sccm_has_client_remote_control_spn,
                network_boot_server=self.network_boot_server,
                disable_loopback_check=self.disable_loopback_check,
                restrict_receiving_ntlm_traffic=self.restrict_receiving_ntlm_traffic,
                sccm_client_certificate_required=self.sccm_client_certificate_required,
                sccm_hosts_content_library=self.sccm_hosts_content_library,
                sccm_is_pxe_support_enabled=self.sccm_is_pxe_support_enabled,
            ),
        )

    @property
    def edges(self):
        """Computer nodes have no edges in Stage 1."""
        return iter(())
