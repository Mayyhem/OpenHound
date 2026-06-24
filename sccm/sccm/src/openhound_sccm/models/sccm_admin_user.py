# src/openhound_sccm/models/sccm_admin_user.py
"""SCCMAdminUser: converts a node_admin_user coalesced row into an SCCMNode.

Each row in the node_admin_user preproc table represents one SCCM RBAC admin
object (keyed by upper(logon_name)). This model reads those rows and emits an
SCCM_AdminUser node with id = '<UPPER_LOGON_NAME>@<root_site_code>'.

Note: the node id uses the uppercased logon_name while properties.name keeps
the original case, matching the casing rule in the node_admin_user coalesce.
"""
import logging

from openhound.core.asset import BaseAsset
from pydantic import ConfigDict

from ..graph import SCCMNode, SCCMAdminUserProperties
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)


class SCCMAdminUser(BaseAsset):
    """One coalesced admin user row -> one OpenGraph SCCM_AdminUser node.

    Fields map directly to the node_admin_user columns produced by
    transforms._node_admin_user(). Extra columns from the DB are silently
    ignored (extra="ignore") so schema drift doesn't crash convert.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    logon_name: str | None = None
    admin_id: str | None = None
    admin_sid: str | None = None
    display_name: str | None = None
    distinguished_name: str | None = None
    is_group: bool | None = None
    account_type: int | None = None
    root_site_code: str | None = None

    @property
    def as_node(self) -> SCCMNode | None:
        """Build the SCCMNode, or return None if the row has no usable logon_name."""
        logon = self.logon_name or ""
        key = logon.upper() or None
        if not key:
            logger.warning("SCCMAdminUser: dropping row with no logon_name")
            return None

        root = self.root_site_code or ""
        node_id = f"{key}@{root}" if root else key
        display = self.display_name or logon or node_id

        return SCCMNode(
            id=node_id,
            kinds=[nk.SCCM_ADMIN_USER],
            properties=SCCMAdminUserProperties(
                name=logon or node_id,
                displayname=display,
                environmentid=root or key,
                sccm_admin_id=self.admin_id,
                admin_sid=self.admin_sid,
                distinguished_name=self.distinguished_name,
                is_group=self.is_group,
                account_type=self.account_type,
                root_site_code=self.root_site_code,
            ),
        )

    @property
    def edges(self):
        """Admin user membership edges are built in a later task (C4/C5)."""
        return iter(())
