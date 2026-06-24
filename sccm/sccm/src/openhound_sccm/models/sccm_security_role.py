# src/openhound_sccm/models/sccm_security_role.py
"""SCCMSecurityRole: converts a node_security_role coalesced row into an SCCMNode.

Each row in the node_security_role preproc table represents one SCCM security
role (keyed by role_id). This model reads those rows and emits an
SCCM_SecurityRole node with id = '<ROLE_ID>@<root_site_code>'.
"""
import logging

from openhound.core.asset import BaseAsset
from pydantic import ConfigDict

from ..graph import SCCMNode, SCCMSecurityRoleProperties
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)


class SCCMSecurityRole(BaseAsset):
    """One coalesced security role row -> one OpenGraph SCCM_SecurityRole node.

    Fields map directly to the node_security_role columns produced by
    transforms._node_security_role(). Extra columns from the DB are silently
    ignored (extra="ignore") so schema drift doesn't crash convert.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    role_id: str | None = None
    role_name: str | None = None
    role_description: str | None = None
    is_built_in: bool | None = None
    is_sec_admin_role: bool | None = None
    copied_from_id: str | None = None
    number_of_admins: int | None = None
    operations: list[str] = []
    root_site_code: str | None = None

    @property
    def as_node(self) -> SCCMNode | None:
        """Build the SCCMNode, or return None if the row has no usable role_id."""
        rid = (self.role_id or "").upper() or None
        if not rid:
            logger.warning("SCCMSecurityRole: dropping row with no role_id")
            return None

        root = self.root_site_code or ""
        node_id = f"{rid}@{root}" if root else rid
        display = f"{self.role_name}@{root}" if (self.role_name and root) else (self.role_name or node_id)

        return SCCMNode(
            id=node_id,
            kinds=[nk.SCCM_SECURITY_ROLE],
            properties=SCCMSecurityRoleProperties(
                name=self.role_name or node_id,
                displayname=display,
                environmentid=root or rid,
                sccm_role_id=rid,
                sccm_role_name=self.role_name,
                role_description=self.role_description,
                is_built_in=self.is_built_in,
                is_sec_admin_role=self.is_sec_admin_role,
                copied_from_id=self.copied_from_id,
                number_of_admins=self.number_of_admins,
                operations=list(self.operations or []),
                root_site_code=self.root_site_code,
            ),
        )

    @property
    def edges(self):
        """Security role membership edges are built in a later task."""
        return iter(())
