from dataclasses import dataclass, field
from openhound.core.models.entries_dataclass import EdgeProperties
from openhound.core.models.entries_dataclass import Node as BaseNode
from openhound.core.models.entries_dataclass import NodeProperties as BaseProperties


@dataclass
class SCCMNodeProperties(BaseProperties):
    """Common properties carried by every node emitted by this extension.

    The `node_id` field is the canonical identifier used to construct the OpenGraph
    `id`. For AD-derived nodes this is the SID; for SCCM_Site it's the site code; for
    MSSQL_Server it's `<HOSTNAME>:1433`; for SCCM_ClientDevice it's `GUID:<resource-guid>`.

    Attributes:
        node_id: Stable identifier used as the OpenGraph node id.
        collectionSource: List of collection sources that contributed to this node.
    """
    node_id: str = field(metadata={"description": "Stable identifier used as the OpenGraph node id."})


@dataclass
class SCCMNode(BaseNode):
    """OpenGraph node for SCCM-extension entities. ``id`` is derived from ``properties.node_id``."""
    properties: SCCMNodeProperties
    kinds: list[str]
    id: str = field(init=False)

    def __post_init__(self):
        self.id = self.properties.node_id


@dataclass
class SCCMEdgeProperties(EdgeProperties):
    """Extends EdgeProperties with optional composition query and reason."""

    query_composition: str | None = None
    reason: str | None = None
