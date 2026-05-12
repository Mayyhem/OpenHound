from dataclasses import dataclass, field
from openhound.core.models.entries_dataclass import EdgeProperties
from openhound.core.models.entries_dataclass import Node as BaseNode
from openhound.core.models.entries_dataclass import NodeProperties as BaseProperties


@dataclass
class mssqlNodeProperties(BaseProperties):
    """Extends the base properties with additional fields

    Attributes:
        example_of_required_id: An example field representing a required identifier for the node, used to set the node's ID.
    """
    example_of_required_id: str


@dataclass
class mssqlNode(BaseNode):
    properties: mssqlNodeProperties  # type: ignore[assignment]
    kinds: list[str]
    id: str = field(init=False)

    def __post_init__(self):
        # Use the resource's native node_id as the OpenGraph node id so edges can
        # reference nodes by the same identifier used during collection. Otherwise, create
        # a dynamic guid using BaseNode.guid(self.properties..., self.properties...)
        self.id = self.properties.example_of_required_id


@dataclass
class mssqlEdgeProperties(EdgeProperties):
    """Extends EdgeProperties with optional composition query and reason."""

    query_composition: str | None = None
    reason: str | None = None
