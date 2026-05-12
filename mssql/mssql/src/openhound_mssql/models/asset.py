from openhound.core.models.entries import Edge, EdgePath
from openhound_mssql.graph import mssqlNodeProperties, mssqlNode
from openhound_mssql.kinds import nodes as nk, edges as ek
from openhound_mssql.main import app
from openhound.core.asset import BaseAsset, EdgeDef, NodeDef
from dataclasses import dataclass

@dataclass
class AssetProperties(mssqlNodeProperties):
    """Example Asset

    Attributes:
        hostname: The hostname of the example asset
    """
    hostname: str


# The resource decorator specifies that the model is an OpenGraph asset
# with nodes and/or edges
@app.asset(
    node=NodeDef(
        kind=nk.ASSET,
        description="Example Asset",
        icon="cog",
        properties=AssetProperties
    ),
    edges=[
        EdgeDef(
            start=nk.ASSET,
            end=nk.GROUP,
            kind=ek.MEMBER_OF,
            description="Asset belongs to group",
        )
    ]
)
class Asset(BaseAsset):
    id: int
    name: str
    hostname: str
    groups: list[str]

    @property
    def as_node(self):
        properties = AssetProperties(
            name=self.name, displayname=self.name, hostname=self.hostname, example_of_required_id=str(self.id)
        )
        return mssqlNode(kinds=[nk.ASSET], properties=properties)

    @property
    def _groups_memberships(self):
        for group in self.groups:
            start = EdgePath(value=self.as_node.id, match_by="id")
            end = EdgePath(value=group, match_by="id")
            yield Edge(kind=ek.MEMBER_OF, start=start, end=end)

    @property
    def edges(self):
        yield from self._groups_memberships
