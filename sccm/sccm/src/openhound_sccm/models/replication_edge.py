# src/openhound_sccm/models/replication_edge.py
"""ReplicationEdge: converts a graph_edges row into an SCCM_AdminsReplicatedTo edge.

Each row in the graph_edges preproc table represents one directed replication
relationship between two SCCM sites. This model reads those rows and emits an
Edge with site-code endpoints matched by id. It never produces a node (as_node
returns None) because replication rows are pure edge data.
"""
import logging
from typing import Iterator

from openhound.core.asset import BaseAsset
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import ConfigDict

logger = logging.getLogger(__name__)


class ReplicationEdge(BaseAsset):
    """One graph_edges row -> one OpenGraph SCCM_AdminsReplicatedTo edge.

    Fields map directly to the graph_edges columns produced by
    transforms._graph_edges(). Extra columns are silently ignored (extra="ignore")
    so schema drift doesn't crash convert.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    start_id: str | None = None   # site code of the edge's start endpoint
    end_id: str | None = None     # site code of the edge's end endpoint
    kind: str | None = None       # edge kind constant (e.g. SCCM_AdminsReplicatedTo)

    @property
    def as_node(self) -> None:
        """Replication edges never produce a node."""
        return None

    @property
    def edges(self) -> Iterator[Edge]:
        """Yield one Edge for this replication relationship.

        If start_id, end_id, or kind is missing, the row is dropped with a
        warning rather than emitting a malformed edge.
        """
        if not self.start_id or not self.end_id or not self.kind:
            logger.warning(
                "ReplicationEdge: dropping row with missing fields "
                "(start_id=%r, end_id=%r, kind=%r)",
                self.start_id,
                self.end_id,
                self.kind,
            )
            return

        yield Edge(
            kind=self.kind,
            start=EdgePath(match_by="id", value=self.start_id),
            end=EdgePath(match_by="id", value=self.end_id),
            properties=EdgeProperties(),
        )
