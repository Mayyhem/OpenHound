# src/openhound_sccm/models/graph_edge.py
"""GraphEdge: converts any graph_edges row into an OpenGraph edge of the matching kind.

Each row in the graph_edges preproc table represents one directed relationship
between two graph nodes. This model reads those rows and emits an Edge whose
`traversable` property is set from the CMBP allow-list. It never produces a node
(as_node returns None) because graph_edges rows are pure edge data.
"""
import logging
from typing import Iterator

from openhound.core.asset import BaseAsset
from openhound.core.models.entries_dataclass import Edge, EdgePath
from pydantic import ConfigDict

from ..graph import SCCMEdgeProperties
from ..kinds.edges import TRAVERSABLE_EDGE_KINDS

logger = logging.getLogger(__name__)


class GraphEdge(BaseAsset):
    """One graph_edges row -> one OpenGraph edge of any kind. Endpoints matched by id;
    `traversable` is set from the CMBP allow-list. Never produces a node."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    start_id: str | None = None
    end_id: str | None = None
    kind: str | None = None
    collection_source: list[str] | None = None

    @property
    def as_node(self) -> None:
        """Graph edges never produce a node."""
        return None

    @property
    def edges(self) -> Iterator[Edge]:
        """Yield one Edge for this row.

        If start_id, end_id, or kind is missing, the row is dropped with a
        warning rather than emitting a malformed edge.
        """
        if not self.start_id or not self.end_id or not self.kind:
            logger.warning(
                "GraphEdge: dropping incomplete row (start=%r end=%r kind=%r)",
                self.start_id, self.end_id, self.kind,
            )
            return
        yield Edge(
            kind=self.kind,
            start=EdgePath(match_by="id", value=self.start_id),
            end=EdgePath(match_by="id", value=self.end_id),
            properties=SCCMEdgeProperties(
                traversable=self.kind in TRAVERSABLE_EDGE_KINDS,
                collectionSource=self.collection_source or [],
            ),
        )
