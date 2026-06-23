# src/openhound_sccm/models/replication_edge_test.py
"""Tests for ReplicationEdge: the SCCM_AdminsReplicatedTo edge model.

ReplicationEdge reads a row from graph_edges (start_id, end_id, kind) and emits
one Edge with the correct kind and endpoint paths. as_node returns None because
edges don't produce node objects.
"""
from dataclasses import asdict

import pytest

from openhound_sccm.models.replication_edge import ReplicationEdge
from openhound_sccm.kinds.edges import SCCM_ADMINS_REPLICATED_TO


def test_edges_yields_one_edge():
    """A ReplicationEdge row yields exactly one Edge."""
    model = ReplicationEdge(
        start_id="CAS",
        end_id="PS1",
        kind=SCCM_ADMINS_REPLICATED_TO,
    )
    edge_list = list(model.edges)
    assert len(edge_list) == 1


def test_edge_kind_matches_row():
    """The emitted Edge carries the kind from the row."""
    model = ReplicationEdge(
        start_id="CAS",
        end_id="PS1",
        kind=SCCM_ADMINS_REPLICATED_TO,
    )
    edge = list(model.edges)[0]
    assert edge.kind == SCCM_ADMINS_REPLICATED_TO


def test_edge_start_path_is_id_match():
    """start EdgePath uses match_by='id' and the start_id value."""
    model = ReplicationEdge(start_id="CAS", end_id="PS1", kind=SCCM_ADMINS_REPLICATED_TO)
    edge = list(model.edges)[0]
    assert edge.start.match_by == "id"
    assert edge.start.value == "CAS"


def test_edge_end_path_is_id_match():
    """end EdgePath uses match_by='id' and the end_id value."""
    model = ReplicationEdge(start_id="CAS", end_id="PS1", kind=SCCM_ADMINS_REPLICATED_TO)
    edge = list(model.edges)[0]
    assert edge.end.match_by == "id"
    assert edge.end.value == "PS1"


def test_as_node_returns_none():
    """Edges don't produce node objects — as_node must return None."""
    model = ReplicationEdge(start_id="PS1", end_id="CAS", kind=SCCM_ADMINS_REPLICATED_TO)
    assert model.as_node is None


def test_edge_serializes_with_asdict():
    """The Edge dataclass must be serializable via dataclasses.asdict (used by convert)."""
    model = ReplicationEdge(start_id="PS1", end_id="SS1", kind=SCCM_ADMINS_REPLICATED_TO)
    edge = list(model.edges)[0]
    d = asdict(edge)
    assert d["kind"] == SCCM_ADMINS_REPLICATED_TO
    assert d["start"]["match_by"] == "id"
    assert d["start"]["value"] == "PS1"
    assert d["end"]["match_by"] == "id"
    assert d["end"]["value"] == "SS1"
