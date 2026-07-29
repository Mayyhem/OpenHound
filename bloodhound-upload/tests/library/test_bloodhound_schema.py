import json

from openhound_collector_common.bloodhound.schema import disable_possible_edges


def _schema():
    return json.dumps({
        "schema": {"name": "SCCM"},
        "relationship_kinds": [
            {"name": "SCCM_CoerceAndRelayToSMB", "is_traversable": True},
            {"name": "SCCM_Contains", "is_traversable": True},
        ],
    }).encode()


def test_flips_only_named_kinds():
    out = json.loads(disable_possible_edges(_schema(), ["SCCM_CoerceAndRelayToSMB"]))
    by_name = {r["name"]: r["is_traversable"] for r in out["relationship_kinds"]}
    assert by_name["SCCM_CoerceAndRelayToSMB"] is False
    assert by_name["SCCM_Contains"] is True


def test_no_kinds_is_identity_shape():
    out = json.loads(disable_possible_edges(_schema(), []))
    assert all(r["is_traversable"] for r in out["relationship_kinds"])
