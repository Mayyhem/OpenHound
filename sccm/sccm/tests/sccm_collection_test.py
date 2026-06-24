# src/openhound_sccm/models/sccm_collection_test.py
from openhound_sccm.models.sccm_collection import SCCMCollection


def test_collection_as_node():
    n = SCCMCollection(collection_id="PS100016", name="All Systems", collection_type=2,
                       member_count=42, collection_variables_count=3, root_site_code="CAS").as_node
    assert n.id == "PS100016@CAS"
    assert n.kinds == ["SCCM_Collection"]
    assert n.properties.environmentid == "CAS"
    assert n.properties.sccm_collection_id == "PS100016"
    assert n.properties.sccm_collection_type == "Device"
    assert n.properties.collection_variables_count == 3


def test_collection_no_id_returns_none():
    assert SCCMCollection(collection_id=None, root_site_code="CAS").as_node is None
