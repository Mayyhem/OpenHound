# src/openhound_sccm/models/sccm_client_device_test.py
from openhound_sccm.models.sccm_client_device import SCCMClientDevice


def test_client_device_as_node():
    n = SCCMClientDevice(smsid="GUID-1", name="WS01", site_code="PS1", root_site_code="CAS",
                         resource_id_str="7@PS1").as_node
    assert n.id == "GUID-1"
    assert n.kinds == ["SCCM_ClientDevice"]
    assert n.properties.environmentid == "CAS"
    assert n.properties.smsid == "GUID-1"


def test_client_device_no_smsid_returns_none():
    assert SCCMClientDevice(smsid=None, name="x").as_node is None
