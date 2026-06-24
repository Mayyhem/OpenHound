# src/openhound_sccm/models/sccm_security_role_test.py
from openhound_sccm.models.sccm_security_role import SCCMSecurityRole


def test_security_role_as_node():
    n = SCCMSecurityRole(role_id="SMS000AR", role_name="Full Administrator",
                         root_site_code="CAS", is_built_in=True).as_node
    assert n.id == "SMS000AR@CAS"
    assert n.kinds == ["SCCM_SecurityRole"]
    assert n.properties.environmentid == "CAS"
    assert n.properties.sccm_role_name == "Full Administrator"


def test_security_role_no_id_returns_none():
    assert SCCMSecurityRole(role_id=None, root_site_code="CAS").as_node is None
