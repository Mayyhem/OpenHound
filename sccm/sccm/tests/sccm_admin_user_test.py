# src/openhound_sccm/models/sccm_admin_user_test.py
from openhound_sccm.models.sccm_admin_user import SCCMAdminUser


def test_admin_user_as_node():
    n = SCCMAdminUser(logon_name="MAYYHEM\\sccmadmin", admin_sid="S-1-5-21-1-2-3-1110",
                      is_group=False, root_site_code="CAS").as_node
    assert n.id == "MAYYHEM\\SCCMADMIN@CAS"      # id uppercases logon_name
    assert n.kinds == ["SCCM_AdminUser"]
    assert n.properties.environmentid == "CAS"
    assert n.properties.is_group is False


def test_admin_user_no_logon_returns_none():
    assert SCCMAdminUser(logon_name=None, root_site_code="CAS").as_node is None
