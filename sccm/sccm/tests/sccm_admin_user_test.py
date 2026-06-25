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


def test_admin_user_audit_scalars_on_node():
    """Audit scalar fields are exposed on the node properties."""
    n = SCCMAdminUser(
        logon_name="MAYYHEM\\adm",
        admin_sid="S-1-5-21-1-2-3-1110",
        is_group=False,
        root_site_code="CAS",
        display_name="adm disp",
        source_site_code="CAS",
        created_by="admin@x",
        created_date="2024-01-01",
        last_modified_by="mod@x",
        last_modified_date="2024-06-01",
    ).as_node
    assert n.properties.display_name == "adm disp"
    assert n.properties.source_site_code == "CAS"
    assert n.properties.created_by == "admin@x"
    assert n.properties.created_date == "2024-01-01"
    assert n.properties.last_modified_by == "mod@x"
    assert n.properties.last_modified_date == "2024-06-01"


def test_admin_user_list_fields_on_node():
    """List fields (collection_ids, role_ids, member_of) are exposed on node properties."""
    n = SCCMAdminUser(
        logon_name="MAYYHEM\\adm",
        root_site_code="CAS",
        collection_ids=["SMS00001@CAS"],
        role_ids=["SMS0001R"],
        member_of=["SMS0001R@CAS"],
    ).as_node
    assert n.properties.collection_ids == ["SMS00001@CAS"]
    assert n.properties.role_ids == ["SMS0001R"]
    assert n.properties.member_of == ["SMS0001R@CAS"]


def test_admin_user_list_fields_default_empty():
    """List fields default to empty lists when not provided."""
    n = SCCMAdminUser(logon_name="MAYYHEM\\adm", root_site_code="CAS").as_node
    assert n.properties.collection_ids == []
    assert n.properties.role_ids == []
    assert n.properties.member_of == []
