from openhound_sccm.kinds import edges as ek


def test_stage3_edge_kind_values():
    assert ek.SCCM_CONTAINS == "SCCM_Contains"
    assert ek.SCCM_FULL_ADMINISTRATOR == "SCCM_FullAdministrator"
    assert ek.SCCM_ALL_PERMISSIONS == "SCCM_AllPermissions"
    assert ek.SCCM_ASSIGN_ALL_PERMISSIONS == "SCCM_AssignAllPermissions"


def test_traversable_set_unchanged_for_role_edges():
    # Only FullAdministrator + ApplicationAdministrator are traversable among the 7 (CMBP :2216-2249).
    assert ek.SCCM_FULL_ADMINISTRATOR in ek.TRAVERSABLE_EDGE_KINDS
    assert ek.SCCM_APPLICATION_ADMINISTRATOR in ek.TRAVERSABLE_EDGE_KINDS
    assert ek.SCCM_APPLICATION_AUTHOR not in ek.TRAVERSABLE_EDGE_KINDS
    assert ek.SCCM_OSD_MANAGER not in ek.TRAVERSABLE_EDGE_KINDS
