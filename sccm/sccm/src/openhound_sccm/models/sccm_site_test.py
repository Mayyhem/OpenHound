# src/openhound_sccm/models/sccm_site_test.py
"""Tests for SCCMSite model: row -> OpenGraph node conversion."""
from openhound_sccm.models.sccm_site import SCCMSite
from openhound_sccm.kinds import nodes as nk


def test_sccm_site_as_node_id_and_kinds():
    """id = site_code; kinds = [SCCM_Site]."""
    row = {
        "site_code": "PS1",
        "root_site_code": "CAS",
        "site_type": 2,
        "site_name": "Primary",
        "server_name": "srv.lab",
    }
    node = SCCMSite(**row).as_node
    assert node.id == "PS1"
    assert node.kinds == [nk.SCCM_SITE]


def test_sccm_site_environmentid_is_root():
    """environmentid = root_site_code when present."""
    row = {"site_code": "PS1", "root_site_code": "CAS", "site_type": 2}
    node = SCCMSite(**row).as_node
    assert node.properties.environmentid == "CAS"


def test_sccm_site_environmentid_falls_back_to_site_code():
    """environmentid = site_code when root_site_code is absent."""
    row = {"site_code": "PS1", "root_site_code": None, "site_type": 2}
    node = SCCMSite(**row).as_node
    assert node.properties.environmentid == "PS1"


def test_sccm_site_type_int_to_string_mapping():
    """site_type integer maps to the correct human-readable string."""
    for int_type, expected in [(1, "Secondary Site"), (2, "Primary Site"), (4, "Central Administration Site")]:
        row = {"site_code": "X01", "root_site_code": None, "site_type": int_type}
        node = SCCMSite(**row).as_node
        assert node.properties.site_type == expected, f"site_type={int_type} should map to {expected!r}"


def test_sccm_site_unknown_type_is_none():
    """An unrecognised site_type integer maps to None (no crash)."""
    row = {"site_code": "X01", "root_site_code": None, "site_type": 99}
    node = SCCMSite(**row).as_node
    assert node.properties.site_type is None


def test_sccm_site_no_site_code_returns_none():
    """A row with no site_code cannot be keyed; as_node returns None."""
    node = SCCMSite(site_code=None).as_node
    assert node is None


def test_sccm_site_properties_lowercase_keys():
    """Property keys are lowercase (no PascalCase / camelCase)."""
    from dataclasses import asdict
    row = {"site_code": "PS1", "root_site_code": "CAS", "site_type": 2, "site_name": "Primary"}
    node = SCCMSite(**row).as_node
    props = asdict(node)["properties"]
    for key in props:
        assert key == key.lower(), f"Property key {key!r} must be lowercase"


def test_sccm_site_extra_fields_ignored():
    """Extra columns from the DB are silently ignored (extra='ignore')."""
    row = {"site_code": "PS1", "root_site_code": None, "site_type": 2, "unexpected_column": "boom"}
    # Should not raise
    node = SCCMSite(**row).as_node
    assert node is not None


def test_sccm_site_build_number_and_install_dir_emitted():
    """build_number and install_dir are passed through to node properties."""
    row = {
        "site_code": "PS1",
        "root_site_code": "CAS",
        "site_type": 2,
        "build_number": "9107",
        "install_dir": r"C:\Program Files\Microsoft Configuration Manager",
    }
    node = SCCMSite(**row).as_node
    assert node.properties.build_number == "9107"
    assert node.properties.install_dir == r"C:\Program Files\Microsoft Configuration Manager"
