# src/openhound_sccm/models/computer_test.py
"""Tests for ComputerNode: row -> SCCMNode conversion."""
import pytest
from openhound_sccm.models.computer import ComputerNode


def test_computer_as_node_full_row():
    """A well-formed row with a domain SID should produce a Computer+Base node."""
    row = {
        "sid": "S-1-5-21-1-2-3-1104",
        "name": "HOST1",
        "dnshostname": "host1.lab",
        "sccm_infra": True,
        "site_system_roles": ["SMS Provider"],
        "resource_ids": ["7@PS1"],
        "sms_unique_identifier": "GUID:abc",
        "smb_signing_required": True,
        "sam_account_name": "HOST1$",
    }
    node = ComputerNode(**row).as_node
    assert node is not None
    assert node.id == "S-1-5-21-1-2-3-1104"
    assert node.kinds == ["Computer", "Base"]
    assert node.properties.environmentid == "S-1-5-21-1-2-3"
    assert node.properties.sccm_site_system_roles == ["SMS Provider"]
    assert node.properties.sccm_resource_ids == ["7@PS1"]
    assert node.properties.sccm_client_device_identifier == "GUID:abc"
    assert node.properties.smb_signing_required is True
    assert node.properties.sccm_infra is True


def test_computer_as_node_lowercased_sid_is_uppercased():
    """The model must uppercase a lowercase SID."""
    row = {"sid": "s-1-5-21-1-2-3-1104", "name": "HOST1"}
    node = ComputerNode(**row).as_node
    assert node is not None
    assert node.id == "S-1-5-21-1-2-3-1104"


def test_computer_no_sid_returns_none():
    """A row with no SID must return None (no identity key, cannot emit)."""
    assert ComputerNode(sid=None, name="x").as_node is None


def test_computer_empty_sid_returns_none():
    """An empty string SID must also return None."""
    assert ComputerNode(sid="", name="x").as_node is None


def test_computer_extra_fields_ignored():
    """extra='ignore' means unknown columns from the DB don't raise an error."""
    row = {
        "sid": "S-1-5-21-1-2-3-1104",
        "name": "HOST1",
        "unexpected_column": "should_be_ignored",
    }
    # Should not raise
    node = ComputerNode(**row).as_node
    assert node is not None


def test_computer_all_extra_properties():
    """All Computer-specific properties pass through to ComputerProperties."""
    row = {
        "sid": "S-1-5-21-1-2-3-1104",
        "name": "HOST1",
        "sccm_has_client_remote_control_spn": True,
        "network_boot_server": True,
        "disable_loopback_check": True,
        "restrict_receiving_ntlm_traffic": "Deny_All",
        "sccm_client_certificate_required": True,
        "sccm_hosts_content_library": True,
        "sccm_is_pxe_support_enabled": False,
    }
    node = ComputerNode(**row).as_node
    assert node is not None
    props = node.properties
    assert props.sccm_has_client_remote_control_spn is True
    assert props.network_boot_server is True
    assert props.disable_loopback_check is True
    assert props.restrict_receiving_ntlm_traffic == "Deny_All"
    assert props.sccm_client_certificate_required is True
    assert props.sccm_hosts_content_library is True
    assert props.sccm_is_pxe_support_enabled is False


@pytest.mark.parametrize("dnshostname,sam_account_name,distinguished_name", [
    ("ws01.lab", "WS01$", "CN=WS01,OU=Computers,DC=lab,DC=local"),
    ("dc01.lab", "DC01$", "CN=DC01,OU=Domain Controllers,DC=lab,DC=local"),
    (None, None, None),
])
def test_computer_exposes_dnshostname_samaccountname_distinguished_name(
    dnshostname, sam_account_name, distinguished_name
):
    """dnshostname, sam_account_name, and distinguished_name must be exposed on
    ComputerProperties and flow through from the ComputerNode fields."""
    n = ComputerNode(
        sid="S-1-5-21-1-2-3-1104",
        name="WS01",
        dnshostname=dnshostname,
        sam_account_name=sam_account_name,
        distinguished_name=distinguished_name,
    ).as_node
    assert n is not None
    assert n.properties.dnshostname == dnshostname
    assert n.properties.sam_account_name == sam_account_name
    assert n.properties.distinguished_name == distinguished_name
