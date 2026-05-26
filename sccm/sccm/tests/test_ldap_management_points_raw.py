import pytest
from openhound_sccm.collectors.ldap import _parse_mp_capabilities


PRIMARY_XML = """<ClientOperationalSettings>
  <CCM CommandLine="SMSSITECODE=PS1" />
  <RootSiteCode>CAS</RootSiteCode>
</ClientOperationalSettings>"""

SECONDARY_CMDLINE_FALLBACK_XML = """<ClientOperationalSettings>
  <CCM CommandLine="SMSSITECODE=PS1" />
</ClientOperationalSettings>"""

FSP_XML = """<ClientOperationalSettings>
  <CCM CommandLine="SMSSITECODE=PS1" />
  <RootSiteCode>CAS</RootSiteCode>
  <FSP>
    <FSPServer>fsp1.contoso.com</FSPServer>
    <FSPServer>fsp2.contoso.com</FSPServer>
  </FSP>
</ClientOperationalSettings>"""

STANDALONE_PRIMARY_XML = """<ClientOperationalSettings>
  <CCM CommandLine="SMSSITECODE=PS1" />
</ClientOperationalSettings>"""


def test_primary_site_with_cas_parent():
    result = _parse_mp_capabilities(PRIMARY_XML, "PS1")
    assert result["site_type"] == "Primary Site"
    assert result["parent_site_code"] == "CAS"
    assert result["command_line_site_code"] == "PS1"
    assert result["root_site_code"] == "CAS"


def test_cas_site():
    result = _parse_mp_capabilities(PRIMARY_XML, "CAS")
    assert result["site_type"] == "Central Administration Site"
    assert result["parent_site_code"] == "None"


def test_secondary_site():
    result = _parse_mp_capabilities(PRIMARY_XML, "SEC")
    assert result["site_type"] == "Secondary Site"
    assert result["parent_site_code"] == "CAS"


def test_secondary_site_cmdline_fallback_parent():
    # Secondary with no RootSiteCode — parent falls back to CommandLine site code
    result = _parse_mp_capabilities(SECONDARY_CMDLINE_FALLBACK_XML, "SEC")
    assert result["site_type"] == "Secondary Site"
    assert result["parent_site_code"] == "PS1"


def test_primary_standalone_no_root():
    result = _parse_mp_capabilities(STANDALONE_PRIMARY_XML, "PS1")
    assert result["site_type"] == "Primary Site"
    assert result["parent_site_code"] == "None"


def test_fsp_hostnames_extracted():
    result = _parse_mp_capabilities(FSP_XML, "PS1")
    assert result["fsp_hostnames"] == ["fsp1.contoso.com", "fsp2.contoso.com"]


def test_empty_fsp_list_when_no_fsp_element():
    result = _parse_mp_capabilities(PRIMARY_XML, "PS1")
    assert result["fsp_hostnames"] == []


def test_malformed_xml_returns_safe_defaults():
    result = _parse_mp_capabilities("<<not xml>>", "PS1")
    assert result["site_type"] == "Secondary Site"
    assert result["parent_site_code"] == "Undetermined"
    assert result["fsp_hostnames"] == []


def test_empty_string_returns_safe_defaults():
    result = _parse_mp_capabilities("", "PS1")
    assert result["site_type"] == "Secondary Site"
    assert result["parent_site_code"] == "Undetermined"
    assert result["fsp_hostnames"] == []
