# src/openhound_sccm/node_computer_test.py
"""Tests for the _node_computer coalesce in transforms.py.

Each test seeds only the tables that are relevant to what it's checking,
relying on _safe() to silently skip any missing sources.
"""
import duckdb
import pytest
from openhound_sccm.transforms import transforms


def _seed_base(con):
    """Seed the minimum tables for transforms() to run without error."""
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    # site_hierarchy needs at least one of these; _safe skips if absent
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT 'PS1' AS site_code, NULL AS parent_site_code, 2 AS site_type"
    )


def test_node_computer_coalesces_one_row_per_sid():
    """Two sources (r_system + smb_computers) with the same SID should produce
    exactly one node_computer row with merged roles, resource_ids, etc."""
    con = duckdb.connect(":memory:")
    _seed_base(con)

    con.execute(
        "CREATE TABLE sccm.adminservice_r_system AS SELECT "
        "'HOST1' AS name, 'S-1-5-21-1-2-3-1104' AS sid, false AS obsolete, "
        "7 AS resource_id, 'PS1' AS source_site_code, "
        "'SMS Provider' AS system_roles, 'GUID:abc' AS sms_unique_identifier"
    )
    con.execute(
        "CREATE TABLE sccm.smb_computers AS SELECT "
        "'S-1-5-21-1-2-3-1104' AS object_sid, 'HOST1' AS name, "
        "'host1.lab' AS dns_host_name, true AS smb_signing_required, "
        "'SMS Distribution Point' AS sccm_site_system_roles, "
        "true AS sccm_infra, "
        "true AS sccm_hosts_content_library, "
        "false AS sccm_is_pxe_support_enabled"
    )

    transforms(con)

    rows = con.execute(
        "SELECT sid, name, dnshostname, sccm_infra, sms_unique_identifier, "
        "smb_signing_required, list_sort(site_system_roles), list_sort(resource_ids) "
        "FROM sccm.node_computer"
    ).fetchall()

    assert len(rows) == 1
    sid, name, dns, infra, smsid, signing, roles, rids = rows[0]
    assert sid == "S-1-5-21-1-2-3-1104"
    assert dns == "host1.lab"
    assert infra is True
    assert smsid == "GUID:abc"
    assert signing is True
    assert roles == ["SMS Distribution Point", "SMS Provider"]
    assert rids == ["7@PS1"]


def test_node_computer_sccm_has_client_remote_control_spn():
    """An ldap_cmrc_devices row should synthesize sccm_has_client_remote_control_spn=True."""
    con = duckdb.connect(":memory:")
    _seed_base(con)

    con.execute(
        "CREATE TABLE sccm.ldap_cmrc_devices AS SELECT "
        "'S-1-5-21-1-2-3-1200' AS object_sid, 'CMRC1' AS name, "
        "'cmrc1.lab' AS dns_host_name, 'CMRC1$' AS sam_account_name, "
        "true AS sccm_infra, NULL AS sccm_site_system_roles"
    )

    transforms(con)

    row = con.execute(
        "SELECT sid, sccm_has_client_remote_control_spn FROM sccm.node_computer "
        "WHERE sid = 'S-1-5-21-1-2-3-1200'"
    ).fetchone()
    assert row is not None
    assert row[1] is True


def test_node_computer_disable_loopback_and_restrict_ntlm():
    """remoteregistry_computers supplies disable_loopback_check (bool) and
    restrict_receiving_ntlm_traffic (string)."""
    con = duckdb.connect(":memory:")
    _seed_base(con)

    con.execute(
        "CREATE TABLE sccm.remoteregistry_computers AS SELECT "
        "'S-1-5-21-1-2-3-1300' AS object_sid, 'RGREG1' AS name, "
        "'rgreg1.lab' AS dns_host_name, 'RGREG1$' AS sam_account_name, "
        "true AS disable_loopback_check, 'Deny_All' AS restrict_receiving_ntlm_traffic, "
        "false AS smb_signing_required, true AS sccm_infra, "
        "NULL AS sccm_site_system_roles"
    )

    transforms(con)

    row = con.execute(
        "SELECT sid, disable_loopback_check, restrict_receiving_ntlm_traffic "
        "FROM sccm.node_computer WHERE sid = 'S-1-5-21-1-2-3-1300'"
    ).fetchone()
    assert row is not None
    assert row[1] is True
    assert row[2] == "Deny_All"


def test_node_computer_network_boot_server():
    """ldap_network_boot_servers membership synthesizes network_boot_server=True."""
    con = duckdb.connect(":memory:")
    _seed_base(con)

    con.execute(
        "CREATE TABLE sccm.ldap_network_boot_servers AS SELECT "
        "'S-1-5-21-1-2-3-1400' AS object_sid, 'NBSRV' AS name, "
        "'nbsrv.lab' AS dns_host_name, 'NBSRV$' AS sam_account_name, "
        "true AS sccm_infra, NULL AS sccm_site_system_roles"
    )

    transforms(con)

    row = con.execute(
        "SELECT sid, network_boot_server FROM sccm.node_computer "
        "WHERE sid = 'S-1-5-21-1-2-3-1400'"
    ).fetchone()
    assert row is not None
    assert row[1] is True


def test_node_computer_sccm_client_certificate_required():
    """http_management_points with client_cert_required=True sets sccm_client_certificate_required."""
    con = duckdb.connect(":memory:")
    _seed_base(con)

    con.execute(
        "CREATE TABLE sccm.http_management_points AS SELECT "
        "'S-1-5-21-1-2-3-1500' AS object_sid, 'MP1' AS name, "
        "'mp1.lab' AS dns_host_name, NULL AS sam_account_name, "
        "true AS sccm_infra, 'Management Point' AS sccm_site_system_roles, "
        "true AS client_cert_required"
    )

    transforms(con)

    row = con.execute(
        "SELECT sid, sccm_client_certificate_required FROM sccm.node_computer "
        "WHERE sid = 'S-1-5-21-1-2-3-1500'"
    ).fetchone()
    assert row is not None
    assert row[1] is True


def test_node_computer_obsolete_rows_dropped():
    """r_system rows with obsolete=True must not appear in node_computer."""
    con = duckdb.connect(":memory:")
    _seed_base(con)

    con.execute(
        "CREATE TABLE sccm.adminservice_r_system AS SELECT "
        "'GHOST' AS name, 'S-1-5-21-1-2-3-9999' AS sid, true AS obsolete, "
        "NULL AS resource_id, NULL AS source_site_code, "
        "NULL AS system_roles, NULL AS sms_unique_identifier"
    )

    transforms(con)

    rows = con.execute("SELECT sid FROM sccm.node_computer").fetchall()
    assert all(r[0] != "S-1-5-21-1-2-3-9999" for r in rows)


def test_node_computer_distinguished_name_from_smb_computers():
    """smb_computers spreads **ad_object which includes distinguished_name;
    it must appear in node_computer after the coalesce."""
    con = duckdb.connect(":memory:")
    _seed_base(con)

    con.execute(
        "CREATE TABLE sccm.smb_computers AS SELECT "
        "'S-1-5-21-1-2-3-1600' AS object_sid, 'SMBHOST' AS name, "
        "'smbhost.lab' AS dns_host_name, NULL AS sam_account_name, "
        "'CN=SMBHOST,OU=Computers,DC=lab,DC=local' AS distinguished_name, "
        "false AS smb_signing_required, true AS sccm_infra, "
        "NULL AS sccm_hosts_content_library, NULL AS sccm_is_pxe_support_enabled"
    )

    transforms(con)

    row = con.execute(
        "SELECT distinguished_name FROM sccm.node_computer "
        "WHERE sid = 'S-1-5-21-1-2-3-1600'"
    ).fetchone()
    assert row is not None
    assert row[0] == "CN=SMBHOST,OU=Computers,DC=lab,DC=local"


def test_node_computer_distinguished_name_from_wmi_site_definitions_computers():
    """wmi_site_definitions_computers spreads **ad_object (same as the adminservice arm),
    so distinguished_name must not be silently dropped to NULL.

    This is a regression guard for the C6 bug where the wmi arm emitted
    NULL AS distinguished_name while the adminservice arm correctly forwarded it.
    """
    con = duckdb.connect(":memory:")
    _seed_base(con)

    # Use a parameterised insert to avoid any backslash-escaping issues with the DN value.
    con.execute("CREATE TABLE sccm.wmi_site_definitions_computers ("
                "object_sid VARCHAR, name VARCHAR, dns_host_name VARCHAR, "
                "distinguished_name VARCHAR, sccm_site_system_roles VARCHAR, "
                "sccm_infra BOOLEAN)")
    con.execute(
        "INSERT INTO sccm.wmi_site_definitions_computers VALUES (?, ?, ?, ?, ?, ?)",
        ["S-1-5-21-1-2-3-1800", "WMIHOST", "wmihost.lab",
         "CN=WMIHOST,OU=Computers,DC=lab,DC=local", "SMS Site Server", True],
    )

    transforms(con)

    row = con.execute(
        "SELECT distinguished_name FROM sccm.node_computer "
        "WHERE sid = 'S-1-5-21-1-2-3-1800'"
    ).fetchone()
    assert row is not None, "wmi_site_definitions_computers row not found in node_computer"
    assert row[0] == "CN=WMIHOST,OU=Computers,DC=lab,DC=local"


def test_node_computer_distinguished_name_any_value_wins():
    """When smb_computers and remoteregistry_computers both have distinguished_name
    for the same SID, any_value picks the first non-null (idempotent)."""
    con = duckdb.connect(":memory:")
    _seed_base(con)

    con.execute(
        "CREATE TABLE sccm.smb_computers AS SELECT "
        "'S-1-5-21-1-2-3-1700' AS object_sid, 'MULTI' AS name, "
        "'multi.lab' AS dns_host_name, NULL AS sam_account_name, "
        "'CN=MULTI,OU=Computers,DC=lab,DC=local' AS distinguished_name, "
        "false AS smb_signing_required, true AS sccm_infra, "
        "NULL AS sccm_hosts_content_library, NULL AS sccm_is_pxe_support_enabled"
    )
    con.execute(
        "CREATE TABLE sccm.remoteregistry_computers AS SELECT "
        "'S-1-5-21-1-2-3-1700' AS object_sid, 'MULTI' AS name, "
        "'multi.lab' AS dns_host_name, NULL AS sam_account_name, "
        "'CN=MULTI,OU=Computers,DC=lab,DC=local' AS distinguished_name, "
        "false AS smb_signing_required, false AS sccm_infra, "
        "false AS disable_loopback_check, NULL AS restrict_receiving_ntlm_traffic, "
        "NULL AS sccm_site_system_roles"
    )

    transforms(con)

    rows = con.execute("SELECT sid FROM sccm.node_computer").fetchall()
    assert len(rows) == 1
    row = con.execute(
        "SELECT distinguished_name FROM sccm.node_computer "
        "WHERE sid = 'S-1-5-21-1-2-3-1700'"
    ).fetchone()
    assert row is not None
    assert row[0] == "CN=MULTI,OU=Computers,DC=lab,DC=local"
