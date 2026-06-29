import duckdb
from openhound_sccm.transforms import transforms


def _hierarchy(con):
    # Standalone primary site PS1 -> root_site_code = 'PS1'.
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )


def test_real_client_ad_domain_sid_resolved_from_r_system():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _hierarchy(con)
    con.execute(
        "CREATE TABLE sccm.adminservice_r_system AS SELECT "
        "'S-1-5-21-1-2-3-1104' AS sid, 'GUID:ABC' AS sms_unique_identifier, "
        "16777220 AS resource_id, 'PS1' AS source_site_code, false AS obsolete"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_client_devices AS SELECT "
        "'GUID:ABC' AS smsid, 'HOST1' AS name, 'PS1' AS site_code, "
        "16777220 AS resource_id, true AS is_client, false AS is_obsolete"
    )
    transforms(con)
    sid = con.execute(
        "SELECT ad_domain_sid FROM sccm.node_client_device WHERE smsid = 'GUID:ABC'"
    ).fetchone()[0]
    assert sid == "S-1-5-21-1-2-3-1104"


def test_possible_client_ad_domain_sid_preserved():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _hierarchy(con)
    con.execute(
        "CREATE TABLE sccm.ldap_cmrc_devices AS SELECT "
        "'S-1-5-21-1-2-3-1200' AS object_sid, 'HOST2' AS name"
    )
    transforms(con)
    sid = con.execute(
        "SELECT ad_domain_sid FROM sccm.node_client_device "
        "WHERE smsid = 'S-1-5-21-1-2-3-1200@PS1'"
    ).fetchone()[0]
    assert sid == "S-1-5-21-1-2-3-1200"
