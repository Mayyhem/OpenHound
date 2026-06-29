# src/openhound_sccm/models/sccm_client_device_test.py
from openhound_sccm.models.sccm_client_device import SCCMClientDevice


def test_client_device_as_node():
    n = SCCMClientDevice(smsid="GUID-1", name="WS01", site_code="PS1", root_site_code="CAS",
                         resource_id_str="7@PS1").as_node
    assert n.id == "GUID-1"
    assert n.kinds == ["SCCM_ClientDevice"]
    assert n.properties.environmentid == "CAS"
    assert n.properties.SMSID == "GUID-1"


def test_client_device_no_smsid_returns_none():
    assert SCCMClientDevice(smsid=None, name="x").as_node is None


def test_client_device_c4_fields_mapped():
    """Stage 3 C4: new scalars, resolved SIDs, and collection lists survive model round-trip."""
    n = SCCMClientDevice(
        smsid="GUID-2", name="WS02", site_code="CAS", root_site_code="CAS",
        resource_id_str="50@CAS",
        ad_last_logon_time="2026-01-02",
        ad_last_logon_user_domain="CORP",
        source_site_code="CAS",
        last_active_time="2026-01-10",
        last_online_time="2026-01-11",
        last_offline_time="2026-01-09",
        primary_user_sid="S-1-5-21-1-2-3-1200",
        current_logon_user_sid="S-1-5-21-1-2-3-1201",
        ad_last_logon_user_sid="S-1-5-21-1-2-3-1202",
        last_reported_mp_server_sid="S-1-5-21-1-2-3-500",
        collection_ids=["SMS00001@CAS"],
        collection_names=["All Systems"],
    ).as_node
    p = n.properties
    assert p.ADLastLogonTime == "2026-01-02"
    assert p.ADLastLogonUserDomain == "CORP"
    assert p.sourceSiteCode == "CAS"
    assert p.lastActiveTime == "2026-01-10"
    assert p.lastOnlineTime == "2026-01-11"
    assert p.lastOfflineTime == "2026-01-09"
    assert p.primaryUserSID == "S-1-5-21-1-2-3-1200"
    assert p.currentLogonUserSID == "S-1-5-21-1-2-3-1201"
    assert p.ADLastLogonUserSID == "S-1-5-21-1-2-3-1202"
    assert p.lastReportedMPServerSID == "S-1-5-21-1-2-3-500"
    assert p.collectionIds == ["SMS00001@CAS"]
    assert p.collectionNames == ["All Systems"]
