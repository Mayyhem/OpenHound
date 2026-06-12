"""Unit tests for the AdminService collect-only per-host collector.

Transport-neutral row shaping (``_snake``/``_row``/``_prop``/column sets) is
tested in ``test_sms_rows.py``; this module covers the HTTP plumbing
(``_get_value``/``_paginate``/``_identification``), the per-collection helpers,
and the orchestrator order + the AdminService completion marker.
"""
import json

from openhound_sccm.clients.http import ErrorClass, HttpResult
from openhound_sccm.collectors import adminservice as a


class FakeClient:
    """Canned AdminService client. `pages` maps a WMI class name to its full row
    list; `_paginate`/`_get_value` slice it by $top/$skip. status/error_class let
    tests simulate non-providers and backend errors."""

    def __init__(self, pages=None, status=200, error_class=ErrorClass.RESPONSE):
        self.pages = pages or {}
        self.status = status
        self.error_class = error_class
        self.calls = []

    def get(self, path):
        self.calls.append(path)
        if self.error_class is not ErrorClass.RESPONSE:
            return HttpResult(None, None, self.error_class)
        cls = path.split("wmi/", 1)[1].split("?", 1)[0]
        rows = self.pages.get(cls)
        if rows is None:
            return HttpResult(404, b"", ErrorClass.RESPONSE)
        top = _qint(path, "$top")
        skip = _qint(path, "$skip") or 0
        page = rows[skip:skip + top] if top else rows
        return HttpResult(self.status, json.dumps({"value": page}).encode(), ErrorClass.RESPONSE)

    def close(self):
        pass


def _qint(path, key):
    for part in path.replace("?", "&").split("&"):
        if part.startswith(key + "="):
            return int(part.split("=", 1)[1])
    return None


class _Ctx:
    """Minimal SourceContext stand-in.

    ``principal`` is what ``resolve_principal`` returns for any name — None to
    simulate an unresolvable principal (suppresses AD-enriched / *_computers
    rows), or a dict to simulate a resolved AD object.
    """
    def __init__(self, enabled=True, principal=None):
        self._enabled = enabled
        self.domain = "mayyhem.com"
        self.username = None
        self.password = None
        self.nt_hash = None
        self.kerberos_ticket = None
        self.ad = None
        self._principal = principal
        self.target_hosts_by_hostname = {}

    def method_enabled(self, name):
        return self._enabled

    def resolve_principal(self, name):
        return self._principal


# --- plumbing -------------------------------------------------------------

def test_identification_returns_site_code():
    fake = FakeClient({"SMS_Identification": [{"ThisSiteCode": "PS1", "ThisSiteName": "Primary"}]})
    assert a._identification(fake) == "PS1"


def test_identification_aborts_when_empty():
    assert a._identification(FakeClient({"SMS_Identification": []})) is None
    assert a._identification(FakeClient({})) is None  # 404 -> None


def test_paginate_stops_on_short_page():
    rows = [{"n": i} for i in range(2500)]
    fake = FakeClient({"SMS_R_System": rows})
    got = list(a._paginate(fake, "wmi/SMS_R_System"))
    assert len(got) == 2500
    skips = [_qint(c, "$skip") for c in fake.calls]
    assert skips == [0, 1000, 2000]  # 3 pages: 1000, 1000, 500 (short page ends it)


def test_gate_failure_yields_nothing(monkeypatch):
    fake = FakeClient({"SMS_Identification": []})
    monkeypatch.setattr(a.HttpClient, "from_context", classmethod(lambda cls, ctx, target, **kw: fake))
    assert list(a.collect_adminservice("ps1-sms.mayyhem.com", _Ctx())) == []


def test_method_disabled_yields_nothing():
    assert list(a.collect_adminservice("ps1-sms.mayyhem.com", _Ctx(enabled=False))) == []


# --- sites + site definitions --------------------------------------------

def test_sites_emits_site_and_definition_with_flattened_props():
    pages = {
        "SMS_Site": [{"SiteCode": "PS1", "ServerName": "ps1.mayyhem.com", "BuildNumber": "9078",
                      "SiteName": "Primary", "Type": 2, "Version": "5.0"}],
        "SMS_SCI_SiteDefinition": [{
            "SiteCode": "PS1", "SiteServerName": "ps1.mayyhem.com", "SQLDatabaseName": "CM_PS1",
            "SQLServerName": "ps1-db", "Props": [
                {"PropertyName": "siteGUID", "Value1": "{GUID}"},
                {"PropertyName": "SQLServerFQDN", "Value1": "ps1-db.mayyhem.com"},
                {"PropertyName": "SQLServicePort", "Value": 1433},
            ]}],
    }
    # principal=None -> site/SQL servers don't resolve, so no *_computers rows.
    rows = list(a._sites(FakeClient(pages), "PS1", _Ctx(principal=None)))
    tables = {t for t, _ in rows}
    assert tables == {"adminservice_sites", "adminservice_site_definitions"}
    site = next(r for t, r in rows if t == "adminservice_sites")
    assert site["site_code"] == "PS1" and site["build_number"] == "9078" and site["source_site_code"] == "PS1"
    sdef = next(r for t, r in rows if t == "adminservice_site_definitions")
    assert sdef["site_guid"] == "{GUID}"
    assert sdef["sql_server_fqdn"] == "ps1-db.mayyhem.com"
    assert sdef["sql_service_port"] == 1433
    assert "props" not in sdef  # raw Props blob dropped after flattening


def test_sites_emits_computer_rows_when_servers_resolve():
    pages = {
        "SMS_Site": [{"SiteCode": "PS1", "ServerName": "ps1.mayyhem.com"}],
        "SMS_SCI_SiteDefinition": [{
            "SiteCode": "PS1", "SiteServerName": "ps1.mayyhem.com",
            "Props": [{"PropertyName": "SQLServerFQDN", "Value1": "ps1-db.mayyhem.com"}]}],
    }
    ctx = _Ctx(principal={"object_sid": "S-1-5-21-1", "name": "resolved"})
    rows = list(a._sites(FakeClient(pages), "PS1", ctx))
    computer_rows = [r for t, r in rows if t == "adminservice_site_definitions_computers"]
    # One for the site server, one for the SQL server.
    assert len(computer_rows) == 2
    assert all(r["sccm_infra"] is True for r in computer_rows)


# --- reserved accounts + client devices ----------------------------------

def test_reserved_accounts_enriches_resolved_principal():
    pages = {"SMS_SCI_Reserved": [{"UserName": "MAYYHEM\\svc_naa", "SiteCode": "PS1"}]}
    ctx = _Ctx(principal={"object_sid": "S-1-5-21-7", "name": "svc_naa"})
    rows = list(a._reserved_accounts(FakeClient(pages), "PS1", ctx))
    assert rows[0][0] == "adminservice_reserved_accounts"
    r = rows[0][1]
    assert r["source"] == "AdminService-SMS_SCI_Reserved" and r["sccm_infra"] is True
    assert r["object_sid"] == "S-1-5-21-7" and r["UserName"] == "MAYYHEM\\svc_naa"


def test_reserved_accounts_skips_unresolvable():
    pages = {"SMS_SCI_Reserved": [{"UserName": "MAYYHEM\\ghost", "SiteCode": "PS1"}]}
    assert list(a._reserved_accounts(FakeClient(pages), "PS1", _Ctx(principal=None))) == []


def test_client_devices_filters_non_clients_and_obsolete():
    pages = {"SMS_CombinedDeviceResources": [
        {"Name": "WS1", "SMSID": "GUID1", "IsClient": True, "IsObsolete": False, "ResourceID": 1},
        {"Name": "WS2", "SMSID": "GUID2", "IsClient": False, "IsObsolete": False, "ResourceID": 2},
        {"Name": "WS3", "SMSID": "GUID3", "IsClient": True, "IsObsolete": True, "ResourceID": 3},
    ]}
    rows = list(a._client_devices(FakeClient(pages), "PS1", _Ctx()))
    names = [r["name"] for _, r in rows]
    assert names == ["WS1"]  # non-client + obsolete skipped
    assert rows[0][0] == "adminservice_client_devices"


# --- R_System + R_User ----------------------------------------------------

def test_r_system_rows():
    pages = {"SMS_R_System": [{"Name": "WS1", "SID": "S-1-5-21-1", "ResourceID": 1,
                               "SMSUniqueIdentifier": "GUID1", "Client": 1, "Obsolete": 0,
                               "SecurityGroupName": ["MAYYHEM\\g1", "MAYYHEM\\g2"]}]}
    rows = list(a._r_system(FakeClient(pages), "PS1", _Ctx()))
    assert rows[0][0] == "adminservice_r_system"
    assert rows[0][1]["security_group_name"] == ["MAYYHEM\\g1", "MAYYHEM\\g2"]
    assert rows[0][1]["sid"] == "S-1-5-21-1"


def test_r_user_rows():
    pages = {"SMS_R_User": [{"Name": "MAYYHEM\\alice", "SID": "S-1-5-21-9", "ResourceID": 5,
                             "SecurityGroupName": ["MAYYHEM\\admins"], "UserName": "alice"}]}
    rows = list(a._r_user(FakeClient(pages), "PS1", _Ctx()))
    assert rows[0][0] == "adminservice_r_user"
    assert rows[0][1]["user_name"] == "alice"


# --- collections + members ------------------------------------------------

def test_collections_rows():
    pages = {"SMS_Collection": [{"CollectionID": "PS100001", "Name": "All Systems",
                                 "CollectionType": 2, "MemberCount": 42, "IsBuiltIn": True}]}
    rows = list(a._collections(FakeClient(pages), "PS1", _Ctx()))
    assert rows[0][0] == "adminservice_collections"
    assert rows[0][1]["collection_id"] == "PS100001" and rows[0][1]["member_count"] == 42


def test_collection_members_rows():
    pages = {"SMS_FullCollectionMembership": [{"CollectionID": "PS100001", "ResourceID": 16777220,
                                               "SiteCode": "PS1"}]}
    rows = list(a._collection_members(FakeClient(pages), "PS1", _Ctx()))
    assert rows[0][0] == "adminservice_collection_members"
    assert rows[0][1]["resource_id"] == 16777220


# --- security roles + admins (whitelist) ----------------------------------

def test_security_roles_whitelists_columns():
    pages = {"SMS_Role": [{"RoleID": "SMS0001R", "RoleName": "Full Administrator",
                           "IsBuiltIn": True, "NumberOfAdmins": 1,
                           "LazyJunkColumn": "should be dropped"}]}
    rows = list(a._security_roles(FakeClient(pages), "PS1", _Ctx()))
    assert rows[0][0] == "adminservice_security_roles"
    r = rows[0][1]
    assert r["role_id"] == "SMS0001R" and r["role_name"] == "Full Administrator"
    assert "lazy_junk_column" not in r  # whitelist drops un-listed columns


def test_admins_keeps_role_and_collection_assignments():
    pages = {"SMS_Admin": [{"AdminID": 1, "LogonName": "MAYYHEM\\admin", "AdminSid": "S-1-5-21-7",
                            "Roles": ["SMS0001R"], "RoleNames": ["Full Administrator"],
                            "CollectionNames": "All Systems, All Users", "IsGroup": False,
                            "SecretJunk": "dropped"}]}
    rows = list(a._admins(FakeClient(pages), "PS1", _Ctx()))
    assert rows[0][0] == "adminservice_admins"
    r = rows[0][1]
    assert r["roles"] == ["SMS0001R"] and r["collection_names"] == "All Systems, All Users"
    assert "secret_junk" not in r


# --- site systems ---------------------------------------------------------

def test_site_systems_flattens_service_account():
    pages = {"SMS_SCI_SysResUse": [{
        "NetworkOSPath": "\\\\ps1-db.mayyhem.com", "SiteCode": "PS1", "RoleName": "SMS SQL Server",
        "Props": [{"PropertyName": "SQL Server Service Logon Account", "Value2": "MAYYHEM\\svc_sql"}]}]}
    rows = list(a._site_systems(FakeClient(pages), "PS1", _Ctx()))
    assert rows[0][0] == "adminservice_site_systems"
    r = rows[0][1]
    assert r["network_os_path"] == "\\\\ps1-db.mayyhem.com" and r["role_name"] == "SMS SQL Server"
    assert r["sql_server_service_logon_account"] == "MAYYHEM\\svc_sql"
    assert "props" not in r


# --- orchestrator end-to-end ----------------------------------------------

def test_orchestrator_runs_all_collections_in_order(monkeypatch):
    pages = {
        "SMS_Identification": [{"ThisSiteCode": "PS1", "ThisSiteName": "Primary"}],
        "SMS_Site": [{"SiteCode": "PS1", "ServerName": "ps1"}],
        "SMS_SCI_SiteDefinition": [{"SiteCode": "PS1", "Props": []}],
        "SMS_SCI_Reserved": [{"UserName": "MAYYHEM\\naa", "SiteCode": "PS1"}],
        "SMS_CombinedDeviceResources": [{"Name": "WS1", "SMSID": "G1", "IsClient": True, "IsObsolete": False}],
        "SMS_R_System": [{"Name": "WS1", "SID": "S-1", "SecurityGroupName": []}],
        "SMS_R_User": [{"Name": "MAYYHEM\\u", "SID": "S-2", "SecurityGroupName": []}],
        "SMS_Collection": [{"CollectionID": "PS100001", "Name": "All"}],
        "SMS_FullCollectionMembership": [{"CollectionID": "PS100001", "ResourceID": 1, "SiteCode": "PS1"}],
        "SMS_Role": [{"RoleID": "R1", "RoleName": "Full Admin"}],
        "SMS_Admin": [{"AdminID": 1, "LogonName": "MAYYHEM\\a", "Roles": ["R1"]}],
        "SMS_SCI_SysResUse": [{"NetworkOSPath": "\\\\ps1", "SiteCode": "PS1", "RoleName": "MP", "Props": []}],
    }
    fake = FakeClient(pages)
    monkeypatch.setattr(a.HttpClient, "from_context", classmethod(lambda cls, ctx, target, **kw: fake))
    # principal truthy so reserved accounts resolve and emit a row; the test's
    # SMS_SCI_SiteDefinition carries no server names, so no *_computers rows.
    ctx = _Ctx(principal={"object_sid": "S-1-5-21-9", "name": "naa"})
    rows = list(a.collect_adminservice("ps1-sms.mayyhem.com", ctx))
    tables = [t for t, _ in rows]
    # The SMS_Identification gate ran first.
    assert "wmi/SMS_Identification" in fake.calls[0]
    expected = {
        "adminservice_sites", "adminservice_site_definitions", "adminservice_reserved_accounts",
        "adminservice_client_devices", "adminservice_r_system",
        "adminservice_r_user", "adminservice_collections",
        "adminservice_collection_members", "adminservice_security_roles", "adminservice_admins",
        "adminservice_site_systems",
    }
    assert set(tables) == expected
    # All emitted table names are declared as phase streams.
    from openhound_sccm.per_host_phases import PER_HOST_PHASES, all_table_names
    assert expected <= set(all_table_names(PER_HOST_PHASES))


def test_orchestrator_marks_completed_phase(monkeypatch):
    from openhound_sccm.models.target_entry import TargetEntry
    pages = {"SMS_Identification": [{"ThisSiteCode": "PS1"}], "SMS_Site": []}
    fake = FakeClient(pages)
    monkeypatch.setattr(a.HttpClient, "from_context", classmethod(lambda cls, ctx, target, **kw: fake))
    entry = TargetEntry(hostname="ps1-sms.mayyhem.com", ad_object=None)
    ctx = _Ctx()
    ctx.target_hosts_by_hostname = {"ps1-sms.mayyhem.com": entry}
    list(a.collect_adminservice("ps1-sms.mayyhem.com", ctx))
    assert "AdminService" in entry.completed_phases


def test_gate_failure_does_not_mark_completed_phase(monkeypatch):
    from openhound_sccm.models.target_entry import TargetEntry
    fake = FakeClient({"SMS_Identification": []})  # not a provider
    monkeypatch.setattr(a.HttpClient, "from_context", classmethod(lambda cls, ctx, target, **kw: fake))
    entry = TargetEntry(hostname="ps1-sms.mayyhem.com", ad_object=None)
    ctx = _Ctx()
    ctx.target_hosts_by_hostname = {"ps1-sms.mayyhem.com": entry}
    list(a.collect_adminservice("ps1-sms.mayyhem.com", ctx))
    assert "AdminService" not in entry.completed_phases


def test_one_failing_collection_does_not_abort_rest(monkeypatch):
    # SMS_Site succeeds; every other collection class 404s. Sites must still be
    # collected and the orchestrator must complete without raising.
    pages = {"SMS_Identification": [{"ThisSiteCode": "PS1"}],
             "SMS_Site": [{"SiteCode": "PS1"}]}
    fake = FakeClient(pages)
    monkeypatch.setattr(a.HttpClient, "from_context", classmethod(lambda cls, ctx, target, **kw: fake))
    tables = {t for t, _ in a.collect_adminservice("ps1-sms.mayyhem.com", _Ctx(principal=None))}
    assert "adminservice_sites" in tables
