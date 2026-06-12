"""Unit tests for the WMI fallback collector (collectors/wmi.py) and the
should_run_phase fallback gate."""
from openhound_sccm.collectors import wmi as w
from openhound_sccm.models.target_entry import TargetEntry


class FakeWmi:
    """Canned WmiClient: `pages` maps a WMI class name to its row list (already
    normalized to {Name: value}); records the queries issued."""

    def __init__(self, pages=None, site="PS1"):
        self.pages = pages or {}
        self._site = site
        self.queries = []
        self.closed = False

    def identify(self):
        return self._site

    def query(self, class_name, *, columns=None, where=None):
        self.queries.append((class_name, columns, where))
        return self.pages.get(class_name)

    def close(self):
        self.closed = True


class _Ctx:
    """Minimal SourceContext stand-in (mirrors test_adminservice._Ctx)."""
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


# --- sites + site definitions --------------------------------------------

def test_sites_emits_site_and_definition_with_flattened_props():
    pages = {
        "SMS_Site": [{"SiteCode": "PS1", "ServerName": "ps1.mayyhem.com", "BuildNumber": "9078"}],
        "SMS_SCI_SiteDefinition": [{
            "SiteCode": "PS1", "SiteServerName": "ps1.mayyhem.com",
            "Props": [
                {"PropertyName": "siteGUID", "Value1": "{GUID}"},
                {"PropertyName": "SQLServerFQDN", "Value1": "ps1-db.mayyhem.com"},
                {"PropertyName": "SQLServicePort", "Value": 1433},
            ]}],
    }
    rows = list(w._sites(FakeWmi(pages), "PS1", _Ctx(principal=None)))
    tables = {t for t, _ in rows}
    assert tables == {"wmi_sites", "wmi_site_definitions"}
    sdef = next(r for t, r in rows if t == "wmi_site_definitions")
    assert sdef["site_guid"] == "{GUID}"
    assert sdef["sql_server_fqdn"] == "ps1-db.mayyhem.com"
    assert sdef["sql_service_port"] == 1433
    assert "props" not in sdef
    site = next(r for t, r in rows if t == "wmi_sites")
    assert site["source"] == "WMI-SMS_Site" and site["build_number"] == "9078"


def test_sites_emits_computer_rows_when_servers_resolve():
    pages = {
        "SMS_Site": [{"SiteCode": "PS1"}],
        "SMS_SCI_SiteDefinition": [{
            "SiteCode": "PS1", "SiteServerName": "ps1.mayyhem.com",
            "Props": [{"PropertyName": "SQLServerFQDN", "Value1": "ps1-db.mayyhem.com"}]}],
    }
    ctx = _Ctx(principal={"object_sid": "S-1-5-21-1", "name": "resolved"})
    rows = list(w._sites(FakeWmi(pages), "PS1", ctx))
    computer_rows = [r for t, r in rows if t == "wmi_site_definitions_computers"]
    assert len(computer_rows) == 2  # site server + SQL server
    assert all(r["sccm_infra"] is True and r["source"] == "WMI-SiteDefinition" for r in computer_rows)


# --- reserved accounts + client devices ----------------------------------

def test_reserved_accounts_enriches_resolved_principal():
    pages = {"SMS_SCI_Reserved": [{"UserName": "MAYYHEM\\svc_naa", "SiteCode": "PS1"}]}
    ctx = _Ctx(principal={"object_sid": "S-1-5-21-7"})
    rows = list(w._reserved_accounts(FakeWmi(pages), "PS1", ctx))
    assert rows[0][0] == "wmi_reserved_accounts"
    r = rows[0][1]
    assert r["source"] == "WMI-SMS_SCI_Reserved" and r["sccm_infra"] is True
    assert r["object_sid"] == "S-1-5-21-7" and r["UserName"] == "MAYYHEM\\svc_naa"


def test_reserved_accounts_skips_unresolvable():
    pages = {"SMS_SCI_Reserved": [{"UserName": "MAYYHEM\\ghost"}]}
    assert list(w._reserved_accounts(FakeWmi(pages), "PS1", _Ctx(principal=None))) == []


def test_client_devices_filters_non_clients_and_obsolete():
    pages = {"SMS_CombinedDeviceResources": [
        {"Name": "WS1", "SMSID": "G1", "IsClient": True, "IsObsolete": False, "ResourceID": 1},
        {"Name": "WS2", "SMSID": "G2", "IsClient": False, "IsObsolete": False, "ResourceID": 2},
        {"Name": "WS3", "SMSID": "G3", "IsClient": True, "IsObsolete": True, "ResourceID": 3},
    ]}
    rows = list(w._client_devices(FakeWmi(pages), "PS1", _Ctx()))
    assert [r["name"] for _, r in rows] == ["WS1"]
    assert rows[0][0] == "wmi_client_devices"


# --- R_System + R_User + collections + members ----------------------------

def test_r_system_and_r_user_rows():
    pages = {"SMS_R_System": [{"Name": "WS1", "SID": "S-1", "SecurityGroupName": ["g1"]}],
             "SMS_R_User": [{"Name": "MAYYHEM\\u", "SID": "S-2", "UserName": "u"}]}
    sys_rows = list(w._r_system(FakeWmi(pages), "PS1", _Ctx()))
    user_rows = list(w._r_user(FakeWmi(pages), "PS1", _Ctx()))
    assert sys_rows[0][0] == "wmi_r_system" and sys_rows[0][1]["sid"] == "S-1"
    assert user_rows[0][0] == "wmi_r_user" and user_rows[0][1]["user_name"] == "u"


def test_collections_and_members_rows():
    pages = {"SMS_Collection": [{"CollectionID": "PS100001", "Name": "All", "MemberCount": 42}],
             "SMS_FullCollectionMembership": [{"CollectionID": "PS100001", "ResourceID": 16777220, "SiteCode": "PS1"}]}
    coll = list(w._collections(FakeWmi(pages), "PS1", _Ctx()))
    mem = list(w._collection_members(FakeWmi(pages), "PS1", _Ctx()))
    assert coll[0][0] == "wmi_collections" and coll[0][1]["member_count"] == 42
    assert mem[0][0] == "wmi_collection_members" and mem[0][1]["resource_id"] == 16777220


# --- security roles + admins + site systems (whitelist / flatten) ---------

def test_security_roles_and_admins_whitelist():
    pages = {"SMS_Role": [{"RoleID": "R1", "RoleName": "Full Admin", "LazyJunk": "drop"}],
             "SMS_Admin": [{"AdminID": 1, "LogonName": "MAYYHEM\\a", "Roles": ["R1"], "SecretJunk": "drop"}]}
    roles = list(w._security_roles(FakeWmi(pages), "PS1", _Ctx()))
    admins = list(w._admins(FakeWmi(pages), "PS1", _Ctx()))
    assert roles[0][0] == "wmi_security_roles" and roles[0][1]["role_name"] == "Full Admin"
    assert "lazy_junk" not in roles[0][1]
    assert admins[0][0] == "wmi_admins" and admins[0][1]["roles"] == ["R1"]
    assert "secret_junk" not in admins[0][1]


def test_site_systems_flattens_service_account():
    pages = {"SMS_SCI_SysResUse": [{
        "NetworkOSPath": "\\\\ps1-db.mayyhem.com", "SiteCode": "PS1", "RoleName": "SMS SQL Server",
        "Props": [{"PropertyName": "SQL Server Service Logon Account", "Value2": "MAYYHEM\\svc_sql"}]}]}
    rows = list(w._site_systems(FakeWmi(pages), "PS1", _Ctx()))
    assert rows[0][0] == "wmi_site_systems"
    assert rows[0][1]["sql_server_service_logon_account"] == "MAYYHEM\\svc_sql"
    assert "props" not in rows[0][1]


# --- orchestrator ---------------------------------------------------------

def test_orchestrator_runs_all_collections_in_order(monkeypatch):
    pages = {
        "SMS_Site": [{"SiteCode": "PS1"}],
        "SMS_SCI_SiteDefinition": [{"SiteCode": "PS1", "Props": []}],
        "SMS_SCI_Reserved": [{"UserName": "MAYYHEM\\naa"}],
        "SMS_CombinedDeviceResources": [{"Name": "WS1", "IsClient": True, "IsObsolete": False}],
        "SMS_R_System": [{"Name": "WS1", "SID": "S-1"}],
        "SMS_R_User": [{"Name": "MAYYHEM\\u", "SID": "S-2"}],
        "SMS_Collection": [{"CollectionID": "C1", "Name": "All"}],
        "SMS_FullCollectionMembership": [{"CollectionID": "C1", "ResourceID": 1}],
        "SMS_Role": [{"RoleID": "R1", "RoleName": "Full Admin"}],
        "SMS_Admin": [{"AdminID": 1, "LogonName": "MAYYHEM\\a"}],
        "SMS_SCI_SysResUse": [{"NetworkOSPath": "\\\\ps1", "RoleName": "MP", "Props": []}],
    }
    fake = FakeWmi(pages)
    monkeypatch.setattr(w.WmiClient, "from_context", classmethod(lambda cls, ctx, target: fake))
    ctx = _Ctx(principal={"object_sid": "S-1-5-21-9"})
    entry = TargetEntry(hostname="ps1-sms.mayyhem.com", ad_object=None)
    ctx.target_hosts_by_hostname = {"ps1-sms.mayyhem.com": entry}
    rows = list(w.collect_wmi("ps1-sms.mayyhem.com", ctx))
    tables = {t for t, _ in rows}
    expected = {
        "wmi_sites", "wmi_site_definitions", "wmi_reserved_accounts", "wmi_client_devices",
        "wmi_r_system", "wmi_r_user", "wmi_collections", "wmi_collection_members",
        "wmi_security_roles", "wmi_admins", "wmi_site_systems",
    }
    assert set(tables) == expected
    # First class queried is SMS_Site (collection order starts with _sites).
    assert fake.queries[0][0] == "SMS_Site"
    # The host is marked collected via WMI for downstream gating.
    assert "WMI" in entry.completed_phases
    # All emitted tables are declared as phase streams.
    from openhound_sccm.per_host_phases import PER_HOST_PHASES, all_table_names
    assert expected <= set(all_table_names(PER_HOST_PHASES))


def test_method_disabled_yields_nothing():
    assert list(w.collect_wmi("ps1-sms.mayyhem.com", _Ctx(enabled=False))) == []


def test_identify_failure_yields_nothing(monkeypatch):
    fake = FakeWmi(pages={}, site=None)  # identify() -> None
    monkeypatch.setattr(w.WmiClient, "from_context", classmethod(lambda cls, ctx, target: fake))
    assert list(w.collect_wmi("ps1-sms.mayyhem.com", _Ctx())) == []
    assert fake.closed  # client cleaned up even on the early-return path


# --- should_run_phase fallback gate ---------------------------------------

class _GateCtx:
    def __init__(self, entries, enabled=True):
        self.target_hosts_by_hostname = entries
        self._enabled = enabled

    def method_enabled(self, name):
        return self._enabled


def _wmi_phase():
    from openhound_sccm.per_host_phases import PER_HOST_PHASES
    return next(p for p in PER_HOST_PHASES if p.name == "WMI")


def test_should_run_phase_skips_wmi_after_adminservice():
    from openhound_sccm.per_host_phases import should_run_phase
    entry = TargetEntry(hostname="h", ad_object=None, completed_phases={"AdminService"})
    ctx = _GateCtx({"h": entry})
    assert should_run_phase("h", _wmi_phase(), ctx) is False


def test_should_run_phase_runs_wmi_when_adminservice_absent():
    from openhound_sccm.per_host_phases import should_run_phase
    entry = TargetEntry(hostname="h", ad_object=None)  # no completed phases
    ctx = _GateCtx({"h": entry})
    assert should_run_phase("h", _wmi_phase(), ctx) is True


def test_should_run_phase_runs_wmi_when_no_entry():
    from openhound_sccm.per_host_phases import should_run_phase
    ctx = _GateCtx({})  # target not registered
    assert should_run_phase("h", _wmi_phase(), ctx) is True


def test_should_run_phase_respects_method_gating():
    from openhound_sccm.per_host_phases import should_run_phase
    entry = TargetEntry(hostname="h", ad_object=None)
    ctx = _GateCtx({"h": entry}, enabled=False)
    assert should_run_phase("h", _wmi_phase(), ctx) is False
