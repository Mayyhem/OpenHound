"""Unit tests for the WMI transport client (clients/wmi.py).

Transports are mocked: these cover the auth-ladder logic, the rung->backend
mapping, WQL construction, and the row normalization (including the embedded
SMS ``Props`` array) without any network or DCOM.
"""
from openhound_sccm.clients import wmi as w


# --- WQL builder ----------------------------------------------------------

def test_build_wql_select_star_when_no_columns():
    assert w._build_wql("SMS_Role") == "SELECT * FROM SMS_Role"


def test_build_wql_columns_and_where():
    wql = w._build_wql("SMS_SCI_SiteDefinition", ("SiteCode", "Props"), "SiteCode = 'PS1'")
    assert wql == "SELECT SiteCode,Props FROM SMS_SCI_SiteDefinition WHERE SiteCode = 'PS1'"


# --- normalization --------------------------------------------------------

class _FakeObj:
    """Stand-in for impacket IWbemClassObject: getProperties() -> {name: {'value': ...}}."""
    def __init__(self, props):
        self._props = props

    def getProperties(self):
        return self._props


def test_normalize_flattens_scalar_values():
    props = {"SiteCode": {"value": "PS1"}, "BuildNumber": {"value": 9078}}
    assert w._normalize(props) == {"SiteCode": "PS1", "BuildNumber": 9078}


def test_normalize_unwraps_embedded_props_array():
    props = {
        "SiteCode": {"value": "PS1"},
        "Props": {"value": [
            _FakeObj({"PropertyName": {"value": "siteGUID"}, "Value1": {"value": "{G}"}}),
        ]},
    }
    out = w._normalize(props)
    assert out["SiteCode"] == "PS1"
    assert out["Props"] == [{"PropertyName": "siteGUID", "Value1": "{G}"}]


# --- ladder ---------------------------------------------------------------

class FakeBackend:
    """Records connect/query and can simulate a connect failure."""
    def __init__(self, *, rows=None, connect_error=None):
        self.rows = rows if rows is not None else []
        self.connect_error = connect_error
        self.connected = False
        self.queries = []
        self.closed = False

    def connect(self):
        if self.connect_error:
            raise self.connect_error
        self.connected = True

    def query(self, namespace, wql):
        self.queries.append((namespace, wql))
        return self.rows

    def close(self):
        self.closed = True


def _client(**kw):
    base = dict(target="ps1-sms.mayyhem.com", domain="mayyhem.com")
    base.update(kw)
    return w.WmiClient(**base)


def test_ladder_explicit_creds_tries_kerberos_then_ntlm(monkeypatch):
    attempted = []
    kerb = FakeBackend(connect_error=OSError("kerberos down"))
    ntlm = FakeBackend(rows=[{"SiteCode": "PS1", "ProviderForLocalSite": True}])
    backends = {"kerberos": kerb, "ntlm": ntlm}

    client = _client(username="MAYYHEM\\domainadmin", password="pw")

    def fake_build(rung):
        attempted.append(rung)
        return backends.get(rung)

    monkeypatch.setattr(client, "_build_backend", fake_build)
    assert client.identify() == "PS1"
    assert attempted == ["kerberos", "ntlm"]   # advanced past the failed kerberos rung
    assert kerb.closed and ntlm.connected       # failed rung closed; winner kept
    assert client._backend is ntlm


def test_ladder_skips_anonymous_when_no_creds(monkeypatch):
    monkeypatch.setattr(w.http_auth, "sspi_negotiate_available", lambda: False)
    client = _client()  # no creds
    # _build_backend('anonymous') returns None; identify must not construct anything.
    assert client.identify() is None
    assert client._backend is None


def test_ladder_sspi_uses_pywin32_backend(monkeypatch):
    monkeypatch.setattr(w.http_auth, "sspi_negotiate_available", lambda: True)
    client = _client()  # no creds + sspi available -> ['sspi']
    backend = client._build_backend("sspi")
    assert isinstance(backend, w._PyWin32Backend)


def test_build_backend_maps_rungs_to_impacket_with_kerberos_flag():
    client = _client(username="MAYYHEM\\domainadmin", password="pw", nt_hash="8846f7eaee8fb117ad06bdd830b7586c")
    ntlm = client._build_backend("ntlm")
    kerb = client._build_backend("kerberos")
    assert isinstance(ntlm, w._ImpacketBackend) and ntlm._do_kerberos is False
    assert isinstance(kerb, w._ImpacketBackend) and kerb._do_kerberos is True
    # NT hash flows into the LM:NT split impacket expects.
    assert ntlm._nthash == "8846f7eaee8fb117ad06bdd830b7586c"
    assert client._build_backend("anonymous") is None


# --- identify -> query ----------------------------------------------------

def test_query_requires_prior_identify():
    client = _client(username="u", password="p")
    assert client.query("SMS_Site") is None  # no identify() yet


def test_query_builds_namespace_and_wql(monkeypatch):
    backend = FakeBackend(rows=[{"SiteCode": "PS1", "ProviderForLocalSite": True}])
    client = _client(username="u", password="p")
    monkeypatch.setattr(client, "_build_backend", lambda rung: backend if rung == "kerberos" else None)
    assert client.identify() == "PS1"
    backend.rows = [{"RoleName": "Full Admin"}]
    rows = client.query("SMS_Role")
    assert rows == [{"RoleName": "Full Admin"}]
    ns, wql = backend.queries[-1]
    assert ns == "root\\SMS\\site_PS1"
    assert wql == "SELECT * FROM SMS_Role"


def test_site_code_picks_local_provider():
    rows = [{"SiteCode": "AAA", "ProviderForLocalSite": False},
            {"SiteCode": "PS1", "ProviderForLocalSite": True}]
    assert w.WmiClient._site_code_from_providers(rows) == "PS1"
    # Falls back to the first row when none is flagged local.
    assert w.WmiClient._site_code_from_providers([{"SiteCode": "AAA"}]) == "AAA"
    assert w.WmiClient._site_code_from_providers([]) is None
