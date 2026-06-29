"""Unit tests for target discovery + classification (`collection.targets`).

Ported 1:1 from the Go reference's table-driven tests
``MSSQLHound/cmd/mssqlhound/main_test.go``:

  * ``TestClassifyTarget``        -> :func:`test_classify_target`
  * ``TestExtractTargetCredentials`` -> :func:`test_extract_target_credentials`
  * ``TestParsePortList``         -> :func:`test_parse_port_list`

The Go ``classifyTarget`` returns ``(instance, listFile, list)`` (exactly one
non-empty); the Python port collapses that to ``(kind, payload)``. Each Go row is
translated to the equivalent ``(kind, payload)`` expectation.
"""

from __future__ import annotations

import pytest

from openhound_mssql.collection import targets


# ---------------------------------------------------------------------------
# classify_target  (Go TestClassifyTarget)
# ---------------------------------------------------------------------------
def test_classify_target(tmp_path):
    # Existing file → ("file", path), like Go's wantListFile.
    server_file = tmp_path / "servers.txt"
    server_file.write_text("host1\nhost2\n", encoding="utf-8")
    server_file_str = str(server_file)

    cases = [
        # name, input, expected (kind, payload)
        ("empty input", "", ("instance", "")),
        ("single hostname", "sqlserver1", ("instance", "sqlserver1")),
        ("hostname with port (colon)", "sqlserver1:1433", ("instance", "sqlserver1:1433")),
        ("hostname with named instance", "sqlserver1\\SQLEXPRESS", ("instance", "sqlserver1\\SQLEXPRESS")),
        ("SPN format", "MSSQLSvc/sqlserver1.domain.com:1433", ("instance", "MSSQLSvc/sqlserver1.domain.com:1433")),
        ("SPN format with instance name", "MSSQLSvc/sqlserver1.domain.com:SQLEXPRESS", ("instance", "MSSQLSvc/sqlserver1.domain.com:SQLEXPRESS")),
        ("FQDN", "sqlserver1.domain.com", ("instance", "sqlserver1.domain.com")),
        ("FQDN with port", "sqlserver1.domain.com:1434", ("instance", "sqlserver1.domain.com:1434")),
        ("comma-separated list", "host1,host2,host3", ("list", "host1,host2,host3")),
        ("comma-separated with ports", "host1:1433,host2:1434", ("list", "host1:1433,host2:1434")),
        ("file path", server_file_str, ("file", server_file_str)),
        # A non-existent path is treated as a hostname (single instance).
        ("non-existent file path treated as hostname", "/no/such/file.txt", ("instance", "/no/such/file.txt")),
    ]
    for name, value, expected in cases:
        assert targets.classify_target(value) == expected, name


# ---------------------------------------------------------------------------
# extract_target_credentials  (Go TestExtractTargetCredentials)
# ---------------------------------------------------------------------------
def test_extract_target_credentials():
    cases = [
        # name, input, (user, pass, target, ok)
        ("simple hostname", "sa:password@sqlserver1", ("sa", "password", "sqlserver1", True)),
        ("hostname with port", "sa:password@sqlserver1:1433", ("sa", "password", "sqlserver1:1433", True)),
        ("FQDN", "sa:password@sqlserver1.domain.com", ("sa", "password", "sqlserver1.domain.com", True)),
        ("named instance", "sa:password@sqlserver1\\SQLEXPRESS", ("sa", "password", "sqlserver1\\SQLEXPRESS", True)),
        ("SPN format", "sa:password@MSSQLSvc/sqlserver1.domain.com:1433", ("sa", "password", "MSSQLSvc/sqlserver1.domain.com:1433", True)),
        # DOMAIN\admin:P@ssw0rd@sqlserver1 — split on LAST @, FIRST :.
        ("domain backslash user", "DOMAIN\\admin:P@ssw0rd@sqlserver1", ("DOMAIN\\admin", "P@ssw0rd", "sqlserver1", True)),
        # UPN user survives because we split on the LAST @.
        ("UPN user (user@domain)", "admin@domain.com:secret@sqlserver1", ("admin@domain.com", "secret", "sqlserver1", True)),
        # Password containing ':' survives because we split creds on the FIRST :.
        ("password with special chars", "sa:p@ss:w0rd!@sqlserver1", ("sa", "p@ss:w0rd!", "sqlserver1", True)),
        ("empty password", "sa:@sqlserver1", ("sa", "", "sqlserver1", True)),
        # not-ok cases: original value returned unchanged as the target.
        ("no credentials - plain hostname", "sqlserver1", ("", "", "sqlserver1", False)),
        ("no colon - not credentials", "user@sqlserver1", ("", "", "user@sqlserver1", False)),
        ("empty user", ":password@sqlserver1", ("", "", ":password@sqlserver1", False)),
        ("empty target", "sa:password@", ("", "", "sa:password@", False)),
    ]
    for name, value, expected in cases:
        assert targets.extract_target_credentials(value) == expected, name


# ---------------------------------------------------------------------------
# parse_port_list  (Go TestParsePortList)
# ---------------------------------------------------------------------------
def test_parse_port_list_ok():
    assert targets.parse_port_list("1433") == [1433]
    assert targets.parse_port_list("1433,1444,51433") == [1433, 1444, 51433]
    # Spaces are trimmed and duplicates collapsed (first-seen order kept).
    assert targets.parse_port_list(" 1433, 1444,1433 ") == [1433, 1444]


@pytest.mark.parametrize(
    "value",
    [
        "",            # empty
        "1433,,1444",  # empty item
        "1433,abc",    # not numeric
        "0",           # zero (below range)
        "65536",       # above range
    ],
)
def test_parse_port_list_errors(value):
    with pytest.raises(ValueError):
        targets.parse_port_list(value)


# ---------------------------------------------------------------------------
# extract_and_apply_credentials  (Go extractAndApplyCredentials behaviour)
# ---------------------------------------------------------------------------
class _Cfg:
    """Minimal duck-typed config for the credential-application tests."""

    def __init__(self, user=None, password=None):
        self.user = user
        self.password = password


def test_extract_and_apply_credentials_single():
    cfg = _Cfg()
    cleaned = targets.extract_and_apply_credentials("sa:password@sqlserver1", cfg)
    assert cleaned == "sqlserver1"
    assert cfg.user == "sa"
    assert cfg.password == "password"


def test_extract_and_apply_credentials_first_match_wins():
    cfg = _Cfg()
    cleaned = targets.extract_and_apply_credentials(
        "sa:pw1@host1,admin:pw2@host2,host3", cfg
    )
    assert cleaned == "host1,host2,host3"
    # First entry with credentials wins.
    assert cfg.user == "sa"
    assert cfg.password == "pw1"


def test_extract_and_apply_credentials_does_not_override_existing_user():
    cfg = _Cfg(user="preset", password="presetpw")
    cleaned = targets.extract_and_apply_credentials("sa:password@sqlserver1", cfg)
    # Target is still cleaned, but cfg creds are left untouched.
    assert cleaned == "sqlserver1"
    assert cfg.user == "preset"
    assert cfg.password == "presetpw"


def test_extract_and_apply_credentials_no_creds():
    cfg = _Cfg()
    cleaned = targets.extract_and_apply_credentials("host1,host2", cfg)
    assert cleaned == "host1,host2"
    assert cfg.user is None
    assert cfg.password is None


# ---------------------------------------------------------------------------
# parse_server_string  (Go parseServerString behaviour)
# ---------------------------------------------------------------------------
def test_parse_server_string_bare_host():
    t = targets.parse_server_string("sqlserver1")
    assert (t.host, t.port, t.instance) == ("sqlserver1", 1433, "")


def test_parse_server_string_host_port():
    t = targets.parse_server_string("sqlserver1:1434")
    assert (t.host, t.port, t.instance) == ("sqlserver1", 1434, "")


def test_parse_server_string_host_instance_via_colon():
    # A non-numeric after ':' is an instance name.
    t = targets.parse_server_string("sqlserver1:SQLEXPRESS")
    assert (t.host, t.port, t.instance) == ("sqlserver1", 1433, "SQLEXPRESS")


def test_parse_server_string_host_backslash_instance():
    t = targets.parse_server_string("sqlserver1\\SQLEXPRESS")
    assert (t.host, t.port, t.instance) == ("sqlserver1", 1433, "SQLEXPRESS")


def test_parse_server_string_spn_prefix_stripped():
    t = targets.parse_server_string("MSSQLSvc/sqlserver1.domain.com:1433")
    assert (t.host, t.port, t.instance) == ("sqlserver1.domain.com", 1433, "")


def test_parse_server_string_spn_with_instance():
    t = targets.parse_server_string("MSSQLSvc/sqlserver1.domain.com:SQLEXPRESS")
    assert (t.host, t.port, t.instance) == ("sqlserver1.domain.com", 1433, "SQLEXPRESS")


def test_parse_server_string_host_comma_port():
    t = targets.parse_server_string("sqlserver1,1434")
    assert (t.host, t.port, t.instance) == ("sqlserver1", 1434, "")


# ---------------------------------------------------------------------------
# Target.finalize / ObjectIdentifier construction
# ---------------------------------------------------------------------------
def test_target_finalize_hostname_default_instance_keys_by_port():
    t = targets.Target(host="PS1-DB.MAYYHEM.COM", port=1433).finalize()
    assert t.object_identifier == "ps1-db.mayyhem.com:1433"


def test_target_finalize_named_instance_keys_by_instance():
    t = targets.Target(host="ps1-db", port=1433, instance="SQLEXPRESS").finalize()
    assert t.object_identifier == "ps1-db:SQLEXPRESS"


def test_target_finalize_sid_keys_by_sid():
    sid = "S-1-5-21-1004336348-1177238915-682003330-1001"
    t = targets.Target(host="ps1-db", port=1433, object_sid=sid).finalize()
    assert t.object_identifier == f"{sid}:1433"
