"""Unit tests for ObjectIdentifier construction (`openhound_mssql.ids`).

The expected IDs are taken from MSSQLHound's Go output / fixtures so the
emitted graph keys line up with the validators.
"""

from openhound_mssql import ids

# A representative resolved computer SID (matches the spec/Go examples).
COMPUTER_SID = "S-1-5-21-1004336348-1177238915-682003330-1001"
SERVER_OID = f"{COMPUTER_SID}:1433"


def test_server_oid_sid_default_instance():
    # Resolved SID + default instance keys by port.
    assert (
        ids.server_oid(COMPUTER_SID, "ps1-db.mayyhem.com", "MSSQLSERVER", 1433)
        == SERVER_OID
    )


def test_server_oid_sid_empty_instance_uses_port():
    # Empty instance name also keys by port.
    assert ids.server_oid(COMPUTER_SID, "ps1-db", "", 1433) == SERVER_OID


def test_server_oid_named_instance_keys_by_instance():
    # A non-default instance keys by instance name, not port.
    assert (
        ids.server_oid(COMPUTER_SID, "ps1-db", "SQLEXPRESS", 1433)
        == f"{COMPUTER_SID}:SQLEXPRESS"
    )


def test_server_oid_hostname_fallback_lowercased():
    # No SID -> lowercased hostname base, keyed by port for default instance.
    assert ids.server_oid(None, "PS1-DB.MAYYHEM.COM", "MSSQLSERVER", 1433) == (
        "ps1-db.mayyhem.com:1433"
    )


def test_server_oid_hostname_fallback_named_instance():
    assert ids.server_oid("", "PS1-DB", "SQLEXPRESS", 1433) == "ps1-db:SQLEXPRESS"


def test_principal_oid():
    assert ids.principal_oid("sa", SERVER_OID) == f"sa@{SERVER_OID}"
    assert ids.principal_oid("sysadmin", SERVER_OID) == f"sysadmin@{SERVER_OID}"


def test_database_oid():
    assert ids.database_oid(SERVER_OID, "msdb") == f"{SERVER_OID}\\msdb"


def test_db_principal_oid_dbo():
    # Matches the Go example: dbo@<serverOID>\msdb
    assert ids.db_principal_oid("dbo", SERVER_OID, "msdb") == f"dbo@{SERVER_OID}\\msdb"


def test_db_principal_oid_public():
    # Matches the Go example: public@<serverOID>\msdb
    assert (
        ids.db_principal_oid("public", SERVER_OID, "msdb")
        == f"public@{SERVER_OID}\\msdb"
    )


def test_extract_db_id_returns_database_oid():
    # extract_db_id splits on the first "@" and returns the part after it,
    # which for a db-principal OID is exactly the database OID.
    db_oid = ids.database_oid(SERVER_OID, "msdb")
    principal = ids.db_principal_oid("dbo", SERVER_OID, "msdb")
    assert ids.extract_db_id(principal) == db_oid


def test_extract_db_id_roundtrip_public():
    db_oid = ids.database_oid(SERVER_OID, "msdb")
    assert ids.extract_db_id(f"public@{db_oid}") == db_oid


def test_extract_db_id_no_at_returns_input():
    # Go returns the input unchanged when there is no "@".
    assert ids.extract_db_id(SERVER_OID) == SERVER_OID


def test_extract_db_id_splits_on_first_at_only():
    # Only the first "@" is the delimiter; later "@"s stay in the result.
    assert ids.extract_db_id("a@b@c") == "b@c"


def test_rewrite_server_id_principals_and_databases():
    old = "ps1-db:1433"
    new = SERVER_OID
    objs = [
        {"object_identifier": f"sa@{old}", "kind": "login"},
        {"object_identifier": f"{old}\\msdb", "kind": "database"},
        {"object_identifier": f"dbo@{old}\\msdb", "kind": "db_principal"},
        {"object_identifier": "unrelated-value", "n": 5},
    ]
    ids.rewrite_server_id(old, new, objs)
    assert objs[0]["object_identifier"] == f"sa@{new}"
    assert objs[1]["object_identifier"] == f"{new}\\msdb"
    assert objs[2]["object_identifier"] == f"dbo@{new}\\msdb"
    # Unrelated values and non-strings are left untouched.
    assert objs[3]["object_identifier"] == "unrelated-value"
    assert objs[3]["n"] == 5
