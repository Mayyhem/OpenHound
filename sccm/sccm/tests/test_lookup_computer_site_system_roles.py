import duckdb
import pytest
from openhound_sccm.lookup import SCCMLookup

SCHEMA = "sccm"


@pytest.fixture
def con():
    conn = duckdb.connect(":memory:")
    conn.execute(f"CREATE SCHEMA {SCHEMA}")
    conn.execute(f"""
        CREATE TABLE {SCHEMA}.computer_site_system_roles (
            hostname VARCHAR,
            role VARCHAR,
            site_code VARCHAR
        )
    """)
    conn.execute(f"""
        INSERT INTO {SCHEMA}.computer_site_system_roles VALUES
        ('mp.contoso.com',  'SMS Management Point@PS1',       'PS1'),
        ('fsp.contoso.com', 'SMS Fallback Status Point@PS1',  'PS1'),
        ('multi.contoso.com', 'SMS Management Point@PS1',     'PS1'),
        ('multi.contoso.com', 'SMS Fallback Status Point@PS1','PS1')
    """)
    yield conn
    conn.close()


@pytest.fixture
def lookup(con):
    return SCCMLookup(con, schema=SCHEMA)


def test_fqdn_match(lookup):
    roles = lookup.computer_site_system_roles("S-1-5-21-1", "mp.contoso.com")
    assert "SMS Management Point@PS1" in roles


def test_short_name_match(lookup):
    # hostname stored as FQDN should still match when only short name is given
    roles = lookup.computer_site_system_roles("S-1-5-21-2", "fsp")
    assert "SMS Fallback Status Point@PS1" in roles


def test_case_insensitive(lookup):
    roles = lookup.computer_site_system_roles("S-1-5-21-3", "MP.CONTOSO.COM")
    assert "SMS Management Point@PS1" in roles


def test_multiple_roles_for_one_host(lookup):
    roles = lookup.computer_site_system_roles("S-1-5-21-4", "multi.contoso.com")
    assert "SMS Management Point@PS1" in roles
    assert "SMS Fallback Status Point@PS1" in roles


def test_no_match_returns_empty_tuple(lookup):
    roles = lookup.computer_site_system_roles("S-1-5-21-5", "unknown.contoso.com")
    assert roles == ()


def test_none_dns_returns_empty_tuple(lookup):
    roles = lookup.computer_site_system_roles("S-1-5-21-6", None)
    assert roles == ()


def test_missing_table_returns_empty_tuple(con):
    con.execute(f"DROP TABLE {SCHEMA}.computer_site_system_roles")
    lkp = SCCMLookup(con, schema=SCHEMA)
    roles = lkp.computer_site_system_roles("S-1-5-21-7", "mp.contoso.com")
    assert roles == ()
