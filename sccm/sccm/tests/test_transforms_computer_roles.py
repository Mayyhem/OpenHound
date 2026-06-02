import duckdb
import pytest
from openhound_sccm.transforms import transforms

SCHEMA = "sccm"


@pytest.fixture
def con():
    conn = duckdb.connect(":memory:")
    conn.execute(f"CREATE SCHEMA {SCHEMA}")
    yield conn
    conn.close()


@pytest.fixture
def con_with_raw(con):
    con.execute(f"""
        CREATE TABLE {SCHEMA}.ldap_management_points_raw (
            mp_hostname VARCHAR,
            site_code VARCHAR,
            site_type VARCHAR,
            parent_site_code VARCHAR,
            command_line_site_code VARCHAR,
            root_site_code VARCHAR,
            fsp_hostname VARCHAR
        )
    """)
    con.execute(f"""
        INSERT INTO {SCHEMA}.ldap_management_points_raw VALUES
        ('mp.contoso.com', 'PS1', 'Primary Site', 'CAS', 'PS1', 'CAS', 'fsp1.contoso.com'),
        ('cas-mp.contoso.com', 'CAS', 'Central Administration Site', 'None', 'PS1', 'CAS', NULL),
        (NULL, 'SEC', 'Secondary Site', 'PS1', NULL, 'PS1', NULL)
    """)
    return con


def test_site_types_built(con_with_raw):
    transforms(con_with_raw)
    rows = con_with_raw.execute(
        f"SELECT site_code, site_type, parent_site_code FROM {SCHEMA}.site_types ORDER BY site_code"
    ).fetchall()
    assert ("CAS", "Central Administration Site", "None") in rows
    assert ("PS1", "Primary Site", "CAS") in rows
    assert ("SEC", "Secondary Site", "PS1") in rows


def test_computer_mp_roles_built(con_with_raw):
    transforms(con_with_raw)
    rows = con_with_raw.execute(
        f"SELECT hostname, role FROM {SCHEMA}.computer_mp_roles"
    ).fetchall()
    assert ("mp.contoso.com", "SMS Management Point@PS1") in rows
    assert ("cas-mp.contoso.com", "SMS Management Point@CAS") in rows


def test_computer_mp_roles_excludes_null_hostname(con_with_raw):
    transforms(con_with_raw)
    rows = con_with_raw.execute(
        f"SELECT hostname FROM {SCHEMA}.computer_mp_roles WHERE hostname IS NULL"
    ).fetchall()
    assert rows == []


def test_computer_fsp_roles_built(con_with_raw):
    transforms(con_with_raw)
    rows = con_with_raw.execute(
        f"SELECT hostname, role FROM {SCHEMA}.computer_fsp_roles ORDER BY hostname"
    ).fetchall()
    assert ("fsp1.contoso.com", "SMS Fallback Status Point@PS1") in rows
    assert len(rows) == 1  # CAS and SEC rows had no fsp_hostname


def test_computer_site_system_roles_union(con_with_raw):
    transforms(con_with_raw)
    rows = con_with_raw.execute(
        f"SELECT hostname, role FROM {SCHEMA}.computer_site_system_roles ORDER BY hostname"
    ).fetchall()
    hostnames = [r[0] for r in rows]
    assert "mp.contoso.com" in hostnames
    assert "fsp1.contoso.com" in hostnames
    assert "cas-mp.contoso.com" in hostnames


def test_graceful_degradation_no_raw_table(con):
    # transforms() must not crash when ldap_management_points_raw is absent
    transforms(con)
    # empty placeholder tables should exist
    for table in ("site_types", "computer_mp_roles", "computer_fsp_roles", "computer_site_system_roles"):
        count = con.execute(
            f"SELECT COUNT(*) FROM information_schema.tables "
            f"WHERE table_schema = '{SCHEMA}' AND table_name = '{table}'"
        ).fetchone()[0]
        assert count == 1, f"Expected placeholder table {table} to exist"
