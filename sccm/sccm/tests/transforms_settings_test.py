# src/openhound_sccm/transforms_settings_test.py
import duckdb
from openhound_sccm.transforms import _read_disable_possible


def test_read_disable_possible_absent_defaults_false():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    assert _read_disable_possible(con, "sccm") is False


def test_read_disable_possible_true():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.collection_settings AS "
                "SELECT true AS disable_possible_edges, false AS enable_bad_opsec")
    assert _read_disable_possible(con, "sccm") is True


def test_read_disable_possible_false():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.collection_settings AS "
                "SELECT false AS disable_possible_edges, false AS enable_bad_opsec")
    assert _read_disable_possible(con, "sccm") is False
