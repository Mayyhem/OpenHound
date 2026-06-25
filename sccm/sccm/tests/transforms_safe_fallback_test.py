"""Tests for _safe() fallback-mirror log-level logic.

The SCCM collector produces EITHER wmi_<X> OR adminservice_<X> tables per
data type, depending on which transport was used. When only one family is
present, every _safe() call referencing the absent sibling would previously
log a WARNING, creating noise in routine operation.

After the fix:
  - Missing wmi_<X> when adminservice_<X> exists  -> DEBUG
  - Missing adminservice_<X> when wmi_<X> exists   -> DEBUG
  - Missing table with no sibling at all           -> WARNING  (unchanged)
"""
import logging

import duckdb
import pytest

from openhound_sccm.transforms import _safe


# ---------------------------------------------------------------------------
# (a) wmi_foo absent but adminservice_foo present -> DEBUG, not WARNING
# ---------------------------------------------------------------------------

def test_safe_wmi_miss_with_adminservice_sibling_logs_debug(caplog):
    """Missing wmi_foo when adminservice_foo exists must log at DEBUG."""
    con = duckdb.connect(":memory:")
    # Seed the adminservice sibling but NOT the wmi table.
    con.execute("CREATE SCHEMA sccm")
    con.execute("CREATE TABLE sccm.adminservice_foo (id INTEGER)")
    con.execute("INSERT INTO sccm.adminservice_foo VALUES (1)")

    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.transforms"):
        _safe(
            con,
            "test<-wmi_foo",
            "INSERT INTO sccm.adminservice_foo SELECT id FROM sccm.wmi_foo",
        )

    # Find the log record that mentions this label.
    relevant = [r for r in caplog.records if "test<-wmi_foo" in r.message]
    assert relevant, "Expected at least one log record mentioning test<-wmi_foo"
    for rec in relevant:
        assert rec.levelno == logging.DEBUG, (
            f"Expected DEBUG for expected fallback miss, got {rec.levelname}: {rec.message}"
        )


# ---------------------------------------------------------------------------
# (b) adminservice_bar absent but wmi_bar present -> DEBUG, not WARNING
# ---------------------------------------------------------------------------

def test_safe_adminservice_miss_with_wmi_sibling_logs_debug(caplog):
    """Missing adminservice_bar when wmi_bar exists must log at DEBUG."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA sccm")
    con.execute("CREATE TABLE sccm.wmi_bar (id INTEGER)")
    con.execute("INSERT INTO sccm.wmi_bar VALUES (2)")

    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.transforms"):
        _safe(
            con,
            "test<-adminservice_bar",
            "INSERT INTO sccm.wmi_bar SELECT id FROM sccm.adminservice_bar",
        )

    relevant = [r for r in caplog.records if "test<-adminservice_bar" in r.message]
    assert relevant, "Expected at least one log record mentioning test<-adminservice_bar"
    for rec in relevant:
        assert rec.levelno == logging.DEBUG, (
            f"Expected DEBUG for expected fallback miss, got {rec.levelname}: {rec.message}"
        )


# ---------------------------------------------------------------------------
# (c) No sibling at all -> WARNING (the old behaviour must be preserved)
# ---------------------------------------------------------------------------

def test_safe_no_sibling_logs_warning(caplog):
    """Missing table with no wmi_/adminservice_ sibling must still log at WARNING."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA sccm")
    # Neither sccm.adminservice_baz nor sccm.wmi_baz exists.

    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.transforms"):
        _safe(
            con,
            "test<-wmi_baz",
            "SELECT 1 FROM sccm.wmi_baz",
        )

    relevant = [r for r in caplog.records if "test<-wmi_baz" in r.message]
    assert relevant, "Expected at least one log record mentioning test<-wmi_baz"
    warning_records = [r for r in relevant if r.levelno == logging.WARNING]
    assert warning_records, (
        f"Expected WARNING when no sibling exists; got levels: {[r.levelname for r in relevant]}"
    )
