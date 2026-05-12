"""Unit tests for ``SourceContext.method_enabled`` (the ``-m / --collection-methods``
flag's gating logic).

Replicates the matching semantics of CMBP's ``-m`` flag: comma-separated method
names, case-insensitive, with the literal ``All`` keyword enabling every
method. Whitespace tolerant. Empty / missing value treated as ``"All"``.
"""

from __future__ import annotations

import pytest

from openhound_sccm.clients.ad import ADClient, ADCredentials
from openhound_sccm.source import SourceContext


def _ctx(methods: str) -> SourceContext:
    """Build a minimal ``SourceContext`` for gating tests.

    The ``ADClient`` is constructed but never actually connects since
    ``method_enabled`` doesn't touch it. Domain / DC values are bogus.
    """
    creds = ADCredentials(
        domain="example.com",
        domain_controller="dc.example.com",
        username=None,
        password=None,
    )
    return SourceContext(
        ad=ADClient(creds),
        domain="example.com",
        collection_methods=methods,
    )


@pytest.mark.parametrize("method", [
    "LDAP", "Local", "DNS", "DHCP", "RemoteRegistry",
    "MSSQL", "AdminService", "WMI", "HTTP", "SMB",
])
def test_all_enables_every_method(method):
    assert _ctx("All").method_enabled(method)


@pytest.mark.parametrize("methods,expected", [
    ("LDAP", "LDAP"),
    ("ldap", "LDAP"),
    ("LDAP,SMB", "SMB"),
    ("ldap, smb , wmi", "WMI"),
])
def test_single_method_csv_is_case_insensitive(methods, expected):
    assert _ctx(methods).method_enabled(expected)


def test_method_not_in_list_returns_false():
    ctx = _ctx("LDAP,SMB")
    assert not ctx.method_enabled("AdminService")
    assert not ctx.method_enabled("MSSQL")
    assert not ctx.method_enabled("HTTP")


def test_empty_collection_methods_acts_like_all():
    """An empty string defaults to enabling everything (matches CMBP)."""
    ctx = _ctx("")
    assert ctx.method_enabled("AdminService")
    assert ctx.method_enabled("MSSQL")


def test_all_with_extra_methods_still_enables_all():
    """If 'All' is anywhere in the list, every method is enabled."""
    ctx = _ctx("LDAP,All,SMB")
    assert ctx.method_enabled("MSSQL")


def test_unknown_method_name_returns_false():
    ctx = _ctx("LDAP")
    assert not ctx.method_enabled("NotARealMethod")


def test_whitespace_tolerant():
    ctx = _ctx("  LDAP ,  SMB  ")
    assert ctx.method_enabled("LDAP")
    assert ctx.method_enabled("SMB")
