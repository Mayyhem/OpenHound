"""Property-level parity regression tests.

Three test layers protect against CMBP/PS1 parity regressions:

1. **Node-property surface** — every new field on a ``<Kind>Properties``
   dataclass actually appears on the emitted node when the source fixture
   carries a value.
2. **Lookup-method behaviour** — the SID-resolution and role-aggregation
   ``SCCMLookup`` methods produce the expected output given synthetic
   ``ldap_computers`` / ``ldap_users`` / ``adminservice_*`` rows in
   in-memory DuckDB.
3. **Edge aggregator** — ``transforms.py`` views all carry a
   ``collection_source`` column and ``_emit_edge`` surfaces it on the
   produced ``Edge``.

These tests are intentionally lean — they construct minimal in-memory
fixtures and exercise the affected code paths without spinning up the
full pipeline.
"""

from __future__ import annotations

import duckdb
import pytest


# ---------------------------------------------------------------------------
# Layer 1 — Node properties surface
# ---------------------------------------------------------------------------


def _props_dict(node):
    """Convert a SCCMNode/properties dataclass to a flat dict of {field: value}.

    Filters out ``None`` so the assertion ``key in props`` reads as
    "the property has a real value" rather than "the slot exists".
    """
    p = node.properties
    if hasattr(p, "__dict__"):
        return {k: v for k, v in p.__dict__.items() if v is not None}
    return {}


def test_sccm_site_node_carries_cmbp_property_surface():
    from openhound_sccm.models.sccm_site import SCCMSite

    site = SCCMSite(
        site_code="PS1",
        site_guid="{deadbeef-0000-0000-0000-000000000001}",
        distinguished_name="CN=SMS-Site-PS1,CN=System Management,CN=System,DC=lab,DC=local",
        source_forest="lab.local",
        site_type="Primary",
        parent_site_code="CAS",
        display_name="Primary Site PS1",
        site_server_name="ps1.lab.local",
        sql_server_name="sql.lab.local",
        sql_database_name="CM_PS1",
        sql_service_account_name="lab\\sqlsvc",
        version="5.00.9135.1001",
        collection_source=["LDAP-mSSMSSite", "AdminService-SMS_Site", "AdminService-SMS_SCI_SiteDefinition"],
    )
    node = site.as_node
    props = _props_dict(node)

    # CMBP-parity property names must all appear with the values we passed in.
    assert props.get("siteCode") == "PS1"
    assert props.get("displayName") == "Primary Site PS1"
    assert props.get("siteServerName") == "ps1.lab.local"
    assert props.get("SQLServerName") == "sql.lab.local"
    assert props.get("SQLDatabaseName") == "CM_PS1"
    # CMBP/PS1 emit the bare sAMAccountName (no DOMAIN\ prefix); we strip in as_node.
    assert props.get("SQLServiceAccountName") == "sqlsvc"
    assert props.get("reportToSite") == "CAS"
    assert props.get("SCCMInfra") is True
    assert props.get("version") == "5.00.9135.1001"
    # versionCVEs is computed via cve_table; this build (5.00.9135.1001) is
    # the SCCM 2503 base, so a non-empty CVE list is expected.
    assert isinstance(props.get("versionCVEs"), list) and len(props["versionCVEs"]) > 0
    assert props.get("collectionSource") and "LDAP-mSSMSSite" in props["collectionSource"]
    # Type marker preserved
    assert props.get("Type") == "SCCM_Site"


def test_sccm_site_node_tolerates_missing_enrichment():
    """When the AdminService fold-in produces nothing, the node still
    emits with the structural minimum (no crash, defaults are None)."""
    from openhound_sccm.models.sccm_site import SCCMSite

    node = SCCMSite(site_code="PS1").as_node
    props = _props_dict(node)
    assert props.get("siteCode") == "PS1"
    assert props.get("SCCMInfra") is True
    # No enrichment ⇒ no displayName/SQL fields.
    assert "SQLServerName" not in props
    assert "siteServerName" not in props


def test_computer_node_carries_site_system_roles_field():
    """SCCMSiteSystemRoles field is declared on ComputerProperties.

    Lookup is None in this synthetic test (no DuckDB), so the field stays
    None — but the dataclass declaration is what matters for the convert
    pipeline (Pydantic ``extra='ignore'`` drops un-declared keys).
    """
    from dataclasses import fields
    from openhound_sccm.models.computer import ComputerProperties

    declared = {f.name for f in fields(ComputerProperties)}
    assert "SCCMSiteSystemRoles" in declared, (
        "ComputerProperties must declare SCCMSiteSystemRoles for CMBP parity; "
        "extra='ignore' on the asset would drop it otherwise."
    )


def test_sccm_admin_user_carries_resolved_id_lists():
    from dataclasses import fields
    from openhound_sccm.models.sccm_admin_user import SCCMAdminUserProperties

    declared = {f.name for f in fields(SCCMAdminUserProperties)}
    assert "securityRoles" in declared
    assert "collectionIDs" in declared


# ---------------------------------------------------------------------------
# Layer 2 — Lookup methods
# ---------------------------------------------------------------------------


@pytest.fixture
def lookup():
    """Stand up an in-memory DuckDB with the minimum schema the lookup methods
    need, run the preproc transforms (so precomputed views like
    ``sccm.computer_sccm_infra`` / ``sccm.host_site_system_roles`` /
    ``sccm.ad_principals`` exist), then hand back a SCCMLookup."""
    from openhound_sccm.lookup import SCCMLookup
    from openhound_sccm.transforms import (
        _build_ad_principals,
        _build_computer_sccm_infra,
        _build_host_site_system_roles,
    )

    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA sccm")

    con.execute("""
        CREATE TABLE sccm.ldap_computers (
            object_sid VARCHAR,
            sam_account_name VARCHAR,
            name VARCHAR,
            dns_host_name VARCHAR,
            domain VARCHAR
        )
    """)
    con.execute("""
        INSERT INTO sccm.ldap_computers VALUES
            ('S-1-5-21-1-1-1-1001', 'PS1$',     'PS1', 'ps1.lab.local',  'lab.local'),
            ('S-1-5-21-1-1-1-1002', 'SQL$',     'SQL', 'sql.lab.local',  'lab.local'),
            ('S-1-5-21-1-1-1-1003', 'SCCMSVR$', 'SCCMSVR', 'sccmsvr.lab.local', 'lab.local')
    """)
    con.execute("""
        CREATE TABLE sccm.ldap_users (
            object_sid VARCHAR,
            sam_account_name VARCHAR,
            user_principal_name VARCHAR
        )
    """)
    con.execute("""
        INSERT INTO sccm.ldap_users VALUES
            ('S-1-5-21-1-1-1-1100', 'sqlsvc', 'sqlsvc@lab.local')
    """)

    con.execute("""
        CREATE TABLE sccm.adminservice_site_systems (
            hostname VARCHAR,
            role VARCHAR,
            site_code VARCHAR
        )
    """)
    con.execute("""
        INSERT INTO sccm.adminservice_site_systems VALUES
            ('ps1.lab.local', 'SMS Site Server', 'PS1'),
            ('ps1.lab.local', 'SMS Management Point', 'PS1'),
            ('sql.lab.local', 'SMS SQL Server', 'PS1')
    """)

    con.execute("""
        CREATE TABLE sccm.hierarchies (
            root_code VARCHAR,
            member_code VARCHAR
        )
    """)
    con.execute("INSERT INTO sccm.hierarchies VALUES ('CAS', 'CAS'), ('CAS', 'PS1')")

    con.execute("""
        CREATE TABLE sccm.adminservice_collections (
            collection_id VARCHAR,
            site_code VARCHAR,
            name VARCHAR
        )
    """)
    con.execute("""
        INSERT INTO sccm.adminservice_collections VALUES
            ('SMS00001', 'PS1', 'All Systems'),
            ('SMS00002', 'PS1', 'All Users and User Groups')
    """)

    con.execute("""
        CREATE TABLE sccm.adminservice_security_roles (
            role_id VARCHAR,
            site_code VARCHAR,
            role_name VARCHAR
        )
    """)
    con.execute("""
        INSERT INTO sccm.adminservice_security_roles VALUES
            ('SMS0001R', 'PS1', 'Full Administrator')
    """)

    # Build the Phase E2 lookup precomputation views. We call the specific
    # builders rather than the full transforms() chain because transforms()
    # rebuilds sccm.hierarchies from sccm.site_types — which would overwrite
    # the fixture's hand-curated hierarchy.
    _build_computer_sccm_infra(con, schema="sccm")
    _build_ad_principals(con, schema="sccm")
    _build_host_site_system_roles(con, schema="sccm")

    return SCCMLookup(con, schema="sccm")


def test_computer_sid_by_hostname_fqdn_match(lookup):
    assert lookup.computer_sid_by_hostname("sql.lab.local") == "S-1-5-21-1-1-1-1002"


def test_computer_sid_by_hostname_short_match(lookup):
    assert lookup.computer_sid_by_hostname("PS1") == "S-1-5-21-1-1-1-1001"


def test_computer_sid_by_hostname_returns_none_when_unknown(lookup):
    assert lookup.computer_sid_by_hostname("unknown.example.com") is None


def test_principal_sid_by_account_name_user(lookup):
    assert lookup.principal_sid_by_account_name("LAB\\sqlsvc") == "S-1-5-21-1-1-1-1100"


def test_principal_sid_by_account_name_bare(lookup):
    assert lookup.principal_sid_by_account_name("sqlsvc") == "S-1-5-21-1-1-1-1100"


def test_principal_sid_by_account_name_falls_back_to_computer(lookup):
    # Computer with sam_account_name SCCMSVR$ should match when the
    # service account is the gMSA form 'SCCMSVR$'.
    assert lookup.principal_sid_by_account_name("LAB\\SCCMSVR$") == "S-1-5-21-1-1-1-1003"


def test_computer_site_system_roles_aggregates_all_roles(lookup):
    roles = lookup.computer_site_system_roles("S-1-5-21-1-1-1-1001", "ps1.lab.local")
    assert "SMS Site Server@PS1" in roles
    assert "SMS Management Point@PS1" in roles


def test_admin_user_collection_ids_uses_provider_site(lookup):
    # PS1 emits one SCCM_Collection node per SMS Provider (site_code), so
    # admin lookups must use the provider's raw site_code rather than the
    # hierarchy root. The fixture row carries site_code=PS1.
    ids = lookup.admin_user_collection_ids(("All Systems",), "PS1")
    assert ids == ("SMS00001@PS1",)


def test_admin_user_role_ids_uses_provider_site(lookup):
    # Same per-provider behaviour as the collection lookup above.
    ids = lookup.admin_user_role_ids(("Full Administrator",), "PS1")
    assert ids == ("SMS0001R@PS1",)


# ---------------------------------------------------------------------------
# Layer 3 — Edge aggregator collection_source plumbing
# ---------------------------------------------------------------------------


def test_emit_edge_attaches_collection_source():
    from openhound_sccm.models.derived.aggregator import _emit_edge

    edge = _emit_edge("S-1-5-21-1-1-1-1001", "PS1", "SCCM_Contains",
                     collection_source="AdminService-SMS_Admin")
    assert edge is not None
    # The SCCMEdgeProperties dataclass carries collectionSource as a list[str].
    props = edge.properties
    cs = getattr(props, "collectionSource", None)
    assert cs == ["AdminService-SMS_Admin"], (
        f"Expected collectionSource=['AdminService-SMS_Admin'], got {cs!r}"
    )


def test_emit_edge_without_source_still_traversable():
    """Edges without a collection_source still fire — they just don't carry
    the source tag. Used by upstream calls that haven't been migrated yet."""
    from openhound_sccm.models.derived.aggregator import _emit_edge

    edge = _emit_edge("a", "b", "SAME_HOST_AS")
    assert edge is not None
    assert getattr(edge.properties, "traversable", False) is True


def test_emit_edge_drops_empty_endpoints():
    from openhound_sccm.models.derived.aggregator import _emit_edge
    assert _emit_edge("", "b", "X") is None
    assert _emit_edge("a", "", "X") is None


def test_empty_schemas_declare_collection_source_for_every_edge_view():
    """Regression guard: every edge view must have a collection_source column
    in its empty-schema declaration so the aggregator read loops can SELECT it
    even when the upstream data is missing."""
    from openhound_sccm.transforms import _EMPTY_SCHEMAS

    edge_tables = [name for name in _EMPTY_SCHEMAS if name.endswith("_edges")]
    missing = [
        name for name in edge_tables
        if "collection_source" not in _EMPTY_SCHEMAS[name].lower()
    ]
    assert not missing, f"Edge views missing collection_source column: {missing}"


# ---------------------------------------------------------------------------
# CVE table smoke test (used by SCCM_Site.as_node)
# ---------------------------------------------------------------------------


def test_cve_table_known_build_returns_cves():
    from openhound_sccm.cve_table import lookup_cves

    # SCCM 2503 base build — patches none of the listed CVEs.
    cves = lookup_cves("5.00.9135.1001")
    assert isinstance(cves, list)
    # The base build should be vulnerable to at least one of the listed CVEs.
    assert len(cves) > 0


def test_cve_table_unknown_version_returns_empty():
    from openhound_sccm.cve_table import lookup_cves
    assert lookup_cves("9.99.9999.9999") == []
    assert lookup_cves("") == []
    assert lookup_cves(None) == []
