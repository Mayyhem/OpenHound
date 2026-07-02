"""Unit tests for the MSSQL graph dataclasses (`openhound_mssql.graph`).

Convert serializes via `dataclasses.asdict`, so these tests build a node and
an edge, run `asdict`, and assert the JSON shape from spec §7 plus the exact
MSSQLHound camelCase property names (decision D11).
"""

from dataclasses import asdict

from openhound.core.models.entries_dataclass import Edge, EdgePath

from openhound_mssql import graph, ids
from openhound_mssql.kinds import edges, nodes

COMPUTER_SID = "S-1-5-21-1004336348-1177238915-682003330-1001"
SERVER_OID = ids.server_oid(COMPUTER_SID, "ps1-db.mayyhem.com", "MSSQLSERVER", 1433)


def _build_server_node() -> graph.MSSQLNode:
    props = graph.ServerProperties(
        name="ps1-db.mayyhem.com:1433",
        displayname="ps1-db.mayyhem.com:1433",
        environmentid=SERVER_OID,
        hostname="ps1-db.mayyhem.com",
        fqdn="ps1-db.mayyhem.com",
        sqlServerName="PS1-DB",
        port=1433,
        isMixedModeAuthEnabled=True,
        isClustered=False,
        servicePrincipalNames=["MSSQLSvc/ps1-db.mayyhem.com:1433"],
        databases=["master", "msdb"],
        isAnyDomainPrincipalSysadmin=True,
        domainPrincipalsWithSysadmin=[f"jdoe@{SERVER_OID}"],
    )
    return graph.MSSQLNode(
        kinds=[nodes.SERVER],
        properties=props,
        object_identifier=SERVER_OID,
        icon=nodes.ICONS[nodes.SERVER],
    )


def test_server_node_post_init_sets_id():
    node = _build_server_node()
    assert node.id == SERVER_OID


def test_server_node_shape():
    node = _build_server_node()
    d = asdict(node)
    # Node envelope: id / kinds / properties (+ icon).
    assert d["id"] == SERVER_OID
    assert d["kinds"] == [nodes.SERVER]
    assert d["icon"]["name"] == "server"
    assert "properties" in d


def test_server_node_property_names_exact_camelcase():
    node = _build_server_node()
    props = asdict(node)["properties"]
    # Exact MSSQLHound camelCase names (D11) — no snake_case.
    for key in (
        "isMixedModeAuthEnabled",
        "sqlServerName",
        "servicePrincipalNames",
        "isAnyDomainPrincipalSysadmin",
        "domainPrincipalsWithSysadmin",
        "isClustered",
    ):
        assert key in props, key
    assert props["isMixedModeAuthEnabled"] is True
    assert props["servicePrincipalNames"] == ["MSSQLSvc/ps1-db.mayyhem.com:1433"]
    # Framework base fields stay present (additive, harmless).
    for base in ("name", "displayname", "environmentid", "last_seen"):
        assert base in props


def test_database_node_property_names_exact():
    db_oid = ids.database_oid(SERVER_OID, "msdb")
    props = graph.DatabaseProperties(
        name="msdb",
        displayname="msdb",
        environmentid=SERVER_OID,
        databaseId=4,
        SQLServer="PS1-DB",
        SQLServerID=SERVER_OID,
        ownerPrincipalID="1",
        OwnerObjectIdentifier=f"sa@{SERVER_OID}",
        isTrustworthy=True,
    )
    node = graph.MSSQLNode(
        kinds=[nodes.DATABASE],
        properties=props,
        object_identifier=db_oid,
        icon=nodes.ICONS[nodes.DATABASE],
    )
    d = asdict(node)["properties"]
    assert d["SQLServer"] == "PS1-DB"
    assert d["SQLServerID"] == SERVER_OID
    assert d["ownerPrincipalID"] == "1"
    assert d["OwnerObjectIdentifier"] == f"sa@{SERVER_OID}"
    assert d["isTrustworthy"] is True


def test_memberof_edge_shape():
    start = f"jdoe@{SERVER_OID}"
    end = f"sysadmin@{SERVER_OID}"
    edge = Edge(
        kind=edges.MEMBER_OF,
        start=EdgePath(match_by="id", value=start),
        end=EdgePath(match_by="id", value=end),
        properties=graph.MSSQLEdgeProperties(
            traversable=True,
            general="Member of the sysadmin server role.",
            windowsAbuse="...",
        ),
    )
    d = asdict(edge)
    # Edge envelope: kind / start / end / properties (spec §7).
    assert d["kind"] == "MSSQL_MemberOf"
    assert d["start"]["value"] == start
    assert d["end"]["value"] == end
    # Edge property names are verbatim MSSQLHound keys.
    assert d["properties"]["general"] == "Member of the sysadmin server role."
    assert d["properties"]["windowsAbuse"] == "..."
    assert d["properties"]["traversable"] is True
    # Injected typed props exist on the dataclass (default None when unset).
    assert d["properties"]["ownerPrincipalID"] is None
    assert d["properties"]["credentialId"] is None
    assert d["properties"]["proxyId"] is None


def test_owns_edge_injected_owner_principal_id():
    edge = Edge(
        kind=edges.OWNS,
        start=EdgePath(match_by="id", value=f"sa@{SERVER_OID}"),
        end=EdgePath(match_by="id", value=ids.database_oid(SERVER_OID, "msdb")),
        properties=graph.MSSQLEdgeProperties(traversable=True, ownerPrincipalID="1"),
    )
    d = asdict(edge)
    assert d["kind"] == "MSSQL_Owns"
    assert d["properties"]["ownerPrincipalID"] == "1"
