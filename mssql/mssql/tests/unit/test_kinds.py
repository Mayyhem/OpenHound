"""Unit tests for node/edge kind constants and traversability partitions.

Cross-checks the edge-kind master set against MSSQLHound's authoritative
38 `knownEdgeTypes` and asserts the three traversability partitions are
disjoint and exhaustive, matching the Go `IsTraversableEdge` switch + the
`PossibleEdgeKinds` list.
"""

from openhound_mssql.kinds import edges, nodes

# The 38 authoritative edge types from MSSQLHound's
# internal/collector/integration_report_test.go `knownEdgeTypes`.
KNOWN_EDGE_TYPES = frozenset(
    {
        "HasSession",
        "MSSQL_AddMember",
        "MSSQL_Alter",
        "MSSQL_AlterAnyAppRole",
        "MSSQL_AlterAnyDBRole",
        "MSSQL_AlterAnyLogin",
        "MSSQL_AlterAnyServerRole",
        "MSSQL_ChangeOwner",
        "MSSQL_ChangePassword",
        "MSSQL_CoerceAndRelayToMSSQL",
        "MSSQL_Connect",
        "MSSQL_ConnectAnyDatabase",
        "MSSQL_Contains",
        "MSSQL_Control",
        "MSSQL_ControlDB",
        "MSSQL_ControlServer",
        "MSSQL_ExecuteAs",
        "MSSQL_ExecuteAsOwner",
        "MSSQL_ExecuteOnHost",
        "MSSQL_GetAdminTGS",
        "MSSQL_GetTGS",
        "MSSQL_GrantAnyDBPermission",
        "MSSQL_GrantAnyPermission",
        "MSSQL_HasDBScopedCred",
        "MSSQL_HasLogin",
        "MSSQL_HasMappedCred",
        "MSSQL_HasProxyCred",
        "MSSQL_HostFor",
        "MSSQL_Impersonate",
        "MSSQL_ImpersonateAnyLogin",
        "MSSQL_IsMappedTo",
        "MSSQL_IsTrustedBy",
        "MSSQL_LinkedAsAdmin",
        "MSSQL_LinkedTo",
        "MSSQL_MemberOf",
        "MSSQL_Owns",
        "MSSQL_ServiceAccountFor",
        "MSSQL_TakeOwnership",
    }
)


def test_known_edge_types_count_is_38():
    assert len(KNOWN_EDGE_TYPES) == 38


def test_all_edge_kinds_superset_of_known():
    # The master set must produce at least all 38 authoritative edge types.
    missing = KNOWN_EDGE_TYPES - edges.ALL_EDGE_KINDS
    assert not missing, f"master set missing known edge types: {sorted(missing)}"


def test_partitions_are_disjoint():
    t, p, n = (
        edges.TRAVERSABLE_EDGE_KINDS,
        edges.POSSIBLE_EDGE_KINDS,
        edges.NONTRAVERSABLE_EDGE_KINDS,
    )
    assert not (t & p), sorted(t & p)
    assert not (t & n), sorted(t & n)
    assert not (p & n), sorted(p & n)


def test_partitions_cover_master_set():
    union = (
        edges.TRAVERSABLE_EDGE_KINDS
        | edges.POSSIBLE_EDGE_KINDS
        | edges.NONTRAVERSABLE_EDGE_KINDS
    )
    assert union == edges.ALL_EDGE_KINDS


def test_possible_edges_exact():
    # Mirrors writer.go PossibleEdgeKinds exactly.
    assert edges.POSSIBLE_EDGE_KINDS == frozenset(
        {
            "MSSQL_LinkedTo",
            "MSSQL_IsTrustedBy",
            "MSSQL_ServiceAccountFor",
            "MSSQL_HasDBScopedCred",
            "MSSQL_HasMappedCred",
            "MSSQL_HasProxyCred",
        }
    )


def test_nontraversable_edges_match_go_switch():
    # Exactly the kinds for which edges.go IsTraversableEdge returns false.
    assert edges.NONTRAVERSABLE_EDGE_KINDS == frozenset(
        {
            "MSSQL_Alter",
            "MSSQL_Control",
            "MSSQL_Impersonate",
            "MSSQL_AlterAnyLogin",
            "MSSQL_AlterAnyServerRole",
            "MSSQL_AlterAnyAppRole",
            "MSSQL_AlterAnyDBRole",
            "MSSQL_Connect",
            "MSSQL_ConnectAnyDatabase",
            "MSSQL_TakeOwnership",
            "MSSQL_AlterDB",
            "MSSQL_AlterDBRole",
            "MSSQL_AlterServerRole",
            "MSSQL_ImpersonateDBUser",
            "MSSQL_ImpersonateLogin",
        }
    )


def test_offensive_traversable_subset_present():
    # A sample of the offensive traversable edges from spec §6 must be
    # classified traversable (not possible, not non-traversable).
    for kind in (
        "MSSQL_ControlServer",
        "MSSQL_AddMember",
        "MSSQL_Owns",
        "MSSQL_MemberOf",
        "MSSQL_ExecuteAs",
        "MSSQL_ImpersonateAnyLogin",
        "MSSQL_LinkedAsAdmin",
        "MSSQL_CoerceAndRelayToMSSQL",
        "HasSession",
        "MSSQL_AlterAnyRole",  # NOT in the Go non-traversable switch -> traversable
    ):
        assert kind in edges.TRAVERSABLE_EDGE_KINDS, kind


def test_non_mssql_prefixed_kinds():
    # HasSession and MemberOf semantics: HasSession has no prefix; the MSSQL
    # membership edge keeps the prefix (MSSQL_MemberOf).
    assert edges.HAS_SESSION == "HasSession"
    assert edges.MEMBER_OF == "MSSQL_MemberOf"


# --- Node kinds -------------------------------------------------------------


def test_node_kind_strings():
    assert nodes.SERVER == "MSSQL_Server"
    assert nodes.LOGIN == "MSSQL_Login"
    assert nodes.SERVER_ROLE == "MSSQL_ServerRole"
    assert nodes.DATABASE == "MSSQL_Database"
    assert nodes.DATABASE_USER == "MSSQL_DatabaseUser"
    assert nodes.DATABASE_ROLE == "MSSQL_DatabaseRole"
    assert nodes.APPLICATION_ROLE == "MSSQL_ApplicationRole"
    assert nodes.USER == "User"
    assert nodes.GROUP == "Group"
    assert nodes.COMPUTER == "Computer"
    assert nodes.BASE == "Base"


def test_icons_present_for_all_mssql_kinds():
    # Every MSSQL_* kind has an icon; AD kinds have none.
    for kind in nodes.MSSQL_NODE_KINDS:
        assert kind in nodes.ICONS
        icon = nodes.ICONS[kind]
        assert icon["type"] == "font-awesome"
        assert icon["name"] and icon["color"].startswith("#")
    for kind in nodes.AD_KINDS:
        assert kind not in nodes.ICONS


def test_icon_values_match_go():
    assert nodes.ICONS[nodes.SERVER] == {
        "type": "font-awesome",
        "name": "server",
        "color": "#42b9f5",
    }
    assert nodes.ICONS[nodes.LOGIN]["name"] == "user-gear"
    assert nodes.ICONS[nodes.LOGIN]["color"] == "#dd42f5"
    assert nodes.ICONS[nodes.APPLICATION_ROLE]["name"] == "robot"
