import json
from pathlib import Path

import openhound_sccm
from openhound_sccm.bloodhound_schemas import (
    MSSQL_POSSIBLE_EDGE_KINDS,
    SCCM_POSSIBLE_EDGE_KINDS,
    load_sccm_schemas,
)


def test_schema_files_ship_inside_the_package(tmp_path, monkeypatch):
    """Schemas must resolve from the package dir, not from a path above it.

    Guards the packaging bug where Path(__file__).parents[2] pointed at the repo
    checkout: correct in a source tree, above site-packages once installed, so
    every user who installed from PyPI hit FileNotFoundError on --bloodhound upload.
    """
    pkg_dir = Path(openhound_sccm.__file__).resolve().parent
    assert (pkg_dir / "schema_SCCM.json").is_file()
    assert (pkg_dir / "schema_MSSQL.json").is_file()

    # Loading must not depend on the process working directory.
    monkeypatch.chdir(tmp_path)
    schemas = load_sccm_schemas(disable_possible=False)
    assert len(schemas) == 2 and all(s.startswith(b"{") for s in schemas)


def test_loads_both_schemas_by_namespace():
    schemas = load_sccm_schemas(disable_possible=False)
    namespaces = {json.loads(s)["schema"]["namespace"] for s in schemas}
    assert namespaces == {"SCCM", "MSSQL"}


def test_disable_possible_flips_sccm_and_mssql_kinds():
    schemas = load_sccm_schemas(disable_possible=True)
    rels = {}
    for s in schemas:
        for r in json.loads(s)["relationship_kinds"]:
            rels[r["name"]] = r["is_traversable"]
    for kind in SCCM_POSSIBLE_EDGE_KINDS + MSSQL_POSSIBLE_EDGE_KINDS:
        # Only assert kinds actually present in the shipped schemas.
        if kind in rels:
            assert rels[kind] is False, f"{kind} should be non-traversable"


def test_default_leaves_possible_edges_traversable():
    schemas = load_sccm_schemas(disable_possible=False)
    rels = {}
    for s in schemas:
        for r in json.loads(s)["relationship_kinds"]:
            rels[r["name"]] = r["is_traversable"]
    assert rels.get("SCCM_CoerceAndRelayToSMB") is True
