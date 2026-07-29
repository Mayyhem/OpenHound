"""Load the SCCM collector's BloodHound extensions schemas for upload.

The SCCM collector emits both SCCM_* kinds (schema_SCCM.json) and MSSQL_* kinds
(schema_MSSQL.json) — see kinds/edges.py — so a direct upload registers BOTH so
every emitted edge/node renders. `--disable-possible-edges` flips the uncertain
("possible") relationship kinds to non-traversable in each schema before upload,
mirroring MSSQLHound's SchemaJSONWithDisabledPossibleEdges.
"""
from __future__ import annotations

import logging
from pathlib import Path

from openhound_collector_common.bloodhound import disable_possible_edges

logger = logging.getLogger(__name__)

# The two hand-maintained schema files ship *inside* the package (see the wheel
# target in pyproject.toml), so a package-relative path resolves identically in a
# source checkout and in site-packages. The previous parents[2] hop pointed at the
# repo directory, which does not exist in an installed copy.
_SCHEMA_ROOT = Path(__file__).resolve().parent
_SCCM_SCHEMA = _SCHEMA_ROOT / "schema_SCCM.json"
_MSSQL_SCHEMA = _SCHEMA_ROOT / "schema_MSSQL.json"

# SCCM's Stage-6 coerce-and-relay edges are the collector's "possible" edges.
SCCM_POSSIBLE_EDGE_KINDS: tuple[str, ...] = (
    "SCCM_CoerceAndRelayToAdminService",
    "SCCM_CoerceAndRelayToSMB",
)

# MSSQL "possible" edges — verbatim from Go writer.go PossibleEdgeKinds.
MSSQL_POSSIBLE_EDGE_KINDS: tuple[str, ...] = (
    "MSSQL_LinkedTo",
    "MSSQL_IsTrustedBy",
    "MSSQL_ServiceAccountFor",
    "MSSQL_HasDBScopedCred",
    "MSSQL_HasMappedCred",
    "MSSQL_HasProxyCred",
)


def load_sccm_schemas(disable_possible: bool) -> list[bytes]:
    """Return [SCCM schema, MSSQL schema] as JSON bytes, mutated if requested."""
    schemas: list[bytes] = []
    for path, possible in ((_SCCM_SCHEMA, SCCM_POSSIBLE_EDGE_KINDS),
                           (_MSSQL_SCHEMA, MSSQL_POSSIBLE_EDGE_KINDS)):
        if not path.exists():
            # A missing schema file is a packaging error — surface it loudly.
            logger.error("BloodHound schema file missing: %s", path)
            raise FileNotFoundError(path)
        data = path.read_bytes()
        if disable_possible:
            data = disable_possible_edges(data, possible)
            logger.debug("Loaded schema %s (possible edges disabled)", path.name)
        else:
            logger.debug("Loaded schema %s", path.name)
        schemas.append(data)
    return schemas
