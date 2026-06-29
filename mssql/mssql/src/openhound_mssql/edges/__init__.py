"""Server- and database-level edge derivation for the MSSQL convert phase.

Exposes :func:`derive_edges`, the faithful port of Go ``createEdges`` /
``createFixedRoleEdges`` / ``createServerPermissionEdges`` /
``createDatabasePermissionEdges`` (Stage 6 — server + database level). The
convert pipeline calls it as a standalone edge emitter over the preproc DuckDB.
"""
from .derive import derive_edges

__all__ = ["derive_edges"]
