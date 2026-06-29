"""Raw-table placeholder assets for the per-target collection streams.

``collect_server`` yields ``(table_name, row)`` pairs that the DLT source layer
(``source.py``) streams to raw JSONL — one emit resource per table. Those tables
(``servers``, ``server_principals``, ``databases``, ...) are *staging* data:
``preproc`` loads them into DuckDB and ``convert`` derives the real graph
nodes/edges from them. The raw rows themselves never become BloodHound output.

The framework's conformance tests (``tests/test_extension_methods.py``) still
require every ``@app.resource`` to declare ``columns=<BaseAsset subclass>`` and
for that asset to be registered with the app. For these raw staging tables that
is bookkeeping only — no schema validation matters and the row shapes are
heterogeneous and version-dependent. So, exactly like the SCCM extension's
``models/raw_table.py``, this module factories one zero-edge, no-emit
placeholder asset per table name. ``extra="allow"`` lets every raw column pass
through validation untouched; ``return_validated_models`` keeps the row dicts
intact for the JSONL writer.

When a raw table later grows a typed node/edge meaning (Stage 5+), replace its
placeholder use site with a fully-typed asset.
"""
from __future__ import annotations

from typing import Any, ClassVar, Optional

from dlt.common.libs.pydantic import DltConfig
from openhound.core.asset import BaseAsset
from pydantic import ConfigDict

from openhound_mssql.main import app

# Cache placeholder asset classes by table name so repeated source() calls (e.g.
# in tests) reuse the same registered asset rather than re-registering it.
_CACHE: dict[str, type[BaseAsset]] = {}


def raw_table_asset(name: str, description: str = "") -> type[BaseAsset]:
    """Create (and register) a zero-edge placeholder asset for a raw table.

    ``name`` becomes the class name so the conformance test's error messages
    stay informative. The asset emits no node and no edges — it exists only to
    satisfy the ``columns=`` / registered-asset contract for the emit resource.
    ``extra="allow"`` passes every raw column through pydantic untouched.
    """
    cached = _CACHE.get(name)
    if cached is not None:
        # Already built for this table — reuse the registered class.
        return cached

    @app.asset(
        description=description or f"Raw staging table {name!r} (no graph emission)",
        edges=[],
    )
    class _RawTable(BaseAsset):
        model_config = ConfigDict(populate_by_name=True, extra="allow")
        dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

        # No required fields: raw rows carry arbitrary version-dependent columns
        # (server principal columns differ by SQL version, etc.). ``extra="allow"``
        # accepts them all; this lone Optional marker keeps the model non-empty.
        raw_marker: Optional[Any] = None

        @property
        def as_node(self):
            return None

        @property
        def edges(self):
            return iter(())

    _RawTable.__name__ = name
    _RawTable.__qualname__ = name
    _CACHE[name] = _RawTable
    return _RawTable


__all__ = ["raw_table_asset"]
