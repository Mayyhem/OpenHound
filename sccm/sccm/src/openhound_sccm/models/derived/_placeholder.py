"""Schema-only placeholder factory for derived edge models.

All 10 per-category placeholder models in this directory share the same
shape: register an asset with a small EdgeDef list and contribute to
``app.assets`` for documentation, but never fire at convert time
(the edge fan-out lives in ``aggregator.py``).

Rather than copy-paste 10 nearly-identical files, each placeholder file
calls ``register_placeholder()`` with its specific edge declarations.
This keeps the boilerplate in one place but still gives each edge
category its own importable module name (so the model count goes from
10 -> 21 as Phase 4 acceptance requires).
"""

from __future__ import annotations

from typing import ClassVar

from dlt.common.libs.pydantic import DltConfig
from openhound.core.asset import BaseAsset, EdgeDef
from pydantic import ConfigDict

from openhound_sccm.main import app


def register_placeholder(name: str, description: str, edges: list[EdgeDef]):
    """Register a schema-only placeholder asset and return the new class."""

    @app.asset(description=description, edges=edges)
    class _Placeholder(BaseAsset):
        model_config = ConfigDict(populate_by_name=True, extra="ignore")
        dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

        @property
        def as_node(self):
            return None

        @property
        def edges(self):
            return iter(())

    _Placeholder.__name__ = name
    _Placeholder.__qualname__ = name
    return _Placeholder
