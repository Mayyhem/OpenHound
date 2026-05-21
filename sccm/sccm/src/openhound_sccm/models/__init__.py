"""SCCM extension model registry.

Each module here defines one or more `BaseAsset` subclasses that the OpenHound
convert phase invokes to produce OpenGraph nodes/edges. Models are imported
here so `@app.asset` decorators register with the app on package import.

11 derived edge models are under ``models/derived/``. The actual
edge fan-out is performed by the single ``DerivedEdges`` aggregator
(``models/derived/aggregator.py``); the other 10 are schema-only placeholders
that register their edge kinds with ``app.assets`` for documentation.
"""

from .sccm_site import SCCMSite

__all__ = [
    # Base node models
    "SCCMSite",
    # Derived edge models
]