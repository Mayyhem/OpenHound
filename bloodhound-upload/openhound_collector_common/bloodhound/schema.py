"""Mutate a BloodHound extensions schema before upload.

Port of MSSQLHound's `SchemaJSONWithDisabledPossibleEdges`: given a schema JSON
blob and a set of "possible" relationship kind names, set their `is_traversable`
to false so `--disable-possible-edges` and the uploaded schema agree.
"""
from __future__ import annotations

import json
import logging
from typing import Iterable

logger = logging.getLogger(__name__)


def disable_possible_edges(schema_bytes: bytes, possible_kinds: Iterable[str]) -> bytes:
    """Return *schema_bytes* with the named relationship kinds non-traversable."""
    schema = json.loads(schema_bytes)
    disabled = set(possible_kinds)
    flipped = 0
    for rel in schema.get("relationship_kinds", []):
        if rel.get("name") in disabled:
            rel["is_traversable"] = False
            flipped += 1
    logger.debug("disable_possible_edges: set %d relationship kind(s) non-traversable", flipped)
    return json.dumps(schema, indent=2).encode()
