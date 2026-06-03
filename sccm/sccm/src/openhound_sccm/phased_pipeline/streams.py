"""Named, bounded output streams and the end-of-stream marker.

A *stream* is a ``queue.Queue`` with a maximum length. Phases put ``row`` items
on streams; consumers get them off and write them out. Because the queue is
bounded, a producer that outruns its consumer simply *waits* on ``put`` until a
slot frees up — this backpressure keeps total memory flat regardless of how many
rows are produced.

``DONE`` is a single shared sentinel value. A consumer reads rows until it gets
``DONE``, then stops. :func:`broadcast_done` places that marker on every stream
once collection has reached quiescence.
"""
from __future__ import annotations

import queue
from typing import Iterable


class _Done:
    """Type of the unique :data:`DONE` end-of-stream marker."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return "<DONE>"


# The one shared "no more rows are coming" marker. Compare with ``is DONE``.
DONE = _Done()


def build_streams(names: Iterable[str], maxsize: int) -> dict[str, queue.Queue]:
    """Return a dict mapping each name to a fresh bounded queue of length *maxsize*."""
    return {name: queue.Queue(maxsize=maxsize) for name in names}


def broadcast_done(streams: dict[str, queue.Queue]) -> None:
    """Put the shared :data:`DONE` marker on every stream.

    Uses a blocking ``put`` so delivery is guaranteed even if a stream is
    momentarily full; every consumer will eventually drain to the marker.
    """
    for stream in streams.values():
        stream.put(DONE)
