"""The phased-collection engine.

This module defines:

* :class:`Phase` — the read-only description of one collection step;
* :func:`run_one_target` — run a single target through its phases in order,
  routing each row to its named stream and isolating per-phase failures.

The thread pool that drives many targets concurrently (:func:`run_pipeline`) is
added in the next task.

The engine imports only the standard library — no SCCM, Active Directory, or
DLT — so it stays portable.
"""
from __future__ import annotations

import contextlib
import logging
import queue
from dataclasses import dataclass
from typing import Any, Callable, ContextManager, Iterable, Optional, Sequence

logger = logging.getLogger(__name__)

# A phase's run() yields (stream_name, row) pairs. Rows are opaque to the engine.
PhaseRun = Callable[[str, Any], Iterable[tuple[str, Any]]]
ShouldRun = Callable[[str, "Phase", Any], bool]
PhaseScope = Callable[[str, str], ContextManager[Any]]


@dataclass(frozen=True)
class Phase:
    """One ordered collection step.

    Attributes:
        name: Stable identifier for the phase (e.g. "RemoteRegistry"). Callers
            may also use it as the gating token for ``should_run``.
        streams: The names of every output stream this phase may write to.
        run: A generator function ``(target, context) -> Iterable[(stream, row)]``.
    """

    name: str
    streams: tuple[str, ...]
    run: PhaseRun


def run_one_target(
    target: str,
    context: Any,
    phases: Sequence[Phase],
    streams: dict[str, queue.Queue],
    should_run: Optional[ShouldRun] = None,
    phase_scope: Optional[PhaseScope] = None,
) -> None:
    """Run *target* through *phases* in order, routing rows to *streams*.

    For each phase (unless ``should_run`` says to skip it), the optional
    ``phase_scope(target, phase.name)`` context manager is entered (used by
    callers to set logging context), then the phase's ``run`` is iterated and
    each ``(stream_name, row)`` is put onto ``streams[stream_name]`` — a put that
    blocks when the stream is full (intended backpressure).

    A phase that raises is logged and skipped; the remaining phases still run.
    """
    for phase in phases:
        if should_run is not None and not should_run(target, phase, context):
            continue
        scope: ContextManager[Any] = (
            phase_scope(target, phase.name) if phase_scope is not None else contextlib.nullcontext()
        )
        with scope:
            try:
                for stream_name, row in phase.run(target, context):
                    streams[stream_name].put(row)
            except Exception:
                logger.exception("Phase %r failed for target %r", phase.name, target)
