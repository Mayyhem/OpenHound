# Generalized from sccm/sccm/src/openhound_sccm/log_context.py (SCCM-specific phase
# lists, resource/host completion callbacks, and the SCCM "trace_*"/"cached_with_log"
# helpers stripped; only the generic logging context machinery is kept here).
"""Per-target / per-phase logging context shared across OpenHound collectors.

Importing :mod:`openhound_collector_common.logging.log_context` registers the
VERBOSE log level and exposes the ``[target]``/``[phase]`` contextvar tagging.
This package re-exports the public names for convenience.
"""

from .log_context import (
    VERBOSE,
    LogContextFilter,
    install_filter,
    phase_context,
    target_context,
    with_log_context,
)

__all__ = [
    "VERBOSE",
    "LogContextFilter",
    "install_filter",
    "phase_context",
    "target_context",
    "with_log_context",
]
