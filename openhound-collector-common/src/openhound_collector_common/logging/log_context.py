# Generalized from sccm/sccm/src/openhound_sccm/log_context.py.
#
# "Generalize" per design spec §2.1: this is the same generic logging-context
# machinery the SCCM extension proved out, with everything SCCM-specific stripped:
#   - no hard-coded SCCM phase-name lists (phases are now caller-supplied strings),
#   - no resource/host completion-callback registry (that fed SCCM's ordered file
#     handler, which is intentionally NOT ported — design decision D13: SCCM's
#     Windows-only fixes and diagnostic/ordered file handlers don't reliably work),
#   - no SCCM "trace_node"/"trace_edge"/"cached_with_log" helpers (collector-specific),
#   - the contextvar names are renamed off the SCCM prefix to a neutral one.
#
# What is kept (the genuinely reusable core):
#   - the VERBOSE level (a tier between INFO and DEBUG) + ``logger.verbose(...)``,
#   - the ``target_context``/``phase_context`` contextvar managers,
#   - the ``LogContextFilter`` that folds ``[target][phase]`` into each record,
#   - ``install_filter`` to wire that filter onto the root logger,
#   - the ``with_log_context`` decorator (works for plain functions AND generators).
"""Per-target / per-phase logging context for OpenHound collectors.

Adds three pieces on top of stdlib :mod:`logging`:

1. A ``VERBOSE`` log level (15) sitting between ``INFO`` (20) and ``DEBUG`` (10),
   plus a ``logger.verbose(...)`` shortcut, so a collector's ``-vv`` tier can be
   surfaced without the noise that ``--debug`` brings in (dlt / ldap3 internals).
2. ``contextvars``-backed :func:`target_context` / :func:`phase_context` context
   managers. Whatever is on the stack at log-emission time is folded into the
   record as a ``[target][phase]`` prefix on the message by :class:`LogContextFilter`.
3. A :func:`with_log_context` decorator factory that keeps the right phase/target
   active for the whole duration of a call — including across every ``yield`` of a
   generator (e.g. a dlt ``@app.resource`` body), which dlt drives interleaved.

Stdlib only. No custom formatter and no replacement of the host framework's log
handlers: the filter rewrites ``record.msg`` so the framework's existing handler
(Rich, etc.) keeps rendering timestamps/levels/colors exactly as before.
"""

from __future__ import annotations

import contextlib
import contextvars
import functools
import inspect
import logging
import sys
from typing import Any, Callable, Iterator, Optional, TypeVar


# ---------------------------------------------------------------------------
# VERBOSE log level — between INFO (20) and DEBUG (10). Importing this module
# installs the level globally and adds ``Logger.verbose()`` so collector code
# reads as ``logger.verbose(...)`` rather than ``logger.log(VERBOSE, ...)``.
# ---------------------------------------------------------------------------
VERBOSE = 15
logging.addLevelName(VERBOSE, "VERBOSE")


def _verbose(self: logging.Logger, message: str, *args: Any, **kwargs: Any) -> None:
    """``logger.verbose(...)`` shortcut for the VERBOSE level."""
    # Mirror stdlib's per-level guard so disabled VERBOSE calls stay cheap.
    if self.isEnabledFor(VERBOSE):
        self._log(VERBOSE, message, args, **kwargs)


if not hasattr(logging.Logger, "verbose"):
    # Only patch once — re-importing this module must not clobber the method.
    logging.Logger.verbose = _verbose  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Per-target / per-phase context vars
# ---------------------------------------------------------------------------
_current_target: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "openhound_collector_target", default=None,
)
_current_phase: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "openhound_collector_phase", default=None,
)


def get_current_target() -> Optional[str]:
    """Return the target (host/domain) currently in log context, or None."""
    return _current_target.get(None)


def get_current_phase() -> Optional[str]:
    """Return the phase currently in log context, or None."""
    return _current_phase.get(None)


@contextlib.contextmanager
def target_context(target: Optional[str]) -> Iterator[None]:
    """Push *target* onto the log-context stack for the duration of the block.

    Usage::

        with target_context(hostname):
            logger.info("Probing port 1433...")

    Reentrant: nested blocks shadow the outer value and restore it on exit.
    """
    token = _current_target.set(target)
    try:
        yield
    finally:
        # Always restore the previous value, even if the body raised.
        _current_target.reset(token)


@contextlib.contextmanager
def phase_context(phase: Optional[str]) -> Iterator[None]:
    """Push *phase* onto the log-context stack for the duration of the block.

    Usage::

        with phase_context("LDAP"):
            logger.info("Searching for service principal names...")
    """
    token = _current_phase.set(phase)
    try:
        yield
    finally:
        # Always restore the previous value, even if the body raised.
        _current_phase.reset(token)


# ---------------------------------------------------------------------------
# Filter that folds the [target][phase] prefix into the message text
# ---------------------------------------------------------------------------
class LogContextFilter(logging.Filter):
    """Prepend ``[target][phase]`` (whichever are set) to every record's message
    so the framework's handler renders it inline. Install once via
    :func:`install_filter`.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        # The same LogRecord may pass through multiple handlers (e.g. a file
        # handler + a stream handler). Mutating record.msg each time would
        # duplicate the prefix, so a sentinel attribute short-circuits reruns.
        if getattr(record, "_oh_prefixed", False):
            return True
        target = _current_target.get(None)
        phase = _current_phase.get(None)
        if not target and not phase:
            # Nothing in context — leave the record untouched.
            return True
        parts = []
        if target:
            parts.append(f"[{target}]")
        if phase:
            parts.append(f"[{phase}]")
        prefix = "".join(parts) + " "
        # Prepend the prefix to the *format string* only, leaving record.args
        # untouched so percent-style substitution in getMessage() still works.
        record.msg = prefix + str(record.msg)
        record._oh_prefixed = True  # type: ignore[attr-defined]
        return True


_FILTER_SINGLETON = LogContextFilter()


def install_filter() -> None:
    """Install the ``[target][phase]`` prefix filter on the root logger.

    Idempotent: re-running adds the singleton at most once. The filter is also
    added to each existing root-logger handler, because some handlers (notably
    RichHandler) have historically ignored logger-level filters. Where a Rich
    handler is found, two attribute writes (no framework code edits) keep the
    bracketed prefix renderable: turn ``markup`` off (so ``[host.example.com]``
    isn't mis-parsed as Rich markup and dropped) and hide the trailing
    ``file.py:NN`` column (which steals width and wraps long lines).
    """
    root = logging.getLogger()
    if _FILTER_SINGLETON not in root.filters:
        # Logger-level filter handles the common case.
        root.addFilter(_FILTER_SINGLETON)
    else:
        # Already installed on the logger — nothing to add at the logger level.
        pass
    for handler in root.handlers:
        if _FILTER_SINGLETON not in handler.filters:
            # Belt-and-suspenders for handlers that bypass logger-level filters.
            handler.addFilter(_FILTER_SINGLETON)
        # Duck-typed Rich-handler tidy-up so we need not import rich here.
        if getattr(handler, "markup", False):
            handler.markup = False
        log_render = getattr(handler, "_log_render", None)
        if log_render is not None and hasattr(log_render, "show_path"):
            log_render.show_path = False


# ---------------------------------------------------------------------------
# Decorator factory
# ---------------------------------------------------------------------------
_F = TypeVar("_F", bound=Callable)


def with_log_context(
    *,
    phase: Optional[str] = None,
    target: Optional[str] = None,
    target_from_ctx_attr: Optional[str] = None,
) -> Callable[[_F], _F]:
    """Decorator that pushes a phase/target log context around a call.

    Works for both plain functions and generator functions. The target/phase
    contextvars are active for the duration of the call (including across every
    ``yield`` of a generator) so any ``logger.*`` call in the body sees the right
    context.

    *target* sets a fixed target string. *target_from_ctx_attr* instead reads the
    target from an attribute (e.g. ``"domain"``) of the call's first positional
    argument (the collector's context object) — useful for domain-scoped resources
    whose target isn't known until call time.

    Apply it BELOW a framework resource decorator so the framework wraps our
    wrapper, not the other way round::

        @app.resource(name="ldap_computers", columns=Computer)
        @with_log_context(phase="LDAP", target_from_ctx_attr="domain")
        def ldap_computers(ctx):
            ...
    """

    def _resolve_target(args: tuple, kwargs: dict) -> Optional[str]:
        if target is not None:
            # Explicit fixed target wins.
            return target
        if target_from_ctx_attr:
            # Pull the target off the first positional arg (or kwarg "ctx").
            ctx = args[0] if args else kwargs.get("ctx")
            if ctx is not None:
                value = getattr(ctx, target_from_ctx_attr, None)
                return str(value) if value else None
            # No context object to read from — fall through to "no target".
            return None
        return None

    def decorator(func: _F) -> _F:
        if inspect.isgeneratorfunction(func):
            @functools.wraps(func)
            def gen_wrapper(*args, **kwargs):
                # dlt drives resource generators interleaved (pull one value
                # from A, then B, then A again). Pushing the context once around
                # the whole generator would let the last generator-to-enter leak
                # its contextvars into the others (contextvars are thread-wide).
                # So push/pop per next() call: each iteration sees its own values
                # exclusively, and the yield itself happens outside the context
                # (no logging there) so no interleaved caller observes ours.
                resolved_target = _resolve_target(args, kwargs)
                inner = func(*args, **kwargs)
                while True:
                    phase_token = _current_phase.set(phase) if phase is not None else None
                    target_token = (
                        _current_target.set(resolved_target)
                        if resolved_target is not None
                        else None
                    )
                    try:
                        value = next(inner)
                    except StopIteration:
                        # Generator exhausted normally — stop iterating.
                        return
                    finally:
                        # Restore both contextvars before yielding to the caller.
                        if target_token is not None:
                            _current_target.reset(target_token)
                        if phase_token is not None:
                            _current_phase.reset(phase_token)
                    yield value
            return gen_wrapper  # type: ignore[return-value]

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            resolved_target = _resolve_target(args, kwargs)
            phase_token = _current_phase.set(phase) if phase is not None else None
            target_token = (
                _current_target.set(resolved_target)
                if resolved_target is not None
                else None
            )
            try:
                return func(*args, **kwargs)
            finally:
                # Restore both contextvars whether or not the call raised.
                if target_token is not None:
                    _current_target.reset(target_token)
                if phase_token is not None:
                    _current_phase.reset(phase_token)
        return wrapper  # type: ignore[return-value]

    return decorator


__all__ = [
    "VERBOSE",
    "LogContextFilter",
    "get_current_phase",
    "get_current_target",
    "install_filter",
    "phase_context",
    "target_context",
    "with_log_context",
]
