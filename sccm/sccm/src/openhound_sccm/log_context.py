"""Per-target / per-phase logging context for the OpenHound SCCM extension.

Adds three pieces on top of stdlib ``logging``:

1. ``contextvars``-backed ``target_context()`` / ``phase_context()`` context
   managers. Whatever is on the stack at log-emission time is folded into the
   record as a ``[target][phase]`` prefix on the message.
2. A ``LogContextFilter`` that reads those contextvars and rewrites the
   record's ``msg`` field so the prefix becomes part of the message content
   itself. This means the OpenHound framework's existing log handler (Rich)
   keeps formatting timestamps, levels, and colors exactly as before — the
   prefix just shows up inside each line.
3. Two iterator helpers — ``per_host_iter()`` and ``per_pair_iter()`` —
   that push ``target_context(hostname)`` around each iteration so a plain
   ``for host in per_host_iter(ctx.ldap_computer_hosts()): logger.info(...)``
   automatically gets ``[hostname][PHASE]`` on every line.
4. A ``with_log_context`` decorator factory that wraps ``@app.resource``
   bodies so the right phase (and optionally the domain target) are active
   for every line emitted inside the resource generator — even across
   ``yield`` boundaries.

Stdlib only — no custom formatter, no replacement of the framework's log
handlers. Apply by installing the filter on the root logger once (see
``install_filter()``); after that, every ``logger.info(...)`` inside a
``with target_context(...):`` / ``with phase_context(...):`` block sees the
prefix prepended automatically.
"""

from __future__ import annotations

import contextlib
import contextvars
import functools
import inspect
import logging
from typing import Callable, Iterator, Optional, TypeVar


# ---------------------------------------------------------------------------
# Per-target / per-phase context vars
# ---------------------------------------------------------------------------
_current_target: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "openhound_sccm_target", default=None,
)
_current_phase: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "openhound_sccm_phase", default=None,
)


@contextlib.contextmanager
def target_context(target: Optional[str]) -> Iterator[None]:
    """Push *target* onto the log-context stack for the duration of the block.

    Usage::

        with target_context(hostname):
            logger.info("Probing port 445...")

    Reentrant: nested blocks shadow the outer value and restore it on exit.
    """
    token = _current_target.set(target)
    try:
        yield
    finally:
        _current_target.reset(token)


@contextlib.contextmanager
def phase_context(phase: Optional[str]) -> Iterator[None]:
    """Push *phase* onto the log-context stack for the duration of the block.

    Usage::

        with phase_context("LDAP"):
            logger.info("Searching for mSSMSSite objects...")
    """
    token = _current_phase.set(phase)
    try:
        yield
    finally:
        _current_phase.reset(token)


# ---------------------------------------------------------------------------
# Filter that folds the [target][phase] prefix into the message text
# ---------------------------------------------------------------------------
class LogContextFilter(logging.Filter):
    """Prepend ``[target][phase]`` (whichever of the two are set) to every
    record's message, so the framework's handler renders it inline.

    Applied once on the root logger — see ``install_filter()`` below.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        target = _current_target.get(None)
        phase = _current_phase.get(None)
        if not target and not phase:
            return True
        parts = []
        if target:
            parts.append(f"[{target}]")
        if phase:
            parts.append(f"[{phase}]")
        prefix = "".join(parts) + " "
        # ``record.getMessage()`` applies args to msg — but we only want to
        # prepend the prefix to the *format string*, leaving the args alone.
        # Mutating ``msg`` is the conventional way; ``args`` stay untouched
        # so percent-format substitution still works.
        record.msg = prefix + str(record.msg)
        return True


_FILTER_SINGLETON = LogContextFilter()


def install_filter() -> None:
    """Install the ``[target][phase]`` prefix filter on the root logger
    and disable Rich markup parsing on any ``RichHandler`` it finds.

    Idempotent: re-running it adds the singleton at most once. The framework
    configures its own root handler at import time — we just plug into it.

    Two runtime adjustments to each ``RichHandler`` (no framework code edits,
    just attribute writes on the existing handler instance):

    1. ``markup = False`` — the framework sets ``markup=True``, so Rich
       treats ``[mayyhem.com]`` as a malformed markup tag (the ``.`` trips
       the parser) and silently drops it. With markup off, brackets render
       literally.
    2. ``_log_render.show_path = False`` — drop the trailing ``ldap.py:117``
       column, which steals width and forces long messages to wrap.
    """
    root = logging.getLogger()
    if _FILTER_SINGLETON not in root.filters:
        root.addFilter(_FILTER_SINGLETON)
    # Each existing handler gets the filter too, in case the handler ignores
    # logger-level filters (RichHandler historically has).
    for logger_name in ("", "dlt"):
        target_logger = logging.getLogger(logger_name)
        for handler in target_logger.handlers:
            if _FILTER_SINGLETON not in handler.filters:
                handler.addFilter(_FILTER_SINGLETON)
            # Tidy up RichHandler instances — duck-typed checks so we don't
            # depend on importing rich here. RichHandler stores show_path on
            # its internal LogRender, not as a direct instance attr, so we
            # reach into ``_log_render``.
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
    target_from_ctx_domain: bool = False,
) -> Callable[[_F], _F]:
    """Decorator that pushes a phase/target log context around a call.

    Works for both regular functions and generator functions. The target/phase
    contextvars are active for the duration of the call (including across
    every ``yield`` in a generator) so any ``logger.*`` call inside the body
    sees the correct context.

    Apply it BELOW ``@app.resource(...)`` so DLT's decorator wraps our
    wrapper, not the other way round::

        @app.resource(name="ldap_computers", columns=Computer)
        @with_log_context(phase="LDAP", target_from_ctx_domain=True)
        def ldap_computers(ctx):
            ...
    """

    def _resolve_target(args: tuple, kwargs: dict) -> Optional[str]:
        if target is not None:
            return target
        if target_from_ctx_domain:
            ctx = args[0] if args else kwargs.get("ctx")
            if ctx is not None:
                domain = getattr(ctx, "domain", None)
                return str(domain) if domain else None
        return None

    def decorator(func: _F) -> _F:
        if inspect.isgeneratorfunction(func):
            @functools.wraps(func)
            def gen_wrapper(*args, **kwargs):
                resolved_target = _resolve_target(args, kwargs)
                with contextlib.ExitStack() as stack:
                    if phase is not None:
                        stack.enter_context(phase_context(phase))
                    if resolved_target is not None:
                        stack.enter_context(target_context(resolved_target))
                    yield from func(*args, **kwargs)
            return gen_wrapper  # type: ignore[return-value]

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            resolved_target = _resolve_target(args, kwargs)
            with contextlib.ExitStack() as stack:
                if phase is not None:
                    stack.enter_context(phase_context(phase))
                if resolved_target is not None:
                    stack.enter_context(target_context(resolved_target))
                return func(*args, **kwargs)
        return wrapper  # type: ignore[return-value]

    return decorator


# ---------------------------------------------------------------------------
# Per-host iteration helpers
# ---------------------------------------------------------------------------
def per_host_iter(items, *, key: str = "hostname") -> Iterator:
    """Iterate a list of host-dicts, pushing ``target_context(host[key])`` per item.

    The target contextvar is set before each ``yield`` and restored after the
    caller's loop body finishes the iteration, so any ``logger.*`` call inside
    the loop body sees the correct ``[hostname]`` prefix even when the loop
    body itself is plain (no ``with`` block needed)::

        for host in per_host_iter(ctx.ldap_computer_hosts()):
            hostname = host["hostname"]
            # logger.info(...) here is automatically tagged with [hostname][PHASE]

    Items that aren't dicts are coerced via ``str()``. Items without a value
    for *key* are yielded without a target context push (so generic
    "skipping" log lines from a malformed entry still appear).
    """
    for h in items:
        if isinstance(h, dict):
            target = h.get(key)
        else:
            target = str(h) if h is not None else None
        if target:
            with target_context(str(target)):
                yield h
        else:
            yield h


def per_pair_iter(items) -> Iterator:
    """Iterate ``(target, value)`` pairs, pushing ``target_context(target)`` per pair.

    Useful for ``dict.items()`` iteration where the key is already the host
    name (e.g. ``ctx.adminservice_payloads().items()``)::

        for host, payload in per_pair_iter(ctx.adminservice_payloads().items()):
            logger.info("processing %s", host)  # auto-tagged with [host][PHASE]
    """
    for key, value in items:
        if key:
            with target_context(str(key)):
                yield key, value
        else:
            yield key, value


__all__ = [
    "LogContextFilter",
    "install_filter",
    "per_host_iter",
    "per_pair_iter",
    "phase_context",
    "target_context",
    "with_log_context",
]
