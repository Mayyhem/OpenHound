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
from typing import Any, Callable, Iterator, Optional, TypeVar


# ---------------------------------------------------------------------------
# VERBOSE log level — sits between INFO (20) and DEBUG (10) so ``-vv``
# can surface PS1's ``[Verbose]`` tier without the noise of DLT / ldap3
# internals that ``--debug`` brings in. Importing this module installs the
# level globally and adds ``Logger.verbose()`` so collector code reads as
# ``logger.verbose(...)`` rather than ``logger.log(VERBOSE, ...)``.
# ---------------------------------------------------------------------------
VERBOSE = 15
logging.addLevelName(VERBOSE, "VERBOSE")


def _verbose(self: logging.Logger, message: str, *args: Any, **kwargs: Any) -> None:
    """``logger.verbose(...)`` shortcut for the VERBOSE level."""
    if self.isEnabledFor(VERBOSE):
        self._log(VERBOSE, message, args, **kwargs)


if not hasattr(logging.Logger, "verbose"):
    logging.Logger.verbose = _verbose  # type: ignore[attr-defined]


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
        # Filters run once per handler invocation. The same ``LogRecord`` may
        # be passed through multiple handlers (e.g. a file handler + a stream
        # handler when ``-v`` is set) — mutating ``record.msg`` each time
        # would duplicate the prefix. Use a sentinel attribute to short-circuit
        # on subsequent passes.
        if getattr(record, "_oh_sccm_prefixed", False):
            return True
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
        record._oh_sccm_prefixed = True  # type: ignore[attr-defined]
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
                # DLT runs resource generators interleaved — it pulls one
                # value from generator A, then one from B, then A again,
                # etc. If we push ``phase_context(phase)`` once around the
                # whole generator, the contextvar set by the LAST
                # generator-to-enter leaks into other generators' yields
                # because contextvars are process/thread-wide.
                #
                # Solution: push the phase / target context **per next()
                # call** so each iteration of the inner generator sees the
                # right values exclusively. The yield itself happens
                # outside the context (no logging there) so no interleaved
                # caller sees our values.
                resolved_target = _resolve_target(args, kwargs)
                inner = func(*args, **kwargs)
                while True:
                    try:
                        with contextlib.ExitStack() as stack:
                            if phase is not None:
                                stack.enter_context(phase_context(phase))
                            if resolved_target is not None:
                                stack.enter_context(target_context(resolved_target))
                            value = next(inner)
                    except StopIteration:
                        return
                    yield value
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


# ---------------------------------------------------------------------------
# Cache-with-verbose-logging — replaces ``@lru_cache`` on hot lookups so
# we can emit PS1-equivalent "Resolved X from cache" / "Resolving X" traces.
# ``lru_cache`` itself has no per-call hit indicator, so we keep our own
# dict and log explicitly.
# ---------------------------------------------------------------------------
def cached_with_log(label: str) -> Callable[[_F], _F]:
    """Decorate an instance method so every call logs at VERBOSE whether the
    lookup hit the cache or fell through to the underlying query.

    ``label`` is a short noun phrase used in the log line — typically the
    kind of thing being resolved (e.g. ``"Computer SID"``, ``"User SAM"``).
    Mirrors PS1's ``"Resolved <key> in domain <d> from cache"`` /
    ``"Attempting to resolve <key>"`` Upsert-Node trace.

    Replaces ``@lru_cache`` 1:1: drop-in compatible with bound methods,
    keyed on the positional argument tuple.
    """
    logger = logging.getLogger("openhound_sccm.lookup")

    def decorator(func: _F) -> _F:
        cache: dict[tuple, object] = {}

        @functools.wraps(func)
        def wrapper(self, *args):
            key = args
            if key in cache:
                key_text = ", ".join(repr(a) for a in args)
                logger.verbose("Resolved %s %s from cache", label, key_text)
                return cache[key]
            key_text = ", ".join(repr(a) for a in args)
            logger.verbose("Resolving %s %s via DuckDB", label, key_text)
            result = func(self, *args)
            cache[key] = result
            if result is None:
                logger.verbose("No %s found for %s", label, key_text)
            return result

        wrapper.cache_clear = lambda: cache.clear()  # type: ignore[attr-defined]
        return wrapper  # type: ignore[return-value]

    return decorator


# ---------------------------------------------------------------------------
# Per-node / per-edge VERBOSE trace helpers used by SCCM model classes.
# PS1's Upsert-Node / Upsert-Edge emit these at the framework boundary; in
# OH the equivalent boundary is each model's ``as_node`` / ``edges`` body.
# ---------------------------------------------------------------------------
def trace_node(kind: str, node_id: str, name: Optional[str] = None) -> None:
    """Emit a PS1-equivalent ``Found existing <kind> node: <id> (<name>)`` line."""
    logger = logging.getLogger("openhound_sccm.graph")
    suffix = f" ({name})" if name else ""
    logger.verbose("Found existing %s node: %s%s", kind, node_id, suffix)


def trace_edge(kind: str, start: str, end: str) -> None:
    """Emit a PS1-equivalent ``Found existing edge X -[K]-> Y with identical
    properties, no changes made`` line. OH's emission stage dedupes upstream,
    so this fires for every yielded edge (same intent as PS1's per-touch log)."""
    logger = logging.getLogger("openhound_sccm.graph")
    logger.verbose("Found existing edge %s -[%s]-> %s with identical properties, no changes made", start, kind, end)


def trace_property_added(kind: str, node_id: str, prop_name: str, value) -> None:
    """Emit a PS1-equivalent multi-line ``Added: <prop>: <value>`` trace
    fragment as a single verbose line per property. PS1 emits these inside
    ``Upsert-Node``'s structured update report; we flatten to one line
    per property so each event is independently filterable / greppable.
    Only call when ``value`` is non-None / non-empty to avoid log spam."""
    logger = logging.getLogger("openhound_sccm.graph")
    logger.verbose("    Added on %s %s: %s = %r", kind, node_id, prop_name, value)


def trace_node_with_properties(kind: str, node_id: str, name: Optional[str], properties: Any) -> None:
    """Emit a PS1-equivalent multi-line block: ``Found existing <kind> node:
    <id> (<name>)`` followed by one ``    Added: <prop>: <value>`` line per
    non-None / non-empty property.

    Designed to be called *after* the SCCMNode has been built. ``properties``
    is the SCCM ``*Properties`` dataclass instance (Pydantic model classes
    don't gain ``__dataclass_fields__`` since these are stdlib dataclasses
    that happen to layer on ``SCCMNodeProperties``). We iterate
    ``dataclasses.fields(properties)`` and emit a line for each populated
    field, skipping framework boilerplate (``node_id``, ``displayname``,
    ``name``, ``environmentid``, ``last_seen``).
    """
    import dataclasses
    trace_node(kind, node_id, name)
    if properties is None:
        return
    skip = {"node_id", "displayname", "name", "environmentid", "last_seen"}
    try:
        if not dataclasses.is_dataclass(properties):
            return
        for field in dataclasses.fields(properties):
            if field.name in skip:
                continue
            try:
                value = getattr(properties, field.name)
            except Exception:
                continue
            # Skip None / empty list / empty string — PS1 only logs values that
            # actually change. ``False`` and ``0`` are real values worth showing.
            if value is None or value == [] or value == "":
                continue
            trace_property_added(kind, node_id, field.name, value)
    except Exception:
        # Belt-and-suspenders: a logging helper must never crash the caller.
        pass


__all__ = [
    "LogContextFilter",
    "VERBOSE",
    "cached_with_log",
    "install_filter",
    "per_host_iter",
    "per_pair_iter",
    "phase_context",
    "target_context",
    "trace_edge",
    "trace_node",
    "trace_node_with_properties",
    "trace_property_added",
    "with_log_context",
]
