"""Tests for the portable engine (phased_pipeline.engine).

This module covers the single-target runner (run_one_target) here; the thread
pool / recursion / shutdown (run_pipeline) tests are added alongside in Task 4.
All tests use *fake* phases and no SCCM/AD/DLT code — proving the engine stands
on its own.
"""
import contextlib

from openhound_sccm.phased_pipeline.engine import Phase, run_one_target
from openhound_sccm.phased_pipeline.streams import build_streams


def _drain(q):
    out = []
    while not q.empty():
        out.append(q.get())
    return out


def test_phases_run_in_order_and_rows_arrive_in_order():
    def p1(target, ctx):
        yield ("out", "p1")

    def p2(target, ctx):
        yield ("out", "p2a")
        yield ("out", "p2b")

    def p3(target, ctx):
        yield ("out", "p3")

    phases = [Phase("P1", ("out",), p1), Phase("P2", ("out",), p2), Phase("P3", ("out",), p3)]
    streams = build_streams(["out"], maxsize=100)
    run_one_target("hostA", None, phases, streams)
    assert _drain(streams["out"]) == ["p1", "p2a", "p2b", "p3"]


def test_rows_route_to_their_named_stream():
    def reg(target, ctx):
        yield ("registry", {"name": target})

    def mssql(target, ctx):
        yield ("mssql", {"host": target})

    phases = [Phase("REG", ("registry",), reg), Phase("MSSQL", ("mssql",), mssql)]
    streams = build_streams(["registry", "mssql"], maxsize=100)
    run_one_target("hostA", None, phases, streams)
    assert _drain(streams["registry"]) == [{"name": "hostA"}]
    assert _drain(streams["mssql"]) == [{"host": "hostA"}]


def test_should_run_can_skip_a_phase():
    def reg(target, ctx):
        yield ("registry", "r")

    def mssql(target, ctx):
        yield ("mssql", "m")

    phases = [Phase("RemoteRegistry", ("registry",), reg), Phase("MSSQL", ("mssql",), mssql)]
    streams = build_streams(["registry", "mssql"], maxsize=100)
    run_one_target(
        "hostA", None, phases, streams,
        should_run=lambda target, phase, ctx: phase.name == "RemoteRegistry",
    )
    assert _drain(streams["registry"]) == ["r"]
    assert _drain(streams["mssql"]) == []


def test_a_failing_phase_does_not_stop_the_following_phases():
    def p1(target, ctx):
        yield ("out", "p1")

    def p2(target, ctx):
        yield ("out", "p2a")
        raise RuntimeError("boom")  # p2b is never reached

    def p3(target, ctx):
        yield ("out", "p3")

    phases = [Phase("P1", ("out",), p1), Phase("P2", ("out",), p2), Phase("P3", ("out",), p3)]
    streams = build_streams(["out"], maxsize=100)
    run_one_target("hostA", None, phases, streams)  # must NOT raise
    assert _drain(streams["out"]) == ["p1", "p2a", "p3"]


def test_phase_scope_wraps_each_phase_in_order():
    entered = []

    @contextlib.contextmanager
    def scope(target, phase_name):
        entered.append((target, phase_name))
        yield

    def p1(target, ctx):
        yield ("out", "p1")

    def p2(target, ctx):
        yield ("out", "p2")

    phases = [Phase("P1", ("out",), p1), Phase("P2", ("out",), p2)]
    streams = build_streams(["out"], maxsize=100)
    run_one_target("hostA", None, phases, streams, phase_scope=scope)
    assert entered == [("hostA", "P1"), ("hostA", "P2")]
