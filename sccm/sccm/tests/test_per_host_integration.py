"""Integration tests for the SCCM per-host stage (Stage 2).

These drive the real worker pool + streaming emit against an isolated DLT
filesystem pipeline writing to a temp dir, using the stub phases. Task 7 covers
the orchestration shape; Task 9 adds the full recursion / backpressure /
allow-list scenarios.
"""
import threading

import dlt
from dlt.destinations import filesystem

from openhound_sccm import main as main_mod
from openhound_sccm.context import SourceContext
from openhound_sccm.per_host_phases import PER_HOST_PHASES, all_table_names
from openhound_sccm.phased_pipeline import WorkQueue


def _isolated_pipeline(tmp_path, name):
    return dlt.pipeline(
        pipeline_name=name,
        destination=filesystem(bucket_url=str(tmp_path)),
        dataset_name="sccm",
        pipelines_dir=str(tmp_path / "_pipelines"),
    )


def _written_tables(tmp_path):
    dataset = tmp_path / "sccm"
    return {
        p.name
        for p in dataset.iterdir()
        if p.is_dir() and not p.name.startswith("_dlt")
    }


def _run_stage_with_timeout(pipeline, work_queue, ctx, threads, timeout=60):
    done = threading.Event()
    errbox = {}

    def run():
        try:
            main_mod._run_per_host_stage(pipeline, work_queue, ctx, threads=threads)
        except Exception as exc:  # pragma: no cover - surfaced via errbox
            errbox["exc"] = exc
        finally:
            done.set()

    runner = threading.Thread(target=run)
    runner.start()
    finished = done.wait(timeout=timeout)
    assert finished, "per-host stage did not finish in time (possible deadlock)"
    assert "exc" not in errbox, f"per-host stage raised: {errbox.get('exc')}"


def test_threads_option_defaults_to_10():
    import inspect

    param = inspect.signature(main_mod.collect_sccm).parameters["threads"]
    # typer.Option(...) returns an OptionInfo whose .default holds the value.
    assert param.default.default == 10


def test_run_per_host_stage_writes_all_stub_tables(tmp_path):
    wq = WorkQueue()
    wq.submit("hostA")
    wq.submit("hostB")
    ctx = SourceContext(ad=None, domain="example.com", work_queue=wq, collection_methods="All")
    pipeline = _isolated_pipeline(tmp_path, "test_stage_tables")

    _run_stage_with_timeout(pipeline, wq, ctx, threads=4)

    written = _written_tables(tmp_path)
    for table in all_table_names(PER_HOST_PHASES):
        assert table in written, f"missing table {table}; got {sorted(written)}"
