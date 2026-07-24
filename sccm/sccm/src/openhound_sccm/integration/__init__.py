"""SCCM integration-test wiring: assemble mayyhem fixtures + the shared engine."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Callable

from openhound_collector_common.integration_testing.compare import compare_graphs
from openhound_collector_common.integration_testing.graph import load_graph
from openhound_collector_common.integration_testing.results import write_results_json  # noqa: F401 (re-export)
from openhound_collector_common.integration_testing.runner import run_suite

from openhound_sccm.integration.fixtures.edges import MAYYHEM_EDGE_CASES
from openhound_sccm.integration.fixtures.nodes import MAYYHEM_INVARIANTS, MAYYHEM_NODE_CASES

logger = logging.getLogger(__name__)

# schema_SCCM.json sits at the extension package root: src/openhound_sccm/integration/__init__.py
# -> parents[0]=integration, [1]=openhound_sccm, [2]=src, [3]=sccm/sccm (contains schema_SCCM.json)
SCHEMA_PATH = Path(__file__).resolve().parents[3] / "schema_SCCM.json"


def run_integration_tests(graph_dir: Path, results_path: Path | None = None,
                          log: Callable[[str], None] = logger.info) -> int:
    """Load a collected graph and run it against the mayyhem.com fixtures + schema coverage.

    Returns a process-friendly exit code: 1 if any case failed, else 0.
    """
    graph = load_graph(graph_dir)
    summary = run_suite(graph, MAYYHEM_EDGE_CASES, MAYYHEM_NODE_CASES,
                        invariants=MAYYHEM_INVARIANTS, schema_path=SCHEMA_PATH,
                        results_path=results_path, log=log)
    return 1 if summary.failed > 0 else 0


def compare_to_zip(graph_dir: Path, zip_path: Path, out_path: Path | None = None,
                   log: Callable[[str], None] = logger.info) -> int:
    """Diff a freshly-collected graph against a previously collected OpenGraph zip.

    Informational only -- always returns 0 so a drift report never fails a CI run.
    """
    a = load_graph(graph_dir)
    b = load_graph(zip_path)
    report = compare_graphs(a, b)
    report.render(log=log)
    if out_path is not None:
        Path(out_path).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return 0  # informational: never fails the process
