#!/usr/bin/env python3
"""
Native Python ConfigManBearPig/OpenHound SCCM integration test harness.

The expected-edge assertions are loaded from unit_test_expectations.py. The
runner can test existing OpenGraph ZIP/files/directories, launch the
PowerShell, ConfigManBearPig Python, and OpenHound collectors, and compare
their graph outputs.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from unit_test_expectations import EXPECTED_EDGES_TEMPLATE
except ImportError:
    from lib.unit_test_expectations import EXPECTED_EDGES_TEMPLATE


def find_sccm_workspace() -> Path:
    for parent in [Path(__file__).resolve().parent, *Path(__file__).resolve().parents]:
        if (parent / "ConfigManBearPig").exists() and (parent / "sccm").exists():
            return parent
    return Path(__file__).resolve().parents[1]


WORKSPACE_SCCM = find_sccm_workspace()
CONFIGMAN = WORKSPACE_SCCM / "ConfigManBearPig"
OPENHOUND_SCCM = (
    Path(__file__).resolve().parent
    if (Path(__file__).resolve().parent / "pyproject.toml").exists()
    else WORKSPACE_SCCM / "sccm"
)
POWERSHELL_COLLECTOR = CONFIGMAN / "powershell_deprecated" / "ConfigManBearPig.ps1"
PYTHON_COLLECTOR = CONFIGMAN / "python" / "configmanbearpig.py"
SEED_ID = "9c3a1f7a-1d6b-4d87-b61b-1c3b7a9e4f01"
COLLECTOR_NAMES = ("powershell", "configmanbearpig-python", "openhound")


EDGE_TYPES = [
    "LocalAdminRequired",
    "CoerceAndRelayToAdminService",
    "CoerceAndRelayToMSSQL",
    "CoerceAndRelaytoSMB",
    "HasSession",
    "MSSQL_Contains",
    "MSSQL_ControlDB",
    "MSSQL_ControlServer",
    "MSSQL_ExecuteOnHost",
    "MSSQL_GetAdminTGS",
    "MSSQL_GetTGS",
    "MSSQL_HasLogin",
    "MSSQL_HostFor",
    "MSSQL_IsMappedTo",
    "MSSQL_MemberOf",
    "MSSQL_ServiceAccountFor",
    "SameHostAs",
    "SCCM_AdminsReplicatedTo",
    "SCCM_AllPermissions",
    "SCCM_ApplicationAdministrator",
    "SCCM_AssignAllPermissions",
    "SCCM_AssignSpecificPermissions",
    "SCCM_Contains",
    "SCCM_FullAdministrator",
    "SCCM_HasADLastLogonUser",
    "SCCM_HasClient",
    "SCCM_HasCurrentUser",
    "SCCM_HasMember",
    "SCCM_HasNetworkAccessAccount",
    "SCCM_HasPrimaryUser",
    "SCCM_HasStoredAccount",
    "SCCM_IsAssigned",
    "SCCM_IsMappedTo",
]

NODE_TYPES = [
    "Computer",
    "Group",
    "Host",
    "User",
    "MSSQL_Database",
    "MSSQL_DatabaseRole",
    "MSSQL_DatabaseUser",
    "MSSQL_Login",
    "MSSQL_Server",
    "MSSQL_ServerRole",
    "SCCM_AdminUser",
    "SCCM_ClientDevice",
    "SCCM_Collection",
    "SCCM_SecurityRole",
    "SCCM_Site",
]


@dataclass
class TestResults:
    passed: list[dict[str, Any]] = field(default_factory=list)
    failed: list[dict[str, Any]] = field(default_factory=list)
    skipped: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class GraphBundle:
    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    classic_files: list[str] = field(default_factory=list)

    def without_seed(self) -> GraphBundle:
        nodes = [
            node
            for node in self.nodes
            if get_case_insensitive(node, "id") != SEED_ID
            and "IgnoreMe" not in (get_case_insensitive(node, "kinds") or [])
        ]
        edges = [
            edge
            for edge in self.edges
            if get_case_insensitive(get_case_insensitive(edge, "start"), "value") != SEED_ID
            and get_case_insensitive(get_case_insensitive(edge, "end"), "value") != SEED_ID
        ]
        return GraphBundle(nodes=nodes, edges=edges, files=list(self.files), classic_files=list(self.classic_files))


class Logger:
    def __init__(self, log_file: Path | None):
        self.log_file = log_file
        self.use_color = sys.stdout.isatty() and not bool(os.environ.get("NO_COLOR")) and os.environ.get("TERM") != "dumb"
        if self.log_file:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            self.log_file.write_text("", encoding="utf-8")

    def write(self, message: str, level: str = "Info") -> None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rendered = f"{timestamp} [{level}] {message}"
        color_map = {
            "Success": "\033[32m",
            "Warning": "\033[33m",
            "Error": "\033[31m",
            "Test": "\033[36m",
            "Verbose": "\033[35m",
        }
        if self.use_color and level in color_map:
            print(f"{color_map[level]}{message}\033[0m")
        else:
            print(message)
        if self.log_file:
            with self.log_file.open("a", encoding="utf-8") as handle:
                handle.write(rendered + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Native Python SCCM Collector Test Suite")
    parser.add_argument("--input-path", "--input", dest="input_path", type=Path, help="OpenGraph ZIP, JSON file, or directory")
    parser.add_argument(
        "--enumeration-script",
        type=Path,
        default=POWERSHELL_COLLECTOR,
        help="PowerShell ConfigManBearPig.ps1 path used by --collector powershell",
    )
    parser.add_argument("-d", "--domain", default="mayyhem.com", help="Domain to substitute into test cases")
    parser.add_argument("-dc", "--domain-controller", default="10.2.10.100")
    parser.add_argument("-u", "--username")
    parser.add_argument("-p", "--password")
    parser.add_argument("--log-file", type=Path, default=Path("ConfigManBearPig_UnitTests_output_python.log"))
    parser.add_argument("--limit-edge-type", "--limit-to-edge-type", dest="limit_edge_type")
    parser.add_argument("--show-debug", action="store_true")
    parser.add_argument("--action", choices=["All", "Setup", "Test", "Teardown"], default="All")
    parser.add_argument("--skip-collection", action="store_true")
    parser.add_argument("--collector", choices=[*COLLECTOR_NAMES, "all"])
    parser.add_argument(
        "--collectors",
        nargs="+",
        choices=COLLECTOR_NAMES,
        help="Collector subset to run and compare; defaults to all three with --collector all",
    )
    parser.add_argument("--all-collectors", action="store_true", help="Run PowerShell, ConfigManBearPig Python, and OpenHound collectors")
    parser.add_argument("--fail-fast", action="store_true", help="Stop the all-collector run after the first collector or test failure")
    parser.add_argument("--output-dir", type=Path, default=OPENHOUND_SCCM / "output")
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument("--collection-methods", default="All")
    parser.add_argument("--computers")
    parser.add_argument("--computer-file")
    parser.add_argument("--sms-provider")
    parser.add_argument("--site-codes")
    parser.add_argument("--ldap-port", type=int, default=389)
    parser.add_argument("--ldaps", action="store_true")
    parser.add_argument("--ldap-start-tls", action="store_true")
    parser.add_argument("--ldap-signing", choices=["auto", "required", "disabled"], default="auto")
    parser.add_argument("--ldap-channel-binding", choices=["auto", "required", "disabled"], default="auto")
    parser.add_argument("--disable-possible-edges", action="store_true")
    parser.add_argument("--enable-bad-opsec", action="store_true")
    parser.add_argument("--show-cleartext-passwords", action="store_true")
    parser.add_argument("--machine-name")
    parser.add_argument("--machine-pass")
    parser.add_argument("--client-name")
    parser.add_argument("--create-machine-account", nargs="?", const="auto")
    parser.add_argument("--use-altauth", action="store_true")
    parser.add_argument("--registration-sleep", type=int, default=10)
    parser.add_argument("--socks-proxy")
    parser.add_argument("--compare", action="append", default=[], help="Named graph to compare, in name=path form")
    parser.add_argument("--signature-compare", action="store_true", help="Compare canonical node and edge signatures")
    parser.add_argument("--all-signatures", action="store_true", help="With --signature-compare, list every mismatching signature (default behaviour now; kept for back-compat)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Propagate -v / -Verbose to every collector invocation and tee its console output to a per-collector log file under <output-dir>/.")
    parser.add_argument("--console-diff", action="store_true", help="After a multi-collector sweep, run a normalized line-level diff across the three collector console logs.")
    parser.add_argument("--include-seed", dest="exclude_seed", action="store_false", help="Include seed IgnoreMe declarations")
    parser.add_argument("--no-seed", dest="exclude_seed", action="store_true", help="Exclude seed IgnoreMe declarations")
    parser.set_defaults(exclude_seed=True, run_edge_tests=True)
    parser.add_argument("--run-edge-tests", dest="run_edge_tests", action="store_true", help="Run expected-edge assertions")
    parser.add_argument("--skip-edge-tests", dest="run_edge_tests", action="store_false", help="Only print graph totals/checks")
    return parser.parse_args()


def substitute_domain(value: Any, domain: str) -> Any:
    if isinstance(value, str):
        return value.replace("$Domain", domain).replace("$:", ":")
    if isinstance(value, list):
        return [substitute_domain(item, domain) for item in value]
    if isinstance(value, dict):
        return {key: substitute_domain(item, domain) for key, item in value.items()}
    return value


def find_default_input() -> Path | None:
    candidates = sorted(Path.cwd().glob("bloodhound-sccm*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


def powershell_exe() -> str | None:
    return shutil.which("powershell.exe") or shutil.which("powershell") or shutil.which("pwsh")


def resolve_collectors(args: argparse.Namespace) -> list[str]:
    if args.collectors:
        return list(dict.fromkeys(args.collectors))
    if args.all_collectors or args.collector == "all":
        return list(COLLECTOR_NAMES)
    if args.collector:
        return [args.collector]
    return []


def get_case_insensitive(mapping: dict[str, Any] | None, key: str) -> Any:
    if not isinstance(mapping, dict):
        return None
    if key in mapping:
        return mapping[key]
    lower_key = key.lower()
    for actual_key, value in mapping.items():
        if actual_key.lower() == lower_key:
            return value
    return None


def merge_graph_payload(bundle: GraphBundle, content: dict[str, Any], label: str) -> None:
    graph = content.get("graph")
    if isinstance(graph, dict):
        nodes = graph.get("nodes") or []
        edges = graph.get("edges") or []
        if isinstance(nodes, list):
            bundle.nodes.extend(node for node in nodes if isinstance(node, dict))
        if isinstance(edges, list):
            bundle.edges.extend(edge for edge in edges if isinstance(edge, dict))
        bundle.files.append(label)
    elif "data" in content and "meta" in content:
        bundle.classic_files.append(label)


def load_json_payload(raw: bytes | str) -> dict[str, Any] | None:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def load_graph(input_path: Path, logger: Logger) -> GraphBundle:
    bundle = GraphBundle()
    if input_path.is_dir():
        json_files = sorted(input_path.rglob("*.json"))
        logger.write(f"Found {len(json_files)} JSON files in input", "Info")
        for json_file in json_files:
            logger.write(f"Reading JSON from: {json_file.name}", "Info")
            content = load_json_payload(json_file.read_text(encoding="utf-8"))
            if content is not None:
                merge_graph_payload(bundle, content, str(json_file))
    elif input_path.suffix.lower() == ".zip":
        with zipfile.ZipFile(input_path) as archive:
            json_names = sorted(name for name in archive.namelist() if name.lower().endswith(".json"))
            logger.write(f"Found {len(json_names)} JSON files in input", "Info")
            for name in json_names:
                logger.write(f"Reading JSON from: {Path(name).name}", "Info")
                content = load_json_payload(archive.read(name))
                if content is not None:
                    merge_graph_payload(bundle, content, f"{input_path}!{name}")
    elif input_path.is_file():
        logger.write("Found 1 JSON file in input", "Info")
        content = load_json_payload(input_path.read_text(encoding="utf-8"))
        if content is not None:
            merge_graph_payload(bundle, content, str(input_path))
    else:
        raise ValueError(f"Input path must be a ZIP, JSON file, or directory: {input_path}")

    logger.write(f"Combined output: {len(bundle.nodes)} nodes, {len(bundle.edges)} edges", "Info")
    return bundle


def aliases_for_edge_kind(kind: str | None) -> set[str]:
    if not kind:
        return set()
    lower = kind.lower()
    aliases = {lower}
    if lower.startswith("sccm_"):
        aliases.add(lower[5:])
    special = {
        "mssql_coerceandrelaytomssql": "coerceandrelaytomssql",
        "sccm_coerceandrelaytosmb": "coerceandrelaytosmb",
        "sccm_samehostas": "samehostas",
        "sccm_hasclient": "hasclient",
        "sccm_hasmember": "hasmember",
        "sccm_hasadlastlogonuser": "hasadlastlogonuser",
        "sccm_hascurrentuser": "hascurrentuser",
        "sccm_hasprimaryuser": "hasprimaryuser",
        "sccm_hasstoredaccount": "hasstoredaccount",
        "sccm_hasnetworkaccessaccount": "hasnetworkaccessaccount",
        "sccm_isassigned": "isassigned",
        "sccm_ismappedto": "ismappedto",
        "sccm_localadminrequired": "localadminrequired",
        "sccm_coerceandrelaytoadminservice": "coerceandrelaytoadminservice",
    }
    alias = special.get(lower)
    if alias:
        aliases.add(alias)
    return aliases


def aliases_for_node_kind(kind: str | None) -> set[str]:
    if not kind:
        return set()
    lower = kind.lower()
    aliases = {lower}
    if lower.startswith("sccm_"):
        aliases.add(lower[5:])
    return aliases


def edge_kind_matches(actual: str | None, expected: str | None) -> bool:
    return bool(aliases_for_edge_kind(actual) & aliases_for_edge_kind(expected))


def node_kind_matches(actual_kinds: list[str], expected_kind: str) -> bool:
    if expected_kind.lower() == "base":
        return True
    expected_aliases = aliases_for_node_kind(expected_kind)
    return any(aliases_for_node_kind(str(actual)) & expected_aliases for actual in actual_kinds)


def property_match(actual: Any, expected: Any) -> bool:
    if actual is None and expected is None:
        return True
    if actual is None or expected is None:
        return False
    if isinstance(expected, list) and isinstance(actual, list):
        return all(any(property_match(actual_item, expected_item) for actual_item in actual) for expected_item in expected)
    if isinstance(expected, list) or isinstance(actual, list):
        return False
    if isinstance(expected, bool):
        if isinstance(actual, bool):
            return actual == expected
        actual_str = str(actual).lower()
        if actual_str in {"true", "1"}:
            return expected is True
        if actual_str in {"false", "0"}:
            return expected is False
    actual_str = str(actual)
    expected_str = str(expected)
    if "*" in expected_str or "?" in expected_str:
        return fnmatch.fnmatch(actual_str.lower(), expected_str.lower())
    return actual_str.lower() == expected_str.lower()


def property_value(obj: dict[str, Any], prop: str) -> Any:
    props = get_case_insensitive(obj, "properties")
    if isinstance(props, dict):
        value = get_case_insensitive(props, prop)
        if value is not None:
            return value
    return get_case_insensitive(obj, prop)


def dump_edge(edge: dict[str, Any], logger: Logger) -> None:
    start = get_case_insensitive(get_case_insensitive(edge, "start"), "value")
    end = get_case_insensitive(get_case_insensitive(edge, "end"), "value")
    kind = get_case_insensitive(edge, "kind")
    logger.write(f"  Testing Edge: {start}-[{kind}]->{end}", "Verbose")
    logger.write(f"  Kind: {kind}", "Verbose")
    logger.write("  Properties:", "Verbose")
    for key, value in edge.items():
        logger.write(f"    {key}: {value}", "Verbose")


def dump_node(node: dict[str, Any], logger: Logger) -> None:
    logger.write(f"  Testing Node ID: {get_case_insensitive(node, 'id')}", "Verbose")
    kinds = get_case_insensitive(node, "kinds") or []
    logger.write(f"  Kinds: {', '.join(str(item) for item in kinds)}", "Verbose")
    logger.write("  Properties:", "Verbose")
    for key, value in node.items():
        logger.write(f"  {key}: {value}", "Verbose")


def node_pattern_matches(node: dict[str, Any], expected: dict[str, Any], logger: Logger, show_debug: bool) -> bool:
    kinds = get_case_insensitive(node, "kinds") or []
    if expected.get("Kinds"):
        for expected_kind in expected["Kinds"]:
            if not node_kind_matches(list(kinds), str(expected_kind)):
                if show_debug:
                    dump_node(node, logger)
                    logger.write(f"    Node missing kind '{expected_kind}' (has: {', '.join(map(str, kinds))})", "Warning")
                return False

    for prop, expected_value in (expected.get("Properties") or {}).items():
        actual_value = property_value(node, prop)
        if not property_match(actual_value, expected_value):
            if show_debug:
                dump_node(node, logger)
                logger.write(
                    f"    Property '{prop}' doesn't match (expected: {expected_value}, actual: {actual_value})",
                    "Warning",
                )
            return False
    return True


def edge_pattern_matches(
    edge: dict[str, Any],
    node_index: dict[str, dict[str, Any]],
    expected_edge: dict[str, Any],
    logger: Logger,
    show_debug: bool,
) -> bool:
    if not edge_kind_matches(get_case_insensitive(edge, "kind"), expected_edge.get("Kind")):
        return False

    start = get_case_insensitive(get_case_insensitive(edge, "start"), "value")
    end = get_case_insensitive(get_case_insensitive(edge, "end"), "value")
    source_node = node_index.get(str(start))
    target_node = node_index.get(str(end))
    if source_node is None or target_node is None:
        if show_debug:
            dump_edge(edge, logger)
            logger.write("    Could not find source or target node", "Warning")
        return False

    if expected_edge.get("Source") and not node_pattern_matches(source_node, expected_edge["Source"], logger, show_debug):
        if show_debug:
            dump_edge(edge, logger)
            logger.write("    Source node doesn't match pattern", "Warning")
        return False

    if expected_edge.get("Target") and not node_pattern_matches(target_node, expected_edge["Target"], logger, show_debug):
        if show_debug:
            dump_edge(edge, logger)
            logger.write("    Target node doesn't match pattern", "Warning")
        return False

    for prop, expected_value in (expected_edge.get("Properties") or {}).items():
        actual_value = property_value(edge, prop)
        if not property_match(actual_value, expected_value):
            if show_debug:
                dump_edge(edge, logger)
                logger.write(
                    f"    Edge property '{prop}' doesn't match (expected: {expected_value}, actual: {actual_value})",
                    "Verbose",
                )
            return False

    return True


def format_expected_pattern(side: dict[str, Any] | None) -> str:
    if not side:
        return ""
    props = side.get("Properties") or {}
    rendered = [f"{key}={value}" for key, value in props.items()]
    return "{" + ", ".join(rendered) + "}" if rendered else ""


def analyze_missing_match(
    edges: list[dict[str, Any]],
    nodes_by_id: dict[str, dict[str, Any]],
    test_case: dict[str, Any],
    logger: Logger,
) -> None:
    target_aliases = aliases_for_edge_kind(test_case["Kind"])
    same_kind_edges = [edge for edge in edges if aliases_for_edge_kind(str(get_case_insensitive(edge, "kind"))) & target_aliases]
    if same_kind_edges:
        logger.write(
            f"  Analysis: Found {len(same_kind_edges)} {test_case['Kind']} edge(s) but none matched the pattern",
            "Warning",
        )
        mismatch_reasons: list[str] = []
        checked_nodes: set[str] = set()
        for edge in same_kind_edges[:3]:
            source_id = str(get_case_insensitive(get_case_insensitive(edge, "start"), "value"))
            target_id = str(get_case_insensitive(get_case_insensitive(edge, "end"), "value"))
            source_node = nodes_by_id.get(source_id)
            target_node = nodes_by_id.get(target_id)
            if test_case.get("Source") and source_node and source_id not in checked_nodes:
                checked_nodes.add(source_id)
                collect_mismatch_reasons(mismatch_reasons, "Source", source_id, source_node, test_case["Source"])
            if test_case.get("Target") and target_node and target_id not in checked_nodes:
                checked_nodes.add(target_id)
                collect_mismatch_reasons(mismatch_reasons, "Target", target_id, target_node, test_case["Target"])
        if mismatch_reasons:
            logger.write("  Common issues found:", "Info")
            for index, reason in enumerate(dict.fromkeys(mismatch_reasons)):
                if index >= 5:
                    break
                logger.write(f"    - {reason}", "Info")
        logger.write(f"  Existing {test_case['Kind']} edges:", "Info")
        for edge in same_kind_edges[:2]:
            start = get_case_insensitive(get_case_insensitive(edge, "start"), "value")
            end = get_case_insensitive(get_case_insensitive(edge, "end"), "value")
            kind = get_case_insensitive(edge, "kind")
            logger.write(f"    ({start}) -[{kind}]-> ({end})", "Info")
        if len(same_kind_edges) > 2:
            logger.write(f"    ... and {len(same_kind_edges) - 2} more", "Info")
        return

    logger.write(f"  Analysis: No {test_case['Kind']} edges found in the data", "Warning")
    logger.write("  Suggestion: Verify that the collector is producing this edge type", "Info")


def collect_mismatch_reasons(
    mismatch_reasons: list[str],
    side: str,
    node_id: str,
    node: dict[str, Any],
    expected: dict[str, Any],
) -> None:
    for prop, expected_value in (expected.get("Properties") or {}).items():
        actual_value = property_value(node, prop)
        if not property_match(actual_value, expected_value):
            mismatch_reasons.append(f"{side} node {node_id}: {prop} = '{actual_value}' (expected '{expected_value}')")


def graph_stats(bundle: GraphBundle) -> dict[str, Any]:
    return {
        "node_total": len(bundle.nodes),
        "edge_total": len(bundle.edges),
        "node_kind_counts": Counter(kind for node in bundle.nodes for kind in (get_case_insensitive(node, "kinds") or [])),
        "edge_kind_counts": Counter(get_case_insensitive(edge, "kind") for edge in bundle.edges),
    }


def log_counter_differences(label: str, baseline: Counter, candidate: Counter, logger: Logger) -> None:
    keys = sorted(set(baseline) | set(candidate), key=lambda item: str(item))
    deltas = [(key, baseline.get(key, 0), candidate.get(key, 0)) for key in keys if baseline.get(key, 0) != candidate.get(key, 0)]
    if not deltas:
        return
    logger.write(f"  {label} differences:", "Error")
    for key, baseline_count, candidate_count in deltas:
        logger.write(f"    {key}: {baseline_count} != {candidate_count} ({candidate_count - baseline_count:+d})", "Error")


def print_graph_totals(bundle: GraphBundle, logger: Logger) -> None:
    stats = graph_stats(bundle)
    logger.write(f"Total edges found: {stats['edge_total']}", "Info")
    logger.write(f"Total nodes found: {stats['node_total']}", "Info")
    logger.write("\nEdge types found:", "Info")
    for kind, count in sorted(stats["edge_kind_counts"].items()):
        logger.write(f"  {kind}: {count}", "Info")


def run_edge_tests(
    bundle: GraphBundle,
    expected_edges: list[dict[str, Any]],
    logger: Logger,
    limit_edge_type: str | None,
    show_debug: bool,
) -> TestResults:
    logger.write("\nTesting Edges...", "Test")
    logger.write("=" * 30, "Info")
    print_graph_totals(bundle, logger)

    node_index = {}
    for node in bundle.nodes:
        node_id = get_case_insensitive(node, "id")
        if node_id is not None and str(node_id) not in node_index:
            node_index[str(node_id)] = node

    results = TestResults()
    logger.write("\nRunning edge tests...", "Test")
    for test_case in expected_edges:
        if limit_edge_type and str(test_case.get("Kind")) != limit_edge_type:
            continue

        if not any(test_case.get(key) for key in ("Source", "Target", "Properties")):
            logger.write(f"{test_case['Kind']}: no Source/Target/Properties specified - SKIPPED (coverage placeholder)", "Warning")
            results.skipped.append(test_case)
            continue

        matching_edges = [
            edge
            for edge in bundle.edges
            if edge_pattern_matches(edge, node_index, test_case, logger, show_debug)
        ]
        found = bool(matching_edges)

        if test_case.get("Negative"):
            if not found:
                logger.write(f"{test_case['Kind']}: {test_case['Description']} - PASS (correctly absent)", "Success")
                reason = test_case.get("Reason")
                if reason:
                    logger.write(f"  Reason: {reason}", "Info")
                results.passed.append(test_case)
            else:
                logger.write(f"{test_case['Kind']}: {test_case['Description']} - FAIL (incorrectly present)", "Error")
                logger.write(f"  This edge should not exist: {test_case.get('Reason')}", "Error")
                log_matching_edges(matching_edges, logger, "Error")
                results.failed.append(test_case)
            continue

        if found:
            expected_count = test_case.get("Count")
            if expected_count and len(matching_edges) != expected_count:
                logger.write(f"{test_case['Kind']}: {test_case['Description']} - FAIL (wrong count)", "Error")
                logger.write(f"  Expected {expected_count} matching edge(s) but found {len(matching_edges)}", "Error")
                log_matching_edges(matching_edges, logger, "Error")
                results.failed.append(test_case)
                continue

            logger.write(f"{test_case['Kind']}: {test_case['Description']} - PASS", "Success")
            logger.write(f"  Found {len(matching_edges)} matching edge(s)", "Success")
            log_matching_edges(matching_edges, logger, "Info")
            results.passed.append(test_case)
            continue

        logger.write(f"{test_case['Kind']}: {test_case['Description']} - FAIL (not found)", "Error")
        source_pattern = format_expected_pattern(test_case.get("Source"))
        target_pattern = format_expected_pattern(test_case.get("Target"))
        rendered_patterns = []
        if source_pattern:
            rendered_patterns.append(f"Source: {source_pattern}")
        if target_pattern:
            rendered_patterns.append(f"Target: {target_pattern}")
        if rendered_patterns:
            logger.write(f"  Expected: {' -> '.join(rendered_patterns)}", "Error")
        analyze_missing_match(bundle.edges, node_index, test_case, logger)
        results.failed.append(test_case)

    logger.write("\nEdge Test Summary:", "Info")
    logger.write(f"  Passed: {len(results.passed)}", "Success")
    logger.write(f"  Failed: {len(results.failed)}", "Error" if results.failed else "Success")
    logger.write(f"  Skipped: {len(results.skipped)}", "Warning")
    return results


def log_matching_edges(edges: list[dict[str, Any]], logger: Logger, level: str = "Info") -> None:
    logger.write("  Matching edges:", level)
    for edge in edges:
        start = get_case_insensitive(get_case_insensitive(edge, "start"), "value")
        end = get_case_insensitive(get_case_insensitive(edge, "end"), "value")
        kind = get_case_insensitive(edge, "kind")
        logger.write(f"    ({start}) -[{kind}]-> ({end})", level)


def run_client_device_memberof_check(bundle: GraphBundle, logger: Logger) -> bool:
    try:
        site_nodes = [
            node for node in bundle.nodes if node_kind_matches(get_case_insensitive(node, "kinds") or [], "SCCM_Site")
        ]
        root_site = next((node for node in site_nodes if str(get_case_insensitive(node, "id")) == "CAS"), None)
        if root_site is None:
            logger.write("ClientDevice memberOf normalization check: could not find CAS root site node; skipping check", "Warning")
            return True
        root_site_code = str(get_case_insensitive(root_site, "id"))
        ok = True
        client_devices = [
            node for node in bundle.nodes if node_kind_matches(get_case_insensitive(node, "kinds") or [], "SCCM_ClientDevice")
        ]
        for device in client_devices:
            member_of = property_value(device, "memberOf")
            if not member_of:
                continue
            bad_entries = []
            for entry in member_of:
                match = re.match(r"^(.+)@([A-Z0-9]{3})$", str(entry))
                if match and match.group(2) != root_site_code:
                    bad_entries.append(str(entry))
            device_id = str(get_case_insensitive(device, "id"))
            if bad_entries:
                logger.write("ClientDevice memberOf normalization check - FAIL", "Error")
                logger.write(f"  Device ID: {device_id}", "Error")
                logger.write(f"  Found non-root memberOf entries: {', '.join(bad_entries)}", "Error")
                ok = False
            else:
                logger.write(f"ClientDevice memberOf normalization check - PASS for device {device_id}", "Success")
        return ok
    except Exception as exc:
        logger.write(f"Error during client device normalization check: {exc}", "Error")
        return False


def kind_present(actual_counts: Counter, expected: str, alias_func) -> bool:
    expected_aliases = alias_func(expected)
    return any(alias_func(str(actual)) & expected_aliases for actual in actual_counts)


def log_coverage_summary(bundle: GraphBundle, results: TestResults, logger: Logger) -> None:
    stats = graph_stats(bundle)
    logger.write("Edge Type Coverage Summary:", "Info")
    tests_executed = bool(results.passed or results.failed or results.skipped)
    failed_edge_types = sorted({str(case["Kind"]) for case in results.failed})
    untested_edges = sorted(set(EDGE_TYPES) - {str(case["Kind"]) for case in results.passed + results.failed + results.skipped})
    missing_edges = sorted(edge_type for edge_type in EDGE_TYPES if not kind_present(stats["edge_kind_counts"], edge_type, aliases_for_edge_kind))
    missing_nodes = sorted(node_type for node_type in NODE_TYPES if not kind_present(stats["node_kind_counts"], node_type, aliases_for_node_kind))
    if missing_nodes:
        logger.write("Node types without output:", "Warning")
        for node_type in missing_nodes:
            logger.write(f"  - {node_type}", "Warning")
    if missing_edges:
        logger.write("Edge types without output:", "Warning")
        for edge_type in missing_edges:
            logger.write(f"  - {edge_type}", "Warning")
    if tests_executed and untested_edges:
        logger.write("Edge types without expectation cases:", "Warning")
        for edge_type in untested_edges:
            logger.write(f"  - {edge_type}", "Warning")
    if failed_edge_types:
        logger.write("Failed edge types:", "Error")
        for edge_type in failed_edge_types:
            logger.write(f"  - {edge_type}", "Error")


def canonicalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: canonicalize(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return sorted((canonicalize(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True))
    return value


def node_signature(node: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(get_case_insensitive(node, "id")),
        json.dumps(sorted(get_case_insensitive(node, "kinds") or [])),
        json.dumps(canonicalize(get_case_insensitive(node, "properties") or {}), sort_keys=True, separators=(",", ":")),
    )


def edge_signature(edge: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(get_case_insensitive(edge, "kind")),
        str(get_case_insensitive(get_case_insensitive(edge, "start"), "value")),
        str(get_case_insensitive(get_case_insensitive(edge, "end"), "value")),
        json.dumps(canonicalize(get_case_insensitive(edge, "properties") or {}), sort_keys=True, separators=(",", ":")),
    )


def compare_graphs(named: dict[str, GraphBundle], logger: Logger, signature_compare: bool = False) -> bool:
    names = list(named)
    if len(names) < 2:
        return True
    baseline_name = names[0]
    baseline = named[baseline_name]
    baseline_stats = graph_stats(baseline)
    baseline_nodes = Counter(node_signature(node) for node in baseline.nodes)
    baseline_edges = Counter(edge_signature(edge) for edge in baseline.edges)
    ok = True

    logger.write("\nCross-Collector Compare", "Test")
    for name in names[1:]:
        bundle = named[name]
        stats = graph_stats(bundle)
        metric_mismatches = []
        if stats["node_total"] != baseline_stats["node_total"]:
            metric_mismatches.append(f"nodes {baseline_stats['node_total']} != {stats['node_total']}")
        if stats["edge_total"] != baseline_stats["edge_total"]:
            metric_mismatches.append(f"edges {baseline_stats['edge_total']} != {stats['edge_total']}")
        if stats["node_kind_counts"] != baseline_stats["node_kind_counts"]:
            metric_mismatches.append("node kind counts differ")
        if stats["edge_kind_counts"] != baseline_stats["edge_kind_counts"]:
            metric_mismatches.append("edge kind counts differ")
        logger.write(
            f"{baseline_name} vs {name}: "
            f"nodes {baseline_stats['node_total']} vs {stats['node_total']}; "
            f"edges {baseline_stats['edge_total']} vs {stats['edge_total']}",
            "Info",
        )
        if metric_mismatches:
            ok = False
            for mismatch in metric_mismatches:
                logger.write(f"  Metric mismatch: {mismatch}", "Error")
            log_counter_differences("Node kind count", baseline_stats["node_kind_counts"], stats["node_kind_counts"], logger)
            log_counter_differences("Edge kind count", baseline_stats["edge_kind_counts"], stats["edge_kind_counts"], logger)
        else:
            logger.write("  Totals and kind counts match", "Success")

        if signature_compare:
            ok = compare_signatures(baseline_nodes, baseline_edges, bundle, logger) and ok

    # When we have all three collectors (PS1 + CMBP + OH), print a single
    # 3-column histogram so per-kind drift is visible at a glance — same
    # idea as the standalone ``_compare3.py`` debug script, but built into
    # the harness so it always runs at the end of an ``--all-collectors``
    # sweep.
    if len(names) >= 3:
        _print_kind_histogram(named, logger)
    return ok


def _print_kind_histogram(named: dict[str, "GraphBundle"], logger: "Logger") -> None:
    """Print an aligned ``Kind  PS1  CMBP  OH`` table for every edge / node
    kind that appears in any collector's output. Drift rows get a ``<-- DRIFT``
    marker. Mirrors what ``_compare3.py`` produces, just inlined."""
    names = list(named)
    edge_counts: dict[str, Counter] = {}
    node_counts: dict[str, Counter] = {}
    for name in names:
        b = named[name]
        edge_counts[name] = Counter(e.get("kind", "") for e in b.edges)
        node_counts[name] = Counter((n.get("kinds") or [""])[0] for n in b.nodes)

    def _table(header: str, per_name: dict[str, Counter]) -> None:
        kinds = sorted(set().union(*(set(c) for c in per_name.values())))
        if not kinds:
            return
        logger.write(f"\n{header}", "Test")
        cols = "  ".join(f"{n:<5}" for n in names)
        logger.write(f"  {'Kind':<35} {cols}", "Info")
        for k in kinds:
            row = [per_name[n].get(k, 0) for n in names]
            cells = "  ".join(f"{c:<5}" for c in row)
            mark = "" if len(set(row)) == 1 else "  <-- DRIFT"
            logger.write(f"  {k:<35} {cells}{mark}", "Info")

    _table("Per-edge-kind histogram (3-way)", edge_counts)
    _table("Per-node-kind histogram (3-way)", node_counts)

    totals = "  ".join(
        f"{n}={sum(node_counts[n].values())}/{sum(edge_counts[n].values())}" for n in names
    )
    logger.write(f"\nTOTALS  {totals}", "Info")


def compare_signatures(
    baseline_nodes: Counter,
    baseline_edges: Counter,
    bundle: GraphBundle,
    logger: Logger,
) -> bool:
    """Diff canonical node/edge signatures against *baseline*.

    Reports every mismatching signature grouped by kind, with a per-kind summary
    line (``Edge kind X: +N / -M``) followed by the deterministically sorted
    signatures. Group-then-list makes pull-quoting a specific edge kind during
    triage cheap, and dropping the original ``[:5]`` truncation means we don't
    miss the second-half of a long tail of regressions.
    """
    node_counts = Counter(node_signature(node) for node in bundle.nodes)
    edge_counts = Counter(edge_signature(edge) for edge in bundle.edges)
    node_extra = node_counts - baseline_nodes
    node_missing = baseline_nodes - node_counts
    edge_extra = edge_counts - baseline_edges
    edge_missing = baseline_edges - edge_counts
    if not (node_extra or node_missing or edge_extra or edge_missing):
        logger.write("  Signatures match exactly", "Success")
        return True

    logger.write(
        f"  Mismatch: +nodes={sum(node_extra.values())} -nodes={sum(node_missing.values())} "
        f"+edges={sum(edge_extra.values())} -edges={sum(edge_missing.values())}",
        "Error",
    )

    def node_kind_key(sig: tuple) -> str:
        try:
            return json.loads(sig[1])[0] if sig[1] else ""
        except (ValueError, IndexError):
            return ""

    def edge_kind_key(sig: tuple) -> str:
        return sig[0]

    def render_node_sig(sig: tuple) -> str:
        node_id, kinds_json, props_json = sig
        return f"id={node_id} kinds={kinds_json} properties={props_json}"

    def render_edge_sig(sig: tuple) -> str:
        kind, start, end, props_json = sig
        return f"({start}) -[{kind}]-> ({end}) properties={props_json}"

    sections = (
        ("Missing node (in baseline, absent here)", node_missing, node_kind_key, render_node_sig),
        ("Extra node (here, not in baseline)", node_extra, node_kind_key, render_node_sig),
        ("Missing edge (in baseline, absent here)", edge_missing, edge_kind_key, render_edge_sig),
        ("Extra edge (here, not in baseline)", edge_extra, edge_kind_key, render_edge_sig),
    )
    for label, delta, key_fn, render in sections:
        if not delta:
            continue
        grouped: dict[str, list[tuple[tuple, int]]] = {}
        for sig, count in delta.items():
            grouped.setdefault(key_fn(sig), []).append((sig, count))
        logger.write(f"  {label}:", "Error")
        for kind in sorted(grouped):
            entries = sorted(grouped[kind], key=lambda item: render(item[0]))
            total = sum(count for _sig, count in entries)
            logger.write(f"    {kind or '<unknown>'}: {total}", "Error")
            for sig, count in entries:
                logger.write(f"      x{count}: {render(sig)}", "Error")
    return False


_CONSOLE_NOISE_PATTERNS = (
    # Drop volatile noise (timestamps, thread/PID, absolute paths, progress bars,
    # memory/CPU readouts) so the three transcripts diff on collection intent only.
    (re.compile(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}[.,]?\d*Z?\s*"), ""),
    (re.compile(r"\b\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b"), "<TIME>"),
    (re.compile(r"\[(?:Thread|PID|tid|pid)[: ]?\d+\]\s*"), ""),
    (re.compile(r"\b(?:Memory|CPU) usage[^\n]*"), ""),
    (re.compile(r"\bTime: \d+(?:\.\d+)?s\b"), "Time: <T>s"),
    (re.compile(r"\bRate: \d+(?:\.\d+)?/s\b"), "Rate: <R>/s"),
    (re.compile(r"\b\d+(?:\.\d+)? MB \(\d+(?:\.\d+)?%\)"), "<MEM>"),
    (re.compile(r"in \d+\.\d+\b"), "in <T>"),
    (re.compile(r"\b[A-Z]:\\[^\s\"',]+", re.IGNORECASE), "<PATH>"),
    (re.compile(r"/[A-Za-z0-9_./-]{3,}"), "<PATH>"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE), "<UUID>"),
)


def normalize_console_line(line: str) -> str:
    text = line.rstrip("\r\n").rstrip()
    for pattern, replacement in _CONSOLE_NOISE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text.strip()


def run_console_diff(args: argparse.Namespace, outputs: dict[str, Path], logger: Logger) -> bool:
    """Diff per-collector verbose console logs to surface intent drift.

    Each collector writes to ``<output_dir>/<collector>/console_<collector>.log``
    when ``--verbose`` is set. We normalize timestamps, thread IDs, paths,
    progress bars, and memory readouts, then run a Counter-difference (not a
    line-positional diff — collection stage order between three differently-
    architected collectors is intentionally not byte-aligned) to surface lines
    that one collector emits that another doesn't.
    """
    import difflib

    logger.write("\nConsole Diff", "Test")
    transcripts: dict[str, list[str]] = {}
    for collector_name in outputs:
        path = args.output_dir / collector_name / f"console_{collector_name}.log"
        if not path.exists():
            logger.write(f"  {collector_name}: console log missing at {path}", "Warning")
            continue
        lines = [normalize_console_line(line) for line in path.read_text(encoding="utf-8", errors="replace").splitlines()]
        lines = [line for line in lines if line]
        transcripts[collector_name] = lines
        logger.write(f"  {collector_name}: {len(lines)} normalized lines from {path}", "Info")

    if len(transcripts) < 2:
        logger.write("  Not enough console transcripts to diff.", "Warning")
        return True

    names = list(transcripts)
    baseline_name = names[0]
    baseline_lines = transcripts[baseline_name]
    baseline_set = Counter(baseline_lines)
    ok = True
    for name in names[1:]:
        other_set = Counter(transcripts[name])
        only_baseline = baseline_set - other_set
        only_other = other_set - baseline_set
        if not only_baseline and not only_other:
            logger.write(f"  {baseline_name} vs {name}: console transcripts match (after normalization)", "Success")
            continue
        ok = False
        logger.write(
            f"  {baseline_name} vs {name}: {sum(only_baseline.values())} line(s) unique to {baseline_name}, "
            f"{sum(only_other.values())} unique to {name}",
            "Error",
        )
        for label, delta in ((baseline_name, only_baseline), (name, only_other)):
            if not delta:
                continue
            logger.write(f"    Only in {label}:", "Error")
            for line, count in sorted(delta.items()):
                logger.write(f"      x{count}: {line}", "Error")
        # Also show a small unified diff for the first divergence run, for context.
        diff_lines = list(difflib.unified_diff(baseline_lines[:200], transcripts[name][:200], fromfile=baseline_name, tofile=name, lineterm=""))
        if diff_lines:
            logger.write(f"    First-200-lines unified diff ({baseline_name} vs {name}):", "Info")
            for diff_line in diff_lines[:60]:
                logger.write(f"      {diff_line}", "Info")
    return ok


def run_command(
    cmd: list[str],
    cwd: Path,
    logger: Logger,
    env: dict[str, str] | None = None,
    console_log: Path | None = None,
) -> None:
    """Run *cmd* and (optionally) tee its combined stdout/stderr to *console_log*.

    Without *console_log* this is a direct ``subprocess.run(check=True)``; with
    *console_log*, every output line is written to both the live console and the
    log file so the run is still observable in real time. The log file is
    appended to so back-to-back invocations (collect + preprocess + convert)
    accumulate into one per-collector transcript.
    """
    logger.write(f"Running: {' '.join(cmd)}", "Info")
    if console_log is None:
        subprocess.run(cmd, cwd=str(cwd), env=env, check=True)
        return
    console_log.parent.mkdir(parents=True, exist_ok=True)
    # Windows PowerShell's sys.stdout uses cp1252 by default, so a U+FFFD or
    # any non-cp1252 char from the subprocess will raise ``UnicodeEncodeError``
    # mid-stream. Read bytes from the subprocess and decode with errors="replace"
    # locally; write to console_log (utf-8) directly and to sys.stdout via its
    # buffer with explicit cp1252 / errors="replace" so the tee never raises.
    parent_encoding = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"
    with console_log.open("a", encoding="utf-8", errors="replace") as handle:
        handle.write(f"$ {' '.join(cmd)}\n")
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
        )
        assert proc.stdout is not None
        for raw_line in proc.stdout:
            line = raw_line.decode("utf-8", errors="replace")
            handle.write(line)
            handle.flush()
            try:
                sys.stdout.write(line)
            except UnicodeEncodeError:
                sys.stdout.write(line.encode(parent_encoding, errors="replace").decode(parent_encoding, errors="replace"))
            sys.stdout.flush()
        rc = proc.wait()
    if rc != 0:
        raise subprocess.CalledProcessError(rc, cmd)


def add_if_value(cmd: list[str], flag: str, value: Any) -> None:
    if value not in (None, ""):
        cmd.extend([flag, str(value)])


def collector_log_path(args: argparse.Namespace, output_dir: Path, collector_name: str) -> Path | None:
    if not args.log_file:
        return None
    log_file = Path(args.log_file)
    if log_file.is_absolute():
        return log_file
    if args.collector == "all" or args.all_collectors or args.collectors:
        return output_dir / f"{log_file.stem}-{collector_name}{log_file.suffix}"
    return log_file


def run_collector(
    args: argparse.Namespace,
    logger: Logger,
    collector_name: str | None = None,
    output_dir: Path | None = None,
) -> Path:
    collector_name = collector_name or args.collector
    output_dir = (output_dir or args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    log_path = collector_log_path(args, output_dir, str(collector_name))

    console_log = output_dir / f"console_{collector_name}.log" if args.verbose else None
    if console_log is not None and console_log.exists():
        console_log.unlink()

    if collector_name == "powershell":
        exe = powershell_exe()
        if not exe:
            raise RuntimeError("PowerShell is unavailable")
        enumeration_script = args.enumeration_script.resolve()
        if not enumeration_script.exists():
            raise RuntimeError(f"PowerShell collector not found: {enumeration_script}")
        if args.username or args.password:
            logger.write("PowerShell collector uses the current logon token; --username/--password are ignored for this collector.", "Warning")
        # PS1's -ZipDir treats its value as the full ZIP filename rather than
        # a directory; running PS1 from the output dir with no -ZipDir lets it
        # write bloodhound-sccm-<ts>.zip into cwd, which is what we want.
        cmd = [
            exe,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(enumeration_script),
            "-Domain",
            args.domain,
            # The dev box runs hot at ~96% memory; PS1's default
            # ``-MemoryThresholdPercent 95`` aborts collection mid-run on every
            # invocation. Bump to 99 so the threshold only fires on a true OOM
            # risk instead of as a baseline.
            "-MemoryThresholdPercent", "99",
        ]
        if args.verbose:
            cmd.insert(6, "-Verbose")
        add_if_value(cmd, "-DomainController", args.domain_controller)
        add_if_value(cmd, "-CollectionMethods", args.collection_methods)
        add_if_value(cmd, "-Computers", args.computers)
        add_if_value(cmd, "-ComputerFile", args.computer_file)
        add_if_value(cmd, "-SMSProvider", args.sms_provider)
        add_if_value(cmd, "-SiteCodes", args.site_codes)
        add_if_value(cmd, "-LogFile", log_path)
        if args.disable_possible_edges:
            cmd.append("-DisablePossibleEdges")
        if args.enable_bad_opsec:
            cmd.append("-EnableBadOpsec")
        if args.show_cleartext_passwords:
            cmd.append("-ShowCleartextPasswords")
        run_command(cmd, cwd=output_dir, logger=logger, console_log=console_log)
        zips = sorted(output_dir.glob("bloodhound-sccm*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not zips:
            raise RuntimeError("PowerShell collector did not produce a bloodhound-sccm ZIP")
        return zips[0]

    if collector_name == "configmanbearpig-python":
        if not PYTHON_COLLECTOR.exists():
            raise RuntimeError(f"ConfigManBearPig Python collector not found: {PYTHON_COLLECTOR}")
        if not args.username or args.password is None:
            raise ValueError("--username and --password are required for configmanbearpig-python collection")
        # CMBP-python only accepts the original CMBP argparse surface — it
        # has no --ldap-signing / --ldap-channel-binding knobs; those are
        # OpenHound-only.
        cmd = [
            "uv",
            "run",
            "python",
            str(PYTHON_COLLECTOR),
            "-d",
            args.domain,
            "-o",
            str(output_dir),
            "--threads",
            str(args.threads),
            "--ldap-port",
            str(args.ldap_port),
        ]
        add_if_value(cmd, "-dc", args.domain_controller)
        add_if_value(cmd, "-u", args.username)
        add_if_value(cmd, "-p", args.password)
        add_if_value(cmd, "-m", args.collection_methods)
        add_if_value(cmd, "-c", args.computers)
        add_if_value(cmd, "-cf", args.computer_file)
        add_if_value(cmd, "-sms", args.sms_provider)
        add_if_value(cmd, "-sc", args.site_codes)
        add_if_value(cmd, "--machine-name", args.machine_name)
        add_if_value(cmd, "--machine-pass", args.machine_pass)
        add_if_value(cmd, "--client-name", args.client_name)
        add_if_value(cmd, "--create-machine-account", args.create_machine_account)
        add_if_value(cmd, "--registration-sleep", args.registration_sleep)
        add_if_value(cmd, "--socks-proxy", args.socks_proxy)
        add_if_value(cmd, "--log-file", log_path)
        if args.ldaps:
            cmd.append("--ldaps")
        if args.ldap_start_tls:
            cmd.append("--ldap-start-tls")
        if args.disable_possible_edges:
            cmd.append("--disable-possible-edges")
        if args.enable_bad_opsec:
            cmd.append("--enable-bad-opsec")
        if args.show_cleartext_passwords:
            cmd.append("--show-cleartext-passwords")
        if args.use_altauth:
            cmd.append("--use-altauth")
        if args.verbose:
            cmd.append("-v")
        run_command(cmd, cwd=PYTHON_COLLECTOR.parent, logger=logger, console_log=console_log)
        zips = sorted(output_dir.glob("bloodhound-sccm*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not zips:
            raise RuntimeError("Python collector did not produce a bloodhound-sccm ZIP")
        return zips[0]

    if collector_name == "openhound":
        if not (OPENHOUND_SCCM / "src" / "main.py").exists():
            raise RuntimeError(f"OpenHound SCCM project not found: {OPENHOUND_SCCM}")
        if not args.username or args.password is None:
            raise ValueError("--username and --password are required for OpenHound SCCM collection")
        role = args.username.split("\\")[-1].split("@")[0]
        raw = output_dir / role / "raw"
        raw_dataset = raw / "sccm"
        graph = output_dir / role / "graph"
        lookup = output_dir / role / "lookup.duckdb"
        env = openhound_env(args)
        if log_path:
            env["OPENHOUND_SCCM_LOG_FILE"] = str(log_path)
        verbose_flag = ["-v"] if args.verbose else []
        run_command(
            ["uv", "run", "openhound", "collect", "sccm", str(raw), "--progress", "log", *verbose_flag],
            OPENHOUND_SCCM,
            logger,
            env,
            console_log=console_log,
        )
        # preprocess takes the *parent* of the dlt dataset dir (so it can find
        # ``<input>/sccm/<table>`` JSONL files); convert takes the dataset dir
        # itself. See ``sccm/sccm/justfile`` for the canonical invocations.
        run_command(
            ["uv", "run", "openhound", "preprocess", "sccm", str(raw), str(lookup), "--progress", "log", *verbose_flag],
            OPENHOUND_SCCM,
            logger,
            env,
            console_log=console_log,
        )
        run_command(
            ["uv", "run", "openhound", "convert", "sccm", str(raw_dataset), str(graph), "--lookup-file", str(lookup), "--progress", "log", *verbose_flag],
            OPENHOUND_SCCM,
            logger,
            env,
            console_log=console_log,
        )
        # The per-asset graph dir is *unpruned* — each model emits its own
        # ``<kind>_fs-1.json`` and the same id can appear in multiple files
        # (e.g. an LDAP Computer node and a DerivedNode for the same SID).
        # The package step is what produces the BloodHound-ready (deduped,
        # pruned) bundle that PS1 / CMBP-python directly emit. Return the ZIP
        # so cross-collector comparison sees the same final shape.
        run_command(
            [
                "uv", "run", "python", "-m", "openhound_sccm.main",
                "--graph-dir", str(graph),
                "--output-dir", str(output_dir / role),
            ],
            OPENHOUND_SCCM,
            logger,
            env,
            console_log=console_log,
        )
        zips = sorted((output_dir / role).glob("bloodhound-sccm*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not zips:
            raise RuntimeError("OpenHound package step did not produce a bloodhound-sccm ZIP")
        return zips[0]

    raise ValueError("--collector is required when --input-path is not supplied")


def openhound_env(args: argparse.Namespace) -> dict[str, str]:
    """Build the env for `openhound collect|preprocess|convert sccm` subprocess.

    ``source.py`` reads ``SOURCES__SCCM__*`` env vars (see
    ``src/openhound_sccm/main.py::_FLAG_TO_ENV``). ``LOG_FILE`` is the only
    exception: it's read as ``OPENHOUND_SCCM_LOG_FILE`` by ``log_context.py``.
    """
    env = os.environ.copy()
    source_values = {
        "DOMAIN": args.domain,
        "DOMAIN_CONTROLLER": args.domain_controller,
        "USERNAME": args.username,
        "PASSWORD": args.password,
        "THREADS": str(args.threads),
        "COLLECTION_METHODS": args.collection_methods or "All",
        "COMPUTERS": args.computers,
        "COMPUTER_FILE": args.computer_file,
        "SMS_PROVIDER": args.sms_provider,
        "SITE_CODES": args.site_codes,
        "LDAP_PORT": str(args.ldap_port),
        "LDAPS": str(args.ldaps).lower(),
        "LDAP_START_TLS": str(args.ldap_start_tls).lower(),
        "LDAP_SIGNING": args.ldap_signing,
        "LDAP_CHANNEL_BINDING": args.ldap_channel_binding,
        "DISABLE_POSSIBLE_EDGES": str(args.disable_possible_edges).lower(),
        "ENABLE_BAD_OPSEC": str(args.enable_bad_opsec).lower(),
        "SHOW_CLEARTEXT_PASSWORDS": str(args.show_cleartext_passwords).lower(),
        "MACHINE_NAME": args.machine_name,
        "MACHINE_PASS": args.machine_pass,
        "CLIENT_NAME": args.client_name,
        "CREATE_MACHINE_ACCOUNT": args.create_machine_account,
        "USE_ALTAUTH": str(args.use_altauth).lower(),
        "REGISTRATION_SLEEP": str(args.registration_sleep),
        "SOCKS_PROXY": args.socks_proxy,
    }
    env.update({f"SOURCES__SCCM__{key}": value for key, value in source_values.items() if value not in (None, "")})
    env["OPENHOUND_SCCM_LOG_FILE"] = str(args.log_file)
    env["DLT_TELEMETRY"] = "false"
    env["RUNTIME__DLTHUB_TELEMETRY"] = "false"
    return env


def parse_compare(values: list[str], logger: Logger, exclude_seed: bool) -> dict[str, GraphBundle]:
    graphs: dict[str, GraphBundle] = {}
    for value in values:
        if "=" not in value:
            raise ValueError("--compare must be name=path")
        name, raw_path = value.split("=", 1)
        bundle = load_graph(Path(raw_path), logger)
        graphs[name] = bundle.without_seed() if exclude_seed else bundle
    return graphs


def test_graph_output(
    input_path: Path,
    args: argparse.Namespace,
    logger: Logger,
    expected_edges: list[dict[str, Any]],
    label: str | None = None,
) -> tuple[bool, GraphBundle | None]:
    if label:
        logger.write(f"\nIntegration tests: {label}", "Test")
        logger.write(f"Input: {input_path}", "Info")
    if not input_path.exists():
        logger.write(f"InputPath not found: {input_path}", "Error")
        return False, None

    ok = True
    try:
        bundle = load_graph(input_path, logger)
        if args.exclude_seed:
            bundle = bundle.without_seed()
        if bundle.classic_files:
            logger.write(f"Classic BloodHound files skipped: {len(bundle.classic_files)}", "Warning")
        if args.run_edge_tests:
            if not bundle.edges:
                logger.write("No edges found in output", "Error")
                ok = False
                results = TestResults()
            else:
                results = run_edge_tests(bundle, expected_edges, logger, args.limit_edge_type, args.show_debug)
                ok = ok and not results.failed
        else:
            print_graph_totals(bundle, logger)
            results = TestResults()
            logger.write("\nExpected-edge assertions skipped.", "Info")
        ok = run_client_device_memberof_check(bundle, logger) and ok
        log_coverage_summary(bundle, results, logger)
        return ok, bundle
    except Exception as exc:
        logger.write(f"Error during test execution for {input_path}: {exc}", "Error")
        return False, None


def run_collector_matrix(
    args: argparse.Namespace,
    logger: Logger,
    expected_edges: list[dict[str, Any]],
) -> tuple[bool, dict[str, GraphBundle]]:
    collector_names = resolve_collectors(args)
    if not collector_names:
        logger.write("No collectors selected.", "Error")
        return False, {}
    if args.skip_collection:
        logger.write("Multi-collector mode runs collectors; remove --skip-collection or use --compare with existing outputs.", "Error")
        return False, {}

    ok = True
    outputs: dict[str, Path] = {}
    bundles: dict[str, GraphBundle] = {}
    logger.write("\nCollector Matrix", "Test")
    logger.write(f"Collectors: {', '.join(collector_names)}", "Info")

    for collector_name in collector_names:
        collector_output_dir = args.output_dir / collector_name
        try:
            logger.write(f"\nRunning collector: {collector_name}", "Test")
            output_path = run_collector(args, logger, collector_name=collector_name, output_dir=collector_output_dir)
            outputs[collector_name] = output_path
            logger.write(f"{collector_name} output: {output_path}", "Success")
        except Exception as exc:
            ok = False
            logger.write(f"{collector_name} collection failed: {exc}", "Error")
            if args.fail_fast:
                return False, bundles

    for collector_name, output_path in outputs.items():
        test_ok, bundle = test_graph_output(output_path, args, logger, expected_edges, label=collector_name)
        ok = test_ok and ok
        if bundle is not None:
            bundles[collector_name] = bundle
        if args.fail_fast and not test_ok:
            return False, bundles

    if len(bundles) > 1:
        ok = compare_graphs(bundles, logger, signature_compare=args.signature_compare) and ok
    elif len(collector_names) > 1:
        logger.write("Not enough successful collector outputs to compare.", "Warning")
        ok = False

    if args.console_diff and args.verbose:
        ok = run_console_diff(args, outputs, logger) and ok
    elif args.console_diff:
        logger.write("--console-diff requested without --verbose; per-collector console logs were not captured.", "Warning")

    return ok, bundles


def main() -> int:
    args = parse_args()
    logger = Logger(args.log_file)
    logger.write("=" * 30, "Info")
    logger.write("SCCM Collector Test Suite (Python)", "Info")
    logger.write("=" * 30, "Info")

    if args.action in {"Setup", "Teardown"}:
        logger.write(f"Action {args.action} has no native setup/teardown work in this runner.", "Info")

    ok = True
    expected_edges = substitute_domain(EXPECTED_EDGES_TEMPLATE, args.domain)
    collector_names = resolve_collectors(args)
    multi_collector = bool(args.all_collectors or args.collectors or args.collector == "all" or len(collector_names) > 1)

    if multi_collector and args.action in {"All", "Test"}:
        if args.input_path is not None:
            logger.write("--input-path is ignored in multi-collector mode; collectors produce fresh outputs.", "Warning")
        ok, matrix_graphs = run_collector_matrix(args, logger, expected_edges)
        try:
            extra_graphs = parse_compare(args.compare, logger, args.exclude_seed)
            if extra_graphs:
                ok = compare_graphs({**matrix_graphs, **extra_graphs}, logger, signature_compare=args.signature_compare) and ok
        except Exception as exc:
            logger.write(f"Error during graph comparison: {exc}", "Error")
            return 1
        logger.write("Test suite execution completed!", "Success" if ok else "Error")
        return 0 if ok else 2

    input_path = args.input_path
    if args.action in {"All", "Test"} and not args.skip_collection and input_path is None and len(collector_names) == 1:
        input_path = run_collector(args, logger, collector_name=collector_names[0])
    if input_path is None and not args.compare:
        input_path = find_default_input()

    if input_path is not None:
        test_ok, _bundle = test_graph_output(input_path, args, logger, expected_edges)
        ok = test_ok and ok
    elif not args.compare and args.action in {"All", "Test"}:
        logger.write("No input found. Pass --input-path, --collector, --collector all, --compare, or place a bloodhound-sccm*.zip in the current directory.", "Error")
        return 1

    try:
        graphs = parse_compare(args.compare, logger, args.exclude_seed)
        if graphs:
            ok = compare_graphs(graphs, logger, signature_compare=args.signature_compare) and ok
    except Exception as exc:
        logger.write(f"Error during graph comparison: {exc}", "Error")
        return 1

    logger.write("Test suite execution completed!", "Success" if ok else "Error")
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
