#!/usr/bin/env python3
"""Compare two OpenGraph JSON outputs and identify node/edge differences.

Adapted from mssql/MSSQLHound/util/compare_edges.py with SCCM-specific
extensions for property-level parity work against CMBP / ConfigManBearPig.ps1.

Usage:
    python3 compare_nodes_and_edges.py <file1.json|.zip> <file2.json|.zip> \\
        [--label1 NAME] [--label2 NAME] \\
        [--kinds Kind1,Kind2,...] \\
        [--baseline NAME] \\
        [--normalize-ids] [--normalize-whitespace] [-v]

Examples:
    # Parity check OH vs PS1 (zip) — only show properties PS1 has that OH lacks
    python3 compare_nodes_and_edges.py oh.json cmbp-ps1.zip \\
        --label1 OH --label2 PS1 --baseline PS1 --normalize-ids \\
        --kinds SCCM_Site,Computer,SCCM_AdminUser -v

    # Cross-check OH vs Python CMBP
    python3 compare_nodes_and_edges.py oh.json cmbp-py.json \\
        --label1 OH --label2 CMBP-py --baseline CMBP-py
"""

import argparse
import json
import sys
import zipfile
from collections import defaultdict


def load_json(filepath):
    """Load a JSON file or extract the main JSON from a zip file.

    For Go-style zips that separate AD nodes into computers.json / users.json /
    groups.json alongside the main output, those nodes are merged into the main
    graph so the comparison sees the complete picture. PowerShell CMBP ships
    its output as ``seed_data.json`` inside a zip.
    """
    if filepath.endswith(".zip"):
        with zipfile.ZipFile(filepath) as zf:
            json_files = [n for n in zf.namelist() if n.endswith(".json")]
            if not json_files:
                raise ValueError(f"No JSON files found in {filepath}")
            main_file = max(json_files, key=lambda n: zf.getinfo(n).file_size)
            print(f"  (extracted '{main_file}' from zip)")
            data = json.loads(zf.read(main_file))

            ad_files = [n for n in json_files if n in ("computers.json", "users.json", "groups.json")]
            if ad_files and isinstance(data, dict) and "graph" in data:
                merged_count = 0
                existing_ids = {n["id"] for n in data["graph"].get("nodes", [])}
                for ad_file in sorted(ad_files):
                    ad_data = json.loads(zf.read(ad_file))
                    for node in ad_data.get("graph", {}).get("nodes", []):
                        if node.get("id") not in existing_ids:
                            data["graph"].setdefault("nodes", []).append(node)
                            existing_ids.add(node["id"])
                            merged_count += 1
                if merged_count:
                    print(f"  (merged {merged_count} AD nodes from {', '.join(ad_files)})")
            return data
    with open(filepath, "r", encoding="utf-8-sig") as f:
        return json.load(f)


def extract_nodes(data):
    """Extract nodes from JSON data — handles top-level dict, graph.nodes,
    or bare list shapes."""
    if isinstance(data, dict):
        if "graph" in data and isinstance(data["graph"], dict):
            return data["graph"].get("nodes", [])
        if "nodes" in data:
            return data["nodes"]
    return []


def extract_edges(data):
    """Extract edges from JSON data — handles top-level list, graph.edges,
    and a few other plausible shapes."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ["data", "edges", "relationships", "rels"]:
            if key in data:
                val = data[key]
                if isinstance(val, list):
                    return val
        if "graph" in data and isinstance(data["graph"], dict):
            graph = data["graph"]
            for key in ["edges", "relationships", "rels"]:
                if key in graph:
                    val = graph[key]
                    if isinstance(val, list):
                        return val
        if "start" in data and "end" in data and "kind" in data:
            return [data]
        for _, val in data.items():
            if isinstance(val, list) and len(val) > 0:
                first = val[0]
                if isinstance(first, dict) and ("kind" in first or "type" in first):
                    return val
    return []


def _filter_by_kinds(nodes, kinds_filter):
    """Keep only nodes whose kinds list intersects ``kinds_filter`` (set).
    A node with no kinds is kept when ``kinds_filter`` is empty."""
    if not kinds_filter:
        return nodes
    out = []
    for n in nodes:
        node_kinds = set(n.get("kinds", []))
        if node_kinds & kinds_filter:
            out.append(n)
    return out


def _filter_edges_by_node_kinds(edges, nodes_by_id, kinds_filter):
    """Keep only edges where both endpoints reference a node whose kinds
    overlap ``kinds_filter``. Endpoints we can't resolve are kept (we don't
    know enough to filter them out)."""
    if not kinds_filter:
        return edges
    out = []
    for e in edges:
        start_id = _endpoint_id(e.get("start"))
        end_id = _endpoint_id(e.get("end"))
        start_kinds = set(nodes_by_id.get(start_id, {}).get("kinds", []))
        end_kinds = set(nodes_by_id.get(end_id, {}).get("kinds", []))
        # Keep when EITHER endpoint matches — narrows correctly when one side
        # is a filtered kind but the other side is a generic Computer/User.
        if (not start_kinds and not end_kinds) or (start_kinds & kinds_filter) or (end_kinds & kinds_filter):
            out.append(e)
    return out


def _endpoint_id(endpoint):
    if isinstance(endpoint, dict):
        return endpoint.get("value", endpoint.get("objectid", ""))
    return str(endpoint) if endpoint else ""


def build_node_id_mapping(data1, data2):
    """Build a mapping from file1 node IDs to file2 node IDs based on
    matching (kinds, name). Handles the case where one tool uses SIDs and
    the other uses hostnames for the same node.
    """
    nodes1 = extract_nodes(data1)
    nodes2 = extract_nodes(data2)
    if not nodes1 or not nodes2:
        return {}

    def build_name_map(nodes):
        m = {}
        for n in nodes:
            node_id = n.get("id", "")
            kinds = tuple(sorted(n.get("kinds", [])))
            props = n.get("properties", {})
            name = props.get("name", "")
            if name:
                m[(kinds, name)] = node_id
        return m

    map1 = build_name_map(nodes1)
    map2 = build_name_map(nodes2)
    id_mapping = {}
    for key, id1 in map1.items():
        if key in map2:
            id2 = map2[key]
            if id1 != id2:
                id_mapping[id1] = id2
    return id_mapping


def normalize_id(value, id_mapping):
    if not id_mapping or value not in id_mapping:
        for old_id, new_id in id_mapping.items():
            if value.startswith(old_id):
                return new_id + value[len(old_id):]
        return value
    return id_mapping[value]


def make_edge_key(edge, id_mapping=None):
    source = _endpoint_id(edge.get("start"))
    target = _endpoint_id(edge.get("end"))
    if id_mapping:
        source = normalize_id(source, id_mapping)
        target = normalize_id(target, id_mapping)
    kind = edge.get("kind", edge.get("type", edge.get("label", "UNKNOWN")))
    return (source, target, kind)


def get_edge_properties(edge):
    return edge.get("properties", {})


def normalize_value(v, normalize_ws=False):
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        if v.lower() == "true":
            return True
        if v.lower() == "false":
            return False
        if normalize_ws:
            return normalize_whitespace(v)
    return v


def normalize_whitespace(s):
    import re
    s = s.replace("\r\n", "\n")
    lines = [l.strip() for l in s.split("\n")]
    lines = [l for l in lines if l]
    return "\n".join(lines)


def compare_properties(props1, props2, label1, label2, normalize_ws=False, baseline=None):
    """Compare two property dicts and return a list of diff lines.

    When ``baseline`` is one of ``label1`` / ``label2``, only report
    differences relevant to property-level parity against that baseline:
    properties missing on the non-baseline side, or with differing values.
    Properties that exist only on the non-baseline side are NOT reported
    (they're extras, not parity gaps).
    """
    diffs = []
    all_keys = sorted(set(list(props1.keys()) + list(props2.keys())))
    for key in all_keys:
        in1 = key in props1
        in2 = key in props2
        if in1 and not in2:
            # Only-in-label1: report unless baseline is label2 (then it's a
            # non-baseline-only property — an extra, not a parity gap).
            if baseline is None or baseline == label1:
                diffs.append(f"  Property '{key}' only in {label1}")
        elif in2 and not in1:
            if baseline is None or baseline == label2:
                diffs.append(f"  Property '{key}' only in {label2}")
        else:
            v1 = normalize_value(props1[key], normalize_ws)
            v2 = normalize_value(props2[key], normalize_ws)
            if v1 != v2:
                s1 = str(v1)
                s2 = str(v2)
                if len(s1) > 120:
                    s1 = s1[:120] + "..."
                if len(s2) > 120:
                    s2 = s2[:120] + "..."
                diffs.append(f"  Property '{key}' differs:")
                diffs.append(f"    {label1}: {s1}")
                diffs.append(f"    {label2}: {s2}")
    return diffs


def make_node_key(node, id_mapping=None):
    """Hashable node key. With ``id_mapping`` the file1 id is rewritten to
    the file2 id when an (kinds, name) match exists — so SID-vs-hostname
    asymmetry doesn't surface as a false 'only in' diff.
    """
    kinds = tuple(sorted(node.get("kinds", [])))
    node_id = node.get("id", "")
    if id_mapping and node_id in id_mapping:
        node_id = id_mapping[node_id]
    return (kinds, node_id)


def compare_nodes(data1, data2, label1, label2, verbose=False, normalize_ws=False,
                  kinds_filter=None, baseline=None, id_mapping=None):
    """Compare nodes between two datasets and print the diff."""
    nodes1 = extract_nodes(data1)
    nodes2 = extract_nodes(data2)

    nodes1 = _filter_by_kinds(nodes1, kinds_filter)
    nodes2 = _filter_by_kinds(nodes2, kinds_filter)

    print(f"\n{'='*80}")
    print("NODE COMPARISON" + (f"  (filter: {','.join(sorted(kinds_filter))})" if kinds_filter else ""))
    print(f"{'='*80}")
    print(f"  {label1}: {len(nodes1)} nodes")
    print(f"  {label2}: {len(nodes2)} nodes")

    kind_counts1 = defaultdict(int)
    kind_counts2 = defaultdict(int)
    for n in nodes1:
        k = ", ".join(sorted(n.get("kinds", []))) or "(no kind)"
        kind_counts1[k] += 1
    for n in nodes2:
        k = ", ".join(sorted(n.get("kinds", []))) or "(no kind)"
        kind_counts2[k] += 1

    all_kinds = sorted(set(list(kind_counts1.keys()) + list(kind_counts2.keys())))
    if any(kind_counts1.get(k, 0) != kind_counts2.get(k, 0) for k in all_kinds):
        print(f"\n  {'Node Kind':<45} {label1:>8} {label2:>8}  {'Diff':>6}")
        print(f"  {'-'*45} {'-'*8} {'-'*8}  {'-'*6}")
        for k in all_kinds:
            c1 = kind_counts1.get(k, 0)
            c2 = kind_counts2.get(k, 0)
            d = c1 - c2
            m = " <---" if d != 0 else ""
            print(f"  {k or '(no kind)':<45} {c1:>8} {c2:>8}  {d:>+6}{m}")

    nodes1_by_key = {}
    nodes2_by_key = {}
    for n in nodes1:
        key = make_node_key(n, id_mapping)
        nodes1_by_key[key] = n
    for n in nodes2:
        key = make_node_key(n)
        nodes2_by_key[key] = n

    keys1 = set(nodes1_by_key.keys())
    keys2 = set(nodes2_by_key.keys())
    only_in_1 = sorted(keys1 - keys2)
    only_in_2 = sorted(keys2 - keys1)
    in_both = keys1 & keys2

    print(f"\n  Unique nodes: Only in {label1}: {len(only_in_1)}, Only in {label2}: {len(only_in_2)}, In both: {len(in_both)}")

    # Per-baseline filtering of the "only in" lists
    if (baseline is None or baseline == label1) and only_in_1:
        print(f"\n  NODES ONLY IN {label1} ({len(only_in_1)}):")
        for kinds_tuple, node_id in only_in_1:
            node = nodes1_by_key[(kinds_tuple, node_id)]
            kinds_str = ", ".join(kinds_tuple) or "(no kind)"
            props = node.get("properties", {})
            name = props.get("name", "")
            print(f"    [{kinds_str}] {node_id}  (name: {name})")
            if verbose and props:
                for pk, pv in sorted(props.items()):
                    sv = str(pv)
                    if len(sv) > 100:
                        sv = sv[:100] + "..."
                    print(f"      {pk}: {sv}")

    if (baseline is None or baseline == label2) and only_in_2:
        print(f"\n  NODES ONLY IN {label2} ({len(only_in_2)}):")
        for kinds_tuple, node_id in only_in_2:
            node = nodes2_by_key[(kinds_tuple, node_id)]
            kinds_str = ", ".join(kinds_tuple) or "(no kind)"
            props = node.get("properties", {})
            name = props.get("name", "")
            print(f"    [{kinds_str}] {node_id}  (name: {name})")
            if verbose and props:
                for pk, pv in sorted(props.items()):
                    sv = str(pv)
                    if len(sv) > 100:
                        sv = sv[:100] + "..."
                    print(f"      {pk}: {sv}")

    prop_diff_count = 0
    prop_diffs = []
    for key in sorted(in_both):
        n1 = nodes1_by_key[key]
        n2 = nodes2_by_key[key]
        diffs = compare_properties(n1.get("properties", {}), n2.get("properties", {}),
                                    label1, label2, normalize_ws, baseline)
        if diffs:
            prop_diff_count += 1
            if verbose:
                prop_diffs.append((key, diffs))

    if prop_diff_count > 0:
        print(f"\n  Nodes in both with property differences: {prop_diff_count}")
        if verbose:
            for (kinds_tuple, node_id), diffs in prop_diffs:
                kinds_str = ", ".join(kinds_tuple) or "(no kind)"
                print(f"\n    [{kinds_str}] {node_id}")
                for d in diffs:
                    print(f"    {d}")

    return only_in_1, only_in_2


def compare_edges(data1, data2, label1, label2, verbose=False, normalize_ws=False,
                  kinds_filter=None, baseline=None, id_mapping=None, dedup=False):
    """Compare edges. When ``kinds_filter`` is set, restrict to edges whose
    endpoints touch one of the listed node kinds."""
    edges1 = extract_edges(data1)
    edges2 = extract_edges(data2)

    if kinds_filter:
        nodes1_by_id = {n.get("id", ""): n for n in extract_nodes(data1)}
        nodes2_by_id = {n.get("id", ""): n for n in extract_nodes(data2)}
        edges1 = _filter_edges_by_node_kinds(edges1, nodes1_by_id, kinds_filter)
        edges2 = _filter_edges_by_node_kinds(edges2, nodes2_by_id, kinds_filter)

    print(f"\n  {label1}: {len(edges1)} edges extracted"
          + (f" (kind-filtered)" if kinds_filter else ""))
    print(f"  {label2}: {len(edges2)} edges extracted"
          + (f" (kind-filtered)" if kinds_filter else ""))

    type_counts1 = defaultdict(int)
    type_counts2 = defaultdict(int)
    for e in edges1:
        k = e.get("kind", e.get("type", "UNKNOWN"))
        type_counts1[k] += 1
    for e in edges2:
        k = e.get("kind", e.get("type", "UNKNOWN"))
        type_counts2[k] += 1
    all_types = sorted(set(list(type_counts1.keys()) + list(type_counts2.keys())))

    print(f"\n{'='*80}")
    print("EDGE TYPE COUNTS")
    print(f"{'='*80}")
    print(f"  {'Edge Type':<45} {label1:>10} {label2:>10}  {'Diff':>8}")
    print(f"  {'-'*45} {'-'*10} {'-'*10}  {'-'*8}")
    for t in all_types:
        c1 = type_counts1.get(t, 0)
        c2 = type_counts2.get(t, 0)
        diff = c1 - c2
        diff_str = f"+{diff}" if diff > 0 else (str(diff) if diff != 0 else "")
        marker = " <---" if diff != 0 else ""
        print(f"  {t:<45} {c1:>10} {c2:>10}  {diff_str:>8}{marker}")

    total1 = sum(type_counts1.values())
    total2 = sum(type_counts2.values())
    print(f"  {'-'*45} {'-'*10} {'-'*10}  {'-'*8}")
    print(f"  {'TOTAL':<45} {total1:>10} {total2:>10}  {total1-total2:>+8}")

    edges1_by_key = defaultdict(list)
    edges2_by_key = defaultdict(list)
    for e in edges1:
        edges1_by_key[make_edge_key(e, id_mapping)].append(e)
    for e in edges2:
        edges2_by_key[make_edge_key(e)].append(e)

    if dedup:
        deduped1 = sum(len(v) - 1 for v in edges1_by_key.values() if len(v) > 1)
        deduped2 = sum(len(v) - 1 for v in edges2_by_key.values() if len(v) > 1)
        if deduped1 or deduped2:
            print(f"\n  --dedup: removed {deduped1} duplicate(s) from {label1}, {deduped2} from {label2}")
        edges1_by_key = {k: [v[0]] for k, v in edges1_by_key.items()}
        edges2_by_key = {k: [v[0]] for k, v in edges2_by_key.items()}

    keys1 = set(edges1_by_key.keys())
    keys2 = set(edges2_by_key.keys())
    only_in_1 = keys1 - keys2
    only_in_2 = keys2 - keys1
    in_both = keys1 & keys2

    print(f"\n{'='*80}")
    print("EDGE DIFFERENCE SUMMARY")
    print(f"{'='*80}")
    print(f"  Unique edge keys (source, target, kind):")
    print(f"    Only in {label1}: {len(only_in_1)}")
    print(f"    Only in {label2}: {len(only_in_2)}")
    print(f"    In both: {len(in_both)}")

    if (baseline is None or baseline == label1) and only_in_1:
        print(f"\n  EDGES ONLY IN {label1} ({len(only_in_1)}) — sample of up to 50")
        for source, target, kind in sorted(only_in_1)[:50]:
            print(f"    [{kind}] {source} -> {target}")
    if (baseline is None or baseline == label2) and only_in_2:
        print(f"\n  EDGES ONLY IN {label2} ({len(only_in_2)}) — sample of up to 50")
        for source, target, kind in sorted(only_in_2)[:50]:
            print(f"    [{kind}] {source} -> {target}")

    # Per-edge property diffs for matching edges
    prop_diff_summary = defaultdict(lambda: {"only_in_1": 0, "only_in_2": 0, "differs": 0})
    for key in sorted(in_both):
        _, _, kind = key
        e1 = edges1_by_key[key][0]
        e2 = edges2_by_key[key][0]
        p1 = get_edge_properties(e1)
        p2 = get_edge_properties(e2)
        all_keys = set(list(p1.keys()) + list(p2.keys()))
        for pk in all_keys:
            in1 = pk in p1
            in2 = pk in p2
            if in1 and not in2:
                if baseline is None or baseline == label1:
                    prop_diff_summary[(kind, pk)]["only_in_1"] += 1
            elif in2 and not in1:
                if baseline is None or baseline == label2:
                    prop_diff_summary[(kind, pk)]["only_in_2"] += 1
            else:
                v1 = normalize_value(p1[pk], normalize_ws)
                v2 = normalize_value(p2[pk], normalize_ws)
                if v1 != v2:
                    prop_diff_summary[(kind, pk)]["differs"] += 1

    if prop_diff_summary:
        print(f"\n{'='*80}")
        print("EDGE PROPERTY DIFFERENCES (per kind x property)")
        print(f"{'='*80}")
        print(f"  {'Edge Kind':<40} {'Property':<25} {'Only in '+label1:>14} {'Only in '+label2:>14} {'Value diff':>11}")
        print(f"  {'-'*40} {'-'*25} {'-'*14} {'-'*14} {'-'*11}")
        for (kind, prop) in sorted(prop_diff_summary.keys()):
            c = prop_diff_summary[(kind, prop)]
            o1 = c["only_in_1"]
            o2 = c["only_in_2"]
            vd = c["differs"]
            if not (o1 or o2 or vd):
                continue
            print(f"  {kind:<40} {prop:<25} {o1 if o1 else '':>14} {o2 if o2 else '':>14} {vd if vd else '':>11}")


def main():
    parser = argparse.ArgumentParser(
        description="Compare two OpenGraph JSON outputs (OH vs CMBP / PS1) and identify node and edge property differences for parity validation."
    )
    parser.add_argument("file1", help="First JSON or zip file path")
    parser.add_argument("file2", help="Second JSON or zip file path")
    parser.add_argument("--label1", default=None, help="Label for first file (default: filename)")
    parser.add_argument("--label2", default=None, help="Label for second file (default: filename)")
    parser.add_argument(
        "--kinds",
        default=None,
        help="Comma-separated list of node kinds to restrict the comparison to (e.g. 'SCCM_Site,Computer,SCCM_AdminUser')",
    )
    parser.add_argument(
        "--baseline",
        default=None,
        help="Label of the source-of-truth side. When set, suppresses non-baseline-only entries in the diff (so only baseline-missing-on-other and value-diff entries surface)",
    )
    parser.add_argument(
        "--normalize-ids",
        action="store_true",
        help="Normalize node IDs between files using (kinds, name) matching (handles SID vs hostname identifier asymmetry)",
    )
    parser.add_argument(
        "--normalize-whitespace",
        action="store_true",
        help="Normalize whitespace in string properties before comparing",
    )
    parser.add_argument(
        "--dedup",
        action="store_true",
        help="Deduplicate edges by (source, target, kind) before comparing",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show per-node property diffs and sample edge details",
    )

    args = parser.parse_args()
    label1 = args.label1 or args.file1.split("/")[-1].split("\\")[-1]
    label2 = args.label2 or args.file2.split("/")[-1].split("\\")[-1]
    kinds_filter = set(k.strip() for k in args.kinds.split(",") if k.strip()) if args.kinds else None

    if args.baseline and args.baseline not in (label1, label2):
        print(f"warning: --baseline '{args.baseline}' is not one of label1='{label1}' or label2='{label2}'; "
              f"falling back to bidirectional diff",
              file=sys.stderr)
        baseline = None
    else:
        baseline = args.baseline

    print(f"Loading {label1}...")
    data1 = load_json(args.file1)
    print(f"Loading {label2}...")
    data2 = load_json(args.file2)

    print(f"\n{'='*80}")
    print("TOP-LEVEL STRUCTURE")
    print(f"{'='*80}")
    if isinstance(data1, dict):
        print(f"  {label1}: dict with keys {list(data1.keys())}")
    else:
        print(f"  {label1}: {type(data1).__name__} with {len(data1)} items")
    if isinstance(data2, dict):
        print(f"  {label2}: dict with keys {list(data2.keys())}")
    else:
        print(f"  {label2}: {type(data2).__name__} with {len(data2)} items")

    id_mapping = None
    if args.normalize_ids:
        id_mapping = build_node_id_mapping(data1, data2)
        if id_mapping:
            print(f"\n  ID normalization: mapped {len(id_mapping)} node IDs from {label1} to {label2}")
        else:
            print(f"\n  ID normalization: no mappable differences found")

    compare_nodes(
        data1, data2, label1, label2,
        verbose=args.verbose,
        normalize_ws=args.normalize_whitespace,
        kinds_filter=kinds_filter,
        baseline=baseline,
        id_mapping=id_mapping,
    )
    compare_edges(
        data1, data2, label1, label2,
        verbose=args.verbose,
        normalize_ws=args.normalize_whitespace,
        kinds_filter=kinds_filter,
        baseline=baseline,
        id_mapping=id_mapping,
        dedup=args.dedup,
    )


if __name__ == "__main__":
    main()
