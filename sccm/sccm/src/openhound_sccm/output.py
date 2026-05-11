"""ZIP packager for the OpenHound SCCM extension.

Reads OpenHound's per-table OpenGraph JSON output (default location `graph/sccm/*.json`)
and produces a `bloodhound-sccm-<timestamp>.zip` with the same 5-file layout as the
original ConfigManBearPig output. This lets the existing
`invoke_configmanbearpig_unit_tests.py` runner consume both collectors interchangeably.

Layout:
    computers.json   — Computer nodes only, no `metadata.source_kind`
    groups.json      — Group nodes only, no `metadata.source_kind`
    users.json       — User nodes only, no `metadata.source_kind`
    sccm.json        — All other nodes + ALL edges, with `metadata.source_kind: "SCCM_Base"`
    seed_data.json   — Single IgnoreMe node + edges declaring every kind (BHE schema seed)

This module is intentionally self-contained and does not import from `openhound.core`,
so it can run as a separate Typer subcommand after `convert`.
"""

from __future__ import annotations

import json
import logging
import os
import pathlib
import time
import zipfile
from datetime import datetime
from typing import Any, Iterable

from openhound_sccm.kinds import nodes as nk
from openhound_sccm.kinds import edges as ek

logger = logging.getLogger(__name__)

SCHEMA_URL = (
    "https://raw.githubusercontent.com/MichaelGrafnetter/EntraAuthPolicyHound/"
    "refs/heads/main/bloodhound-opengraph.schema.json"
)
SEED_ID = "9c3a1f7a-1d6b-4d87-b61b-1c3b7a9e4f01"


def _read_jsonl_or_json(path: pathlib.Path) -> list[dict]:
    """Read a JSON file emitted by OpenHound's `opengraph_file` destination.

    OpenHound writes one JSON document per file. The shape varies by framework version:
    most commonly it's `{"nodes": [...], "edges": [...]}` or a wrapper with a `graph`
    key. JSONL is also supported defensively.
    """
    # Use utf-8-sig to transparently strip a BOM if present (CMBP-emitted ZIPs include one).
    text = path.read_text(encoding="utf-8-sig")
    text = text.lstrip()
    if not text:
        return []
    if text[0] == "[":
        return json.loads(text)
    if text[0] == "{":
        # Could be a single object (graph wrapper) or jsonl-with-newlines
        try:
            obj = json.loads(text)
            return [obj] if not isinstance(obj, list) else obj
        except json.JSONDecodeError:
            pass
    # JSONL fallback
    rows: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def _normalize_payload(payload: Any) -> tuple[list[dict], list[dict]]:
    """Pull `nodes`/`edges` out of any of OpenHound's possible per-table shapes."""
    if not isinstance(payload, dict):
        return [], []
    if "graph" in payload and isinstance(payload["graph"], dict):
        inner = payload["graph"]
        return list(inner.get("nodes") or []), list(inner.get("edges") or [])
    return list(payload.get("nodes") or []), list(payload.get("edges") or [])


def _edge_collection_source_tuple(edge: dict) -> tuple[str, ...]:
    """Extract a stable, hashable representation of an edge's collectionSource.

    CMBP retains some edges as duplicates when distinct discovery paths
    populated the same (start, end, kind) — most prominently
    SCCM_HasClient where ``rename_node`` collapses raw-SMS-id and
    ``GUID:<sms>`` device ids during post-processing, leaving one
    ``upsert_edge`` original plus one renamed sibling. We mirror that
    here by including the edge's ``collectionSource`` (sorted, dedup'd
    list, lower-cased) in the dedup key. Edges with no collectionSource
    fall through to the historical ``(start, end, kind)`` key.
    """
    props = edge.get("properties") or {}
    val = props.get("collectionSource")
    if val is None:
        return ()
    if isinstance(val, str):
        return (val.lower(),)
    if isinstance(val, list):
        seen: set[str] = set()
        out: list[str] = []
        for item in val:
            s = str(item).lower()
            if s not in seen:
                seen.add(s)
                out.append(s)
        return tuple(sorted(out))
    return (str(val).lower(),)


def collect_graph_dir(graph_dir: pathlib.Path) -> tuple[list[dict], list[dict]]:
    """Return (nodes, edges) by aggregating every JSON file under `graph_dir` recursively.

    Deduplicates nodes by `id`. Edges dedupe by ``(start.value, end.value,
    kind, collectionSource_tuple)`` — distinct discovery paths produce
    distinct edge rows so the JSON output mirrors CMBP's
    ``rename_node``-driven duplicate retention semantics.
    """
    nodes_by_id: dict[str, dict] = {}
    edges_seen: dict[tuple[str, str, str, tuple[str, ...]], dict] = {}

    if not graph_dir.exists():
        logger.warning("graph dir does not exist: %s", graph_dir)
        return [], []

    for path in sorted(graph_dir.rglob("*.json")):
        # Skip the seed_data file — we always re-emit a fresh one so callers don't
        # double-add the IgnoreMe seed when re-packaging an already-packaged graph dir.
        if path.name.lower() == "seed_data.json":
            continue
        try:
            for payload in _read_jsonl_or_json(path):
                ns, es = _normalize_payload(payload)
                for n in ns:
                    nid = n.get("id")
                    if nid is None:
                        continue
                    existing = nodes_by_id.get(nid)
                    if existing is None:
                        nodes_by_id[nid] = dict(n)
                    else:
                        _merge_node(existing, n)
                for e in es:
                    start = (e.get("start") or {}).get("value")
                    end = (e.get("end") or {}).get("value")
                    kind = e.get("kind", "")
                    if not start or not end:
                        continue
                    cs = _edge_collection_source_tuple(e)
                    edges_seen.setdefault((start, end, kind, cs), dict(e))
        except Exception as exc:
            logger.error("failed to read %s: %s", path, exc)

    return list(nodes_by_id.values()), list(edges_seen.values())


def _merge_node(target: dict, source: dict) -> None:
    """Merge `source` into `target` in place. Mirrors GraphStore.upsert_node semantics."""
    # Merge kinds (case-insensitive dedup)
    target_kinds = list(target.get("kinds") or [])
    seen = {k.lower() for k in target_kinds}
    for k in source.get("kinds") or []:
        if k.lower() not in seen:
            target_kinds.append(k)
            seen.add(k.lower())
    target["kinds"] = target_kinds

    # Merge properties
    src_props = source.get("properties") or {}
    tgt_props = target.setdefault("properties", {})
    for key, value in src_props.items():
        if value is None:
            continue
        existing = tgt_props.get(key)
        if existing is None:
            tgt_props[key] = value
        elif isinstance(existing, list) and isinstance(value, list):
            seen_set = {str(v).lower() if isinstance(v, str) else v for v in existing}
            for item in value:
                ik = str(item).lower() if isinstance(item, str) else item
                if ik not in seen_set:
                    existing.append(item)
                    seen_set.add(ik)
        elif key == "collectionSource":
            ex_list = existing if isinstance(existing, list) else [existing]
            new_list = value if isinstance(value, list) else [value]
            seen_set = {str(v).lower() for v in ex_list}
            for item in new_list:
                if str(item).lower() not in seen_set:
                    ex_list.append(item)
                    seen_set.add(str(item).lower())
            tgt_props[key] = ex_list
        else:
            # scalar override
            tgt_props[key] = value


def _format_size(size_bytes: int) -> str:
    if size_bytes >= 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
    if size_bytes >= 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    if size_bytes >= 1024:
        return f"{size_bytes / 1024:.2f} KB"
    return f"{size_bytes} bytes"


def _write_graph_json(
    out_path: pathlib.Path,
    nodes: Iterable[dict],
    edges: Iterable[dict],
    include_source_kind: bool,
) -> int:
    """Write a single CMBP-style streaming JSON file. Returns byte size."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        f.write("{\n")
        f.write(f'  "$schema": "{SCHEMA_URL}",\n')
        if include_source_kind:
            f.write('  "metadata": {\n')
            f.write('    "source_kind": "SCCM_Base"\n')
            f.write("  },\n")
        f.write('  "graph": {\n')
        f.write('    "nodes": [\n')
        first = True
        for n in nodes:
            if not first:
                f.write(",\n")
            first = False
            f.write("      " + json.dumps(n, separators=(",", ":")))
        if not first:
            f.write("\n")
        f.write("    ],\n")
        f.write('    "edges": [\n')
        first = True
        for e in edges:
            if not first:
                f.write(",\n")
            first = False
            f.write("      " + json.dumps(e, separators=(",", ":")))
        if not first:
            f.write("\n")
        f.write("    ]\n")
        f.write("  }\n")
        f.write("}\n")
    return out_path.stat().st_size


def _write_seed_data(out_path: pathlib.Path) -> int:
    """Write seed_data.json with the static IgnoreMe seed and edge-kind declarations."""
    seed_ref = {"value": SEED_ID}
    seed_data = {
        "metadata": {"source_kind": "SCCM_Seed"},
        "graph": {
            "nodes": [
                {
                    "kinds": [nk.IGNORE_ME],
                    "id": SEED_ID,
                    "properties": {"name": "IgnoreMe"},
                }
            ],
            "edges": [
                {"kind": kind, "start": seed_ref, "end": seed_ref}
                for kind in ek.SEED_EDGE_KINDS
            ],
        },
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(seed_data, separators=(",", ":")), encoding="utf-8")
    return out_path.stat().st_size


def _split_nodes(nodes: list[dict]) -> dict[str, list[dict]]:
    """Split nodes into (computers, groups, users, sccm-and-mssql)."""
    out = {"computers": [], "groups": [], "users": [], "sccm": []}
    for n in nodes:
        kinds = n.get("kinds") or []
        if nk.COMPUTER in kinds:
            out["computers"].append(n)
        elif nk.GROUP in kinds:
            out["groups"].append(n)
        elif nk.USER in kinds:
            out["users"].append(n)
        else:
            out["sccm"].append(n)
    return out


_SCCM_OR_MSSQL_KINDS = frozenset({
    nk.SCCM_SITE, nk.SCCM_CLIENT_DEVICE, nk.SCCM_COLLECTION,
    nk.SCCM_ADMIN_USER, nk.SCCM_SECURITY_ROLE,
    nk.MSSQL_SERVER, nk.MSSQL_LOGIN, nk.MSSQL_DATABASE,
    nk.MSSQL_DATABASE_USER, nk.MSSQL_SERVER_ROLE, nk.MSSQL_DATABASE_ROLE,
})

# SIDs / well-known IDs that should always anchor the BFS even if no LDAP node
# was emitted for them. ``S-1-5-11`` (Authenticated Users) is the most common —
# it's the start of every CoerceAndRelay edge but is rarely an LDAP-discovered
# group object. Match by suffix so any ``<DOMAIN>-S-1-5-11`` form works.
_ANCHOR_ID_SUFFIXES = ("S-1-5-11",)


def _prune_to_sccm_subgraph(
    nodes: list[dict],
    edges: list[dict],
) -> tuple[list[dict], list[dict]]:
    """Drop LDAP nodes (Computer / Group / User) that aren't SCCM-relevant.

    CMBP's output only includes AD principals reached via SCCM admin /
    role / device enumeration. OpenHound's LDAP resources currently emit
    every principal the LDAP server returns. To match parity we treat
    every SCCM_* / MSSQL_* node as an anchor, expand the anchor set
    via non-MemberOf edges (SameHostAs, CoerceAndRelay, SCCM_HasClient,
    HasSession, etc.), and keep only nodes whose ID is in the expanded
    set. MemberOf edges are kept only when both endpoints survive the
    pruning, which mirrors CMBP's "MemberOf only between SCCM-relevant
    principals" behaviour.
    """
    nodes_by_id: dict[str, dict] = {n["id"]: n for n in nodes if n.get("id")}

    # Seed the anchor set with every SCCM_* / MSSQL_* node and any node
    # whose ID matches a well-known anchor SID suffix.
    anchors: set[str] = set()
    for nid, n in nodes_by_id.items():
        kinds = n.get("kinds") or []
        if any(k in _SCCM_OR_MSSQL_KINDS for k in kinds):
            anchors.add(nid)
            continue
        # Computer nodes with SCCMInfra=True (set by the Computer model
        # at convert time when the SID/hostname appears in any
        # smb_*/http_*/ldap_sms_providers anchor table) are SCCM site
        # systems even when no SCCM_AdminUser was emitted. User nodes
        # with SCCMInfra=True (set by the User model when they appear
        # in adminservice_r_user_security_groups) similarly anchor so
        # SMS_R_User-discovered users keep their MemberOf edges.
        props = n.get("properties") or {}
        if (nk.COMPUTER in kinds or nk.USER in kinds) and props.get("SCCMInfra") is True:
            anchors.add(nid)
            continue
        for suffix in _ANCHOR_ID_SUFFIXES:
            if nid.upper().endswith("-" + suffix) or nid.upper() == suffix:
                anchors.add(nid)
                break

    # Two edge classes for BFS expansion:
    # * ``bidirectional`` — non-MemberOf edges. Both endpoints become anchored
    #   when either side is already anchored. This covers SameHostAs,
    #   CoerceAndRelay, SCCM_HasClient, IsMappedTo, etc.
    # * ``forward_only`` — MemberOf. We expand from anchored start to end
    #   (anchored User pulls in the Group it belongs to) but NOT from
    #   anchored end to start (anchored AuthUsers must not pull in every
    #   single User via reverse-MemberOf — that would resurrect the LDAP
    #   superset we just pruned).
    bidirectional: list[tuple[str, str]] = []
    forward_only: list[tuple[str, str]] = []
    for e in edges:
        s = (e.get("start") or {}).get("value")
        t = (e.get("end") or {}).get("value")
        if not s or not t:
            continue
        if e.get("kind") == ek.MEMBER_OF:
            forward_only.append((s, t))
        else:
            bidirectional.append((s, t))

    # BFS until the anchor set stops growing.
    while True:
        next_frontier: set[str] = set()
        for s, t in bidirectional:
            if s in anchors and t not in anchors:
                next_frontier.add(t)
            elif t in anchors and s not in anchors:
                next_frontier.add(s)
        for s, t in forward_only:
            if s in anchors and t not in anchors:
                next_frontier.add(t)
        if not next_frontier:
            break
        anchors |= next_frontier

    # CMBP's emission policy depends on what discovery the user could
    # complete. With AdminService access, CMBP emits every LDAP-discovered
    # Computer (even ones with no SCCM context, like the DC). Without
    # AdminService access, CMBP emits Computers only when there's SCCM
    # context (CmRcService SPN, SMB SCCM share, etc.). We mirror this by
    # turning off the Computer-prune when ANY SCCM_AdminUser node was
    # emitted: that's the cleanest in-graph proxy for "this user could
    # enumerate SCCM admins". Group / User are still pruned in both
    # cases because CMBP filters those even for full-access users.
    has_admin_user_nodes = any(
        nk.SCCM_ADMIN_USER in (n.get("kinds") or []) for n in nodes
    )
    pruned_nodes: list[dict] = []
    for n in nodes:
        nid = n.get("id")
        kinds = n.get("kinds") or []
        is_sccm_or_mssql = any(k in _SCCM_OR_MSSQL_KINDS for k in kinds)
        if is_sccm_or_mssql:
            pruned_nodes.append(n)
            continue
        is_computer = nk.COMPUTER in kinds
        is_group_or_user = nk.GROUP in kinds or nk.USER in kinds
        if is_computer and has_admin_user_nodes:
            # Full-access user — keep all LDAP Computers (matches CMBP).
            pruned_nodes.append(n)
            continue
        if (is_computer or is_group_or_user) and nid not in anchors:
            continue
        pruned_nodes.append(n)

    # Keep an edge only when both endpoints survive pruning. For non-
    # MemberOf edges this is implied by anchor expansion; the explicit
    # filter is here for MemberOf and for any defensive coverage.
    kept_ids = {n["id"] for n in pruned_nodes if n.get("id")}
    pruned_edges: list[dict] = []
    for e in edges:
        s = (e.get("start") or {}).get("value")
        t = (e.get("end") or {}).get("value")
        if s in kept_ids and t in kept_ids:
            pruned_edges.append(e)

    logger.info(
        "pruning: nodes %d -> %d, edges %d -> %d",
        len(nodes), len(pruned_nodes), len(edges), len(pruned_edges),
    )
    return pruned_nodes, pruned_edges


def package(
    graph_dir: pathlib.Path,
    output_dir: pathlib.Path | None = None,
    timestamp: str | None = None,
    keep_temp: bool = False,
) -> pathlib.Path | None:
    """Produce a `bloodhound-sccm-<timestamp>.zip` matching the CMBP layout.

    Args:
        graph_dir: Directory containing OpenHound `opengraph_file` per-table JSON.
        output_dir: Where to drop the ZIP. Defaults to the current working dir.
        timestamp: Override timestamp suffix. Defaults to local-time `%Y%m%d-%H%M%S`.
        keep_temp: If True, keep the intermediate `computers.json`/etc. on disk.

    Returns:
        Path to the produced ZIP, or None if nothing was packaged.
    """
    nodes, edges = collect_graph_dir(graph_dir)
    if not nodes and not edges:
        logger.warning("no nodes or edges found under %s", graph_dir)
        return None

    nodes, edges = _prune_to_sccm_subgraph(nodes, edges)

    output_dir = output_dir or pathlib.Path.cwd()
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = timestamp or datetime.now().strftime("%Y%m%d-%H%M%S")
    temp_dir = output_dir / f"openhound-sccm-{timestamp}"
    temp_dir.mkdir(parents=True, exist_ok=True)

    split = _split_nodes(nodes)
    files: list[pathlib.Path] = []

    for stem, group_nodes in [
        ("computers", split["computers"]),
        ("groups", split["groups"]),
        ("users", split["users"]),
    ]:
        if not group_nodes:
            continue
        path = temp_dir / f"{stem}.json"
        _write_graph_json(path, group_nodes, [], include_source_kind=False)
        files.append(path)

    sccm_path = temp_dir / "sccm.json"
    _write_graph_json(sccm_path, split["sccm"], edges, include_source_kind=True)
    files.append(sccm_path)

    seed_path = temp_dir / "seed_data.json"
    _write_seed_data(seed_path)
    files.append(seed_path)

    zip_path = output_dir / f"bloodhound-sccm-{timestamp}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in files:
            zf.write(path, path.name)

    total_size = sum(p.stat().st_size for p in files)
    zip_size = zip_path.stat().st_size
    logger.info("Packaged %d nodes, %d edges into %s (%s)", len(nodes), len(edges), zip_path, _format_size(zip_size))
    if total_size > 0:
        ratio = (1 - zip_size / total_size) * 100
        logger.info("Compression ratio: %.1f%%", ratio)

    if not keep_temp:
        for path in files:
            try:
                path.unlink()
            except OSError:
                pass
        try:
            temp_dir.rmdir()
        except OSError:
            pass

    return zip_path
