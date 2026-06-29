"""Reshape OpenHound's native convert output into the MSSQLHound envelope.

OpenHound's real deliverable is the OpenGraph JSON the ``convert`` stage writes
(``mssql_nodes-*.json`` / ``mssql_edges-*.json`` under the convert output dir).
The EXISTING MSSQLHound validators, however, read a slightly different shape.
This module is the pure-Python bridge (design spec D6): it merges our convert
files and re-emits the exact envelope the validators consume. It renames NO
property keys (D11 — our output already uses MSSQLHound's verbatim names,
including the hyphenated CVE keys like ``isVulnerableToCVE-2025-49758``); it only
reshapes the *envelope* and normalizes each edge endpoint.

What the two validators expect (verified against the MSSQLHound source):

* Go ``MSSQLHound/internal/bloodhound/writer.go`` — ``ReadFromFile`` -> ``ReadFrom``
  decodes a SINGLE bare JSON object with a ``graph`` field
  (``json.NewDecoder(r).Decode(&struct{ Graph ... }{})``). It is NOT a zip.
  ``Edge.Start``/``Edge.End`` are ``EdgeEndpoint{ Value string }`` — objects with
  ONLY a ``value`` key. Go's decoder ignores extra fields, but we normalize our
  ``{"match_by":"id","value":X}`` down to ``{"value":X}`` anyway for a clean match.
  Edges are deduped by the writer on full JSON serialization of the edge.

* PowerShell ``MSSQLHound/powershell_deprecated/Invoke-MSSQLHoundUnitTests.ps1`` —
  ``-InputFile`` is passed to ``Get-MSSQLOutputFromZip -SpecificFile``, which calls
  ``[System.IO.Compression.ZipFile]::ExtractToDirectory`` and then merges the
  ``graph.nodes`` / ``graph.edges`` of every ``*.json`` inside. So the PS1 path
  expects a ``.zip`` of per-server ``.json`` files.

Hence we support BOTH: :func:`to_mssqlhound_json` builds the bare-JSON dict the Go
reader wants, and :func:`to_mssqlhound_zip` wraps that JSON in a ``.zip`` named
like MSSQLHound's ``mssql-bloodhound-<ts>.zip`` for the PS1 reader.

Provenance: ``writer.go`` (``Node``/``Edge``/``EdgeEndpoint`` structs, ``ReadFrom``,
``WriteToFile``, ``StreamingWriter.WriteEdge`` dedup) and the PS1 validator's
``Get-MSSQLOutputFromZip``.
"""
from __future__ import annotations

import json
import logging
import zipfile
from importlib import resources
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# The schema URL MSSQLHound stamps into every output file (writer.go writeHeader /
# WriteToFile). The validators don't assert on it, but BloodHound ingest and the
# entity panels do, so we reproduce it verbatim.
SCHEMA_URL = (
    "https://raw.githubusercontent.com/MichaelGrafnetter/EntraAuthPolicyHound/"
    "refs/heads/main/bloodhound-opengraph.schema.json"
)


def _normalize_endpoint(endpoint: Any) -> dict[str, Any]:
    """Reduce one edge endpoint to MSSQLHound's ``{"value": <id>}`` shape.

    Our ``GraphEdge`` emits ``EdgePath(match_by="id", value=<id>)`` which serializes
    to ``{"match_by":"id","value":"<id>"}``. Go's ``EdgeEndpoint`` has ONLY ``value``,
    so we drop ``match_by`` (and any other keys). A string endpoint (some callers
    pass a bare id) is wrapped as ``{"value": <string>}``.
    """
    if isinstance(endpoint, str):
        # Bare id — wrap it. Logged at debug since it's an accepted shorthand.
        logger.debug("Endpoint is a bare string id %r; wrapping as {'value': ...}", endpoint)
        return {"value": endpoint}
    if isinstance(endpoint, dict):
        if "value" in endpoint:
            # Normal case: keep only ``value`` (strip match_by and friends).
            return {"value": endpoint["value"]}
        # No ``value`` key — likely a property-matcher (ConditionalEdgePath) we don't
        # emit today. Pass it through untouched so we don't silently corrupt it, but
        # warn loudly because the validators won't understand it.
        logger.warning("Edge endpoint lacks a 'value' key; passing through unchanged: %r", endpoint)
        return dict(endpoint)
    # Anything else is malformed; surface it rather than guess.
    logger.error("Edge endpoint has unexpected type %s: %r", type(endpoint).__name__, endpoint)
    return {"value": endpoint}


def _normalize_edge(edge: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``edge`` with ``start``/``end`` normalized to ``{"value":…}``.

    All other edge fields (``kind``, ``properties``, …) are preserved verbatim so the
    validators see the full property bag (entity-panel parity).
    """
    normalized = dict(edge)
    if "start" in edge:
        normalized["start"] = _normalize_endpoint(edge["start"])
    else:
        # An edge with no start can't be matched; keep it but warn.
        logger.warning("Edge missing 'start': %r", edge)
    if "end" in edge:
        normalized["end"] = _normalize_endpoint(edge["end"])
    else:
        logger.warning("Edge missing 'end': %r", edge)
    return normalized


def _iter_graph_files(convert_output_dir: Path) -> list[Path]:
    """Return the convert ``*.json`` files that carry a ``graph`` object.

    The ``opengraph_file`` destination writes ``mssql_nodes-*.json`` and
    ``mssql_edges-*.json`` (and may write a combined file); each is a
    ``{"graph": {...}, ...}`` object. We read every ``*.json`` in the directory and
    keep the ones that actually contain a ``graph`` key, so adding more output files
    later doesn't require touching this adapter.
    """
    files = sorted(convert_output_dir.glob("*.json"))
    if not files:
        # Empty dir is almost certainly a mistake (convert didn't run / wrong path).
        logger.warning("No *.json files found in convert output dir %s", convert_output_dir)
    else:
        logger.debug("Found %d candidate *.json file(s) in %s", len(files), convert_output_dir)
    return files


def to_mssqlhound_json(
    convert_output_dir: str | Path,
    *,
    source_kind: str = "MSSQL_Base",
    server_name: str | None = None,
) -> dict[str, Any]:
    """Merge our convert output into the single MSSQLHound JSON envelope.

    Reads every ``{graph:{nodes,edges}}`` file under ``convert_output_dir``, merges
    their nodes and edges, normalizes each edge's ``start``/``end`` to ``{"value":…}``,
    dedupes edges by full-edge JSON (matching ``StreamingWriter.WriteEdge``), and wraps
    the result in ``{$schema, metadata:{source_kind}, graph:{nodes,edges}}`` — the shape
    Go ``ReadFrom`` decodes.

    Args:
        convert_output_dir: directory holding the convert ``mssql_*-*.json`` files.
        source_kind: value for ``metadata.source_kind`` (``MSSQL_Base`` by default).
        server_name: optional; reserved for future per-server file splitting. Unused
            today because everything lands in one ``MSSQL_Base`` file; logged if given.

    Returns:
        The MSSQLHound envelope as a plain dict, ready to ``json.dump``.

    NOTE — AD-object handling (Stage 7, not yet implemented): MSSQLHound writes AD
    nodes (Computer/User/Group) into SEPARATE files whose ``metadata`` is ``{}`` (no
    ``source_kind``) — see ``NewStreamingWriterNoSourceKind`` in writer.go. Stage 7
    doesn't emit AD nodes yet, so for now EVERYTHING goes in the single ``MSSQL_Base``
    envelope.
    TODO(Stage 7): split nodes carrying the ``"Base"`` kind (Computer/User/Group) into
    their own ``metadata:{}`` envelope/file, leaving ``MSSQL_*`` nodes here.
    """
    convert_output_dir = Path(convert_output_dir)
    if server_name is not None:
        # Reserved for the Stage 7 per-server split; no behavior today.
        logger.info("server_name=%r supplied but per-server splitting is not implemented yet", server_name)

    nodes: list[Any] = []
    edges: list[dict[str, Any]] = []
    seen_edges: set[str] = set()  # dedup keys, mirroring writer.go's seenEdges
    files_read = 0

    for path in _iter_graph_files(convert_output_dir):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            # A non-graph or unreadable file shouldn't abort the whole merge; skip it.
            logger.warning("Skipping unreadable/invalid JSON file %s: %s", path, exc)
            continue

        graph = data.get("graph")
        if not isinstance(graph, dict):
            # Not an OpenGraph file (no graph object) — ignore quietly at debug level.
            logger.debug("Skipping %s: no 'graph' object", path)
            continue

        files_read += 1
        file_nodes = graph.get("nodes") or []
        file_edges = graph.get("edges") or []
        nodes.extend(file_nodes)

        for edge in file_edges:
            normalized = _normalize_edge(edge)
            # Dedup by full JSON of the normalized edge (sort_keys for stability),
            # exactly like the Go writer dedups on the marshaled edge.
            key = json.dumps(normalized, sort_keys=True)
            if key in seen_edges:
                logger.debug("Dropping duplicate edge: %s", key)
                continue
            seen_edges.add(key)
            edges.append(normalized)

        logger.debug("Merged %s: +%d nodes, +%d edges", path.name, len(file_nodes), len(file_edges))

    logger.info(
        "Adapted convert output from %s: %d file(s) -> %d nodes, %d unique edges (source_kind=%s)",
        convert_output_dir, files_read, len(nodes), len(edges), source_kind,
    )

    return {
        "$schema": SCHEMA_URL,
        "metadata": {"source_kind": source_kind},
        "graph": {"nodes": nodes, "edges": edges},
    }


def to_mssqlhound_zip(
    convert_output_dir: str | Path,
    zip_path: str | Path,
    *,
    source_kind: str = "MSSQL_Base",
    file_name: str = "mssql-graph.json",
) -> Path:
    """Write the MSSQLHound envelope into a ``.zip`` for the PS1 ``-InputFile`` validator.

    The PS1 validator (``Get-MSSQLOutputFromZip``) extracts the zip and merges every
    ``*.json`` inside, so a single per-server ``.json`` entry is sufficient. The zip is
    intended to be named like MSSQLHound's ``mssql-bloodhound-<ts>.zip``; the caller
    chooses ``zip_path``.

    Args:
        convert_output_dir: directory holding the convert ``mssql_*-*.json`` files.
        zip_path: destination ``.zip`` path (created/overwritten).
        source_kind: ``metadata.source_kind`` for the contained JSON.
        file_name: name of the single ``.json`` entry inside the zip.

    Returns:
        The ``Path`` to the written zip.
    """
    zip_path = Path(zip_path)
    envelope = to_mssqlhound_json(convert_output_dir, source_kind=source_kind)
    payload = json.dumps(envelope, indent=2)

    # Ensure the parent dir exists so callers don't have to pre-create it.
    zip_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(file_name, payload)
            # Seed data: a single fake instance of every MSSQL_* edge kind (+ the
            # IgnoreMe sentinel node), so BloodHound pre-registers the kinds and the
            # saved Cypher queries don't fail before any real edge of that kind
            # exists. Go embeds seed_data.json and writes it verbatim into the zip
            # (collector.go createZipFile). We ship the identical file so our output
            # matches Go's node/edge totals + edge-kind set exactly.
            seed = _read_seed_data()
            if seed is not None:
                zf.writestr("seed_data.json", seed)
    except OSError as exc:
        # Writing the zip is the whole point of this call; failing it is fatal here.
        logger.error("Failed to write MSSQLHound zip %s: %s", zip_path, exc)
        raise

    logger.info("Wrote MSSQLHound zip %s containing %s + seed_data.json (%d bytes JSON)",
                zip_path, file_name, len(payload))
    return zip_path


def _read_seed_data() -> str | None:
    """Return the packaged ``seed_data.json`` text, or None if it can't be read.

    Identical to MSSQLHound's embedded seed file (collector.go //go:embed). A
    missing/unreadable file is logged and skipped rather than aborting the zip — the
    seed only registers edge kinds, so its absence degrades gracefully.
    """
    try:
        return resources.files("openhound_mssql").joinpath("seed_data.json").read_text(encoding="utf-8")
    except (OSError, ModuleNotFoundError) as exc:
        logger.warning("Could not read packaged seed_data.json; omitting from zip: %s", exc)
        return None
