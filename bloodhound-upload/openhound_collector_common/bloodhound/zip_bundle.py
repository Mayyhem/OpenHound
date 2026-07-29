"""Bundle a directory of OpenGraph JSON files into a single zip for upload.

BloodHound CE's file-upload API accepts a zip of OpenGraph JSON files. We zip
every top-level `*.json` in the convert output dir (flat, basenames only). No
`seed_data.json` is added — the schema PUT already registers every kind.
"""
from __future__ import annotations

import logging
import zipfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def bundle_graph_dir(graph_dir: Path, out_zip: Path) -> Optional[Path]:
    """Zip the `*.json` files in *graph_dir* into *out_zip*.

    Returns the zip path, or None if the directory is missing or has no JSON
    files (nothing to upload).
    """
    graph_dir = Path(graph_dir)
    if not graph_dir.is_dir():
        logger.warning("Graph directory does not exist, nothing to bundle: %s", graph_dir)
        return None

    json_files = sorted(graph_dir.glob("*.json"))
    if not json_files:
        logger.warning("No OpenGraph .json files found in %s; nothing to upload", graph_dir)
        return None

    out_zip = Path(out_zip)
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for f in json_files:
            zf.write(f, arcname=f.name)
    logger.info("Bundled %d OpenGraph file(s) into %s", len(json_files), out_zip)
    return out_zip
