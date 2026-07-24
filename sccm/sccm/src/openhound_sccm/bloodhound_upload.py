"""Dispatch a BloodHound CE upload for the SCCM collector.

One entry point (`run_upload`) shared by `collect --run-all` and `convert`, so
the schema/results decision logic lives in exactly one place. Schemas are pushed
first (they register the kinds); results are the convert output dir zipped into
one archive and uploaded under a single job.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from openhound_collector_common.bloodhound import (
    BloodHoundUploader,
    UploadSummary,
    bundle_graph_dir,
)

_ZIP_NAME = "sccm-bloodhound-upload.zip"


def run_upload(
    *,
    uploader: BloodHoundUploader,
    schemas: list[bytes],
    results_dir: Optional[Path],
    work_dir: Path,
    upload_schema: bool,
    upload_results: bool,
    logger: logging.Logger,
) -> UploadSummary:
    """Push schema and/or results to BloodHound; return a combined summary."""
    summary = UploadSummary()

    if upload_schema:
        logger.info("Uploading %d schema(s) to BloodHound...", len(schemas))
        summary.merge(uploader.upload_schemas(schemas))
    else:
        logger.debug("Schema upload skipped (--upload-results-only)")

    if upload_results:
        if results_dir is None:
            # Nothing converted / no dir to upload — schema-only effectively.
            logger.warning(
                "Results upload requested but no graph directory is available; "
                "run with --run-all or pass --upload-dir. Skipping results.")
        else:
            zip_path = bundle_graph_dir(results_dir, Path(work_dir) / _ZIP_NAME)
            if zip_path is None:
                logger.warning("No OpenGraph files to upload in %s", results_dir)
            else:
                logger.info("Uploading results zip to BloodHound...")
                summary.merge(uploader.upload_files([zip_path]))
    else:
        logger.debug("Results upload skipped (--upload-schema-only)")

    if summary.ok:
        logger.info("BloodHound upload complete: %d schema(s), %d file(s)",
                    summary.schemas_uploaded, summary.files_uploaded)
    else:
        logger.warning("BloodHound upload finished with problems: %s", "; ".join(summary.errors))
    return summary
