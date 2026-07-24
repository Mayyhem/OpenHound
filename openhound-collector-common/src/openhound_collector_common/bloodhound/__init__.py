"""Reusable BloodHound CE upload client for OpenHound collectors.

Ports the Go MSSQLHound upload flow (schema via PUT /api/v2/extensions, results
via the /api/v2/file-upload job API) as framework-agnostic, pure-Python building
blocks. No `openhound` or `dlt` imports — collectors wire these into their CLI.
"""

from .client import BloodHoundClient, BloodHoundHTTPError
from .schema import disable_possible_edges
from .uploader import (
    BloodHoundUploader,
    UploadSummary,
    build_uploader,
    parse_bloodhound_shorthand,
    resolve_credentials,
)
from .zip_bundle import bundle_graph_dir

__all__ = [
    "BloodHoundClient",
    "BloodHoundHTTPError",
    "BloodHoundUploader",
    "UploadSummary",
    "build_uploader",
    "bundle_graph_dir",
    "disable_possible_edges",
    "parse_bloodhound_shorthand",
    "resolve_credentials",
]
