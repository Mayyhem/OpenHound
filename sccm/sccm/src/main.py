"""SCCM extension entry point used by `uv run python src/main.py ...`.

Sets `RUNTIME__DLTHUB_TELEMETRY=false` in `os.environ` before `openhound.main`
imports `dlt` so the pipeline doesn't phone home. The DLT-internal
`dlt.config[...] = False` knob runs too late to disable the telemetry HTTPS
call because the pipeline takes a config snapshot at construction time.
"""

from __future__ import annotations

import os

# Must precede any `import dlt` (transitively via `openhound.main`).
os.environ.setdefault("RUNTIME__DLTHUB_TELEMETRY", "false")
os.environ.setdefault("DLT__RUNTIME__DLTHUB_TELEMETRY", "false")

from openhound.main import app  # noqa: E402

if __name__ == "__main__":
    app()
