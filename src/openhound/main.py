# Disable dlt's anonymous telemetry BEFORE anything can initialize the dlt
# runtime. The `dlt.config[...] = False` line further down runs too late: the
# `import openhound.core.logging` below constructs CustomLogger at import time,
# which touches dlt.config, initializes the dlt runtime, and arms the anonymous
# tracker with telemetry still ON (dlt latches "started" once, so the later
# disable is a no-op). Setting the env var here — before any import — is honored
# by dlt's config resolution regardless of import order. setdefault() so an
# operator who deliberately set it keeps control.
import os

os.environ.setdefault("RUNTIME__DLTHUB_TELEMETRY", "false")

from pathlib import Path

import dlt

import openhound.core.logging  # noqa: F401
from openhound.cli.collect import collect
from openhound.cli.convert import convert
from openhound.cli.create import create_app
from openhound.cli.override import TyperOverride
from openhound.cli.preproc import preprocess
from openhound.cli.privilege_zone import privilege_zone
from openhound.cli.saved_search import saved_searches

BASE_SOUCE_PATH = Path(__file__).parent / "sources"

dlt.config["runtime.dlthub_telemetry"] = False
app = TyperOverride(sources_path=BASE_SOUCE_PATH, pretty_exceptions_enable=True)

app.add_typer(collect, name="collect")
app.add_typer(convert, name="convert")
app.add_typer(preprocess, name="preprocess")
app.add_typer(create_app, name="create")
app.add_typer(saved_searches, name="searches")
app.add_typer(privilege_zone, name="rules")

if __name__ == "__main__":
    app()
