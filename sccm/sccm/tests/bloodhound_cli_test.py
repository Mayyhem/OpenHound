import logging
from pathlib import Path

import pytest

import openhound_sccm.main as main


class RecordingUploader:
    last = None

    def __init__(self):
        RecordingUploader.last = self
        self.schema_calls = []
        self.file_calls = []

    def upload_schemas(self, schemas):
        from openhound_collector_common.bloodhound import UploadSummary
        self.schema_calls.append(list(schemas))
        return UploadSummary(schemas_uploaded=len(schemas))

    def upload_files(self, files):
        from openhound_collector_common.bloodhound import UploadSummary
        self.file_calls.append([Path(f).name for f in files])
        return UploadSummary(files_uploaded=len(files))


def test_upload_mutual_exclusion_raises():
    with pytest.raises(main.typer.BadParameter):
        main._resolve_upload_mode(upload_schema_only=True, upload_results_only=True)


def test_resolve_upload_mode_defaults_to_both():
    assert main._resolve_upload_mode(False, False) == (True, True)
    assert main._resolve_upload_mode(True, False) == (True, False)
    assert main._resolve_upload_mode(False, True) == (False, True)


def test_dispatch_uploads_schema_only_for_skip_collection(monkeypatch, tmp_path):
    # build_uploader returns our recording fake regardless of creds.
    monkeypatch.setattr(main, "build_uploader",
                        lambda *a, **k: RecordingUploader())
    main._dispatch_bloodhound_upload(
        url="https://bh", token_id="i", token_key="k",
        disable_possible=False, results_dir=None, work_dir=tmp_path,
        upload_schema=True, upload_results=True, logger=logging.getLogger("t"))
    up = RecordingUploader.last
    assert up.schema_calls and not up.file_calls  # no results_dir -> schema only


def test_app_converter_is_callable_after_handregister():
    # run_end_to_end depends on app.converter being set to an in-process callable.
    assert callable(main.app.converter)


def test_convert_command_registered_with_upload_flags():
    # The hand-registered command must expose the BloodHound flags.
    names = {c.name for c in main._convert_typer.registered_commands}
    assert "sccm" in names
    sccm_cmd = next(c for c in main._convert_typer.registered_commands if c.name == "sccm")
    params = {p for p in sccm_cmd.callback.__annotations__}
    assert {"bloodhound", "upload_dir", "skip_collection"} <= params
