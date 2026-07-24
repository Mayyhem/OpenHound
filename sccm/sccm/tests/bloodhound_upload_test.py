# sccm/sccm/tests/bloodhound_upload_test.py
import logging
from pathlib import Path

from openhound_collector_common.bloodhound import UploadSummary
from openhound_sccm.bloodhound_upload import run_upload


class FakeUploader:
    def __init__(self):
        self.schema_calls = []
        self.file_calls = []

    def upload_schemas(self, schemas):
        self.schema_calls.append(list(schemas))
        return UploadSummary(schemas_uploaded=len(schemas))

    def upload_files(self, files):
        self.file_calls.append([Path(f).name for f in files])
        return UploadSummary(files_uploaded=len(files))


def _graph(tmp_path):
    g = tmp_path / "graph"
    g.mkdir()
    (g / "sccm_nodes-1.json").write_text('{"graph": {}}')
    return g


def test_uploads_schema_and_results(tmp_path):
    up = FakeUploader()
    summary = run_upload(
        uploader=up, schemas=[b"{}", b"{}"], results_dir=_graph(tmp_path),
        work_dir=tmp_path, upload_schema=True, upload_results=True,
        logger=logging.getLogger("t"))
    assert up.schema_calls == [[b"{}", b"{}"]]
    assert up.file_calls and up.file_calls[0][0].endswith(".zip")
    assert summary.schemas_uploaded == 2 and summary.files_uploaded == 1


def test_schema_only_skips_results(tmp_path):
    up = FakeUploader()
    run_upload(uploader=up, schemas=[b"{}"], results_dir=_graph(tmp_path),
               work_dir=tmp_path, upload_schema=True, upload_results=False,
               logger=logging.getLogger("t"))
    assert up.schema_calls and not up.file_calls


def test_results_only_skips_schema(tmp_path):
    up = FakeUploader()
    run_upload(uploader=up, schemas=[b"{}"], results_dir=_graph(tmp_path),
               work_dir=tmp_path, upload_schema=False, upload_results=True,
               logger=logging.getLogger("t"))
    assert not up.schema_calls and up.file_calls


def test_results_requested_but_no_dir_is_noop_for_files(tmp_path):
    up = FakeUploader()
    summary = run_upload(uploader=up, schemas=[b"{}"], results_dir=None,
                         work_dir=tmp_path, upload_schema=True, upload_results=True,
                         logger=logging.getLogger("t"))
    assert up.schema_calls and not up.file_calls
    assert summary.schemas_uploaded == 1
