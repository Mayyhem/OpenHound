def test_public_api_importable():
    """The bloodhound subpackage must re-export its whole public API from its root.

    This is a contract test for a published library: SCCM (and soon MSSQL) import these
    names from ``openhound_collector_common.bloodhound``, so moving one deeper without a
    re-export breaks a downstream package rather than this one.

    Checked with ``hasattr`` over a named tuple rather than by importing the eight names
    directly. The direct-import form is what this test used to do, and seven of the eight
    were then flagged unused (F401) because they are named, never called — so
    ``ruff check --fix`` would have deleted them and left a test that still passed while
    checking nothing. Naming them as data keeps the contract explicit, keeps the linter
    honest, and reports precisely which export went missing.
    """
    from openhound_collector_common import bloodhound

    expected = (
        "BloodHoundClient",
        "BloodHoundHTTPError",
        "BloodHoundUploader",
        "UploadSummary",
        "build_uploader",
        "bundle_graph_dir",
        "disable_possible_edges",
        "resolve_credentials",
    )
    missing = [name for name in expected if not hasattr(bloodhound, name)]
    assert not missing, f"no longer exported from openhound_collector_common.bloodhound: {missing}"

    # build_uploader returns None when given no BloodHound configuration at all, which is
    # how the collectors decide "upload not requested" without branching at the call site.
    assert bloodhound.build_uploader(None, None, None) is None
