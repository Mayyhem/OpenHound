"""Unit tests for the CVE-2025-49758 check (`openhound_mssql.cve`).

Rows are ported 1:1 from MSSQLHound's Go tests (`internal/collector/cve_test.go`):
``TestParseSQLVersion`` and ``TestCheckCVE202549758``. A lab-observed @@VERSION
banner is added as a sanity case asserting the cve.go-computed verdict.
"""

import pytest

from openhound_mssql.cve import SQLVersion, check_cve_2025_49758, parse_sql_version


# --- parse_sql_version -----------------------------------------------------
# Ported 1:1 from Go TestParseSQLVersion (cve_test.go 7-65). The four success
# rows assert the parsed components; the two error rows assert a ValueError.

@pytest.mark.parametrize(
    "name, input_str, expected",
    [
        ("SQL Server 2019 full version", "15.0.4435.7", SQLVersion(15, 0, 4435, 7)),
        ("SQL Server 2022 version", "16.0.4210.1", SQLVersion(16, 0, 4210, 1)),
        ("Short version", "15.0.4435", SQLVersion(15, 0, 4435, 0)),
        ("Two part version", "15.0", SQLVersion(15, 0, 0, 0)),
    ],
)
def test_parse_sql_version_ok(name, input_str, expected):
    assert parse_sql_version(input_str) == expected


@pytest.mark.parametrize(
    "name, input_str",
    [
        ("Empty string", ""),
        ("Invalid version", "invalid"),
    ],
)
def test_parse_sql_version_error(name, input_str):
    with pytest.raises(ValueError):
        parse_sql_version(input_str)


# --- check_cve_2025_49758 --------------------------------------------------
# Ported 1:1 from Go TestCheckCVE202549758 (cve_test.go 116-195). Each row
# supplies either a bare version number or a full @@VERSION banner and asserts
# the vulnerable verdict. (Go also tracks IsPatched; in this port a version is
# patched exactly when it is parseable and not vulnerable, so the boolean pair
# is fully captured by `vulnerable`.)

@pytest.mark.parametrize(
    "name, version_input, expected_vulnerable",
    [
        ("SQL 2019 vulnerable version", "15.0.4435.7", True),
        ("SQL 2019 patched version", "15.0.4440.1", False),
        ("SQL 2022 vulnerable version", "16.0.4205.1", True),
        ("SQL 2022 patched version", "16.0.4210.1", False),
        ("SQL 2017 vulnerable version", "14.0.3495.9", True),
        ("SQL 2016 vulnerable version", "13.0.6460.7", True),
        ("SQL 2014 (pre-2016) - vulnerable", "12.0.5000.0", True),
        (
            "Full @@VERSION string",
            "Microsoft SQL Server 2019 (RTM-CU32) (KB5029378) - 15.0.4435.7 (X64)",
            True,
        ),
        ("Newer version not in affected ranges (assume patched)", "16.0.5000.0", False),
    ],
)
def test_check_cve_2025_49758_vulnerable(name, version_input, expected_vulnerable):
    result = check_cve_2025_49758(version_input)
    assert result["vulnerable"] is expected_vulnerable


def test_check_cve_2025_49758_metadata_for_vulnerable_branch():
    # 15.0.4435.7 is the top of the "SQL 2019 CU32+GDR" affected range; the fix
    # is KB5063757 at 15.0.4440.1 (cve.go 99-103).
    result = check_cve_2025_49758("15.0.4435.7")
    assert result == {
        "vulnerable": True,
        "patch_kb": "5063757",
        "required_version": "15.0.4440.1",
        "update_name": "SQL 2019 CU32+GDR",
    }


def test_check_cve_2025_49758_patched_build_falls_through_to_assume_patched():
    # In cve.go each branch's patched_at build sits one step ABOVE its
    # max_affected (here max_affected 15.0.4435.7, patched_at 15.0.4440.1), so a
    # server sitting exactly at the patched build is outside every affected
    # range. Go's lookup then takes the "not in any range -> assume patched"
    # path (cve.go 287-289), which carries empty metadata. We mirror that
    # exactly: not vulnerable, no KB / required-version / update-name.
    result = check_cve_2025_49758("15.0.4440.1")
    assert result == {
        "vulnerable": False,
        "patch_kb": "",
        "required_version": "",
        "update_name": "",
    }


def test_check_cve_2025_49758_metadata_for_in_range_patched_version():
    # A version strictly inside an affected range and at/above its patched_at
    # would carry the branch metadata. cve.go's tables make this unreachable for
    # the >= patched_at case (patched_at is always just past max_affected), so
    # exercise the in-range *vulnerable* path here for the metadata fields: the
    # bottom of the SQL 2022 CU20+GDR range.
    result = check_cve_2025_49758("16.0.4003.1")
    assert result == {
        "vulnerable": True,
        "patch_kb": "5063814",
        "required_version": "16.0.4210.1",
        "update_name": "SQL 2022 CU20+GDR",
    }


def test_check_cve_2025_49758_pre_2016_metadata():
    # Below SQL 2016 -> vulnerable with the out-of-support sentinel (cve.go 258-264).
    result = check_cve_2025_49758("12.0.5000.0")
    assert result == {
        "vulnerable": True,
        "patch_kb": "N/A",
        "required_version": "13.0.6300.2 (SQL 2016 SP3)",
        "update_name": "SQL Server < 2016",
    }


def test_check_cve_2025_49758_unparseable_is_not_vulnerable():
    # Unparseable version -> conservative not-vulnerable (Go nil -> false).
    result = check_cve_2025_49758("not a version")
    assert result == {
        "vulnerable": False,
        "patch_kb": "",
        "required_version": "",
        "update_name": "",
    }


def test_check_cve_2025_49758_accepts_parsed_version():
    # The function also accepts an already-parsed SQLVersion.
    assert check_cve_2025_49758(SQLVersion(15, 0, 4435, 7))["vulnerable"] is True


# --- Lab sanity case -------------------------------------------------------

def test_lab_version_2022_rtm_gdr_kb5063756():
    # Lab-observed banner. 16.0.1145.1 is the patched build for the "SQL 2022
    # RTM+GDR" branch (max affected 16.0.1140.6), so it sits just *above* every
    # affected range and cve.go classifies it as patched (assume-patched
    # fall-through): not vulnerable, empty metadata.
    banner = "Microsoft SQL Server 2022 (RTM-GDR) (KB5063756) - 16.0.1145.1"
    result = check_cve_2025_49758(banner)
    assert result == {
        "vulnerable": False,
        "patch_kb": "",
        "required_version": "",
        "update_name": "",
    }
