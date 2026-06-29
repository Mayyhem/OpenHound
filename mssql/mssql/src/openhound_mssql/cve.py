"""CVE-2025-49758 vulnerability check for SQL Server.

Pure-Python port of MSSQLHound's Go CVE module (`internal/collector/cve.go`).
It parses a SQL Server version string (a bare ``15.0.2000.5`` or a full
``@@VERSION`` banner) and decides whether the instance is still vulnerable to
CVE-2025-49758, the "SQL Server elevation-of-privilege via password change"
flaw fixed by the August 2025 security updates.

Reference: https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2025-49758

How the lookup works (mirrors Go ``CheckCVE202549758``):

* Each entry in :data:`CVE_2025_49758_UPDATES` describes one SQL Server
  servicing branch (e.g. "SQL 2022 RTM+GDR") as a ``[min_affected,
  max_affected]`` build range plus the ``patched_at`` build that carries the
  fix. The detected version is matched against these ranges.
* If the version sits inside a branch's affected range, it is compared to that
  branch's ``patched_at`` build to decide vulnerable vs. patched.
* Anything below SQL Server 2016 (major < 13) is out of mainstream support and
  flagged vulnerable outright.
* A version that matches no branch is newer than every known affected range, so
  it is assumed patched.

Usage (downstream, not implemented here): this verdict gates the
``MSSQL_ChangePassword`` edge. When the server is patched, the collector
*excludes* securityadmin / IMPERSONATE-ANY-LOGIN change-password targets; when
unpatched it emits the edge regardless. The server node also carries the
hyphenated keys ``isVulnerableToCVE-2025-49758``,
``CVE-2025-49758_patchKB``, ``CVE-2025-49758_requiredVersion`` and
``CVE-2025-49758_updateName``; the node/adapter layer maps the clean keys this
function returns onto that exact hyphenated spelling.
"""

from __future__ import annotations

import logging
import re
from typing import NamedTuple

# Registers the custom logger.verbose level used across the extension. Imported
# for its side effect; not referenced directly here.
from openhound_collector_common.logging import log_context  # noqa: F401

logger = logging.getLogger(__name__)


class SQLVersion(NamedTuple):
    """A parsed four-part SQL Server version (Major.Minor.Build.Revision).

    Ordering comes for free from NamedTuple: tuple comparison is lexicographic
    across the four fields in declaration order, which matches Go
    ``SQLVersion.Compare`` (early-exit on the first differing component).
    """

    major: int
    minor: int
    build: int
    revision: int

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.build}.{self.revision}"


class SecurityUpdate(NamedTuple):
    """One SQL Server servicing branch's CVE-2025-49758 fix metadata.

    Mirrors Go ``SecurityUpdate``: an affected build range plus the build at
    which the branch became patched.
    """

    name: str
    kb: str
    min_affected: SQLVersion
    max_affected: SQLVersion
    patched_at: SQLVersion


# Security updates that fix CVE-2025-49758, ported verbatim from Go
# `CVE202549758Updates` in cve.go. Order is preserved (the lookup returns on the
# first matching range), though the ranges are disjoint so order is not
# load-bearing.
CVE_2025_49758_UPDATES: list[SecurityUpdate] = [
    # SQL Server 2022 — cve.go lines 82-95
    SecurityUpdate(
        name="SQL 2022 CU20+GDR",
        kb="5063814",
        min_affected=SQLVersion(16, 0, 4003, 1),
        max_affected=SQLVersion(16, 0, 4205, 1),
        patched_at=SQLVersion(16, 0, 4210, 1),
    ),
    SecurityUpdate(
        name="SQL 2022 RTM+GDR",
        kb="5063756",
        min_affected=SQLVersion(16, 0, 1000, 6),
        max_affected=SQLVersion(16, 0, 1140, 6),
        patched_at=SQLVersion(16, 0, 1145, 1),
    ),
    # SQL Server 2019 — cve.go lines 98-111
    SecurityUpdate(
        name="SQL 2019 CU32+GDR",
        kb="5063757",
        min_affected=SQLVersion(15, 0, 4003, 23),
        max_affected=SQLVersion(15, 0, 4435, 7),
        patched_at=SQLVersion(15, 0, 4440, 1),
    ),
    SecurityUpdate(
        name="SQL 2019 RTM+GDR",
        kb="5063758",
        min_affected=SQLVersion(15, 0, 2000, 5),
        max_affected=SQLVersion(15, 0, 2135, 5),
        patched_at=SQLVersion(15, 0, 2140, 1),
    ),
    # SQL Server 2017 — cve.go lines 114-127
    SecurityUpdate(
        name="SQL 2017 CU31+GDR",
        kb="5063759",
        min_affected=SQLVersion(14, 0, 3006, 16),
        max_affected=SQLVersion(14, 0, 3495, 9),
        patched_at=SQLVersion(14, 0, 3500, 1),
    ),
    SecurityUpdate(
        name="SQL 2017 RTM+GDR",
        kb="5063760",
        min_affected=SQLVersion(14, 0, 1000, 169),
        max_affected=SQLVersion(14, 0, 2075, 8),
        patched_at=SQLVersion(14, 0, 2080, 1),
    ),
    # SQL Server 2016 — cve.go lines 130-143
    SecurityUpdate(
        name="SQL 2016 Azure Connect Feature Pack",
        kb="5063761",
        min_affected=SQLVersion(13, 0, 7000, 253),
        max_affected=SQLVersion(13, 0, 7055, 9),
        patched_at=SQLVersion(13, 0, 7060, 1),
    ),
    SecurityUpdate(
        name="SQL 2016 SP3 RTM+GDR",
        kb="5063762",
        min_affected=SQLVersion(13, 0, 6300, 2),
        max_affected=SQLVersion(13, 0, 6460, 7),
        patched_at=SQLVersion(13, 0, 6465, 1),
    ),
]

# Lowest in-support build: SQL Server 2016 RTM. Anything below major 13 is out
# of mainstream support and treated as vulnerable. cve.go line 258.
_SQL_2016_MIN = SQLVersion(13, 0, 0, 0)

# Matches a four-part (preferred) then three-part numeric version inside a full
# @@VERSION banner. Mirrors Go `ExtractVersionFromFullVersion` (cve.go 206-222),
# which tries the four-part pattern first and falls back to three parts.
_FOUR_PART_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)")
_THREE_PART_RE = re.compile(r"(\d+\.\d+\.\d+)")


def _extract_version(full_version: str) -> str:
    """Pull a numeric version out of a full @@VERSION banner.

    Tries a four-part ``15.0.4435.7`` match first, then a three-part
    ``15.0.4435`` fallback. Mirrors Go ``ExtractVersionFromFullVersion``.

    Args:
        full_version: A @@VERSION banner (or any string to scan).

    Returns:
        The matched numeric version, or "" if none is present.
    """
    match = _FOUR_PART_RE.search(full_version)
    if match:
        return match.group(1)
    match = _THREE_PART_RE.search(full_version)
    if match:
        return match.group(1)
    # No numeric version present in the string.
    return ""


def parse_sql_version(version_string: str) -> SQLVersion:
    """Parse a SQL Server version string into a :class:`SQLVersion`.

    Accepts either a bare dotted number (``15.0.2000.5``, ``15.0.4435``,
    ``15.0``) or a full ``@@VERSION`` banner from which the numeric version is
    extracted first. Build and revision default to 0 when absent. Mirrors Go
    ``ParseSQLVersion`` (cve.go 157-202) plus the banner extraction in
    ``CheckCVE202549758``.

    Args:
        version_string: A dotted version or a @@VERSION banner.

    Returns:
        The parsed :class:`SQLVersion`.

    Raises:
        ValueError: If the string is empty, has no usable numeric version, or
            its components are not integers (matches the Go error cases).
    """
    cleaned = version_string.strip()
    if not cleaned:
        # Go returns "empty version string".
        logger.debug("parse_sql_version: empty version string")
        raise ValueError("empty version string")

    # A full banner ("Microsoft SQL Server 2019 ... - 15.0.4435.7 (X64)") has no
    # leading digit; pull the numeric version out of it first. A bare dotted
    # number starts with a digit and is parsed directly.
    if not cleaned[0].isdigit():
        extracted = _extract_version(cleaned)
        if not extracted:
            logger.debug("parse_sql_version: no numeric version in %r", version_string)
            raise ValueError(f"invalid version format: {version_string}")
        logger.debug("parse_sql_version: extracted %s from banner", extracted)
        cleaned = extracted

    parts = cleaned.split(".")
    if len(parts) < 2:
        # Go requires at least major.minor.
        logger.debug("parse_sql_version: too few components in %r", cleaned)
        raise ValueError(f"invalid version format: {cleaned}")

    # Major and minor are required; build and revision are optional (default 0).
    labels = ("major", "minor", "build", "revision")
    values = [0, 0, 0, 0]
    for index in range(min(len(parts), 4)):
        try:
            values[index] = int(parts[index])
        except ValueError:
            logger.debug(
                "parse_sql_version: non-integer %s component %r",
                labels[index],
                parts[index],
            )
            raise ValueError(f"invalid {labels[index]} version: {parts[index]}") from None

    return SQLVersion(*values)


def check_cve_2025_49758(version_string_or_parts: str | SQLVersion) -> dict:
    """Decide whether a SQL Server version is vulnerable to CVE-2025-49758.

    Accepts a version string (bare number or full @@VERSION banner) or an
    already-parsed :class:`SQLVersion`. Mirrors Go ``CheckCVE202549758``: out of
    range -> assume patched; below SQL 2016 -> vulnerable; otherwise compare
    against the matching servicing branch's patched build.

    Args:
        version_string_or_parts: A version string or a parsed
            :class:`SQLVersion`.

    Returns:
        A dict with keys:

        * ``vulnerable`` (bool) — True if the instance is still exposed.
        * ``patch_kb`` (str) — KB article for the fixing update ("" / "N/A").
        * ``required_version`` (str) — build the instance must reach to be
          patched.
        * ``update_name`` (str) — human-readable servicing-branch name.

        On an unparseable version the result is conservatively "not vulnerable"
        with empty metadata (matches Go ``IsVulnerableToCVE202549758`` returning
        False when the check yields nil — avoids false positives).
    """
    if isinstance(version_string_or_parts, SQLVersion):
        version = version_string_or_parts
    else:
        try:
            version = parse_sql_version(version_string_or_parts)
        except ValueError:
            # Go returns nil here; callers treat nil as "not vulnerable, not
            # patched" to avoid false positives. We surface that as a clean
            # not-vulnerable verdict with empty metadata.
            logger.warning(
                "check_cve_2025_49758: could not parse version %r; treating as not vulnerable",
                version_string_or_parts,
            )
            return _result(vulnerable=False, kb="", required="", name="")

    # Below SQL Server 2016 (major < 13): out of support, vulnerable. cve.go 258.
    if version < _SQL_2016_MIN:
        logger.debug("check_cve_2025_49758: %s is < SQL 2016; vulnerable", version)
        return _result(
            vulnerable=True,
            kb="N/A",
            required="13.0.6300.2 (SQL 2016 SP3)",
            name="SQL Server < 2016",
        )

    # Walk each servicing branch; the affected ranges are disjoint so at most
    # one matches. cve.go 268-285.
    for update in CVE_2025_49758_UPDATES:
        if update.min_affected <= version <= update.max_affected:
            required = str(update.patched_at)
            if version >= update.patched_at:
                logger.debug(
                    "check_cve_2025_49758: %s in %s and >= patched %s; patched",
                    version,
                    update.name,
                    required,
                )
                return _result(
                    vulnerable=False, kb=update.kb, required=required, name=update.name
                )
            logger.debug(
                "check_cve_2025_49758: %s in %s but < patched %s; vulnerable",
                version,
                update.name,
                required,
            )
            return _result(
                vulnerable=True, kb=update.kb, required=required, name=update.name
            )

    # No branch matched: newer than every known affected range -> assume
    # patched. cve.go 287-289.
    logger.debug(
        "check_cve_2025_49758: %s matches no affected range; assuming patched", version
    )
    return _result(vulnerable=False, kb="", required="", name="")


def _result(*, vulnerable: bool, kb: str, required: str, name: str) -> dict:
    """Build the public result dict in one place (clean, non-hyphenated keys)."""
    return {
        "vulnerable": vulnerable,
        "patch_kb": kb,
        "required_version": required,
        "update_name": name,
    }
