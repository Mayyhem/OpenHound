"""SCCM build / CVE lookup table.

Ported from CMBP ``sccm/ConfigManBearPig/python/lib/collectors/version_fingerprint.py``
(originally authored by Mehdi Elyassa at Synacktiv:
https://github.com/synacktiv/SCCMVersionGuesser/blob/main/SCCMVersionGuesser.py).

Used by ``models/sccm_site.py`` to populate the ``versionCVEs`` property when
the site's ``version`` string maps to a known build, so BloodHound queries
that look at ``s.versionCVEs`` against CMBP graphs work identically against
OpenHound graphs.

Synchronise this file with CMBP's ``BUILD_MAP`` / ``CVE_MAP`` whenever CMBP
adds new builds or CVEs upstream.
"""

from __future__ import annotations

from typing import Optional


CVE_MAP: dict[str, list[str]] = {
    "CVE-2025-59501 (Auth Bypass)": ["KB35360093", "KB32851084"],
    "CVE-2025-59213 (Unauth SQLi)": ["KB34503790", "KB34503768"],
    "CVE-2025-55320 (Auth SQLi)": ["KB34503790", "KB34503768"],
    "CVE-2025-47178 (Auth SQLi)": ["KB31909343", "KB33926600", "KB32480179"],
    "CVE-2024-43468 (Unauth SQLi)": ["KB29166583"],
}

BUILD_MAP: dict[str, dict] = {
    "9141": {
        "BaseName": "SCCM 2509",
        "Stack": [
            ("5.00.9141.1000", "Base", "SCCM 2509 Release", "5.00.9141.1000"),
            ("5.00.9141.1015", "KB36495448", "Update", "5.00.9141.1015"),
            ("5.00.9141.1015", "KB36419072", "Update", "5.00.9141.1017"),
        ],
    },
    "9135": {
        "BaseName": "SCCM 2503",
        "Stack": [
            ("5.00.9135.1001", "Base", "SCCM 2503 Release", "5.00.9135.1000"),
            ("5.00.9135.1001", "KB31909343", "Hotfix for 2503", "5.00.9135.1001"),
            ("5.00.9135.1001", "KB32480179", "Hotfix for 2503", "5.00.9135.1003"),
            ("5.00.9135.1006", "KB33177653", "Update for 2503", "5.00.9135.1006"),
            ("5.00.9135.1006", "KB34503790", "Hotfix for 2503", "5.00.9135.1008"),
            ("5.00.9135.1013", "KB32851084", "Hotfix for 2503", "5.00.9135.1013"),
            ("5.00.9135.1013", "KB35958849", "Hotfix for 2503", "5.00.9135.1014"),
            ("5.00.9135.1017", "KB36495448", "Hotfix for 2503", "5.00.9135.1017"),
            ("5.00.9132.1017", "KB36419072", "Hotfix for 2503", "5.00.9135.1019"),
        ],
    },
    "9132": {
        "BaseName": "SCCM 2409",
        "Stack": [
            ("5.00.9132.1011", "Base", "SCCM 2409 Release", "5.00.9132.1000"),
            ("5.00.9132.1013", "KB30833053", "Hotfix KB30833053", "5.00.9132.1013"),
            ("5.00.9132.1023", "KB30385346", "Hotfix Rollup KB30385346", "5.00.9132.1023"),
            ("5.00.9132.1027", "KB33177653", "Hotfix Rollup KB33177653", "5.00.9132.1027"),
            ("5.00.9132.1027", "KB33926600", "Hotfix Rollup KB33926600", "5.00.9132.1028"),
            ("5.00.9132.1027", "KB34503768", "Hotfix Rollup KB34503768", "5.00.9132.1029"),
            ("5.00.9132.1027", "KB35360093", "Hotfix Rollup KB35360093", "5.00.9132.1031"),
            ("5.00.9132.1027", "KB35958849", "Hotfix Rollup KB35958849", "5.00.9132.1032"),
            ("5.00.9132.1027", "KB36419072", "Hotfix Rollup KB36419072", "5.00.9132.1034"),
        ],
    },
    "9128": {
        "BaseName": "SCCM 2403",
        "Stack": [
            ("5.00.9128.1005", "Base", "SCCM 2403 Release", "5.00.9128.1000"),
            ("5.00.9128.1005", "KB28290310", "Hotfix KB28290310", "5.00.9128.1012"),
            ("5.00.9128.1014", "KB28458746", "Hotfix KB28458746", "5.00.9128.1014"),
            ("5.00.9128.1014", "KB29166583", "Hotfix KB29166583", "5.00.9128.1024"),
            ("5.00.9128.1030", "KB28204160", "Rollup KB28204160", "5.00.9128.1030"),
            ("5.00.9128.1033", "KB33177653", "Hotfix KB33177653", "5.00.9128.1033"),
            ("5.00.9128.1033", "KB33926600", "Hotfix KB33926600", "5.00.9128.1034"),
            ("5.00.9128.1033", "KB34503768", "Hotfix KB34503768", "5.00.9128.1035"),
            ("5.00.9128.1033", "KB35360093", "Hotfix KB35360093", "5.00.9128.1037"),
        ],
    },
    "9122": {
        "BaseName": "SCCM 2309",
        "Stack": [
            ("5.00.9122.1002", "Base", "SCCM 2309 Release", "5.00.9122.1000"),
            ("5.00.9122.1007", "KB26129847", "Hotfix KB26129847", "5.00.9122.1007"),
            ("5.00.9122.1018", "KB25858444", "Original Hotfix KB25858444", "5.00.9122.1018"),
            ("5.00.9122.1019", "KB27863823", "Revised Hotfix KB27863823", "5.00.9122.1019"),
            ("5.00.9122.1019", "KB29166583", "MP Hotfix", "5.00.9122.1033"),
        ],
    },
    "9106": {
        "BaseName": "SCCM 2303",
        "Stack": [
            ("5.00.9106.1000", "Base", "SCCM 2303 Release", "5.00.9106.1000"),
            ("5.00.9106.1015", "KB21010486", "Original release", "5.00.9106.1015"),
            ("5.00.9106.1015", "KB24721208", "Hotfix KB24721208", "5.00.9106.1018"),
            ("5.00.9106.1022", "KB24719670", "Revised release", "5.00.9106.1022"),
            ("5.00.9106.1027", "KB25073607", "Hotfix", "5.00.9106.1027"),
            ("5.00.9122.1019", "KB29166583", "MP Hotfix", "5.00.9106.1037"),
        ],
    },
    "9096": {
        "BaseName": "SCCM 2211",
        "Stack": [
            ("5.00.9096.1000", "Base", "SCCM 2211 Release", "5.00.9096.1000"),
            ("5.00.9096.1024", "KB16643863", "Hotfix KB16643863", "5.00.9096.1000"),
        ],
    },
    "9088": {
        "BaseName": "SCCM 2207",
        "Stack": [
            ("5.00.9088.1007", "Base", "SCCM 2207 Release", "5.00.9088.1000"),
            ("5.00.9088.1007", "KB14978429", "Hotfix KB14978429", "5.00.9088.1000"),
            ("5.00.9088.1007", "KB15498768", "Hotfix KB15498768", "5.00.9088.1012"),
            ("5.00.9088.1007", "KB15599094", "Hotfix KB15599094", "5.00.9088.1013"),
            ("5.00.9088.1010", "KB14959905", "Hotfix KB14959905", "5.00.9088.1010"),
            ("5.00.9088.1025", "KB15152495", "Hotfix KB15152495", "5.00.9088.1025"),
        ],
    },
    "9078": {
        "BaseName": "SCCM 2203",
        "Stack": [
            ("5.00.9078.1006", "Base", "SCCM 2203 Release", "5.00.9078.1000"),
            ("5.00.9078.1006", "KB13953025", "Hotfix KB13953025", "5.00.9078.1007"),
            ("5.00.9078.1006", "KB14480034", "Hotfix KB14480034", "5.00.9078.1007"),
            ("5.00.9078.1025", "KB14244456", "Hotfix KB14244456", "5.00.9078.1025"),
        ],
    },
    "9068": {
        "BaseName": "SCCM 2111",
        "Stack": [
            ("5.00.9068.1005", "Base", "SCCM 2111 Release", "5.00.9068.1000"),
            ("5.00.9068.1008", "KB12709700", "Hotfix KB12709700", "5.00.9068.1000"),
            ("5.00.9068.1012", "KB12959506", "Hotfix KB12959506", "5.00.9068.1000"),
            ("5.00.9068.1026", "KB12896009", "Hotfix KB12896009", "5.00.9068.1000"),
        ],
    },
}


def _normalize(version: str) -> str:
    return version.replace(".00.", ".0.")


def _locate_build(detected_ver: str) -> Optional[str]:
    for build_id, data in BUILD_MAP.items():
        for item in data["Stack"]:
            if detected_ver in item[0]:
                return build_id
    return None


def lookup_cves(version: Optional[str]) -> list[str]:
    """Return the list of CVE strings that ``version`` is still vulnerable to.

    Returns an empty list when ``version`` is None / unknown / fully patched.
    Walks the build's ordered hotfix stack — rows at-or-before the first row
    whose client version matches are treated as installed; later rows as
    missing. A CVE is considered patched if any of its fix KBs appears in the
    installed portion.
    """
    if not version:
        return []
    build_id = _locate_build(version)
    if not build_id:
        return []
    stack = BUILD_MAP[build_id]["Stack"]
    detected_norm = _normalize(version)
    installed_kbs: set[str] = set()
    found_current = False
    for client_v, kb, _name, _full_v in stack:
        is_match = version == client_v or detected_norm == _normalize(client_v)
        if not found_current:
            if kb != "Base":
                installed_kbs.add(kb)
            if is_match:
                found_current = True
    missing: list[str] = []
    for cve, fix_kbs in CVE_MAP.items():
        if not any(kb in installed_kbs for kb in fix_kbs):
            missing.append(cve)
    return sorted(missing)
