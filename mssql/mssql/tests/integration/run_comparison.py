#!/usr/bin/env python3
"""Stage 8.2 three-user acceptance harness for the MSSQL OpenHound collector port.

This script is the acceptance GATE that proves our pure-Python OpenHound collector
produces the same BloodHound OpenGraph output as the original MSSQLHound Go binary
(the "oracle"), across three principals with different SQL Server visibility:

    MAYYHEM\\domainadmin  -- sysadmin + local admin: full visibility (all 38 edges)
    MAYYHEM\\roanalyst    -- MSSQL public role only: limited visibility
    MAYYHEM\\lowpriv      -- no MSSQL privileges: SQL connect FAILS -> SPN-only output

Unlike the shipped collector (which must be pure Python), THIS HARNESS may shell out
to Go / PowerShell / our own CLI -- it is a test, not part of the collector.

Flow (see the module docstring blocks below for each step):

  1. Setup ONCE as domainadmin via the Go integration setup test. Manufactures the AD
     objects + SQL fixtures for all 38 edge types (incl. 10 loopback linked servers).
  2. For each user:
       a. Run OUR pipeline: collect -> preprocess -> convert -> to_mssqlhound_zip.
          Our collector must NOT abort if the SQL connect fails for lowpriv; it should
          still emit partial (SPN-only) output, which we capture.
       b. Run the ORACLE (Go binary) for the SAME user -> mssql-bloodhound-*.zip.
       c. VALIDATE our zip two ways (Go TestIntegrationValidateZip + PS1 -Action Test),
          and run the same validators on the Go oracle zip as a control.
       d. DIFF ours-vs-Go: total nodes, total edges, set of edge kinds + per-kind counts.
  3. Teardown in a finally (idempotent) -- always attempted, even on failure.
  4. Emit a per-user report table + the domainadmin 38-type coverage + 3 exact counts.

Usage (from the OpenHound repo root or anywhere -- paths are resolved absolutely):

    python mssql/mssql/tests/integration/run_comparison.py

Env knobs (all have lab defaults):
    OH_REPO_ROOT      repo root (auto-detected from this file's location)
    MSSQL_SERVER      ps1-db.mayyhem.com
    MSSQL_DOMAIN      mayyhem.com
    MSSQL_DC          dc.mayyhem.com
    MSSQL_PASSWORD    password           (shared lab password for all three users)
    OH_SKIP_SETUP     set to "1" to skip the Go setup step (fixtures already present)
    OH_SKIP_TEARDOWN  set to "1" to skip teardown (debugging only -- normally never)
    OH_KEEP_WORKDIRS  set to "1" to leave the per-user temp dirs on disk for inspection
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths + lab configuration
# ---------------------------------------------------------------------------
# Resolve the repo root from this file: .../OpenHound/mssql/mssql/tests/integration
THIS_FILE = Path(__file__).resolve()
REPO_ROOT = Path(os.environ.get("OH_REPO_ROOT", THIS_FILE.parents[4]))
MSSQL_PKG_DIR = REPO_ROOT / "mssql" / "mssql"        # uv project dir for our collector
GO_DIR = REPO_ROOT / "MSSQLHound"                    # Go oracle + integration tests
GO_BIN = GO_DIR / "mssqlhound.exe"                   # prebuilt oracle binary
PS1_VALIDATOR = GO_DIR / "powershell_deprecated" / "Invoke-MSSQLHoundUnitTests.ps1"

# The isolated venv the prompt confirmed working for our collector.
UV_ENV = os.environ.get(
    "UV_PROJECT_ENVIRONMENT",
    "C:/Users/domainadmin/AppData/Local/Temp/oh-mssql-venv",
)

SERVER = os.environ.get("MSSQL_SERVER", "ps1-db.mayyhem.com")
DOMAIN = os.environ.get("MSSQL_DOMAIN", "mayyhem.com")
# DC is used both for LDAP and as the DNS resolver. The Go oracle binary's custom
# (PreferGo) resolver dials "<--dc>:53"; if --dc is a HOSTNAME it has to resolve that
# hostname first, which deadlocks/times out in this lab ("lookup ps1-db: i/o timeout").
# Passing the DC's IP avoids the chicken-and-egg. We resolve the hostname to an IP once
# at startup (see resolve_dc_ip) and use the IP for both our collector and the oracle so
# the comparison is apples-to-apples. Set MSSQL_DC to an IP to skip resolution.
DC = os.environ.get("MSSQL_DC", "dc.mayyhem.com")
PASSWORD = os.environ.get("MSSQL_PASSWORD", "password")


def resolve_dc_ip(dc: str) -> str:
    """Return the DC as an IP. If already an IP (or resolution fails), return as-is."""
    import socket
    # Crude IPv4 check: all dot-separated parts are digits.
    if all(part.isdigit() for part in dc.split(".")) and dc.count(".") == 3:
        return dc
    try:
        ip = socket.gethostbyname(dc)
        print(f"Resolved DC {dc} -> {ip} (used as --dc for both collectors)")
        return ip
    except OSError as exc:
        print(f"WARNING: could not resolve DC {dc} ({exc}); using hostname as-is")
        return dc

# domainadmin is the privileged principal used for setup/teardown and LDAP writes.
ADMIN_USER = f"MAYYHEM\\domainadmin"

# The three principals we compare, in increasing-privilege order is not required;
# we run admin first so its fixtures are warm, then the two limited users.
USERS = ["domainadmin", "roanalyst", "lowpriv"]

# Locate the `go` binary -- the prompt puts it at C:/Program Files/Go/bin.
GO_PATH_DIR = "C:/Program Files/Go/bin"

# The 38 known edge types the oracle can produce (mirrors knownEdgeTypes in
# MSSQLHound/internal/collector/integration_report_test.go). Used for the
# domainadmin coverage check.
KNOWN_EDGE_TYPES = [
    "HasSession",
    "MSSQL_AddMember", "MSSQL_Alter", "MSSQL_AlterAnyAppRole", "MSSQL_AlterAnyDBRole",
    "MSSQL_AlterAnyLogin", "MSSQL_AlterAnyServerRole", "MSSQL_ChangeOwner",
    "MSSQL_ChangePassword", "MSSQL_CoerceAndRelayToMSSQL", "MSSQL_Connect",
    "MSSQL_ConnectAnyDatabase", "MSSQL_Contains", "MSSQL_Control", "MSSQL_ControlDB",
    "MSSQL_ControlServer", "MSSQL_ExecuteAs", "MSSQL_ExecuteAsOwner",
    "MSSQL_ExecuteOnHost", "MSSQL_GetAdminTGS", "MSSQL_GetTGS",
    "MSSQL_GrantAnyDBPermission", "MSSQL_GrantAnyPermission", "MSSQL_HasDBScopedCred",
    "MSSQL_HasLogin", "MSSQL_HasMappedCred", "MSSQL_HasProxyCred", "MSSQL_HostFor",
    "MSSQL_Impersonate", "MSSQL_ImpersonateAnyLogin", "MSSQL_IsMappedTo",
    "MSSQL_IsTrustedBy", "MSSQL_LinkedAsAdmin", "MSSQL_LinkedTo", "MSSQL_MemberOf",
    "MSSQL_Owns", "MSSQL_ServiceAccountFor", "MSSQL_TakeOwnership",
]

# Load-bearing exact edge counts for the domainadmin (full-visibility) run.
LOAD_BEARING_COUNTS = {
    "MSSQL_LinkedTo": 10,
    "MSSQL_LinkedAsAdmin": 8,
    "MSSQL_ServiceAccountFor": 1,
}


# ---------------------------------------------------------------------------
# Small subprocess helper
# ---------------------------------------------------------------------------
def _go_env() -> dict[str, str]:
    """Return os.environ with the Go bin dir on PATH (idempotent)."""
    env = dict(os.environ)
    path = env.get("PATH", "")
    if GO_PATH_DIR not in path:
        env["PATH"] = path + os.pathsep + GO_PATH_DIR
    return env


def run(cmd: list[str], *, cwd: Path | None = None, env: dict | None = None,
        timeout: int = 1800, label: str = "") -> subprocess.CompletedProcess:
    """Run a command, stream-capture stdout+stderr, echo a short header.

    Returns the CompletedProcess (never raises on non-zero -- the caller decides
    what a non-zero exit means; e.g. lowpriv SQL connect failing is expected).
    """
    pretty = " ".join(cmd)
    print(f"\n>>> {label or pretty}")
    print(f"    $ {pretty}")
    if cwd:
        print(f"    (cwd={cwd})")
    started = time.time()
    proc = subprocess.run(
        cmd, cwd=str(cwd) if cwd else None, env=env,
        capture_output=True, text=True, timeout=timeout,
    )
    elapsed = time.time() - started
    print(f"    exit={proc.returncode} ({elapsed:.1f}s)")
    return proc


# ---------------------------------------------------------------------------
# Zip parsing + diff
# ---------------------------------------------------------------------------
@dataclass
class GraphStats:
    """Aggregate node/edge stats parsed from one BloodHound output zip."""
    node_count: int = 0
    edge_count: int = 0
    edge_kind_counts: Counter = field(default_factory=Counter)

    @property
    def edge_kinds(self) -> set[str]:
        return set(self.edge_kind_counts)


def parse_graph_zip(zip_path: Path) -> GraphStats:
    """Parse a MSSQLHound/OpenHound zip and aggregate node/edge stats.

    Both our adapter zip and the Go oracle zip contain one or more ``*.json``
    files, each a ``{"graph": {"nodes": [...], "edges": [...]}}`` envelope (the Go
    binary also writes separate AD-node files whose envelope may have ``metadata:{}``
    -- those still carry a ``graph`` object, so we read them the same way). Edge kinds
    come from each edge's ``kind`` field.
    """
    stats = GraphStats()
    if not zip_path.exists():
        print(f"    WARNING: zip does not exist: {zip_path}")
        return stats

    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            if not name.lower().endswith(".json"):
                continue
            raw = zf.read(name)
            # Strip a UTF-8 BOM if the Go writer emitted one.
            if raw[:3] == b"\xef\xbb\xbf":
                raw = raw[3:]
            try:
                doc = json.loads(raw)
            except json.JSONDecodeError as exc:
                print(f"    WARNING: unparseable JSON {name} in {zip_path.name}: {exc}")
                continue
            graph = doc.get("graph")
            if not isinstance(graph, dict):
                continue
            nodes = graph.get("nodes") or []
            edges = graph.get("edges") or []
            stats.node_count += len(nodes)
            stats.edge_count += len(edges)
            for edge in edges:
                kind = edge.get("kind", "<no-kind>")
                stats.edge_kind_counts[kind] += 1
    return stats


def diff_stats(ours: GraphStats, go: GraphStats) -> tuple[bool, list[str]]:
    """Compare ours vs Go. Return (match, list-of-human-readable-deltas)."""
    deltas: list[str] = []
    if ours.node_count != go.node_count:
        deltas.append(f"node count: ours={ours.node_count} go={go.node_count}")
    if ours.edge_count != go.edge_count:
        deltas.append(f"edge count: ours={ours.edge_count} go={go.edge_count}")

    all_kinds = sorted(ours.edge_kinds | go.edge_kinds)
    for kind in all_kinds:
        o = ours.edge_kind_counts.get(kind, 0)
        g = go.edge_kind_counts.get(kind, 0)
        if o != g:
            deltas.append(f"{kind}: ours={o} go={g}")
    return (not deltas), deltas


# ---------------------------------------------------------------------------
# Step 1: Go integration setup / teardown (sysadmin = domainadmin)
# ---------------------------------------------------------------------------
def _go_integration_env() -> dict[str, str]:
    """Env for the Go integration setup/teardown/validate tests."""
    env = _go_env()
    env.update({
        "MSSQL_SERVER": SERVER,
        "MSSQL_USER": ADMIN_USER,
        "MSSQL_PASSWORD": PASSWORD,
        "MSSQL_DOMAIN": DOMAIN,
        "MSSQL_DC": DC,
        "LDAP_USER": ADMIN_USER,
        "LDAP_PASSWORD": PASSWORD,
    })
    return env


def go_setup() -> bool:
    """Manufacture all AD + SQL fixtures via the Go TestIntegrationSetup test.

    Returns True iff the test exited 0.
    """
    proc = run(
        ["go", "test", "-tags", "integration", "-run", "TestIntegrationSetup",
         "-timeout", "30m", "-v", "./internal/collector/..."],
        cwd=GO_DIR, env=_go_integration_env(), timeout=2100,
        label="Go integration SETUP (manufacture fixtures as domainadmin)",
    )
    _tail(proc, 25)
    return proc.returncode == 0


def go_teardown() -> bool:
    """Idempotent teardown via the Go TestIntegrationTeardown test."""
    proc = run(
        ["go", "test", "-tags", "integration", "-run", "TestIntegrationTeardown",
         "-timeout", "20m", "-v", "./internal/collector/..."],
        cwd=GO_DIR, env=_go_integration_env(), timeout=1500,
        label="Go integration TEARDOWN (remove fixtures)",
    )
    _tail(proc, 15)
    return proc.returncode == 0


def _tail(proc: subprocess.CompletedProcess, n: int) -> None:
    """Print the last n lines of combined stdout/stderr for diagnostics."""
    combined = (proc.stdout or "") + (proc.stderr or "")
    lines = [ln for ln in combined.splitlines() if ln.strip()]
    for ln in lines[-n:]:
        print(f"    | {ln}")


# ---------------------------------------------------------------------------
# Step 2a: OUR pipeline (collect -> preprocess -> convert -> to_mssqlhound_zip)
# ---------------------------------------------------------------------------
def _uv(cmd: list[str], *, timeout: int, label: str) -> subprocess.CompletedProcess:
    """Run an `openhound ...` command in the mssql package's uv environment."""
    env = dict(os.environ)
    env["UV_PROJECT_ENVIRONMENT"] = UV_ENV
    full = ["uv", "--directory", str(MSSQL_PKG_DIR), "run"] + cmd
    return run(full, env=env, timeout=timeout, label=label)


def run_our_pipeline(user: str, workdir: Path) -> Path | None:
    """Run our 4-step pipeline for one user and return the path to ours.zip.

    Steps (exact order, mirroring the prompt):
      collect    -> bucket/
      preprocess -> fresh.duckdb
      convert    -> convert_out/      (--lookup-file fresh.duckdb)
      to_mssqlhound_zip(convert_out, ours.zip)

    The collect step is allowed to exit non-zero / emit partial output (lowpriv's
    SQL connect fails by design); we proceed regardless and let the zip diff show
    what was produced.
    """
    full_user = f"MAYYHEM\\{user}"
    bucket = workdir / "bucket"
    duckdb = workdir / "fresh.duckdb"
    convert_out = workdir / "convert_out"
    ours_zip = workdir / "ours.zip"
    bucket.mkdir(parents=True, exist_ok=True)
    convert_out.mkdir(parents=True, exist_ok=True)

    # --- collect ---
    proc = _uv(
        ["openhound", "collect", "mssql",
         "-t", SERVER, "-u", full_user, "-p", PASSWORD,
         "-d", DOMAIN, "--dc", DC, str(bucket)],
        timeout=1800, label=f"[{user}] OUR collect",
    )
    _tail(proc, 12)
    if proc.returncode != 0:
        # Not necessarily fatal: lowpriv's SQL connect failing is expected, and our
        # collector should still emit partial output. Note it and continue.
        print(f"    NOTE: collect exited {proc.returncode} for {user} "
              f"(expected for lowpriv; checking for partial output)")

    # --- preprocess ---
    proc = _uv(
        ["openhound", "preprocess", "mssql", str(bucket), str(duckdb)],
        timeout=900, label=f"[{user}] OUR preprocess",
    )
    _tail(proc, 8)
    if proc.returncode != 0:
        print(f"    ERROR: preprocess failed for {user}; cannot build zip")
        _tail(proc, 25)
        return None

    # --- convert ---
    proc = _uv(
        ["openhound", "convert", "mssql", str(bucket), str(convert_out),
         "--lookup-file", str(duckdb)],
        timeout=900, label=f"[{user}] OUR convert",
    )
    _tail(proc, 8)
    if proc.returncode != 0:
        print(f"    ERROR: convert failed for {user}; cannot build zip")
        _tail(proc, 25)
        return None

    # --- to_mssqlhound_zip ---
    # Invoke the adapter inside the same venv so it imports openhound_mssql cleanly.
    adapter_script = (
        "import sys; "
        "from openhound_mssql.output_adapter import to_mssqlhound_zip; "
        "to_mssqlhound_zip(sys.argv[1], sys.argv[2])"
    )
    proc = _uv(
        ["python", "-c", adapter_script, str(convert_out), str(ours_zip)],
        timeout=300, label=f"[{user}] OUR to_mssqlhound_zip",
    )
    _tail(proc, 8)
    if proc.returncode != 0 or not ours_zip.exists():
        print(f"    ERROR: to_mssqlhound_zip failed for {user}")
        _tail(proc, 25)
        return None

    return ours_zip


# ---------------------------------------------------------------------------
# Step 2b: ORACLE (Go binary) for the SAME user
# ---------------------------------------------------------------------------
def run_oracle(user: str, workdir: Path) -> Path | None:
    """Run the Go oracle binary for one user; return the path to its zip.

    The binary writes ``mssql-bloodhound-<ts>.zip`` into --zip-dir. We point it at a
    per-user dir and return the freshest matching zip. Like our collector, the oracle
    may exit non-zero for lowpriv (SQL connect fails) but still emit SPN-only output.
    """
    full_user = f"MAYYHEM\\{user}"
    godir = workdir / "go_out"
    godir.mkdir(parents=True, exist_ok=True)

    proc = run(
        [str(GO_BIN), "-t", SERVER, "-u", full_user, "-p", PASSWORD,
         "-d", DOMAIN, "--dc", DC, "--zip-dir", str(godir)],
        env=_go_env(), timeout=1800, label=f"[{user}] ORACLE (Go binary)",
    )
    _tail(proc, 12)
    if proc.returncode != 0:
        print(f"    NOTE: oracle exited {proc.returncode} for {user} "
              f"(expected for lowpriv; checking for partial output)")

    zips = sorted(godir.glob("mssql-bloodhound-*.zip"),
                  key=lambda p: p.stat().st_mtime, reverse=True)
    if not zips:
        print(f"    ERROR: oracle produced no mssql-bloodhound-*.zip for {user}")
        return None
    return zips[0]


# ---------------------------------------------------------------------------
# Step 2c: validators (Go ValidateZip + PS1 -Action Test)
# ---------------------------------------------------------------------------
@dataclass
class ValidationResult:
    passed: int = 0
    failed: int = 0
    ok: bool = False          # True iff failed == 0 and the runner exited cleanly
    note: str = ""


def go_validate_zip(zip_path: Path, label: str) -> ValidationResult:
    """Validate a zip with the Go TestIntegrationValidateZip test (MSSQL_ZIP=...).

    Parses the "Results: N passed, M failed" line the test logs. The overall test
    exit code is also honored (the test fails the moment any subtest fails).
    """
    env = _go_integration_env()
    env["MSSQL_ZIP"] = str(zip_path)
    proc = run(
        ["go", "test", "-tags", "integration", "-run", "TestIntegrationValidateZip",
         "-timeout", "20m", "-v", "./internal/collector/..."],
        cwd=GO_DIR, env=env, timeout=1500, label=f"Go ValidateZip ({label})",
    )
    combined = (proc.stdout or "") + (proc.stderr or "")
    res = ValidationResult()
    for line in combined.splitlines():
        s = line.strip()
        # The runValidateZip helper logs e.g. "Results: 120 passed, 3 failed".
        if "Results:" in s and "passed" in s and "failed" in s:
            try:
                seg = s.split("Results:", 1)[1]
                res.passed = int(seg.split("passed", 1)[0].strip().split()[-1])
                res.failed = int(seg.split(",", 1)[1].split("failed", 1)[0].strip().split()[-1])
            except (ValueError, IndexError):
                pass
    res.ok = (proc.returncode == 0) and (res.failed == 0)
    if res.passed == 0 and res.failed == 0:
        res.note = "no 'Results:' line parsed; see tail"
        _tail(proc, 30)
    else:
        _tail(proc, 12)
    return res


def ps1_validate_zip(zip_path: Path, label: str) -> ValidationResult:
    """Validate a zip with the PS1 unit-test kit (-Action Test -InputFile <zip>).

    -Action Test with -InputFile loads the zip instead of enumerating, so no SQL
    connection is made; -SkipDomainObjects keeps it from touching AD. We parse the
    per-perspective summary the kit prints:
        *     Passed: N      (positive)
        *     Failed: N
        *     Passed (no edge): N   (negative)
        *     Failed (edge exists): N
    """
    proc = run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-File", str(PS1_VALIDATOR),
         "-Action", "Test",
         "-InputFile", str(zip_path),
         "-ServerInstance", SERVER,
         "-Domain", DOMAIN,
         "-SkipDomainObjects"],
        cwd=GO_DIR / "powershell_deprecated", timeout=1500,
        label=f"PS1 -Action Test ({label})",
    )
    combined = (proc.stdout or "") + (proc.stderr or "")
    res = ValidationResult()
    passed = 0
    failed = 0
    # The kit prints two summary blocks per perspective; we anchor ONLY on the
    # unambiguous "<PERSPECTIVE> Perspective Summary:" block (Write-CleanTestSummary)
    # to avoid double-counting the earlier "Test Summary for X perspective" block.
    # Inside that block, positive+negative Passed/Failed each appear once.
    in_summary = False
    for line in combined.splitlines():
        s = line.strip()
        if "Perspective Summary:" in s:
            in_summary = True
            continue
        if not in_summary:
            continue
        # Block lines look like: "*     Passed: 120"  /  "*     Passed (no edge): 40".
        # The number is always after the LAST colon. Lines without Passed/Failed
        # (Expected/Found/Missing edges, "* Positive test cases:") are skipped.
        if "Passed" in s and ":" in s:
            try:
                passed += int(s.rsplit(":", 1)[1].strip())
            except ValueError:
                pass
        elif "Failed" in s and ":" in s:
            try:
                failed += int(s.rsplit(":", 1)[1].strip())
            except ValueError:
                pass
        # The block ends at the negative "Failed (edge exists)" line; the next
        # perspective (if any) re-arms via its own "Perspective Summary:" header.
    res.passed = passed
    res.failed = failed
    res.ok = (proc.returncode == 0) and (failed == 0) and (passed > 0)
    if passed == 0 and failed == 0:
        res.note = "no summary lines parsed; see tail"
        _tail(proc, 40)
    else:
        _tail(proc, 16)
    return res


# ---------------------------------------------------------------------------
# Per-user comparison record
# ---------------------------------------------------------------------------
@dataclass
class UserReport:
    user: str
    ours: GraphStats | None = None
    go: GraphStats | None = None
    match: bool = False
    deltas: list[str] = field(default_factory=list)
    go_validate_ours: ValidationResult | None = None
    go_validate_go: ValidationResult | None = None
    ps1_validate_ours: ValidationResult | None = None
    ps1_validate_go: ValidationResult | None = None
    error: str = ""


def compare_user(user: str, base_tmp: Path) -> UserReport:
    """Run the full per-user comparison and return its report."""
    print("\n" + "=" * 78)
    print(f"USER: MAYYHEM\\{user}")
    print("=" * 78)

    workdir = base_tmp / user
    workdir.mkdir(parents=True, exist_ok=True)
    report = UserReport(user=user)

    # 2a: our pipeline
    ours_zip = run_our_pipeline(user, workdir)
    if ours_zip is None:
        report.error = "our pipeline failed to produce a zip"
        return report

    # 2b: oracle
    go_zip = run_oracle(user, workdir)
    if go_zip is None:
        report.error = "oracle produced no zip"
        # We can still parse our own stats below.

    # 2d: diff (parse both zips)
    report.ours = parse_graph_zip(ours_zip)
    if go_zip is not None:
        report.go = parse_graph_zip(go_zip)
        report.match, report.deltas = diff_stats(report.ours, report.go)
    print(f"\n    [{user}] OURS: nodes={report.ours.node_count} "
          f"edges={report.ours.edge_count} kinds={len(report.ours.edge_kinds)}")
    if report.go is not None:
        print(f"    [{user}] GO  : nodes={report.go.node_count} "
              f"edges={report.go.edge_count} kinds={len(report.go.edge_kinds)}")
        print(f"    [{user}] MATCH={report.match}"
              + ("" if report.match else f"  deltas={report.deltas}"))

    # 2c: validators -- our zip both ways, plus Go zip as control
    report.go_validate_ours = go_validate_zip(ours_zip, f"{user}/OURS")
    report.ps1_validate_ours = ps1_validate_zip(ours_zip, f"{user}/OURS")
    if go_zip is not None:
        report.go_validate_go = go_validate_zip(go_zip, f"{user}/GO-control")
        report.ps1_validate_go = ps1_validate_zip(go_zip, f"{user}/GO-control")

    return report


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def _vr(v: ValidationResult | None) -> str:
    if v is None:
        return "n/a"
    tag = "PASS" if v.ok else "FAIL"
    extra = f" ({v.passed}P/{v.failed}F)"
    if v.note:
        extra += f" [{v.note}]"
    return tag + extra


def print_final_report(reports: list[UserReport], setup_ok: bool) -> None:
    print("\n\n" + "#" * 78)
    print("# STAGE 8.2 ACCEPTANCE REPORT -- ours (OpenHound) vs Go (MSSQLHound oracle)")
    print("#" * 78)
    print(f"# server={SERVER} domain={DOMAIN} dc={DC}")
    print(f"# setup_exit0={setup_ok}  (teardown status printed at the very end)")

    # Per-user table.
    header = (f"{'user':<12} | {'ours n/e/k':>16} | {'go n/e/k':>16} | "
              f"{'match':>5} | {'Go-Valid(ours)':>18} | {'PS1(ours)':>16}")
    print("\n" + header)
    print("-" * len(header))
    for r in reports:
        if r.ours is not None:
            ours_cell = f"{r.ours.node_count}/{r.ours.edge_count}/{len(r.ours.edge_kinds)}"
        else:
            ours_cell = "FAILED"
        if r.go is not None:
            go_cell = f"{r.go.node_count}/{r.go.edge_count}/{len(r.go.edge_kinds)}"
        else:
            go_cell = "n/a"
        match_cell = "YES" if r.match else "NO"
        print(f"{r.user:<12} | {ours_cell:>16} | {go_cell:>16} | "
              f"{match_cell:>5} | {_vr(r.go_validate_ours):>18} | {_vr(r.ps1_validate_ours):>16}")

    # Deltas + control validation per user.
    for r in reports:
        print(f"\n-- MAYYHEM\\{r.user} --")
        if r.error:
            print(f"   ERROR: {r.error}")
        if r.deltas:
            print(f"   edge/node DELTAS (ours vs go): {r.deltas}")
        elif r.go is not None:
            print("   edge/node deltas: NONE (exact match)")
        print(f"   Go ValidateZip  ours={_vr(r.go_validate_ours)}  go-control={_vr(r.go_validate_go)}")
        print(f"   PS1 -Action Test ours={_vr(r.ps1_validate_ours)}  go-control={_vr(r.ps1_validate_go)}")

    # domainadmin 38-type coverage + load-bearing counts.
    admin = next((r for r in reports if r.user == "domainadmin"), None)
    print("\n-- domainadmin 38-edge-type coverage (from OUR zip) --")
    if admin and admin.ours is not None:
        found = admin.ours.edge_kinds
        missing = [k for k in KNOWN_EDGE_TYPES if k not in found]
        print(f"   known edge types: {len(KNOWN_EDGE_TYPES)}; "
              f"found in our output: {len(found & set(KNOWN_EDGE_TYPES))}")
        if missing:
            print(f"   MISSING types: {missing}")
        else:
            print("   ALL 38 known edge types present in our output")
        print("   load-bearing exact counts (ours):")
        for kind, want in LOAD_BEARING_COUNTS.items():
            got = admin.ours.edge_kind_counts.get(kind, 0)
            mark = "OK" if got == want else "MISMATCH"
            print(f"     {kind}: ours={got} expected={want}  [{mark}]")
    else:
        print("   domainadmin run failed; coverage unavailable")

    print("\n" + "#" * 78)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def preflight() -> None:
    """Fail fast if a required tool/path is missing."""
    problems = []
    if not GO_BIN.exists():
        problems.append(f"Go oracle binary missing: {GO_BIN}")
    if not PS1_VALIDATOR.exists():
        problems.append(f"PS1 validator missing: {PS1_VALIDATOR}")
    if not MSSQL_PKG_DIR.exists():
        problems.append(f"mssql package dir missing: {MSSQL_PKG_DIR}")
    if not Path(GO_PATH_DIR).exists():
        problems.append(f"Go bin dir missing: {GO_PATH_DIR}")
    if problems:
        for p in problems:
            print(f"PREFLIGHT ERROR: {p}", file=sys.stderr)
        sys.exit(2)


def main() -> int:
    preflight()
    # Resolve the DC hostname to an IP once so the Go oracle's custom resolver works
    # (see resolve_dc_ip). Reassign the module global so every downstream call uses it.
    global DC
    DC = resolve_dc_ip(DC)
    base_tmp = Path(tempfile.mkdtemp(prefix="oh-mssql-accept-"))
    print(f"Work dir (full-path temp, NOT the scratchpad): {base_tmp}")

    setup_ok = True
    teardown_ok = False
    reports: list[UserReport] = []

    try:
        # Step 1: setup once as domainadmin (unless skipped).
        if os.environ.get("OH_SKIP_SETUP") == "1":
            print("\nOH_SKIP_SETUP=1 -> skipping Go integration setup")
        else:
            setup_ok = go_setup()
            if not setup_ok:
                print("\nFATAL: Go integration setup did not exit 0. "
                      "Continuing to teardown without comparisons.")
                return _finish(reports, setup_ok, base_tmp)

        # Step 2: per-user comparisons.
        for user in USERS:
            try:
                reports.append(compare_user(user, base_tmp))
            except subprocess.TimeoutExpired as exc:
                print(f"\nTIMEOUT during {user}: {exc}")
                reports.append(UserReport(user=user, error=f"timeout: {exc}"))
            except Exception as exc:  # noqa: BLE001 -- keep going to teardown
                print(f"\nUNEXPECTED ERROR during {user}: {exc}")
                reports.append(UserReport(user=user, error=f"exception: {exc}"))

        return _finish(reports, setup_ok, base_tmp)
    finally:
        # Step 3: teardown ALWAYS (idempotent), even on failure/exception.
        if os.environ.get("OH_SKIP_TEARDOWN") == "1":
            print("\nOH_SKIP_TEARDOWN=1 -> skipping teardown (NOT recommended)")
        else:
            try:
                teardown_ok = go_teardown()
            except Exception as exc:  # noqa: BLE001
                print(f"\nTEARDOWN ERROR (non-fatal): {exc}")
        # Reprint the teardown status so it's visible after the report.
        print(f"\nTEARDOWN ran: {teardown_ok}")
        # We can't re-run the report here cleanly, so emit teardown line above.
        if os.environ.get("OH_KEEP_WORKDIRS") == "1":
            print(f"OH_KEEP_WORKDIRS=1 -> leaving work dir: {base_tmp}")
        else:
            shutil.rmtree(base_tmp, ignore_errors=True)
            print(f"Removed work dir: {base_tmp}")


def _finish(reports: list[UserReport], setup_ok: bool, base_tmp: Path) -> int:
    """Print the final report and compute the overall acceptance exit code.

    Note: teardown runs in the caller's finally AFTER this returns, so the report
    shows teardown_ran=False here; the finally block prints the real teardown status.
    """
    print_final_report(reports, setup_ok)
    # Acceptance: domainadmin must match Go AND its Go-ValidateZip must pass.
    admin = next((r for r in reports if r.user == "domainadmin"), None)
    accepted = bool(
        admin and admin.match and admin.go_validate_ours and admin.go_validate_ours.ok
    )
    # roanalyst / lowpriv must equal Go.
    for u in ("roanalyst", "lowpriv"):
        r = next((x for x in reports if x.user == u), None)
        if not (r and r.match):
            accepted = False
    print(f"\nOVERALL ACCEPTANCE: {'PASS' if accepted else 'FAIL'}")
    return 0 if accepted else 1


if __name__ == "__main__":
    sys.exit(main())
