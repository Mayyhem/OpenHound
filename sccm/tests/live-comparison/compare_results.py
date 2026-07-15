#!/usr/bin/env python3
"""Compare two Invoke-ConfigManBearPigUnitTests.ps1 runs side-by-side.

The unit-test kit runs the *same* ordered $ExpectedEdges list every time and logs one
result line per test case ("<Kind>: <Description> - PASS/FAIL/SKIPPED"). We run the kit
twice -- once against the live ConfigManBearPig.ps1 collection, once against the OpenHound
collector's output packaged as a bloodhound-sccm ZIP -- and parse each run's -LogFile,
aligning the two result sequences by position (descriptions are not unique, but the list
order is identical across runs, so index N in run A is the same test case as index N in run B).

We parse the -LogFile (not the console capture): every logical line there is prefixed with
"YYYY-MM-DD HH:MM:SS [Level] " and is NOT wrapped, whereas the console capture wraps long
lines at ~120 columns and would split a result across physical lines. Both CMBP's own
collector logs and the kit's test logs share the file; the result-line pattern and the
region markers isolate the test output from collector chatter.

Emits a Markdown report and prints a terminal summary highlighting divergences.
"""
from __future__ import annotations

import argparse
import re
from dataclasses import dataclass, field
from pathlib import Path

# Every logical LogFile line is "YYYY-MM-DD HH:MM:SS [Level] <message>". We strip this prefix
# and match against <message>. Lines produced by an embedded newline inside a message (e.g. the
# "\nEdge types found:" header) arrive without a prefix; those are matched as-is.
PREFIX_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \[(?P<level>\w+)\] ?(?P<msg>.*)$")

# A test-result message, e.g. "LocalAdminRequired: The CAS primary ... - PASS"
# or "SCCM_AssignSpecificPermissions: no Source/Target/Properties specified - SKIPPED (coverage placeholder)".
# Kind is a single token (edge kinds contain no spaces); the rest up to " - <OUTCOME>" is the description.
RESULT_RE = re.compile(r"^(?P<kind>\S+): (?P<desc>.*?) - (?P<outcome>PASS|FAIL|SKIPPED)(?P<detail>.*)$")

# Bounding markers for the test-results region (avoids matching the collector's own verbose lines).
START_MARKER = "Running edge tests..."
END_MARKER = "Edge Test Summary:"

TOTAL_NODES_RE = re.compile(r"^Total nodes found:\s*(\d+)")
TOTAL_EDGES_RE = re.compile(r"^Total edges found:\s*(\d+)")
SUMMARY_PASSED_RE = re.compile(r"^\s*Passed:\s*(\d+)")
SUMMARY_FAILED_RE = re.compile(r"^\s*Failed:\s*(\d+)")
SUMMARY_SKIPPED_RE = re.compile(r"^\s*Skipped:\s*(\d+)")
MEMBEROF_RE = re.compile(r"^ClientDevice memberOf normalization check - (PASS|FAIL)")
# Histogram lines under "Edge types found:" look like "  <kind>: <count>".
HIST_RE = re.compile(r"^\s{2}(?P<kind>\S+):\s*(?P<count>\d+)\s*$")


@dataclass
class Result:
    kind: str
    desc: str
    outcome: str          # PASS | FAIL | SKIPPED
    detail: str           # trailing note, e.g. " (wrong count)" or " (not found)"


@dataclass
class RunData:
    label: str
    path: Path
    results: list[Result] = field(default_factory=list)
    total_nodes: int | None = None
    total_edges: int | None = None
    summary: dict[str, int] = field(default_factory=dict)   # passed/failed/skipped
    memberof: list[str] = field(default_factory=list)        # PASS/FAIL sequence
    histogram: dict[str, int] = field(default_factory=dict)  # edge kind -> count


def parse_run(label: str, path: Path) -> RunData:
    run = RunData(label=label, path=path)
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    # Strip the "YYYY-MM-DD HH:MM:SS [Level] " prefix from each line up front so the
    # message-level regexes below match cleanly. Prefix-less lines (embedded-newline
    # headers) pass through unchanged.
    msgs = []
    for line in lines:
        pm = PREFIX_RE.match(line)
        msgs.append(pm.group("msg") if pm else line)

    in_results = False
    in_histogram = False
    for msg in msgs:
        # Totals (printed once, before tests).
        m = TOTAL_NODES_RE.match(msg)
        if m:
            run.total_nodes = int(m.group(1))
        m = TOTAL_EDGES_RE.match(msg)
        if m:
            run.total_edges = int(m.group(1))

        # Edge-type histogram block.
        if msg.strip() == "Edge types found:":
            in_histogram = True
            continue
        if in_histogram:
            m = HIST_RE.match(msg)
            if m:
                run.histogram[m.group("kind")] = int(m.group("count"))
                continue
            # A non-matching line ends the histogram block.
            if msg.strip():
                in_histogram = False

        # memberOf normalization node check (may appear multiple times).
        m = MEMBEROF_RE.match(msg)
        if m:
            run.memberof.append(m.group(1))

        # Bound the result region so collector chatter can't masquerade as a result.
        if START_MARKER in msg:
            in_results = True
            continue
        if END_MARKER in msg:
            in_results = False
            continue

        if in_results:
            m = RESULT_RE.match(msg)
            if m:
                run.results.append(
                    Result(
                        kind=m.group("kind"),
                        desc=m.group("desc").strip(),
                        outcome=m.group("outcome"),
                        detail=m.group("detail").strip(),
                    )
                )

    # Summary block (after END_MARKER). The three counts only appear in the Edge Test Summary.
    for msg in msgs:
        m = SUMMARY_PASSED_RE.match(msg)
        if m and "passed" not in run.summary:
            run.summary["passed"] = int(m.group(1))
        m = SUMMARY_FAILED_RE.match(msg)
        if m and "failed" not in run.summary:
            run.summary["failed"] = int(m.group(1))
        m = SUMMARY_SKIPPED_RE.match(msg)
        if m and "skipped" not in run.summary:
            run.summary["skipped"] = int(m.group(1))

    return run


def short(desc: str, n: int = 70) -> str:
    return desc if len(desc) <= n else desc[: n - 3] + "..."


def build_report(cmbp: RunData, oh: RunData) -> tuple[str, dict]:
    """Return (markdown, stats). stats drives the terminal summary."""
    lines: list[str] = []
    a, b = cmbp.results, oh.results
    aligned = max(len(a), len(b))

    # Alignment sanity: both runs should have produced the same number of result lines.
    length_mismatch = len(a) != len(b)

    regressions: list[tuple[int, Result, Result]] = []   # CMBP PASS -> OH not-PASS
    improvements: list[tuple[int, Result, Result]] = []  # CMBP not-PASS -> OH PASS
    both_fail: list[tuple[int, Result, Result]] = []
    agree_pass = 0
    rows: list[str] = []

    for i in range(aligned):
        ra = a[i] if i < len(a) else None
        rb = b[i] if i < len(b) else None
        kind = (ra or rb).kind
        desc = (ra or rb).desc
        oa = ra.outcome if ra else "MISSING"
        ob = rb.outcome if rb else "MISSING"
        da = ra.detail if ra else ""
        db = rb.detail if rb else ""

        if oa == "PASS" and ob == "PASS":
            agree_pass += 1
            flag = ""
        elif oa == "PASS" and ob != "PASS":
            regressions.append((i, ra, rb))
            flag = "❌ REGRESSION"
        elif oa != "PASS" and ob == "PASS":
            improvements.append((i, ra, rb))
            flag = "⚠️ OH-only pass"
        elif oa == "FAIL" and ob == "FAIL":
            both_fail.append((i, ra, rb))
            flag = "both FAIL"
        else:
            flag = "" if oa == ob else "differs"

        rows.append(
            f"| {i} | `{kind}` | {short(desc)} | {oa}{(' '+da) if da else ''} "
            f"| {ob}{(' '+db) if db else ''} | {flag} |"
        )

    # Per-kind rollup.
    kinds = sorted({r.kind for r in a} | {r.kind for r in b})
    def tally(results: list[Result], kind: str) -> tuple[int, int, int]:
        subset = [r for r in results if r.kind == kind]
        return (
            sum(1 for r in subset if r.outcome == "PASS"),
            sum(1 for r in subset if r.outcome == "FAIL"),
            sum(1 for r in subset if r.outcome == "SKIPPED"),
        )

    # ---- Markdown ----
    lines.append("# Unit-test comparison: live ConfigManBearPig.ps1 vs OpenHound SCCM collector")
    lines.append("")
    lines.append("Both runs used the **same** `Invoke-ConfigManBearPigUnitTests.ps1` kit and the identical "
                 "`$ExpectedEdges` list, collected with **All methods + `-DisablePossibleEdges`**. "
                 "Test cases are aligned by position (the kit runs the list in a fixed order).")
    lines.append("")
    lines.append(f"- **CMBP console:** `{cmbp.path}`")
    lines.append(f"- **OpenHound console:** `{oh.path}`")
    lines.append("")

    lines.append("## Top-line")
    lines.append("")
    lines.append("| Metric | CMBP (live) | OpenHound |")
    lines.append("|---|---|---|")
    lines.append(f"| Total nodes | {cmbp.total_nodes} | {oh.total_nodes} |")
    lines.append(f"| Total edges | {cmbp.total_edges} | {oh.total_edges} |")
    lines.append(f"| Tests PASSED | {cmbp.summary.get('passed')} | {oh.summary.get('passed')} |")
    lines.append(f"| Tests FAILED | {cmbp.summary.get('failed')} | {oh.summary.get('failed')} |")
    lines.append(f"| Tests SKIPPED | {cmbp.summary.get('skipped')} | {oh.summary.get('skipped')} |")
    lines.append(f"| Result lines parsed | {len(a)} | {len(b)} |")
    lines.append("")
    if length_mismatch:
        lines.append("> ⚠️ **The two runs produced a different number of result lines.** "
                     "Position alignment may be off past the first divergence; inspect the raw consoles.")
        lines.append("")

    lines.append("## Divergences")
    lines.append("")
    lines.append(f"- **Regressions (CMBP PASS → OpenHound not PASS): {len(regressions)}**")
    lines.append(f"- OpenHound-only passes (CMBP not PASS → OpenHound PASS): {len(improvements)}")
    lines.append(f"- Both FAIL: {len(both_fail)}")
    lines.append(f"- Agree PASS: {agree_pass}")
    lines.append("")

    def dump(title: str, items: list[tuple[int, Result, Result]]) -> None:
        if not items:
            return
        lines.append(f"### {title}")
        lines.append("")
        lines.append("| # | Kind | Description | CMBP | OpenHound |")
        lines.append("|---|---|---|---|---|")
        for i, ra, rb in items:
            oa = f"{ra.outcome} {ra.detail}".strip() if ra else "MISSING"
            ob = f"{rb.outcome} {rb.detail}".strip() if rb else "MISSING"
            lines.append(f"| {i} | `{(ra or rb).kind}` | {short((ra or rb).desc, 90)} | {oa} | {ob} |")
        lines.append("")

    dump("Regressions — present/correct in CMBP, missing/wrong in OpenHound", regressions)
    dump("OpenHound-only passes — investigate whether these are real or false positives", improvements)
    dump("Failing in both", both_fail)

    lines.append("## Per-edge-kind rollup (PASS / FAIL / SKIP)")
    lines.append("")
    lines.append("| Kind | CMBP P/F/S | OpenHound P/F/S |")
    lines.append("|---|---|---|")
    for k in kinds:
        pa, fa, sa = tally(a, k)
        pb, fb, sb = tally(b, k)
        lines.append(f"| `{k}` | {pa}/{fa}/{sa} | {pb}/{fb}/{sb} |")
    lines.append("")

    lines.append("## Edge-type histogram (raw edges emitted, by kind)")
    lines.append("")
    lines.append("| Kind | CMBP | OpenHound |")
    lines.append("|---|---|---|")
    for k in sorted(set(cmbp.histogram) | set(oh.histogram)):
        lines.append(f"| `{k}` | {cmbp.histogram.get(k, 0)} | {oh.histogram.get(k, 0)} |")
    lines.append("")

    lines.append("## Full per-test comparison")
    lines.append("")
    lines.append("| # | Kind | Description | CMBP | OpenHound | Flag |")
    lines.append("|---|---|---|---|---|---|")
    lines.extend(rows)
    lines.append("")

    lines.append("## Node-level: ClientDevice memberOf normalization check")
    lines.append("")
    lines.append(f"- CMBP: {cmbp.memberof or 'not reported'}")
    lines.append(f"- OpenHound: {oh.memberof or 'not reported'}")
    lines.append("")

    stats = {
        "regressions": regressions,
        "improvements": improvements,
        "both_fail": both_fail,
        "agree_pass": agree_pass,
        "length_mismatch": length_mismatch,
    }
    return "\n".join(lines), stats


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cmbp", required=True, type=Path, help="Live CMBP run console capture")
    ap.add_argument("--openhound", required=True, type=Path, help="OpenHound run console capture")
    ap.add_argument("--out", required=True, type=Path, help="Markdown report output path")
    args = ap.parse_args()

    cmbp = parse_run("CMBP (live)", args.cmbp)
    oh = parse_run("OpenHound", args.openhound)
    md, stats = build_report(cmbp, oh)
    args.out.write_text(md, encoding="utf-8")

    # ---- Terminal summary ----
    print("=" * 72)
    print("UNIT-TEST COMPARISON: live ConfigManBearPig.ps1  vs  OpenHound collector")
    print("=" * 72)
    print(f"CMBP     : nodes={cmbp.total_nodes} edges={cmbp.total_edges}  "
          f"PASS={cmbp.summary.get('passed')} FAIL={cmbp.summary.get('failed')} "
          f"SKIP={cmbp.summary.get('skipped')}  ({len(cmbp.results)} result lines)")
    print(f"OpenHound: nodes={oh.total_nodes} edges={oh.total_edges}  "
          f"PASS={oh.summary.get('passed')} FAIL={oh.summary.get('failed')} "
          f"SKIP={oh.summary.get('skipped')}  ({len(oh.results)} result lines)")
    print("-" * 72)
    print(f"Agree PASS: {stats['agree_pass']}   "
          f"Regressions: {len(stats['regressions'])}   "
          f"OH-only pass: {len(stats['improvements'])}   "
          f"Both FAIL: {len(stats['both_fail'])}")
    if stats["length_mismatch"]:
        print("WARNING: runs produced different numbers of result lines - alignment may drift.")
    if stats["regressions"]:
        print("\nREGRESSIONS (CMBP PASS -> OpenHound not PASS):")
        for i, ra, rb in stats["regressions"]:
            print(f"  [{i}] {ra.kind}: {short(ra.desc, 80)}")
            print(f"        CMBP={ra.outcome}{(' '+ra.detail) if ra.detail else ''}  "
                  f"OpenHound={rb.outcome}{(' '+rb.detail) if rb.detail else ''}")
    if stats["both_fail"]:
        print("\nFAILING IN BOTH:")
        for i, ra, rb in stats["both_fail"]:
            print(f"  [{i}] {ra.kind}: {short(ra.desc, 80)}")
    print("-" * 72)
    print(f"Full report written to: {args.out}")


if __name__ == "__main__":
    main()
