"""Throwaway debugger harness for the per-host queueing engine.

Run under the VS Code debugger ("Run and Debug" -> "Debug per-host queue", or
"Debug Python File"). No Active Directory and no DLT are needed: it seeds the
work queue by hand and uses the stub phases, so it exercises the queue,
recursion, ordering, backpressure, and quiescence in isolation.

This file is a scratch helper — delete it when you're done; it isn't imported by
anything and isn't part of the package.

Stepping tips
-------------
* Keep MAX_WORKERS = 1 while stepping so the debugger stays on one worker thread.
  Set it to 10 to watch real concurrency (harder to single-step).
* Set ALLOW_LIST to {"hosta", "hostb"} to watch the allow-list suppress the
  HTTP-stub's discovered hosts (recursion turned off for non-listed machines).
* Set MAXSIZE = 1 to watch backpressure (producers block on put until drained).
  With MAX_WORKERS >= number of tables this still completes; lower it to see a
  stall (that's the dlt-worker-count constraint, here simulated with raw streams).
"""
import logging
import os

from openhound_sccm.context import SourceContext
from openhound_sccm.log_context import VERBOSE, install_filter
from openhound_sccm.main import _apply_log_level, _build_phase_scope, _detect_windows_domain
from openhound_sccm.per_host_phases import PER_HOST_PHASES, all_table_names
from openhound_sccm.phased_pipeline import DONE, WorkQueue, build_streams, run_pipeline

# Log to the console exactly like the main collector: reuse its own setup, which
# lowers the framework's console handler to the VERBOSE tier (-vv parity), strips
# the "(openhound_version=...)" suffix its formatter appends, and installs the
# [target][phase] prefix filter. Reusing the framework handler (rather than adding
# a second one) is what avoids the duplicate / version-suffixed lines.
# (Pass debug=True for the DEBUG tier with dlt / ldap3 internals.)
_apply_log_level(verbose=2, debug=False)

# Fallback: when no console handler is present (e.g. output redirected with no
# TTY, so the framework attached only a file handler), add one so the harness
# still prints — in the same "time=..., msg=..." shape.
_root = logging.getLogger()
if not any(not isinstance(h, logging.FileHandler) for h in _root.handlers):
    _console = logging.StreamHandler()
    _console.setLevel(VERBOSE)
    _console.setFormatter(
        logging.Formatter(
            "%(levelname)-7s time=%(asctime)s, msg=%(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    _root.addHandler(_console)
    if _root.level == 0 or _root.level > VERBOSE:
        _root.setLevel(VERBOSE)
    install_filter()

MAX_WORKERS = 1                 # 1 = easy stepping; 10 = real concurrency
MAXSIZE = 1000                  # 1 = watch backpressure
ALLOW_LIST = frozenset()        # {"hosta", "hostb"} = suppress discovered hosts
SEED_HOSTS = ["ps1-pss.mayyhem.com"]

# The domain context gained during _apply_connection_context: derive it from the
# current Windows user (USERDNSDOMAIN), the same way the CLI does. Its other half
# — DNS-SRV domain-controller resolution — is skipped on purpose: this harness has
# no LDAP/DC dependency and that half calls sys.exit() when SRV lookup fails.
DOMAIN = _detect_windows_domain() or "mayyhem.com"


def main() -> None:
    wq = WorkQueue()
    for host in SEED_HOSTS:
        wq.submit(host)         # [BP] step into submit(): dedup + pending grows

    # ad=None is fine: collect_registry probes the raw target host over SMB and
    # never needs AD resolution.
    ctx = SourceContext(
        ad=None,
        domain=DOMAIN,
        # Same env vars the CLI's -u/-p populate. Unset → impacket falls back to a
        # null SMB session, which usually can't bind Remote Registry; set these if
        # the probe fails to authenticate.
        username=os.environ.get("SOURCES__SCCM__USERNAME"),
        password=os.environ.get("SOURCES__SCCM__PASSWORD"),
        work_queue=wq,
        collection_methods="All",
        allowed_targets=ALLOW_LIST,
    )

    streams = build_streams(all_table_names(PER_HOST_PHASES), maxsize=MAXSIZE)

    # [BP] step into run_pipeline: dispatcher pulls from wq.next(), submits workers;
    # each worker runs run_one_target(host) -> phases in order; the HTTP stub calls
    # ctx.register_target(...) -> wq.submit(...) (recursion). At quiescence
    # wq.next() returns None, the loop breaks, and broadcast_done closes the streams.
    # phase_scope tags each phase's log lines with [target][phase], exactly like
    # the main collector (_run_per_host_stage passes the same _build_phase_scope()).
    run_pipeline(
        wq, ctx, PER_HOST_PHASES, streams,
        max_workers=MAX_WORKERS,
        phase_scope=_build_phase_scope(),
    )

    # Drain and report. DONE was broadcast on every stream at quiescence.
    print("\n=== results ===")
    for table, stream in streams.items():
        rows = []
        while True:
            item = stream.get()
            if item is DONE:
                break
            rows.append(item)
        hosts = sorted({r.get("host") or r.get("name") for r in rows})
        print(f"{table:32} {len(rows):3d} rows  hosts={hosts}")


if __name__ == "__main__":
    main()
