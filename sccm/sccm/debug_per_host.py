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
from openhound_sccm.main import _detect_windows_domain
from openhound_sccm.per_host_phases import PER_HOST_PHASES, all_table_names
from openhound_sccm.phased_pipeline import DONE, WorkQueue, build_streams, run_pipeline

# Log to the console the way the main collector does: the framework's
# "time=..., msg=..." shape at the VERBOSE tier (-vv parity), with the
# [target][phase] prefix filter. The framework handler installed when the
# package imports only writes to a file, so the harness adds its own console
# StreamHandler. (Use logging.INFO for less, or logging.DEBUG to include the
# dlt / ldap3 internals, by changing the level below.)
_console = logging.StreamHandler()
_console.setLevel(VERBOSE)
_console.setFormatter(
    logging.Formatter(
        "%(levelname)-7s time=%(asctime)s, msg=%(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
)
_root = logging.getLogger()
_root.addHandler(_console)
if _root.level == 0 or _root.level > VERBOSE:
    _root.setLevel(VERBOSE)
install_filter()  # attaches the [target][phase] prefix to the console handler

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
    run_pipeline(wq, ctx, PER_HOST_PHASES, streams, max_workers=MAX_WORKERS)

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
