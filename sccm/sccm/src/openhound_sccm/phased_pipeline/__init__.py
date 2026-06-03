"""phased_pipeline — a portable engine for concurrent, recursive, ordered-phase
collection.

This sub-package is deliberately free of any project-specific imports (no SCCM,
Active Directory, or DLT). It understands only four ideas:

* **targets** — opaque identifiers (strings) of things to collect from;
* **phases** — ordered steps run against each target;
* **streams** — named output channels that phases write rows to;
* **recursion** — a phase may discover new targets, which are collected the same
  way until nothing remains.

It can therefore be lifted into its own installable package and reused by any
project that supplies its own phases and consumes the output streams.

The public surface is populated as the engine is built (see ``engine.py``).
"""

from .work_queue import WorkQueue

__all__ = ["WorkQueue"]
