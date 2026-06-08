"""The ordered SCCM per-host phases and the tables they write.

For this framework build the phases point at stub collectors; each is replaced
by a real collector in its own follow-up ticket. Phase names double as the
``--collection-methods`` gating tokens (matching ConfigManBearPig.ps1's
``$script:PhasesPerHost``), so the engine's gate is simply
``ctx.method_enabled(phase.name)``.
"""
from __future__ import annotations

from typing import Sequence

from .collectors import registry
from .phased_pipeline import Phase

PER_HOST_PHASES: tuple[Phase, ...] = (
    Phase(
        "RemoteRegistry",(
            "sccm_sites",
            "computers",
            "users",
            "mssql_servers"
        ), registry.collect_registry
    ),
)

def all_table_names(phases: Sequence[Phase]) -> list[str]:
    """Every table the phases may write, de-duplicated, in declaration order."""
    return list(dict.fromkeys(table for phase in phases for table in phase.streams))
