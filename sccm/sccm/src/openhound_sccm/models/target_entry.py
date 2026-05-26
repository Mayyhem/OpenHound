from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TargetEntry:
    """A device registered as a probe target.

    Mirrors the per-host hashtable entry in PS1's $script:CollectionTargets.
    ``is_new`` reflects whether this specific ``register_target`` call created
    the entry (True) or merged into an existing one (False) — same semantics as
    PS1's IsNew field, which is explicitly reset to $false on the merge path.
    """
    hostname: str
    ad_object: Optional[dict]
    sources: list = field(default_factory=list)
    site_code: Optional[str] = None
    is_new: bool = False
