import threading
from typing import Optional


class TargetQueue:
    """Per-target, per-phase work queue. Thread-safe. Framework-agnostic.

    Mirrors PS1's PhaseStatus dict on each CollectionTarget entry.
    Callers enqueue hostnames (all phases start as 'pending'); each
    per-host resource marks its phase 'done' after processing a host.
    collect_sccm() loops until has_pending() is False.
    """

    def __init__(self, phases: list[str]) -> None:
        self._phases = list(phases)
        # hostname (lowercased) → {phase_name: status}
        self._entries: dict[str, dict[str, str]] = {}
        self._lock = threading.Lock()

    def enqueue(self, hostname: str) -> bool:
        """Add hostname with all phases 'pending'. Returns True if newly added."""
        key = hostname.lower().strip()
        if not key:
            return False
        with self._lock:
            if key in self._entries:
                return False
            self._entries[key] = {p: "pending" for p in self._phases}
            return True

    def get_status(self, hostname: str, phase: str) -> Optional[str]:
        """Return status string for (hostname, phase), or None if unknown."""
        key = hostname.lower().strip()
        with self._lock:
            entry = self._entries.get(key)
            return entry.get(phase) if entry else None

    def mark_done(self, hostname: str, phase: str) -> None:
        self._set_status(hostname, phase, "done")

    def mark_failed(self, hostname: str, phase: str) -> None:
        self._set_status(hostname, phase, "failed")

    def _set_status(self, hostname: str, phase: str, status: str) -> None:
        key = hostname.lower().strip()
        with self._lock:
            if key in self._entries and phase in self._entries[key]:
                self._entries[key][phase] = status

    def pending_for(self, phase: str) -> list[str]:
        """Snapshot of hostnames whose status for phase is 'pending'."""
        with self._lock:
            return [h for h, s in self._entries.items() if s.get(phase) == "pending"]

    def has_pending(self) -> bool:
        """True if any target has any phase still pending."""
        with self._lock:
            return any(
                s == "pending"
                for ss in self._entries.values()
                for s in ss.values()
            )

    def pending_hosts(self) -> set[str]:
        """All hostnames with at least one pending phase."""
        with self._lock:
            return {
                h for h, ss in self._entries.items()
                if any(s == "pending" for s in ss.values())
            }

    def summary(self) -> dict[str, dict[str, int]]:
        """Per-phase counts {phase: {pending, done, failed}} for logging."""
        with self._lock:
            out: dict[str, dict[str, int]] = {
                p: {"pending": 0, "done": 0, "failed": 0} for p in self._phases
            }
            for ss in self._entries.values():
                for phase, status in ss.items():
                    if phase in out and status in out[phase]:
                        out[phase][status] += 1
            return out
