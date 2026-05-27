"""Shared source-run context for SCCM collectors.

``SourceContext`` wraps the LDAP/AD client and all CMBP-equivalent CLI knobs
(``--collection-methods``, ``--computers``, ``--sms-provider``, etc.) and
provides the lazy-loaded caches that every ``@app.resource`` in
``collectors/*`` shares:
"""
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from ldap3 import BASE

from .clients.ad import ADClient
from .models.target_entry import TargetEntry

logger = logging.getLogger(__name__)


@dataclass
class SourceContext:
    ad: ADClient
    domain: str
    username: Optional[str] = None
    password: Optional[str] = None
    # Collection (-m / --collection-methods)
    collection_methods: str = "All"

    # Public, injectable — shared across queue-loop passes via the module-level
    # _shared_* pattern in source.py (same as target_queue).
    allowed_targets: frozenset = field(default_factory=frozenset)
    target_queue: Any = field(default=None)
    ad_resolution_cache: dict = field(default_factory=dict)
    discovered_domains: set = field(default_factory=set)

    # Site codes (UPPERCASE) emitted into the ``ldap_sites`` DLT table by
    # any of the three resources that write to it: ``ldap_sites`` (Phase 1,
    # LDAP-only mSSMSSite + mSSMSManagementPoint), ``ldap_sites_admin_extra``
    # (Phase 7, AdminService-only SMS_Site / SMS_SCI_SiteDefinition rows
    # missing from LDAP) and ``ldap_sites_smb_extra`` (Phase 10, SMB-share
    # discovered site codes on hosts not surfaced by either of the prior
    # two). DLT writes append-mode by default; without this cross-resource
    # dedup set, a single SCCM site visible from all three channels would
    # produce three SCCM_Site nodes with the same node_id.
    _emitted_site_codes: Optional[set] = None

    # CmRcService SPN match cache. Populated by ``cmrc_spn_matches()`` when
    # the LDAP phase first asks for it; the network call is bracketed by
    # ``phase_context("LDAP")`` so the resulting log line is tagged as an
    # LDAP event regardless of which resource forces the lazy build. PS1
    # also runs this query exactly once during its LDAP once-phase
    # (``ConfigManBearPig.ps1:3221``).
    _cmrc_spn_matches: Optional[list[dict[str, Any]]] = None

    # Mutable per-host probe-target accumulator. PS1's ``Add-DeviceToTargets``
    # appends to a live list and each subsequent per-host phase iterates the
    # *updated* list — so an MP discovered mid-run via MPLIST XML parsing
    # still gets RemoteRegistry / MSSQL / WMI / HTTP / SMB probes. The OH
    # per-host resources call ``target_hosts_snapshot()`` to read this set
    # at iteration time so late additions are picked up.
    #
    # Two parallel indexes:
    #   _target_hosts_by_hostname — always populated; key = lowercased canonical hostname
    #   _target_hosts_by_sid      — only when SID available; key = objectSid string
    # Both dicts hold references to the same entry dicts, so a mutation via
    # either index is immediately visible via the other.
    _target_hosts_by_hostname: dict = field(default_factory=dict)  # str -> TargetEntry
    _target_hosts_by_sid: dict = field(default_factory=dict)       # str -> TargetEntry
    _target_hosts_lock: Any = field(default=None)

    @property
    def system_management_dn(self) -> str:
        return f"CN=System Management,CN=System,{self.ad.base_dn}"

    # ---- Collection method gating (-m / --collection-methods) --------
    def method_enabled(self, method: str) -> bool:
        """Return True when ``method`` (e.g. "AdminService", "WMI", "SMB") is
        enabled by the current ``collection_methods`` setting.

        The value is a comma-separated list of method names (case-insensitive),
        matching CMBP's ``-m`` flag. ``"All"`` (the default) enables every
        method. Unknown method names are ignored so callers can pass in
        arbitrary labels without crashing the pipeline.
        """
        if not self.collection_methods:
            return True
        wanted = {m.strip().lower() for m in self.collection_methods.split(",") if m.strip()}
        if "all" in wanted:
            return True
        return method.lower() in wanted

    # ---- Target-host accumulator (PS1 ``Add-DeviceToTargets`` mirror) -----

    def _ensure_target_lock(self) -> Any:
        if self._target_hosts_lock is None:
            import threading
            self._target_hosts_lock = threading.Lock()
        return self._target_hosts_lock

    def _build_domains_to_try(self, hint_domain: Optional[str] = None) -> list:
        """Return an ordered, deduplicated list of domains to search.

        Order: [hint_domain, self.domain, ...discovered_domains]
        hint_domain is the domain extracted from a DOMAIN\\name prefix or FQDN suffix.
        self.domain (the operator-configured domain) is always included as the reliable
        fallback. Previously discovered domains follow as extended coverage — fixing a
        PS1 bug where $script:DiscoveredDomains was tracked but never fed back into
        future lookups.
        """
        seen: set = set()
        domains: list = []

        def _add(d: str) -> None:
            d = d.upper()
            if d and d not in seen:
                seen.add(d)
                domains.append(d)

        if hint_domain:
            _add(hint_domain)
        if self.domain:
            _add(self.domain)
        for d in self.discovered_domains:
            _add(d)
        return domains

    def resolve_principal(self, identifier: str) -> Optional[dict]:
        """Resolve an identifier to an AD object dict, with multi-domain support.

        Mirrors PS1's Resolve-PrincipalInDomain (ConfigManBearPig.ps1:459-905):
        - Strips DOMAIN\\username prefix; uses prefix as a domain hint
        - Extracts domain suffix from FQDNs and records it in discovered_domains
        - Tries domains in order: [hint, configured, previously-discovered]
        - Per-domain cache keys ("domain|name") + all-domains-tried sentinel ("all|name")
        - Both hits and misses cached; second call for the same name never fires LDAP
        - DNs (contain "=") are resolved directly via BASE scope, bypassing domain iteration
        """
        name = identifier.strip()

        # Distinguished names are fully qualified — no domain iteration needed
        if "=" in name:
            cache_key = f"dn|{name.lower()}"
            if cache_key in self.ad_resolution_cache:
                return self.ad_resolution_cache[cache_key]
            result = self._ldap_resolve_dn(name)
            self.ad_resolution_cache[cache_key] = result
            return result

        # Strip DOMAIN\username prefix; use prefix as domain hint
        hint_domain: Optional[str] = None
        if "\\" in name:
            hint_domain, name = name.split("\\", 1)

        # Extract domain suffix from FQDN and register as a discovered domain so
        # future plain-name lookups also try it (fixes PS1 DiscoveredDomains bug)
        if not hint_domain and "." in name:
            parts = name.split(".")
            if len(parts) > 2:
                hint_domain = ".".join(parts[1:]).upper()
                self.discovered_domains.add(hint_domain)

        name = name.lower()

        # Short-circuit: all domains already tried for this name
        if f"all|{name}" in self.ad_resolution_cache:
            return None

        for domain in self._build_domains_to_try(hint_domain):
            domain_key = f"{domain.lower()}|{name}"
            if domain_key in self.ad_resolution_cache:
                cached = self.ad_resolution_cache[domain_key]
                if cached is None:
                    continue  # already failed this domain, try next
                return cached
            result = self._ldap_resolve(name, domain)
            self.ad_resolution_cache[domain_key] = result
            if result is not None:
                return result

        # All domains exhausted — store sentinel so repeat calls short-circuit
        self.ad_resolution_cache[f"all|{name}"] = None
        return None

    def _ldap_resolve_dn(self, dn: str) -> Optional[dict]:
        """Fetch a single AD object by its distinguished name using BASE scope."""
        attrs = [
            "sAMAccountName", "objectSid", "dNSHostName", "cn",
            "distinguishedName", "objectClass", "userPrincipalName", "name",
        ]
        return next(
            self.ad.paged_search("(objectClass=*)", attrs, base=dn, scope=BASE),
            None,
        )

    def _ldap_resolve(self, name: str, domain: str) -> Optional[dict]:
        """Fire a single paged_search for name within the given domain's base DN."""
        from ldap3.utils.conv import escape_filter_chars
        safe = escape_filter_chars(name.rstrip("$"))
        ldap_filter = (
            f"(|(cn={safe})(sAMAccountName={safe})(sAMAccountName={safe}$)"
            f"(dNSHostName={safe})(dNSHostName={safe}.*)(userPrincipalName={safe}))"
        )
        attrs = [
            "sAMAccountName", "objectSid", "dNSHostName", "cn",
            "distinguishedName", "objectClass", "userPrincipalName", "name",
        ]
        base = "DC=" + domain.replace(".", ",DC=") if domain else None
        results = list(self.ad.paged_search(ldap_filter, attrs, base=base, size_limit=1))
        return results[0] if results else None

    def _is_allowed_target(self, identifier: str, ad_object: Optional[dict]) -> bool:
        """Mirror PS1's Test-AllowedTarget: empty allowed_targets means allow all.

        Builds candidate name forms from the identifier and AD object, then
        checks intersection with the pre-lowercased allowed_targets set.
        """
        if not self.allowed_targets:
            return True
        candidates: set = set()
        candidates.add(identifier.lower())
        if "." in identifier:
            candidates.add(identifier.split(".")[0].lower())
        if ad_object:
            for field_name in ("dNSHostName", "name", "sAMAccountName"):
                v = ad_object.get(field_name)
                if isinstance(v, str):
                    candidates.add(v.lower().rstrip("$"))
                    if "." in v:
                        candidates.add(v.split(".")[0].lower())
        return bool(candidates & self.allowed_targets)

    def register_target(
        self,
        identifier: Optional[str],
        source: Optional[str] = None,
        site_code: Optional[str] = None,
        ad_object: Optional[dict] = None,
    ) -> Optional[TargetEntry]:
        """Register a device as a probe target, mirroring PS1's Add-DeviceToTargets.

        Returns the TargetEntry (new or updated) so callers can inspect is_new,
        hostname, ad_object, etc. Returns None when identifier is empty or the
        target is rejected by the allowed-targets filter.
        """
        if not identifier or not identifier.strip():
            return None

        # Step 1: Resolve to AD object (best-effort, non-fatal)
        if not ad_object:
            try:
                ad_object = self.resolve_principal(identifier)
            except Exception:
                logger.warning("AD resolution failed for %r", identifier)

        # Step 2: Allowed-targets filter
        if not self._is_allowed_target(identifier, ad_object):
            logger.warning("Skipping %r — not in allowed targets filter", identifier)
            return None

        # Step 3: Canonical name and dedup key
        sid = ad_object.get("object_sid") if ad_object else None
        if sid:
            canonical = ad_object.get("dNSHostName") or ad_object.get("name") or identifier
        else:
            canonical = identifier
            logger.warning("Could not resolve %r to a domain object; adding target by name", identifier)
        canonical_lower = canonical.lower()

        with self._ensure_target_lock():
            # Step 4: Find existing entry — SID index first, hostname fallback
            existing: Optional[TargetEntry] = (
                self._target_hosts_by_sid.get(sid) if sid else None
            ) or self._target_hosts_by_hostname.get(canonical_lower)

            if existing is not None:
                # FQDN upgrade: re-key _target_hosts_by_hostname
                if "." in canonical_lower and "." not in existing.hostname.lower():
                    logger.verbose("Upgrading hostname %r -> %r", existing.hostname, canonical)
                    del self._target_hosts_by_hostname[existing.hostname.lower()]
                    existing.hostname = canonical
                    self._target_hosts_by_hostname[canonical_lower] = existing
                # Backfill ad_object + SID index if we now have one
                if ad_object and existing.ad_object is None:
                    existing.ad_object = ad_object
                    if sid:
                        self._target_hosts_by_sid[sid] = existing
                # Merge source
                if source and source not in existing.sources:
                    existing.sources.append(source)
                # Merge site_code (first writer wins; warn on conflict)
                if site_code:
                    if not existing.site_code:
                        existing.site_code = site_code
                    elif existing.site_code != site_code:
                        logger.warning(
                            "Target %r already has site_code %r; ignoring %r",
                            canonical, existing.site_code, site_code,
                        )
                existing.is_new = False
                return existing

            # Step 5: New entry
            entry = TargetEntry(
                hostname=canonical,
                ad_object=ad_object,
                sources=[source] if source else [],
                site_code=site_code,
                is_new=True,
            )
            self._target_hosts_by_hostname[canonical_lower] = entry
            if sid:
                self._target_hosts_by_sid[sid] = entry
            if self.target_queue is not None:
                self.target_queue.enqueue(canonical)
            logger.verbose("Added collection target: %r from %r", canonical, source)
            return entry

    def target_hosts_snapshot(self) -> list:
        """Return the current list of probe targets (TargetEntry objects) as a copy.

        Per-host resources iterate this so late-registered hosts are picked
        up by phases that haven't started yet. Thread-safe against concurrent
        ``register_target`` mutations.
        """
        with self._ensure_target_lock():
            return list(self._target_hosts_by_hostname.values())