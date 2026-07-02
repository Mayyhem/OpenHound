"""Stage-7b edge derivation: AD / linked-server / credential / service-account /
coercion edges (port of the matching Go ``createEdges`` blocks + ``createADNodes``
gating).

``derive_ad_edges(lookup)`` is the sibling of :func:`openhound_mssql.edges.derive.
derive_edges`: it yields the same framework :class:`Edge` objects (kind + SID-based
start/end :class:`EdgePath` + :class:`MSSQLEdgeProperties`) for the edge families
the Stage-6 derivation deliberately left out:

* ``MSSQL_HostFor`` / ``MSSQL_ExecuteOnHost``  (Computer <-> Server)
* ``MSSQL_HasLogin``                            (AD principal / local group -> Login)
* ``MSSQL_CoerceAndRelayToMSSQL``               (Authenticated Users -> Login, EPA-Off + computer login)
* ``MSSQL_ServiceAccountFor`` / ``MSSQL_HasSession`` / ``MSSQL_GetTGS`` /
  ``MSSQL_GetAdminTGS``                          (service account <-> Server/Login/Computer)
* ``MSSQL_LinkedTo`` / ``MSSQL_LinkedAsAdmin``   (Server -> Server, per linked login)
* ``MSSQL_HasMappedCred`` / ``MSSQL_HasDBScopedCred`` / ``MSSQL_HasProxyCred``
                                                 (Login/Database -> AD identity SID)

It reads only the raw + derived DuckDB tables (via the same tiny lookup adapter
``edge_rules`` already passes ``derive_edges``, extended with a couple of extra
``table_rows`` reads), so the security logic is a faithful port of
``collector.go`` (the source of truth; preferred over the spec wording on any
divergence). Endpoints use the SID-based node IDs:

* Server OID  = the ``servers`` row's ``<computerSID>:<port>`` (transforms derives it).
* Login OID   = ``name@<serverOID>`` (``ids.principal_oid``).
* Computer    = the host computer SID.
* AD principal/credential/service-account = the raw object SID (S-1-5-21-*).
* Authenticated Users = ``<domain>-S-1-5-11`` (Go ``createADNodes``).
* Local group = ``<host>-<SID>`` (Go ``serverFQDN-SID``).

Traversability + the ``--disable-*`` toggles are NOT applied here: like
``derive_edges`` this always emits every producible edge carrying its correct
static ``traversable`` flag (the kind partition in ``kinds/edges.py``);
``edge_rules`` applies the toggles when it flattens the edges into ``graph_edges``.
"""
from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Optional

from openhound.core.models.entries_dataclass import Edge, EdgePath

from .. import ids
from ..kinds import edges as ek
from ..kinds import nodes as nk
from ..models import _common
from .properties import EdgeCtx, build_edge_properties

logger = logging.getLogger(__name__)

# Well-known SID prefixes (Go uses these literal HasPrefix checks).
_DOMAIN_SID_PREFIX = "S-1-5-21-"
_BUILTIN_SID_PREFIX = "S-1-5-32-"
# Permission states that confer a grant (DENY never grants CONNECT SQL).
_GRANT_STATES = {"GRANT", "GRANT_WITH_GRANT_OPTION"}
# Fixed roles that carry implicit CONNECT SQL (Go hasConnectSQL).
_IMPLICIT_CONNECT_ROLES = {"sysadmin", "securityadmin"}
# Built-in service-account names that map to the host computer (skip HasSession).
_BUILTIN_SA_NAMES = {
    "NT AUTHORITY\\SYSTEM", "LOCALSYSTEM", "NT AUTHORITY\\LOCAL SERVICE",
    "NT AUTHORITY\\NETWORK SERVICE",
}
# Pseudo-authorities that prefix a local/built-in account name (never AD).
_NON_AD_PREFIXES = ("NT SERVICE\\", "NT AUTHORITY\\", "BUILTIN\\")


def _bool(value) -> bool:
    return _common.as_bool(value)


# ---------------------------------------------------------------------------
# Edge factory (shared with derive.py's _edge): build the property bag + the
# static traversable flag from the kind partition.
# ---------------------------------------------------------------------------
def _edge(source_id: str, target_id: str, kind: str, ctx: EdgeCtx) -> Edge:
    ctx.source_id = source_id
    ctx.target_id = target_id
    traversable = kind in ek.TRAVERSABLE_EDGE_KINDS or kind in ek.POSSIBLE_EDGE_KINDS
    props = build_edge_properties(kind, ctx, traversable=traversable)
    return Edge(
        kind=kind,
        start=EdgePath(match_by="id", value=source_id),
        end=EdgePath(match_by="id", value=target_id),
        properties=props,
    )


# ---------------------------------------------------------------------------
# Loaded server principal (only the fields the Stage-7b gating reads).
# ---------------------------------------------------------------------------
@dataclass
class _Principal:
    principal_id: int
    name: str
    type_desc: str
    is_disabled: bool
    is_ad: bool
    sid: str
    object_identifier: str
    perms: set
    member_roles: set


def _is_ad_principal(name: str, type_desc: str, short_host: str = "") -> bool:
    """client.go IsActiveDirectoryPrincipal (same as transforms/ad_nodes).

    Excludes NT SERVICE / NT AUTHORITY / BUILTIN AND local-machine
    (``<MACHINENAME>\\...``) accounts — the Go ``!isLocalMachine`` check. A
    machine-local group like ``ps1-db\\ConfigMgr_DViewAccess`` carries an
    ``S-1-5-21-*`` SID outside the server's domain; without this exclusion it would
    wrongly get a SID-keyed HasLogin / GetTGS instead of a local-group HasLogin.
    """
    if type_desc not in ("WINDOWS_LOGIN", "WINDOWS_GROUP"):
        return False
    if "\\" not in name:
        return False
    upper = name.upper()
    if any(upper.startswith(prefix) for prefix in _NON_AD_PREFIXES):
        return False
    if short_host and upper.startswith(short_host.upper() + "\\"):
        return False
    return True


def _has_connect_sql(perms: set, member_roles: set) -> bool:
    """Go hasConnectSQL: direct CONNECT SQL grant OR member of sysadmin/securityadmin."""
    if "CONNECT SQL" in perms:
        return True
    return any(role in member_roles for role in _IMPLICIT_CONNECT_ROLES)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def derive_ad_edges(lookup) -> Iterator[Edge]:
    """Yield every Stage-7b AD/linked/credential/service-account/coercion edge."""
    server = _ServerData(lookup)
    if not server.server_oid:
        logger.warning("derive_ad_edges: no server context; emitting no edges")
        return
    logger.info("derive_ad_edges: deriving Stage-7b edges for server_oid=%s", server.server_oid)

    yield from _host_edges(server)
    yield from _has_login_and_coerce_edges(server)
    yield from _service_account_edges(server)
    yield from _linked_server_edges(server)
    yield from _credential_edges(server)


# ---------------------------------------------------------------------------
# Loaded server data (built once)
# ---------------------------------------------------------------------------
class _ServerData:
    """All Stage-7b context for the one collected server."""

    def __init__(self, lookup) -> None:
        self.lookup = lookup
        self.server_oid = _common.server_oid_for(lookup)
        self.server_name = _common.sql_server_name_for(lookup)

        server_row = next(iter(lookup.table_rows("servers")), {}) or {}
        self.computer_sid = (
            server_row.get("computer_sid") or server_row.get("computersid") or ""
        )
        self.fqdn = server_row.get("fqdn") or ""
        machine = (
            server_row.get("machine_name") or server_row.get("MachineName")
            or server_row.get("server_name") or server_row.get("ServerName") or ""
        )
        self.hostname = self.fqdn or str(machine).split("\\", 1)[0]
        self.short_host = self.hostname.split(".", 1)[0]
        self.port = _common.as_int(server_row.get("port"), default=1433) or 1433
        self.extended_protection = str(
            server_row.get("extended_protection")
            or server_row.get("extendedProtection") or ""
        )
        self.domain = _domain_from_fqdn(self.fqdn)

        # Server principals (+ their direct GRANT permissions + role memberships).
        self.principals = self._load_principals()
        self.domain_sid = self._domain_sid()
        # Login OID by name -> for HasProxyCred login resolution.
        self.login_oid_by_name = {p.name: p.object_identifier for p in self.principals}

        # Effective high-priv summary (isAnyDomainPrincipalSysadmin + the four
        # domainPrincipalsWith* arrays) for GetAdminTGS.
        self.high_priv_summary = lookup.effective_high_priv(self.server_oid) \
            if hasattr(lookup, "effective_high_priv") else self._summary_fallback()

        # ad_resolved: SID -> object, plus a name-index for credential_identity
        # resolution (credential identity strings resolve to a domain SID).
        self.resolved_by_sid: dict[str, dict] = {}
        self.resolved_by_name: dict[str, dict] = {}
        for r in lookup.table_rows("ad_resolved"):
            sid = r.get("sid")
            if not sid:
                continue
            self.resolved_by_sid[sid] = r
            for key in self._identity_keys(r):
                self.resolved_by_name.setdefault(key, r)

    # -- loaders ----------------------------------------------------------
    def _load_principals(self) -> list:
        principals: list[_Principal] = []
        by_id: dict[int, _Principal] = {}
        for r in self.lookup.table_rows("server_principal_map"):
            pid = _common.as_int(r.get("principal_id"), default=-1)
            if pid < 0:
                continue
            name = r.get("name") or ""
            type_desc = r.get("type_description") or r.get("type_desc") or ""
            sid = r.get("security_identifier") or ""
            p = _Principal(
                principal_id=pid,
                name=name,
                type_desc=type_desc,
                is_disabled=False,  # filled from raw server_principals below
                is_ad=_bool(r.get("is_active_directory_principal")) or _is_ad_principal(name, type_desc, self.short_host),
                sid=sid,
                object_identifier=r.get("object_identifier") or ids.principal_oid(name, self.server_oid),
                perms=set(),
                member_roles=set(),
            )
            principals.append(p)
            by_id[pid] = p

        # is_disabled lives on the raw server_principals table (not the map).
        for r in self.lookup.table_rows("server_principals"):
            pid = _common.as_int(r.get("principal_id"), default=-1)
            p = by_id.get(pid)
            if p is not None:
                p.is_disabled = _bool(r.get("is_disabled"))

        # Direct GRANT permissions (skip DENY).
        for perm in self.lookup.table_rows("server_permissions"):
            grantee = _common.as_int(perm.get("grantee_principal_id"), default=-1)
            state = (perm.get("state_desc") or "").upper()
            name = perm.get("permission_name") or ""
            p = by_id.get(grantee)
            if p is not None and name and state in _GRANT_STATES:
                p.perms.add(name)

        # Direct role memberships (by role name).
        for rm in self.lookup.table_rows("server_role_members"):
            member = by_id.get(_common.as_int(rm.get("member_principal_id"), default=-1))
            role_name = rm.get("role_name") or ""
            if member is not None and role_name:
                member.member_roles.add(role_name)

        return principals

    def _domain_sid(self) -> str:
        for p in self.principals:
            if p.is_ad and p.sid.startswith(_DOMAIN_SID_PREFIX):
                idx = p.sid.rfind("-")
                if idx > 0:
                    return p.sid[:idx]
        return ""

    def _summary_fallback(self) -> dict:
        # Read effective_high_priv_summary directly when the lookup adapter has no
        # effective_high_priv() helper (the preproc _ConnLookup case).
        row = next(
            (r for r in self.lookup.table_rows("effective_high_priv_summary")
             if r.get("server_oid") == self.server_oid),
            None,
        )
        if row is not None:
            return row
        return {
            "isAnyDomainPrincipalSysadmin": False,
            "domainPrincipalsWithSysadmin": [],
            "domainPrincipalsWithControlServer": [],
            "domainPrincipalsWithSecurityadmin": [],
            "domainPrincipalsWithImpersonateAnyLogin": [],
        }

    @staticmethod
    def _identity_keys(resolved: dict) -> list:
        """Candidate lookup keys (lowercased) a credential_identity could match.

        Go resolves the identity name -> a SID via LDAP; we already have the
        resolved object, so match the credential_identity string against the
        object's name (DOMAIN\\sam) and DOMAIN\\samAccountName forms.
        """
        keys: list[str] = []
        name = resolved.get("name")
        if name:
            keys.append(str(name).lower())
        sam = resolved.get("sam_account_name") or resolved.get("samAccountName")
        if sam:
            keys.append(str(sam).lower())
        return keys

    def resolve_identity_sid(self, identity: str) -> Optional[str]:
        """Resolve a credential identity string to its domain SID (Go ResolvedSID).

        Matches the identity (e.g. ``MAYYHEM\\svc``) against the collect-time
        ad_resolved objects by name / sAMAccountName; only domain (S-1-5-21-*)
        results are returned (Go only emits cred edges for domain credentials).
        """
        if not identity:
            return None
        key = identity.strip().lower()
        resolved = self.resolved_by_name.get(key)
        if resolved is None:
            # Try the bare sAMAccountName after a backslash (DOMAIN\sam -> sam).
            if "\\" in key:
                resolved = self.resolved_by_name.get(key.split("\\", 1)[1])
        if resolved is None:
            return None
        sid = resolved.get("sid")
        if sid and str(sid).startswith(_DOMAIN_SID_PREFIX):
            return str(sid)
        return None


# ===========================================================================
# HOST EDGES (Go createEdges, COMPUTER-SERVER RELATIONSHIP)
# ===========================================================================
def _host_edges(d: _ServerData) -> Iterator[Edge]:
    """MSSQL_HostFor (Computer->Server) + MSSQL_ExecuteOnHost (Server->Computer)."""
    if not d.computer_sid:
        # No resolved computer SID -> no Computer node to attach to (Go gate).
        logger.debug("derive_ad_edges: no computer SID; skipping Host/ExecuteOnHost")
        return
    yield _edge(
        d.computer_sid, d.server_oid, ek.HOST_FOR,
        EdgeCtx(source_name=d.hostname, source_type=nk.COMPUTER,
                target_name=d.server_name, target_type=nk.SERVER,
                sql_server_name=d.server_name, sql_server_id=d.server_oid),
    )
    yield _edge(
        d.server_oid, d.computer_sid, ek.EXECUTE_ON_HOST,
        EdgeCtx(source_name=d.server_name, source_type=nk.SERVER,
                target_name=d.hostname, target_type=nk.COMPUTER,
                sql_server_name=d.server_name, sql_server_id=d.server_oid),
    )


# ===========================================================================
# HASLOGIN + COERCEANDRELAY (Go createEdges, AD PRINCIPAL RELATIONSHIP)
# ===========================================================================
def _has_login_and_coerce_edges(d: _ServerData) -> Iterator[Edge]:
    """HasLogin (AD principal / local group -> Login) + CoerceAndRelay.

    Mirrors Go's iteration over enabled domain principals with CONNECT SQL:
    CoerceAndRelay is checked BEFORE the S-1-5-21 filter + dedup; HasLogin only
    for S-1-5-21-* SIDs (deduped). Local groups (BUILTIN or machine-local
    WINDOWS_GROUP) get a HasLogin from the ``<host>-<SID>`` group node.
    """
    seen_sids: set[str] = set()

    for p in d.principals:
        # Path A preconditions: AD principal, has SID, enabled, has CONNECT SQL.
        if not p.is_ad or not p.sid:
            continue
        if p.is_disabled:
            continue
        if not _has_connect_sql(p.perms, p.member_roles):
            continue

        # CoerceAndRelay: EPA Off + computer-account login (name ends $). Checked
        # before the S-1-5-21 filter + dedup (Go ordering). Start = Authenticated
        # Users (domain-prefixed S-1-5-11), end = the login; carries the coercion
        # victim computer SID for the composition.
        if d.extended_protection == "Off" and p.name.endswith("$"):
            authed_users = f"{d.domain}-S-1-5-11" if d.domain else "S-1-5-11"
            yield _edge(
                authed_users, p.object_identifier, ek.COERCE_AND_RELAY_TO_MSSQL,
                EdgeCtx(source_name="AUTHENTICATED USERS", source_type=nk.GROUP,
                        target_name=p.name, target_type=nk.LOGIN,
                        sql_server_name=d.server_name, sql_server_id=d.server_oid,
                        security_identifier=p.sid),
            )

        # HasLogin: only domain SIDs, deduped by SID.
        if not p.sid.startswith(_DOMAIN_SID_PREFIX):
            continue
        if p.sid in seen_sids:
            continue
        seen_sids.add(p.sid)
        yield _edge(
            p.sid, p.object_identifier, ek.HAS_LOGIN,
            EdgeCtx(source_name=p.name, source_type=nk.BASE,
                    target_name=p.name, target_type=nk.LOGIN,
                    sql_server_name=d.server_name, sql_server_id=d.server_oid),
        )

    # Local groups (Go fallback path: BUILTIN S-1-5-32-* or machine-local
    # WINDOWS_GROUP S-1-5-21-* not under the domain SID), enabled + CONNECT SQL.
    for p in d.principals:
        if not p.sid:
            continue
        is_local_group = p.sid.startswith(_BUILTIN_SID_PREFIX) or (
            p.type_desc == "WINDOWS_GROUP"
            and p.sid.startswith(_DOMAIN_SID_PREFIX)
            and (not d.domain_sid or not p.sid.startswith(d.domain_sid + "-"))
        )
        if not is_local_group:
            continue
        if p.is_disabled or not _has_connect_sql(p.perms, p.member_roles):
            continue
        group_oid = f"{d.hostname}-{p.sid}"
        yield _edge(
            group_oid, p.object_identifier, ek.HAS_LOGIN,
            EdgeCtx(source_name=p.name, source_type=nk.GROUP,
                    target_name=p.name, target_type=nk.LOGIN,
                    sql_server_name=d.server_name, sql_server_id=d.server_oid),
        )


# ===========================================================================
# SERVICE ACCOUNT EDGES (Go createEdges, SERVICE ACCOUNT + Kerberoasting)
# ===========================================================================
def _service_account_edges(d: _ServerData) -> Iterator[Edge]:
    """ServiceAccountFor + HasSession + GetAdminTGS + GetTGS per service account.

    Each service account must resolve to a domain SID (S-1-5-21-*). The SID comes
    from the collect-time ad_resolved table (matched by the account name) — a
    built-in account (LocalSystem / NT AUTHORITY\\*) maps to the host computer SID.
    """
    is_any_sysadmin = _bool(d.high_priv_summary.get("isAnyDomainPrincipalSysadmin"))
    # Enabled domain logins with CONNECT SQL -> GetTGS targets (Go list).
    get_tgs_targets = [
        p for p in d.principals
        if p.is_ad and p.sid.startswith(_DOMAIN_SID_PREFIX)
        and not p.is_disabled and _has_connect_sql(p.perms, p.member_roles)
    ]

    for sa_name, sa_sid in _service_account_sids(d):
        if not sa_sid.startswith(_DOMAIN_SID_PREFIX):
            # Skip non-domain accounts (NT AUTHORITY, LOCAL SERVICE, ...).
            continue

        # ServiceAccountFor: service account -> server (always, incl. computer accts).
        yield _edge(
            sa_sid, d.server_oid, ek.SERVICE_ACCOUNT_FOR,
            EdgeCtx(source_name=sa_name, source_type=nk.BASE,
                    target_name=d.server_name, target_type=nk.SERVER,
                    sql_server_name=d.server_name, sql_server_id=d.server_oid),
        )

        # HasSession: computer -> service account, UNLESS the account IS the
        # computer (built-in, name HOST$, or SID == computer SID).
        is_builtin = sa_name.upper() in _BUILTIN_SA_NAMES
        is_computer_name = sa_name.upper() == f"{d.short_host}$".upper()
        is_computer_sid = bool(d.computer_sid) and sa_sid == d.computer_sid
        if d.computer_sid and not is_builtin and not is_computer_name and not is_computer_sid:
            yield _edge(
                d.computer_sid, sa_sid, ek.HAS_SESSION,
                EdgeCtx(source_name=d.hostname, source_type=nk.COMPUTER,
                        target_name=sa_name, target_type=nk.BASE,
                        sql_server_name=d.server_name, sql_server_id=d.server_oid),
            )

        # GetAdminTGS: service account -> server, when any domain principal is admin.
        if is_any_sysadmin:
            yield _edge(
                sa_sid, d.server_oid, ek.GET_ADMIN_TGS,
                EdgeCtx(source_name=sa_name, source_type=nk.BASE,
                        target_name=d.server_name, target_type=nk.SERVER,
                        sql_server_name=d.server_name, sql_server_id=d.server_oid),
            )

        # GetTGS: service account -> each enabled domain login with CONNECT SQL.
        for login in get_tgs_targets:
            yield _edge(
                sa_sid, login.object_identifier, ek.GET_TGS,
                EdgeCtx(source_name=sa_name, source_type=nk.BASE,
                        target_name=login.name, target_type=nk.LOGIN,
                        sql_server_name=d.server_name, sql_server_id=d.server_oid),
            )


def _service_account_sids(d: _ServerData) -> Iterator[tuple]:
    """Yield (account_name, sid) for each collected service account.

    A built-in account (LocalSystem / NT AUTHORITY\\*) maps to the host computer
    SID (Go preprocessServiceAccounts). A real domain account is resolved via the
    ad_resolved table (matched by name). Deduped by SID so one account doesn't
    produce duplicate edge families.
    """
    seen: set[str] = set()
    for row in d.lookup.table_rows("service_accounts"):
        account = (row.get("service_account") or "").strip()
        if not account:
            continue
        upper = account.upper()
        if upper in _BUILTIN_SA_NAMES or account == "LocalSystem":
            # Built-in -> the host computer account.
            sid = d.computer_sid
        else:
            resolved = d.resolve_identity_sid(account)
            sid = resolved or ""
        if not sid or sid in seen:
            continue
        seen.add(sid)
        yield (account, sid)


# ===========================================================================
# LINKED SERVER EDGES (Go createEdges, LinkedTo + LinkedAsAdmin)
# ===========================================================================
def _linked_server_edges(d: _ServerData) -> Iterator[Edge]:
    """MSSQL_LinkedTo (per linked-login mapping) + MSSQL_LinkedAsAdmin.

    Reads the preproc ``linked_server_flags`` table (one row per linked-login
    mapping with the recursive probe's remote-priv flags). Each row -> a LinkedTo
    edge carrying the full Go property bag (the distinct localLogin/remoteLogin
    per row keeps the count from collapsing under JSON dedup); rows whose
    ``is_linked_as_admin`` precondition holds also emit a LinkedAsAdmin edge.
    """
    rows = d.lookup.linked_server_flags(d.server_oid) if hasattr(d.lookup, "linked_server_flags") \
        else [r for r in d.lookup.table_rows("linked_server_flags") if r.get("server_oid") == d.server_oid]
    for row in rows:
        target_id = row.get("resolved_target") or row.get("data_source") or ""
        if not target_id:
            logger.debug("derive_ad_edges: linked-server row with no target; skipping")
            continue
        # Edge source: the collected server for a self-sourced link, or the chained
        # source's resolved id for a link discovered through a remote host (Go uses
        # resolveLinkedServerSourceID). preproc defaults resolved_source to the
        # server's own OID for self-rows, so this is always populated.
        source_id = row.get("resolved_source") or d.server_oid

        link_props = dict(
            localLogin=row.get("local_login"),
            remoteLogin=row.get("remote_login"),
            remoteCurrentLogin=row.get("remote_current_login"),
            dataSource=row.get("data_source"),
            path=row.get("path"),
            product=row.get("product"),
            provider=row.get("provider"),
            dataAccess=_bool(row.get("data_access")),
            rpcOut=_bool(row.get("rpc_out")),
            usesImpersonation=_bool(row.get("uses_impersonation")),
            remoteIsSysadmin=_bool(row.get("remote_is_sysadmin")),
            remoteIsSecurityAdmin=_bool(row.get("remote_is_securityadmin")),
            remoteHasControlServer=_bool(row.get("remote_has_control_server")),
            remoteHasImpersonateAnyLogin=_bool(row.get("remote_has_impersonate_any_login")),
            remoteIsMixedMode=_bool(row.get("remote_is_mixed_mode")),
        )

        linked_to = _edge(
            source_id, target_id, ek.LINKED_TO,
            EdgeCtx(source_name=d.server_name, source_type=nk.SERVER,
                    target_name=str(row.get("linked_server") or target_id), target_type=nk.SERVER,
                    sql_server_name=d.server_name, sql_server_id=d.server_oid),
        )
        _apply_props(linked_to, link_props)
        yield linked_to

        # LinkedAsAdmin when the recursive probe's precondition held (computed in
        # the linked_server_flags transform: SQL remote login + a remote admin
        # privilege + mixed-mode target).
        if _bool(row.get("is_linked_as_admin")):
            linked_admin = _edge(
                source_id, target_id, ek.LINKED_AS_ADMIN,
                EdgeCtx(source_name=d.server_name, source_type=nk.SERVER,
                        target_name=str(row.get("linked_server") or target_id), target_type=nk.SERVER,
                        sql_server_name=d.server_name, sql_server_id=d.server_oid),
            )
            _apply_props(linked_admin, link_props)
            yield linked_admin


# ===========================================================================
# CREDENTIAL EDGES (Go createEdges: HasMappedCred / HasProxyCred / HasDBScopedCred)
# ===========================================================================
def _credential_edges(d: _ServerData) -> Iterator[Edge]:
    """HasMappedCred (Login->AD) + HasProxyCred (Login->AD) + HasDBScopedCred (DB->AD).

    Each only emits for a credential identity that resolves to a domain SID (the Go
    ``ResolvedSID != ""`` gate). The identity->SID resolution uses the collect-time
    ad_resolved objects (matched by name).
    """
    yield from _has_mapped_cred_edges(d)
    yield from _has_proxy_cred_edges(d)
    yield from _has_db_scoped_cred_edges(d)


def _has_mapped_cred_edges(d: _ServerData) -> Iterator[Edge]:
    """Login -> AD identity for each login with a mapped credential (2012+).

    The login<->credential mapping comes from server_principal_credentials; the
    credential identity from the credentials table. The edge target is the
    identity's resolved domain SID.
    """
    # credential_id -> (identity, name) from the credentials table.
    cred_by_id: dict[int, dict] = {}
    for c in d.lookup.table_rows("credentials"):
        cid = _common.as_int(c.get("credential_id"), default=-1)
        if cid >= 0:
            cred_by_id[cid] = c
    login_by_id = {p.principal_id: p for p in d.principals}

    for m in d.lookup.table_rows("server_principal_credentials"):
        pid = _common.as_int(m.get("principal_id"), default=-1)
        cid = _common.as_int(m.get("credential_id"), default=-1)
        login = login_by_id.get(pid)
        if login is None:
            continue
        identity = m.get("credential_identity") or (cred_by_id.get(cid, {}).get("credential_identity"))
        resolved_sid = d.resolve_identity_sid(str(identity or ""))
        if not resolved_sid:
            # Go only emits HasMappedCred for domain credentials with a resolved SID.
            continue
        edge = _edge(
            login.object_identifier, resolved_sid, ek.HAS_MAPPED_CRED,
            EdgeCtx(source_name=login.name, source_type=nk.LOGIN,
                    target_name=str(identity or ""), target_type=nk.BASE,
                    sql_server_name=d.server_name, sql_server_id=d.server_oid),
        )
        edge.properties.credentialId = _id_str(cid)
        yield edge


def _has_proxy_cred_edges(d: _ServerData) -> Iterator[Edge]:
    """Login -> AD identity for each login authorized to use a SQL Agent proxy.

    For each proxy with a resolved domain credential, one edge per authorized
    login (proxy_logins). Carries credentialId + proxyId.
    """
    # proxy_id -> authorized login names.
    logins_by_proxy: dict[int, list] = {}
    for pl in d.lookup.table_rows("proxy_logins"):
        pid = _common.as_int(pl.get("proxy_id"), default=-1)
        name = pl.get("login_name")
        if pid >= 0 and name:
            logins_by_proxy.setdefault(pid, []).append(name)
    # proxy subsystems (for the entity panel text).
    subsystems_by_proxy: dict[int, list] = {}
    for ps in d.lookup.table_rows("proxy_subsystems"):
        pid = _common.as_int(ps.get("proxy_id"), default=-1)
        sub = ps.get("subsystem")
        if pid >= 0 and sub:
            subsystems_by_proxy.setdefault(pid, []).append(sub)

    for proxy in d.lookup.table_rows("proxy_accounts"):
        proxy_id = _common.as_int(proxy.get("proxy_id"), default=-1)
        cred_id = _common.as_int(proxy.get("credential_id"), default=-1)
        identity = proxy.get("credential_identity") or ""
        resolved_sid = d.resolve_identity_sid(str(identity))
        if not resolved_sid:
            continue
        proxy_name = proxy.get("proxy_name") or ""
        enabled = _bool(proxy.get("enabled"))
        subsystems = ", ".join(subsystems_by_proxy.get(proxy_id, []))
        for login_name in logins_by_proxy.get(proxy_id, []):
            login_oid = d.login_oid_by_name.get(login_name)
            if not login_oid:
                continue
            edge = _edge(
                login_oid, resolved_sid, ek.HAS_PROXY_CRED,
                EdgeCtx(source_name=login_name, source_type=nk.LOGIN,
                        target_name=str(identity), target_type=nk.BASE,
                        sql_server_name=d.server_name, sql_server_id=d.server_oid,
                        proxy_name=str(proxy_name), credential_identity=str(identity),
                        subsystems=subsystems, is_enabled=enabled),
            )
            edge.properties.credentialId = _id_str(cred_id)
            edge.properties.proxyId = _id_str(proxy_id)
            yield edge


def _has_db_scoped_cred_edges(d: _ServerData) -> Iterator[Edge]:
    """Database -> AD identity for each database-scoped credential (2016+)."""
    for cred in d.lookup.table_rows("database_scoped_credentials"):
        db_name = cred.get("database") or cred.get("database_name") or ""
        identity = cred.get("credential_identity") or ""
        resolved_sid = d.resolve_identity_sid(str(identity))
        if not resolved_sid:
            continue
        db_oid = ids.database_oid(d.server_oid, db_name)
        cred_id = _common.as_int(cred.get("credential_id"), default=-1)
        edge = _edge(
            db_oid, resolved_sid, ek.HAS_DB_SCOPED_CRED,
            EdgeCtx(source_name=db_name, source_type=nk.DATABASE,
                    target_name=str(identity), target_type=nk.BASE,
                    sql_server_name=d.server_name, sql_server_id=d.server_oid,
                    database_name=db_name),
        )
        edge.properties.credentialId = _id_str(cred_id)
        yield edge


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _apply_props(edge: Edge, props: dict) -> None:
    """Set each non-None linked-server property on the edge's property bag."""
    for key, value in props.items():
        if value is not None:
            setattr(edge.properties, key, value)


def _id_str(value: int) -> Optional[str]:
    """Render an id as a string (Go uses fmt.Sprintf("%d", …)); None when absent."""
    return str(value) if value is not None and value >= 0 else None


def _domain_from_fqdn(fqdn: str) -> str:
    """The DNS domain suffix of *fqdn* (everything after the first dot), or ""."""
    if not fqdn or "." not in fqdn:
        return ""
    return fqdn.split(".", 1)[1]


__all__ = ["derive_ad_edges"]
