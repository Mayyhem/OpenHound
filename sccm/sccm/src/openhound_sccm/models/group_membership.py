"""AD group membership edge model.

Reads from the ``ldap_group_memberships`` DLT resource table — one row per
``(group_sid, member_dn)`` pair, produced by re-running the LDAP groups query
in ``source.py`` and flattening the ``member`` multi-valued attribute.

This is an EDGE-ONLY asset — ``as_node`` returns ``None``. The actual Group,
User and Computer nodes are emitted from their respective models.

Both ``User -> Group`` and ``Computer -> Group`` ``MemberOf`` edges are
declared up-front because a group may contain a mixture of user and computer
principals. The framework's ``EdgePath`` schema only allows ``match_by="id"``
or ``match_by="property"``, so we resolve the member DN to an objectSid
locally via ``SCCMLookup.principal_id_by_dn`` (built from the same JSONL).
Foreign / unresolvable DNs (e.g. ``CN=S-1-5-11,CN=ForeignSecurityPrincipals``)
yield no edge.
"""

from __future__ import annotations

from typing import ClassVar, Optional

from dlt.common.libs.pydantic import DltConfig
from openhound.core.asset import BaseAsset, EdgeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import ConfigDict

from openhound_sccm.kinds import edges as ek
from openhound_sccm.kinds import nodes as nk
from openhound_sccm.main import app


@app.asset(
    description="AD group membership edge",
    edges=[
        EdgeDef(
            kind=ek.MEMBER_OF,
            start=nk.USER,
            end=nk.GROUP,
            description="User is a member of an AD group",
        ),
        EdgeDef(
            kind=ek.MEMBER_OF,
            start=nk.COMPUTER,
            end=nk.GROUP,
            description="Computer is a member of an AD group",
        ),
    ],
)
class GroupMembership(BaseAsset):
    """One MemberOf edge per (member_dn, group_sid) pair."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    # Raw fields from ldap_group_memberships JSONL
    group_sid: str
    group_name: Optional[str] = None
    member_dn: str

    @property
    def as_node(self) -> None:
        return None

    @property
    def edges(self):
        if not self.member_dn or not self.group_sid:
            return
        # Resolve member DN -> SID via the convert-time lookup.
        member_sid = self._lookup.principal_id_by_dn(self.member_dn)
        if not member_sid:
            return
        # When the resolved member is a User present in
        # adminservice_r_user_security_groups, suppress the LDAP-derived
        # MemberOf edge — the SMS_R_User path (emitted via the
        # ``r_user_member_of_edges`` SQL view in transforms.py) is
        # closer to CMBP's emission semantics and avoids the LDAP
        # overcount that LDAP's ``member`` attribute introduces. Same
        # logic for Computer principals: when the SMS_R_System path
        # (``r_system_member_of_edges``) covers the same Computer, drop
        # the LDAP-derived edge so we don't double-emit. CMBP only
        # emits MemberOf from SMS_R_User and SMS_R_System; OH's LDAP
        # ``member`` enumeration is purely a fallback for low-priv
        # runs that never reach AdminService.
        if self._lookup.user_is_sccm_infra(member_sid):
            return
        if self._lookup.computer_is_in_r_system_groups(member_sid):
            return
        # Suppress Group->Group LDAP MemberOf when AdminService
        # SMS_R_System / SMS_R_User membership data is available. CMBP
        # never queries LDAP ``member`` and only emits MemberOf via
        # SMS_R_*; mirroring that behaviour drops the ~11-edge
        # Group->Group overshoot we see for full-access users.
        if self._lookup.is_group_sid(member_sid) and self._lookup.adminservice_membership_available():
            return
        yield Edge(
            kind=ek.MEMBER_OF,
            start=EdgePath(value=member_sid, match_by="id"),
            end=EdgePath(value=self.group_sid, match_by="id"),
            # CMBP/PS1 marks MemberOf edges as non-traversable (informational
            # only — not used for attack-path traversal). Match that so the
            # BloodHound traversal flag agrees between collectors.
            properties=EdgeProperties(traversable=False),
        )
