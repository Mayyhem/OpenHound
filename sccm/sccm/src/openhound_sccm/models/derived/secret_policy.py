"""Secret-policy derived-edge schema placeholder.

Four edge kinds materialised in ``sccm.secret_policy_edges``:

  * SCCM_HasNetworkAccessAccount  — ClientDevice -> NAA secret (when
    CRED-2/3 attack flows recover one; currently empty input)
  * SCCM_HasStoredAccount         — ClientDevice -> stored account secret
    (CRED-5; currently empty input)
  * SCCM_HasCollectionVar         — ClientDevice -> collection variable
    (always populated when AdminService produced collection_variables rows)
  * SCCM_HasTaskSequence          — ClientDevice -> task sequence
    (always populated when AdminService produced task_sequences rows)

Emitter is ``aggregator.py``.
"""

from __future__ import annotations

from openhound.core.asset import EdgeDef

from openhound_sccm.kinds import edges as ek
from openhound_sccm.kinds import nodes as nk

from ._placeholder import register_placeholder

SecretPolicyEdge = register_placeholder(
    name="SecretPolicyEdge",
    description="Schema-only placeholder for secret-policy edges; emitter in aggregator.py.",
    edges=[
        EdgeDef(kind=ek.SCCM_HAS_NETWORK_ACCESS_ACCOUNT, start=nk.SCCM_CLIENT_DEVICE, end=nk.USER,
                description="ClientDevice -> NAA secret recovered by CRED-* flows."),
        EdgeDef(kind=ek.SCCM_HAS_STORED_ACCOUNT, start=nk.SCCM_CLIENT_DEVICE, end=nk.USER,
                description="ClientDevice -> stored-account secret."),
        EdgeDef(kind=ek.SCCM_HAS_COLLECTION_VAR, start=nk.SCCM_CLIENT_DEVICE, end=nk.BASE,
                description="ClientDevice -> collection variable secret."),
        EdgeDef(kind=ek.SCCM_HAS_TASK_SEQUENCE, start=nk.SCCM_CLIENT_DEVICE, end=nk.BASE,
                description="ClientDevice -> task sequence secret."),
    ],
)
