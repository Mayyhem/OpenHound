"""Shared utilities for CRED-discovered secret handling.

Vendored from ``sccm/ConfigManBearPig/python/lib/secret_utils.py`` (~119 LOC),
adapted to drop the ``GraphStore`` dependency. CMBP's helpers wrote nodes
directly into a stateful in-memory graph; in OpenHound's DLT model, resources
*yield rows* and the convert phase materialises nodes from JSONL. So the
adapted helpers return dicts that the calling resource turns into rows.

Two tiers of secret nodes:
- Domain credentials (DOMAIN\\user) -> AD-resolved User row (link by SID via
  ``lookup.user_by_sid`` at convert time) plus optional discoveredSecretType
  property.
- Non-domain credentials (NAA passwords, collection variables, task sequence
  scripts) -> ``SCCM_Secret`` row keyed by hash(value) so identical secrets
  found by multiple sources dedupe.

Used by Phase 2 (Local CRED-4 / DHCP CRED-1) and Phase 4 secret-policy
post-processing. Phase 2's once-phases don't currently emit CRED-4 secrets —
that's Phase 3/4 — but the helpers are vendored here so the next phase has
them ready.
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Matches DOMAIN\user patterns (e.g., MAYYHEM\svc_naa, CONTOSO\admin)
DOMAIN_USER_PATTERN = re.compile(r"[A-Za-z0-9._-]+\\[A-Za-z0-9._-]+")


def extract_domain_users(text: str) -> list[str]:
    """Extract DOMAIN\\user patterns from text."""
    return DOMAIN_USER_PATTERN.findall(text)


def build_secret_user_row(
    username: str,
    secret_type: str,  # "NAA", "CollectionVariable", "TaskSequence"
    site_code: Optional[str],
    collection_source: str,
    extra_props: Optional[dict] = None,
) -> dict[str, Any]:
    """Build a row representing a discovered DOMAIN\\user secret.

    Equivalent to CMBP's ``resolve_and_create_secret_user`` minus the AD
    resolver call (deferred to the convert/lookup phase). Returns a dict the
    caller can yield from a DLT resource. The convert phase uses
    ``SCCMLookup.user_by_sam`` (or a future ``user_by_domain_sam``) to attach
    the SID; if no match is found, the row still produces a synthetic
    ``SCCM_Secret_<type>_<sam>`` id.
    """
    if "\\" in username:
        domain_part, sam = username.split("\\", 1)
    else:
        domain_part, sam = "", username

    props: dict[str, Any] = {
        "raw_username": username,
        "domain": domain_part,
        "sam_account_name": sam,
        "secret_type": secret_type,
        "site_code": site_code,
        "collection_source": collection_source,
    }
    if secret_type == "NAA":
        props["is_sccm_network_access_account"] = True
    if extra_props:
        props.update(extra_props)
    return props


def build_secret_node_row(
    secret_type: str,  # "NAA_Password", "CollectionVariable", "TaskSequence"
    value: str,
    site_code: Optional[str],
    collection_source: str,
    name: Optional[str] = None,
    show_cleartext: bool = False,
    extra_props: Optional[dict] = None,
) -> dict[str, Any]:
    """Build a row representing a non-domain SCCM_Secret.

    Equivalent to CMBP's ``create_secret_node`` minus the GraphStore write.
    Uses a deterministic ID (sha256 of value) so identical secrets discovered
    from multiple sources dedupe at convert time.
    """
    val_hash = hashlib.sha256(value.encode()).hexdigest()[:12]
    node_id = f"SCCM_Secret_{secret_type}_{val_hash}"

    row: dict[str, Any] = {
        "node_id": node_id,
        "secret_type": secret_type,
        "site_code": site_code,
        "collection_source": collection_source,
        "name": name or secret_type,
    }
    if show_cleartext:
        row["secret_value"] = value
    if extra_props:
        row.update(extra_props)
    return row
