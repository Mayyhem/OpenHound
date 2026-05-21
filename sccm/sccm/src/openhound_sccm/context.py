"""Shared source-run context for SCCM collectors.

``SourceContext`` wraps the LDAP/AD client and all CMBP-equivalent CLI knobs
(``--collection-methods``, ``--computers``, ``--sms-provider``, etc.) and
provides the lazy-loaded caches that every ``@app.resource`` in
``collectors/*`` shares:
"""
from dataclasses import dataclass
from typing import Any, Optional

from .clients.ad import ADClient


@dataclass
class SourceContext:
    ad: ADClient
    domain: str
    username: Optional[str] = None
    password: Optional[str] = None
    # Collection (-m / --collection-methods)
    collection_methods: str = "All"

    
    # Site codes (UPPERCASE) emitted into the ``ldap_sites`` DLT table by
    # any of the three resources that write to it: ``ldap_sites`` (Phase 1,
    # LDAP-only mSSMSSite + mSSMSManagementPoint), ``ldap_sites_admin_extra``
    # (Phase 7, AdminService-only SMS_Site / SMS_SCI_SiteDefinition rows
    # missing from LDAP) and ``ldap_sites_smb_extra`` (Phase 10, SMB-share
    # discovered site codes on hosts not surfaced by either of the prior
    # two). DLT writes append-mode by default; without this cross-resource
    # dedup set, a single SCCM site visible from all three channels would
    # produce three SCCM_Site nodes with the same node_id.
    _emitted_site_codes: Optional[set[str]] = None
    
    @property
    def system_management_dn(self) -> str:
        return f"CN=System Management,CN=System,{self.ad.base_dn}"