import json, sys
from pathlib import Path
from openhound_collector_common.integration_testing.graph import load_graph
from openhound_collector_common.integration_testing.compare import compare_graphs

W = Path(r"C:/Users/domainadmin/Desktop/OpenHound/sccm/tests/live-comparison/parity_props_check")
CMBP = Path(r"C:/Users/domainadmin/Desktop/OpenHound/sccm/tests/live-comparison/results/bloodhound-sccm-20260714-141659.zip")

a = load_graph(W / "graph")          # current OpenHound run (with new props)
b = load_graph(CMBP)                 # CMBP baseline
rep = compare_graphs(a, b)

# Target kinds/props we set out to close.
TARGET = {
    "Computer": ["Domain","Enabled","IsDomainPrincipal","Type","objectClass","servicePrincipalName","CN"],
    "User":     ["Domain","Enabled","IsDomainPrincipal","Type","objectClass","servicePrincipalName","CN"],
    "Group":    ["Domain","Enabled","IsDomainPrincipal","Type","objectClass","servicePrincipalName","CN"],
    "SCCM_Site":["siteSystemRoles"],
    "SCCM_ClientDevice":["currentManagementPoint","currentManagementPointSID","previousSMSID",
                         "previousSMSIDChangeDate","userName","userDomainName","lastOnlineTime","lastOfflineTime"],
}
print(f"A(current): {len(a.nodes)} nodes / {len(a.edges)} edges")
print(f"B(CMBP):    {len(b.nodes)} nodes / {len(b.edges)} edges")
print("\n=== node_kind_rollup for target kinds (only_a = prop keys unique to OpenHound; only_b = still-missing-from-OpenHound) ===")
for kind, props in TARGET.items():
    roll = rep.node_kind_rollup.get(kind, {"only_a":[],"only_b":[]})
    still_missing = [p for p in props if p in roll.get("only_b", [])]
    now_present   = [p for p in props if p not in roll.get("only_b", [])]
    print(f"\n[{kind}]  target props now present in A: {now_present}")
    print(f"          target props STILL only_in_B (missing from A): {still_missing}")
    print(f"          (full only_b for this kind: {sorted(roll.get('only_b', []))})")

# IsMappedTo.SCCMInfra edge check
er = rep.edge_kind_rollup.get("SCCM_IsMappedTo", {"only_a":[],"only_b":[]})
print(f"\n[SCCM_IsMappedTo edge]  only_b (missing from A): {sorted(er.get('only_b', []))}  | SCCMInfra in only_b? {'SCCMInfra' in er.get('only_b', [])}")

# Dump full report for the record
(W / "compare_report.json").write_text(json.dumps(rep.to_dict(), indent=2, default=str), encoding="utf-8")
print(f"\nfull report -> {W/'compare_report.json'}")
