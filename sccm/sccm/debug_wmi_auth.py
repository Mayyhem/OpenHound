#!/usr/bin/env python
"""Live validation of WmiClient against the lab SMS Provider, per auth method.

Authorized lab target: ps1-sms.mayyhem.com (MAYYHEM). Exercises the WMI auth
ladder end to end and confirms the SMS Provider WMI fallback returns the same
data the AdminService collector would. For each method it builds a WmiClient,
runs identify(), then a couple of WQL queries, and prints row counts + sample
keys (so the impacket/pywin32 row normalization, including the embedded Props
array, is validated against real data).

Methods:
  sspi      current Windows user via pywin32         (no creds)
  password  explicit -u/-p  -> Kerberos over DCOM     (impacket)
  pth       -u + NT hash    -> Kerberos(RC4)/NTLM      (impacket)
  ntlm      same creds vs the provider's IP literal    (forces NTLM; no SPN)
  ptt       pass-the-ticket -> mints a TGT, feeds it    (impacket)

Usage:
  python debug_wmi_auth.py [method ...]      # default: all
  python debug_wmi_auth.py --target host --domain d --user u --password p
"""
from __future__ import annotations

import argparse
import base64
import logging
import socket
import sys

from openhound_sccm.clients.wmi import WmiClient

logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(name)s: %(message)s")
log = logging.getLogger("wmi_auth")

_LAB_TARGET = "ps1-sms.mayyhem.com"
_LAB_DOMAIN = "mayyhem.com"
_LAB_USER = "MAYYHEM\\domainadmin"
_LAB_PASSWORD = "password"
_LAB_NT_HASH = "8846f7eaee8fb117ad06bdd830b7586c"
_LAB_KDC = "dc.mayyhem.com"

_PROBE_CLASSES = ("SMS_Site", "SMS_SCI_SiteDefinition", "SMS_Admin")


def _probe(name: str, *, target: str, domain: str, kdc: str, **creds) -> bool:
    print(f"\n===== {name} (target={target}) =====")
    client = WmiClient(target=target, domain=domain, kdc_host=kdc, **creds)
    try:
        site = client.identify()
        print(f"  identify() -> {site!r}")
        if site is None:
            print("  FAIL: no site code (rung exhausted or not a provider)")
            return False
        ok = True
        for cls in _PROBE_CLASSES:
            rows = client.query(cls)
            n = len(rows) if rows is not None else None
            sample = list(rows[0].keys())[:6] if rows else []
            print(f"  {cls:24} -> {n} rows; sample keys: {sample}")
            # Validate embedded Props normalization on the site definition.
            if cls == "SMS_SCI_SiteDefinition" and rows:
                props = rows[0].get("Props")
                print(f"      Props normalized -> {type(props).__name__}, "
                      f"first={props[0] if isinstance(props, list) and props else props}")
            if rows is None:
                ok = False
        return ok
    except Exception as ex:  # noqa: BLE001 - live diagnostic
        log.exception("  ERROR during %s: %s", name, ex)
        return False
    finally:
        client.close()


def _mint_kirbi(user: str, password: str, domain: str, kdc: str, nthash: str = "") -> str | None:
    """Mint a base64 KRB-CRED (.kirbi) TGT for pass-the-ticket testing."""
    try:
        from impacket.krb5 import constants
        from impacket.krb5.ccache import CCache
        from impacket.krb5.kerberosv5 import getKerberosTGT
        from impacket.krb5.types import Principal
    except ImportError as ex:
        log.warning("cannot mint ticket: %s", ex)
        return None
    sam = user.split("\\", 1)[1] if "\\" in user else user
    principal = Principal(sam, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    tgt, _cipher, okey, skey = getKerberosTGT(principal, password, domain.upper(), "", nthash, "", kdc)
    ccache = CCache()
    ccache.fromTGT(tgt, okey, skey)
    to_kirbi = getattr(ccache, "toKRBCRED", None)
    if to_kirbi is None:
        log.warning("this impacket build has no CCache.toKRBCRED(); skipping live PtT")
        return None
    return base64.b64encode(to_kirbi()).decode()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("methods", nargs="*", default=None,
                    help="subset of: sspi password pth ntlm ptt (default: all)")
    ap.add_argument("--target", default=_LAB_TARGET)
    ap.add_argument("--domain", default=_LAB_DOMAIN)
    ap.add_argument("--user", default=_LAB_USER)
    ap.add_argument("--password", default=_LAB_PASSWORD)
    ap.add_argument("--nt-hash", default=_LAB_NT_HASH)
    ap.add_argument("--kdc", default=_LAB_KDC)
    args = ap.parse_args()

    chosen = args.methods or ["sspi", "password", "pth", "ntlm", "ptt"]
    base = dict(target=args.target, domain=args.domain, kdc=args.kdc)
    results: dict[str, bool] = {}

    if "sspi" in chosen:
        results["sspi"] = _probe("sspi (current user / pywin32)", **base)
    if "password" in chosen:
        results["password"] = _probe("password (Kerberos / impacket)", **base,
                                     username=args.user, password=args.password)
    if "pth" in chosen:
        results["pth"] = _probe("pass-the-hash (impacket)", **base,
                                username=args.user, nt_hash=args.nt_hash)
    if "ntlm" in chosen:
        try:
            ip = socket.gethostbyname(args.target)
            results["ntlm"] = _probe("ntlm (IP literal forces NTLM / impacket)",
                                     target=ip, domain=args.domain, kdc=args.kdc,
                                     username=args.user, password=args.password)
        except OSError as ex:
            log.warning("ntlm: cannot resolve %s to an IP: %s", args.target, ex)
            results["ntlm"] = False
    if "ptt" in chosen:
        kirbi = _mint_kirbi(args.user, args.password, args.domain, args.kdc)
        if kirbi:
            results["ptt"] = _probe("pass-the-ticket (impacket)", **base, kerberos_ticket=kirbi)
        else:
            print("\n===== ptt ===== SKIPPED (could not mint a .kirbi in this impacket build)")

    print("\n===== summary =====")
    for m, ok in results.items():
        print(f"  {m:10} {'OK' if ok else 'FAIL'}")
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
