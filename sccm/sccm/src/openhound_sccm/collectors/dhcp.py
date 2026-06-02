"""SCCM collectors split out from ``source.py``.

This module hosts the ``@app.resource`` generators for the dhcp phase.
The shared :class:`SourceContext` cache is built once in ``source.py`` and
passed into each resource. All decorators register onto the same
``app`` instance created in ``main.py``.
"""

from __future__ import annotations

import logging
import os
import platform
import re
import socket
import subprocess
from typing import Any, Iterable, Optional

import dlt

from ..clients.ad import ADClient, ADCredentials
from ..context import SourceContext
from ..main import app
from ..models.raw_table import raw_table_asset
from ..log_context import with_log_context
from .local import _normalize_host

logger = logging.getLogger(__name__)


@app.resource(name="dhcp_pxe_dps", parallelized=False, columns=raw_table_asset("dhcp_pxe_dps"))
@with_log_context(phase="DHCP", target_from_ctx_domain=True)
def dhcp_pxe_dps(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield rows for PXE-enabled distribution points discovered via DHCP.

    Sends a single DHCPINFORM with vendor class ``PXEClient`` to
    ``255.255.255.255:4011`` and parses any responses. Each PXE-capable
    response yields a row with the resolved hostname, the next-server IP, and
    boot-file metadata. Skipped silently if:
      - we don't have UDP broadcast permission, or
      - no SCCM PXE infrastructure responds within the 6s timeout window.

    CMBP reference: ``lib/collectors/dhcp_collector.py``. The TFTP-based
    media-variable-file fetch + decryption (CRED-1) is *not* ported here —
    that's Phase 4 secret-policy material. We only do the discovery probe.
    SOCKS5 mode is also deferred.
    """
    import random
    import struct
    import time

    if not ctx.method_enabled("DHCP"):
        return
    logger.info("Starting DHCP collection...")

    if not _have_udp_broadcast_priv():
        logger.error(
            "Insufficient privileges for UDP broadcast. DHCP collection requires "
            "root/sudo or CAP_NET_RAW. Run elevated for PXE discovery."
        )
        return

    mac = _get_local_mac()
    logger.info("Using MAC address: %s", mac.hex(":"))
    packet = _build_dhcp_inform_packet(mac)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            sock.bind(("0.0.0.0", 0))
        except OSError as e:
            logger.debug("dhcp_pxe_dps: bind failed (%s); continuing on ephemeral port", e)
        logger.info("dhcp_pxe_dps: sending DHCPINFORM (%d bytes) -> 255.255.255.255:4011", len(packet))
        sock.sendto(packet, ("255.255.255.255", 4011))
    except (PermissionError, OSError) as e:
        logger.info("dhcp_pxe_dps: DHCPINFORM send failed: %s", e)
        return

    # Collect responses for ~6s
    deadline = time.monotonic() + 6.0
    sock.settimeout(min(6.0, max(0.1, deadline - time.monotonic())))
    seen_servers: set[str] = set()
    try:
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            except OSError:
                break

            sender_ip = addr[0]
            if sender_ip in seen_servers:
                continue

            parsed = _parse_dhcp_response(data)
            if parsed is None:
                continue
            if not _is_pxe_response(parsed):
                continue

            seen_servers.add(sender_ip)
            hint_ip = parsed.get("tftp_server") or (parsed.get("siaddr") if parsed.get("siaddr") not in (None, "0.0.0.0") else sender_ip)
            host = _resolve_ip_to_hostname(hint_ip) or hint_ip
            host_norm = _normalize_host(host)
            if not host_norm:
                continue

            logger.info("PXE server found: %s (%s)", host_norm, hint_ip)
            yield {
                "hostname": host_norm,
                "pxe_next_server": parsed.get("siaddr"),
                "pxe_boot_file": parsed.get("boot_file_option") or parsed.get("boot_file"),
                "pxe_tftp_server": parsed.get("tftp_server"),
                "pxe_vendor_class": parsed.get("vendor_class"),
                "source": "DHCP-PXE",
                "domain": ctx.domain,
            }

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
    finally:
        try:
            sock.close()
        except Exception:
            pass
    if not seen_servers:
        logger.info("No PXE (proxy DHCP) responses — PXE discovery yielded nothing")
    logger.info("DHCP collection completed")


# ---- DHCP helpers (subset of CMBP dhcp_collector) -------------------------

def _have_udp_broadcast_priv() -> bool:
    """Best-effort check that this process can send a UDP broadcast.

    On Windows, sending broadcast generally works without elevation. On Linux,
    raw UDP broadcast typically requires root or CAP_NET_RAW.
    """
    if hasattr(os, "geteuid") and os.geteuid() == 0:  # type: ignore[attr-defined]
        return True
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(b"\x00", ("255.255.255.255", 0))
        s.close()
        return True
    except (PermissionError, OSError):
        return False


def _get_local_mac() -> bytes:
    """Return the first non-loopback active interface's MAC address.

    On Linux: reads /sys/class/net. On Windows: enumerates via uuid.getnode()
    fallback. Returns 6 zero bytes if none found.
    """
    # Linux fast path
    net_dir = "/sys/class/net"
    if os.path.isdir(net_dir):
        try:
            for iface in sorted(os.listdir(net_dir)):
                if iface == "lo":
                    continue
                operstate_path = os.path.join(net_dir, iface, "operstate")
                addr_path = os.path.join(net_dir, iface, "address")
                try:
                    with open(operstate_path) as f:
                        if f.read().strip() != "up":
                            continue
                    with open(addr_path) as f:
                        mac_str = f.read().strip()
                        if mac_str and mac_str != "00:00:00:00:00:00":
                            parts = mac_str.split(":")
                            if len(parts) == 6:
                                return bytes(int(p, 16) for p in parts)
                except (IOError, OSError, ValueError):
                    continue
        except OSError:
            pass

    # Windows / generic fallback via uuid.getnode()
    import uuid
    try:
        node = uuid.getnode()
        # If getnode() returned a randomly-generated locally-administered MAC,
        # the 41st bit is set (RFC 4122). Still usable for our purposes.
        return node.to_bytes(6, "big")
    except Exception:
        pass

    logger.warning("dhcp_pxe_dps: could not detect MAC address, using zeros")
    return b"\x00" * 6


def _build_dhcp_inform_packet(mac: bytes) -> bytes:
    """Build a DHCPINFORM packet for PXE proxy discovery (port 4011).

    Options: 53=INFORM(8), 60="PXEClient", 55=[60,66,67], 255=end.
    """
    import random
    import struct

    xid = random.randbytes(4)

    header = bytearray(236)
    header[0] = 0x01   # op: BOOTREQUEST
    header[1] = 0x01   # htype: Ethernet
    header[2] = 0x06   # hlen
    header[3] = 0x00   # hops
    header[4:8] = xid
    header[10] = 0x80  # flags: broadcast
    header[28 : 28 + len(mac)] = mac

    options = bytearray(b"\x63\x82\x53\x63")
    options.extend(b"\x35\x01\x08")  # 53: INFORM (8)
    vendor = b"PXEClient"
    options.extend(bytes([60, len(vendor)]) + vendor)
    options.extend(b"\x37\x03\x3c\x42\x43")  # 55: [60, 66, 67]
    options.append(0xFF)  # end

    return bytes(header) + bytes(options)


def _parse_dhcp_response(data: bytes) -> Optional[dict[str, Any]]:
    """Parse a DHCP response packet enough to identify a PXE responder."""
    if len(data) < 240:
        return None
    if data[236:240] != b"\x63\x82\x53\x63":
        return None

    siaddr = socket.inet_ntoa(data[20:24])
    boot_file = data[108:236].split(b"\x00")[0].decode("ascii", errors="ignore")

    vendor_class: Optional[str] = None
    tftp_server: Optional[str] = None
    boot_file_option: Optional[str] = None

    idx = 240
    while idx < len(data):
        code = data[idx]
        idx += 1
        if code == 255:
            break
        if code == 0:
            continue
        if idx >= len(data):
            break
        length = data[idx]
        idx += 1
        if idx + length > len(data):
            break
        value = data[idx : idx + length]
        idx += length
        if code == 60:
            vendor_class = value.decode("ascii", errors="ignore")
        elif code == 66:
            tftp_server = _convert_opt66_to_host(value)
        elif code == 67:
            boot_file_option = value.decode("ascii", errors="ignore")

    return {
        "siaddr": siaddr,
        "boot_file": boot_file,
        "vendor_class": vendor_class,
        "tftp_server": tftp_server,
        "boot_file_option": boot_file_option,
    }


def _convert_opt66_to_host(val: bytes) -> Optional[str]:
    """Parse DHCP option 66 (TFTP Server Name) — IPv4 or hostname."""
    if not val:
        return None
    if len(val) == 4:
        try:
            return socket.inet_ntoa(val)
        except Exception:  # noqa: BLE001
            pass
    try:
        return val.decode("ascii", errors="ignore").rstrip("\x00")
    except Exception:  # noqa: BLE001
        return None


def _is_pxe_response(parsed: dict[str, Any]) -> bool:
    """Heuristic: any of vendor=PXEClient / boot_file / option-67 means PXE."""
    if (parsed.get("vendor_class") or "").find("PXEClient") >= 0:
        return True
    if parsed.get("boot_file"):
        return True
    if parsed.get("boot_file_option"):
        return True
    return False


def _resolve_ip_to_hostname(ip: Optional[str]) -> Optional[str]:
    """Reverse-DNS an IP, falling back to the IP literal."""
    if not ip:
        return None
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return ip

