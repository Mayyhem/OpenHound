"""SCCM collectors split out from ``source.py``.

This module hosts the ``@app.resource`` generators for the mssql phase.
The shared :class:`SourceContext` cache is built once in ``source.py`` and
passed into each resource. All decorators register onto the same
``app`` instance created in ``main.py``.
"""

from __future__ import annotations

import logging
import socket
from typing import Any, Iterable, Optional

from ..context import SourceContext
from ..main import app
from ..log_context import per_host_iter, with_log_context
from ..models import MSSQLServer

logger = logging.getLogger(__name__)


# TDS PRELOGIN token types — ported from CMBP ``mssql_collector.py:30-35``.
# Missing constants caused ``_build_tds_prelogin_payload`` to raise
# ``NameError`` inside ``_probe_mssql_epa``'s try/except, silently producing
# zero MSSQL_Server rows for every host (and downstream MSSQL_* node + edge
# fan-out). Without these, OH emits no MSSQL graph data even on lab hosts
# where 1433 is reachable.
_TDS_PRELOGIN_VERSION = 0x00
_TDS_PRELOGIN_ENCRYPTION = 0x01
_TDS_PRELOGIN_INSTOPT = 0x02
_TDS_PRELOGIN_THREADID = 0x03
_TDS_PRELOGIN_MARS = 0x04
_TDS_PRELOGIN_TERMINATOR = 0xFF


def _build_tds_prelogin_payload() -> bytes:
    """Build the TDS PRELOGIN payload (5 options + terminator).

    Direct port of ``mssql_collector._build_tds_prelogin``.
    """
    import struct

    num_options = 5
    option_header_size = num_options * 5 + 1
    version_data = struct.pack(">BBBBH", 16, 0, 0, 1, 0)
    encryption_data = bytes([0x00])
    instopt_data = bytes([0x00])
    threadid_data = struct.pack(">I", 0)
    mars_data = bytes([0x00])

    offset = option_header_size
    options = bytearray()
    for token, data in (
        (_TDS_PRELOGIN_VERSION, version_data),
        (_TDS_PRELOGIN_ENCRYPTION, encryption_data),
        (_TDS_PRELOGIN_INSTOPT, instopt_data),
        (_TDS_PRELOGIN_THREADID, threadid_data),
        (_TDS_PRELOGIN_MARS, mars_data),
    ):
        options.extend(struct.pack(">BHH", token, offset, len(data)))
        offset += len(data)
    options.append(_TDS_PRELOGIN_TERMINATOR)
    payload = bytes(options) + version_data + encryption_data + instopt_data + threadid_data + mars_data
    return payload


def _parse_tds_prelogin_response(payload: bytes) -> Optional[int]:
    """Return the encryption byte (0x00..0x03) or None if not present.

    Same parsing as ``mssql_collector._parse_prelogin_response`` but returns
    the raw byte so callers can label EPA themselves (Off/Allowed/Required).
    """
    import struct

    offset = 0
    while offset < len(payload):
        token = payload[offset]
        if token == _TDS_PRELOGIN_TERMINATOR:
            break
        if offset + 5 > len(payload):
            break
        data_offset = struct.unpack(">H", payload[offset + 1:offset + 3])[0]
        data_length = struct.unpack(">H", payload[offset + 3:offset + 5])[0]
        if token == _TDS_PRELOGIN_ENCRYPTION and data_offset + data_length <= len(payload):
            return payload[data_offset]
        offset += 5
    return None


def _probe_mssql_epa(hostname: str, port: int = 1433) -> Optional[dict[str, Any]]:
    """Send a TDS PRELOGIN to ``hostname:port`` and return EPA metadata.

    Returns ``None`` if the TCP connect or the prelogin handshake fails.
    Returns a dict with the encryption byte + a textual EPA label otherwise.
    """
    import struct

    try:
        sock = socket.create_connection((hostname, port), timeout=5)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        logger.debug("mssql: %s:%d unreachable: %s", hostname, port, e)
        return None

    try:
        payload = _build_tds_prelogin_payload()
        header = struct.pack(">BBHHBB", 0x12, 0x01, len(payload) + 8, 0, 1, 0)
        sock.sendall(header + payload)

        sock.settimeout(5.0)
        # Read TDS header (8 bytes), then payload of length-8.
        head = b""
        while len(head) < 8:
            chunk = sock.recv(8 - len(head))
            if not chunk:
                return None
            head += chunk
        total_len = struct.unpack(">H", head[2:4])[0]
        body = b""
        while len(body) < total_len - 8:
            chunk = sock.recv(total_len - 8 - len(body))
            if not chunk:
                break
            body += chunk
        encryption_byte = _parse_tds_prelogin_response(body)
    except Exception as e:  # noqa: BLE001
        logger.debug("mssql: TDS PRELOGIN to %s:%d failed: %s", hostname, port, e)
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass

    if encryption_byte is None:
        return None
    # 0x00=ENCRYPT_OFF, 0x01=ENCRYPT_ON, 0x02=ENCRYPT_NOT_SUP, 0x03=ENCRYPT_REQ
    label_map = {0x00: "Off", 0x01: "Allowed", 0x02: "NotSupported", 0x03: "Required"}
    return {
        "encryption_byte": int(encryption_byte),
        "epa": label_map.get(encryption_byte, f"Unknown(0x{encryption_byte:02x})"),
        "epa_enabled": encryption_byte in (0x01, 0x03),
    }


@app.resource(name="mssql_epa_flags", parallelized=False, columns=MSSQLServer)
@with_log_context(phase="MSSQL")
def mssql_epa_flags(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield one row per MSSQL host that responds to a TDS PRELOGIN on TCP/1433.

    EPA detection is the most valuable Phase 3a signal because it drives the
    Phase 4 ``CoerceAndRelayToMSSQL`` derived edges. Hosts not listening on
    1433 silently yield no row.

    The probe set is gated by ``ctx.sccm_discovered_hosts()`` — i.e. we only
    probe hosts that have been discovered through an SCCM channel (SMS
    provider, MP record, SCCM-naming pattern, or AdminService SMS_Site /
    SMS_SCI_SiteDefinition / SMS_SCI_SysResUse). This matches CMBP's
    per-host MSSQL phase scoping (CMBP's ``TargetManager`` only includes
    hosts surfaced by these same channels) and avoids emitting phantom
    MSSQL_Server nodes for arbitrary domain computers that happen to be
    listening on TCP/1433. Without the gate, a low-priv user with no
    AdminService access would still see CAS-DB / PS1-DB nodes via raw
    LDAP-walk + 1433 scan, while CMBP correctly emits zero such nodes.
    """
    if not ctx.method_enabled("MSSQL"):
        return
    discovered = ctx.sccm_discovered_hosts()
    for host in per_host_iter(ctx.target_hosts_snapshot()):
        hostname = host["hostname"]
        host_low = hostname.lower()
        host_short = host_low.split(".", 1)[0]
        if ctx.target_queue is not None and ctx.target_queue.get_status(hostname, "mssql_epa_flags") == "done":
            continue
        if host_low in discovered or host_short in discovered:
            logger.info("Starting MSSQL collection on %s...", hostname)
            epa = _probe_mssql_epa(hostname, 1433)
            if not epa:
                logger.info("MSSQL port 1433 not open on %s", hostname)
            else:
                logger.info("MSSQL port 1433 is open on %s", hostname)
                epa_label = "ENABLED" if epa.get("epa_enabled") else "DISABLED"
                logger.info("EPA is %s on %s:1433", epa_label, hostname)
                yield {
                    "hostname": hostname,
                    "port": 1433,
                    "fqdn": hostname,
                    "epa": epa["epa"],
                    "epa_value": epa["encryption_byte"],
                    "epa_enabled": epa["epa_enabled"],
                    "computer_sid": host.get("sid"),
                    "source": "MSSQL-TDS",
                    "domain": ctx.domain,
                }
                logger.info("MSSQL collection completed for %s", hostname)
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(hostname, "mssql_epa_flags")
