"""Minimal TFTP client for the OpenHound SCCM extension.

Vendored from ``sccm/ConfigManBearPig/python/lib/tftp_client.py`` (~290 LOC).
Adjusted only for module-relative imports (``from openhound_sccm.clients.socks5_udp``
instead of ``from lib.socks5_udp``) and logger name.

Downloads files from TFTP servers (port 69) using the TFTP protocol (RFC 1350).
Used for PXE boot media variable file retrieval (CRED-1, CRED-6) — Phase 4
material; Phase 2 only uses ``tftp_reachable`` for the discovery probe.

Supports both direct UDP and SOCKS5 UDP relay (for proxied environments).
SOCKS5 TFTP is limited to the first block (~512 bytes) because ACKs are
sent to the relay, not to the TFTP server's ephemeral data port.

Reference: https://datatracker.ietf.org/doc/html/rfc1350
"""

from __future__ import annotations

import logging
import socket
import struct
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from openhound_sccm.clients.socks5_udp import SOCKS5UDPRelay

logger = logging.getLogger(__name__)

# TFTP opcodes
_OPCODE_RRQ = 1   # Read Request
_OPCODE_DATA = 3  # Data
_OPCODE_ACK = 4   # Acknowledgment
_OPCODE_ERROR = 5  # Error

# Default TFTP block size (RFC 1350)
_BLOCK_SIZE = 512


def tftp_download(
    host: str,
    filename: str,
    port: int = 69,
    timeout: float = 5.0,
    max_size: int = 10 * 1024 * 1024,  # 10 MB max
) -> Optional[bytes]:
    """Download a file from a TFTP server.

    Returns file contents as bytes, or None on failure.
    """
    try:
        addr_info = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
        if not addr_info:
            logger.warning("Cannot resolve TFTP server: %s", host)
            return None
        server_addr = (addr_info[0][4][0], port)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        rrq = struct.pack(">H", _OPCODE_RRQ)
        rrq += filename.encode("ascii") + b"\x00"
        rrq += b"octet\x00"
        sock.sendto(rrq, server_addr)

        filedata = b""
        expected_block = 1

        while True:
            try:
                data, from_addr = sock.recvfrom(4 + _BLOCK_SIZE)
            except socket.timeout:
                logger.debug("TFTP timeout waiting for block %d", expected_block)
                break

            if len(data) < 4:
                break

            opcode, block = struct.unpack(">HH", data[:4])

            if opcode == _OPCODE_ERROR:
                error_msg = data[4:].split(b"\x00")[0].decode("ascii", errors="ignore")
                logger.debug("TFTP error from %s: %s", host, error_msg)
                sock.close()
                return None

            if opcode != _OPCODE_DATA:
                logger.debug("Unexpected TFTP opcode: %d", opcode)
                break

            if block != expected_block:
                logger.debug("TFTP block mismatch: expected %d, got %d", expected_block, block)
                ack = struct.pack(">HH", _OPCODE_ACK, expected_block - 1)
                sock.sendto(ack, from_addr)
                continue

            filedata += data[4:]
            expected_block += 1

            ack = struct.pack(">HH", _OPCODE_ACK, block)
            sock.sendto(ack, from_addr)

            if len(filedata) > max_size:
                logger.warning("TFTP download exceeded max size (%d bytes), aborting", max_size)
                break

            if len(data) - 4 < _BLOCK_SIZE:
                break

        sock.close()

        if filedata:
            logger.info("TFTP download complete: %s (%d bytes)", filename, len(filedata))
            return filedata
        logger.debug("TFTP download returned no data for %s", filename)
        return None

    except Exception as e:  # noqa: BLE001
        logger.debug("TFTP download failed (%s:%s): %s", host, filename, e)
        return None


def tftp_reachable(
    host: str,
    filename: str = "pxecheck.bin",
    port: int = 69,
    timeout_ms: int = 1500,
) -> Optional[bool]:
    """Test if a TFTP server is reachable by sending a RRQ.

    Any response (DATA or ERROR) indicates the server is listening.
    Returns True if reachable, False if timeout, None on error.
    """
    try:
        addr_info = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
        if not addr_info:
            return None
        server_addr = (addr_info[0][4][0], port)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout_ms / 1000.0)

        rrq = struct.pack(">H", _OPCODE_RRQ)
        rrq += filename.encode("ascii") + b"\x00"
        rrq += b"octet\x00"
        sock.sendto(rrq, server_addr)

        try:
            data, _ = sock.recvfrom(4 + _BLOCK_SIZE)
            sock.close()
            return True
        except socket.timeout:
            sock.close()
            return False

    except Exception:  # noqa: BLE001
        return None


def tftp_download_socks5(
    host: str,
    filename: str,
    socks_relay: "SOCKS5UDPRelay",
    port: int = 69,
    timeout: float = 5.0,
) -> Optional[bytes]:
    """Download a file from a TFTP server via SOCKS5 UDP relay (first block only)."""
    try:
        rrq = struct.pack(">H", _OPCODE_RRQ)
        rrq += filename.encode("ascii") + b"\x00"
        rrq += b"octet\x00"

        logger.info("[TFTP/SOCKS5] Sending RRQ (%d bytes) -> %s:%d for '%s'", len(rrq), host, port, filename)
        socks_relay.sendto(rrq, host, port)

        result = socks_relay.recvfrom(bufsize=4 + _BLOCK_SIZE, timeout=timeout)
        if result is None:
            logger.debug("[TFTP/SOCKS5] No response from %s:%d", host, port)
            return None

        data, sender_ip, sender_port = result
        if len(data) < 4:
            logger.debug("[TFTP/SOCKS5] Response too short (%d bytes)", len(data))
            return None

        opcode, block = struct.unpack(">HH", data[:4])

        if opcode == _OPCODE_ERROR:
            error_msg = data[4:].split(b"\x00")[0].decode("ascii", errors="ignore")
            logger.info("[TFTP/SOCKS5] Error from %s: %s", host, error_msg)
            return None

        if opcode != _OPCODE_DATA or block != 1:
            logger.debug("[TFTP/SOCKS5] Unexpected response: opcode=%d block=%d", opcode, block)
            return None

        filedata = data[4:]
        logger.info("[TFTP/SOCKS5] Received block 1 (%d bytes) from %s:%d", len(filedata), sender_ip, sender_port)

        ack = struct.pack(">HH", _OPCODE_ACK, 1)
        socks_relay.sendto(ack, host, port)

        if len(filedata) >= _BLOCK_SIZE:
            logger.warning(
                "[TFTP/SOCKS5] File is larger than %d bytes. SOCKS5 relay limits TFTP to the first block.",
                _BLOCK_SIZE,
            )

        return filedata if filedata else None

    except Exception as e:  # noqa: BLE001
        logger.debug("[TFTP/SOCKS5] Download failed (%s:%s): %s", host, filename, e)
        return None


def tftp_reachable_socks5(
    host: str,
    socks_relay: "SOCKS5UDPRelay",
    filename: str = "pxecheck.bin",
    port: int = 69,
    timeout: float = 1.5,
) -> Optional[bool]:
    """Test if a TFTP server is reachable via SOCKS5 relay."""
    try:
        rrq = struct.pack(">H", _OPCODE_RRQ)
        rrq += filename.encode("ascii") + b"\x00"
        rrq += b"octet\x00"

        socks_relay.sendto(rrq, host, port)
        result = socks_relay.recvfrom(bufsize=4 + _BLOCK_SIZE, timeout=timeout)
        return True if result is not None else False
    except Exception:  # noqa: BLE001
        return None
