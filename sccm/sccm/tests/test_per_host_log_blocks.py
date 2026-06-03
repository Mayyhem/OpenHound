"""Tests for per-host ordered-log blocks.

Per-host worker records carry a target (host) context but no resource context.
The ordered-log handler buckets them by host and flushes a contiguous [host]
block when that host's phase sequence completes, so the FILE reads host-by-host
even though the console interleaves.
"""
import logging

from openhound_sccm.log_context import (
    fire_host_complete,
    register_host_complete_callback,
    target_context,
    unregister_host_complete_callback,
)
from openhound_sccm.main import _OrderedLogFileHandler


def test_host_complete_callback_fires_once_with_hostname():
    got = []
    register_host_complete_callback(got.append)
    try:
        fire_host_complete("hostA")
    finally:
        unregister_host_complete_callback(got.append)
    assert got == ["hostA"]


def test_per_host_records_flush_as_contiguous_blocks_in_completion_order(tmp_path):
    log_path = tmp_path / "ordered.log"
    handler = _OrderedLogFileHandler(log_path, level=logging.INFO)
    logger = logging.getLogger("test_per_host_log_blocks")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    register_host_complete_callback(handler.flush_host)
    try:
        # Interleave two hosts' records, as two concurrent workers would.
        with target_context("hostA"):
            logger.info("A-1")
        with target_context("hostB"):
            logger.info("B-1")
        with target_context("hostA"):
            logger.info("A-2")
        with target_context("hostB"):
            logger.info("B-2")
        # hostA finishes first, then hostB.
        fire_host_complete("hostA")
        fire_host_complete("hostB")
    finally:
        register_host_complete_callback(handler.flush_host)  # ensure registered for cleanup symmetry
        unregister_host_complete_callback(handler.flush_host)
        logger.removeHandler(handler)
        handler.close()

    text = log_path.read_text(encoding="utf-8")
    # Both of hostA's lines appear before either of hostB's (contiguous blocks,
    # hostA before hostB because it completed first).
    a1, a2 = text.index("A-1"), text.index("A-2")
    b1, b2 = text.index("B-1"), text.index("B-2")
    assert a1 < a2 < b1 < b2
    # The block is labelled with the host name.
    assert "# hostA" in text and "# hostB" in text
