#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""WPS PIN keyspace helpers.

An 8-digit WPS PIN is split into two independently-verified halves:
  P1 = first 4 digits
  P2 = last 4 digits (3 free digits + WSC checksum of the first 7)

The AP verifies each half separately: ~10,000 + ~1,000 = ~11,000 worst-case
guesses instead of 10^8.

This module provides:
  - COMMON_PINS: the first list to try (hits a surprising number of routers)
  - known_pins_for(bssid_str): BSSID-derived candidates from published algorithms
  - seed_pins_for(bssid_str): ranked union of both (call this from the WPS attack)
"""

from __future__ import annotations
from typing import List

from .wps_algos import pins_for as _algos_for

_HEX = '0123456789abcdefABCDEF'


# Canonical defaults / factory PINs seen on many consumer routers.
COMMON_PINS: List[str] = [
    '12345670',   # WSC spec example / many demos
    '00000000',
    '11111111',
    '88888888',
    '12345678',   # Not checksum-valid but some firmwares accept it
    '20172527',   # D-Link family
    '28296607',   # Belkin family
    '10000005',
]


def known_pins_for(bssid: str) -> List[str]:
    """BSSID-derived candidate WPS PINs (any separator / case).

    Returns [] if bssid is not a full 6-octet MAC.
    """
    hexstr = ''.join(c for c in bssid if c in _HEX)[:12]
    if len(hexstr) < 12:
        return []
    return _algos_for(bytes.fromhex(hexstr))


def seed_pins_for(bssid: str) -> List[str]:
    """Ranked, de-duped seed PIN list for reaver/bully: BSSID-derived first,
    then common defaults.  Call this before the generic 11k sweep."""
    seen: set[str] = set()
    result: List[str] = []

    for p in known_pins_for(bssid):
        if p not in seen:
            seen.add(p)
            result.append(p)

    for p in COMMON_PINS:
        if p not in seen:
            seen.add(p)
            result.append(p)

    return result
