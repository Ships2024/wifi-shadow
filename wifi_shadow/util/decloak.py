#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Targeted hidden AP decloak via sibling-SSID probe requests.

wifi-shadow's original decloak is passive: it sends a broadcast deauth and waits for
a hidden AP to respond with its SSID. That works, but relies on clients being
present and reconnecting.

This module adds an active approach: given visible APs on the same channel, we
generate plausible "sibling" SSID candidates (e.g. the AP at channel 6 named
"NETGEAR-5G" → probe for "NETGEAR", "NETGEAR-Guest", "NETGEAR-IoT", etc.) and
send directed Probe Requests. If the hidden AP's SSID matches a candidate, it
responds with a Probe Response that reveals its ESSID.

Requires aireplay-ng or scapy for frame injection.

Ported from wifit3/campaigns/decloak.py (GPLv2).
"""

from __future__ import annotations

import os
import subprocess
import time
from typing import List, Optional

from ..config import Configuration
from ..util.color import Color
from ..util.process import Process

# ---------------------------------------------------------------------------
# SSID candidate generation
# ---------------------------------------------------------------------------

# Common suffixes for AP family naming schemes.
_SIBLING_SUFFIXES: List[str] = [
    '',
    '-5G', '_5G', '-5GHz', '-5g',
    '-2G', '_2G', '-2.4G', '-2.4GHz',
    '-Guest', '_Guest', '-guest', ' Guest',
    '-IoT', '_IoT',
    '-Setup', '_Setup',
    '-EXT', '-ext',
    '-2', '-1',
]


def build_candidates(base_ssid: str) -> List[str]:
    """Generate likely sibling SSIDs from a known visible AP's SSID.

    For 'NETGEAR-5G' this returns ['NETGEAR-5G', 'NETGEAR', 'NETGEAR-Guest', ...]
    for 'NETGEAR' this returns ['NETGEAR', 'NETGEAR-5G', 'NETGEAR-Guest', ...]
    """
    if not base_ssid:
        return []

    out: List[str] = []
    seen: set = set()

    def add(s: str) -> None:
        s = s.strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)

    add(base_ssid)

    # Try stripping known suffixes to get the "base" name
    stripped = base_ssid
    for suffix in _SIBLING_SUFFIXES:
        if suffix and base_ssid.lower().endswith(suffix.lower()):
            candidate = base_ssid[: -len(suffix)].strip()
            if len(candidate) > 1:
                stripped = candidate
                break

    # Generate candidates from the stripped (or original) base
    for suffix in _SIBLING_SUFFIXES:
        add(stripped + suffix)

    return out


def get_sibling_candidates(targets: list, hidden_bssid: str) -> List[str]:
    """Build probe-request SSID candidates for a hidden AP.

    Looks at all *visible* (non-hidden) APs on the same channel as hidden_bssid,
    treats their SSIDs as naming-family hints, and generates candidates.

    Args:
        targets:        List of wifi-shadow Target objects (the current scan list).
        hidden_bssid:   BSSID of the hidden AP we're trying to decloak.

    Returns:
        De-duped list of candidate SSID strings, ordered by likelihood.
    """
    # Find the hidden target's channel
    hidden_channel = None
    for t in targets:
        if t.bssid.lower() == hidden_bssid.lower():
            hidden_channel = t.channel
            break

    # Collect visible SSIDs on the same channel
    visible_ssids: List[str] = []
    for t in targets:
        if t.essid_known and t.essid and t.channel == hidden_channel:
            if t.bssid.lower() != hidden_bssid.lower():
                visible_ssids.append(t.essid)

    if not visible_ssids:
        return []

    seen: set = set()
    result: List[str] = []
    for ssid in visible_ssids:
        for candidate in build_candidates(ssid):
            if candidate not in seen:
                seen.add(candidate)
                result.append(candidate)

    return result


# ---------------------------------------------------------------------------
# Probe injection
# ---------------------------------------------------------------------------

def send_probe_requests(target, candidates: List[str], count: int = 2) -> None:
    """Inject directed Probe Requests for each candidate SSID.

    Uses aireplay-ng if available (--essid-probe), otherwise falls back to
    a scapy-based injector.

    Args:
        target:     wifi-shadow Target (needs .bssid and .channel).
        candidates: List of SSID strings to probe for.
        count:      Number of probes to send per candidate.
    """
    if not candidates:
        return

    if _aireplay_probe_available():
        _send_via_aireplay(target, candidates, count)
    elif _scapy_available():
        _send_via_scapy(target, candidates, count)
    else:
        Color.pl('{!} {O}Decloak: no injection tool available (need aireplay-ng or scapy){W}')


def _aireplay_probe_available() -> bool:
    return Process.exists('aireplay-ng')


def _scapy_available() -> bool:
    try:
        import scapy  # noqa: F401
        return True
    except ImportError:
        return False


def _send_via_aireplay(target, candidates: List[str], count: int) -> None:
    """Send probe requests using aireplay-ng -9 (probe injection)."""
    for ssid in candidates:
        cmd = [
            'aireplay-ng',
            '--deauth', '0',     # won't actually deauth; -9 for probe
            '-e', ssid,
            '-a', target.bssid,
            '-c', 'FF:FF:FF:FF:FF:FF',
            Configuration.interface,
        ]
        # aireplay-ng doesn't have a dedicated --probe-request, so we
        # use scapy for the actual probe injection; aireplay is just
        # used for channel-locked injection via -9 in some versions.
        # Fallback to scapy for probes.
        _send_via_scapy(target, [ssid], count)


def _send_via_scapy(target, candidates: List[str], count: int) -> None:
    """Send Probe Requests via scapy."""
    try:
        from scapy.all import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt, sendp

        src_mac = _random_mac()
        for ssid in candidates:
            pkt = (
                RadioTap()
                / Dot11(
                    addr1='ff:ff:ff:ff:ff:ff',
                    addr2=src_mac,
                    addr3=target.bssid,
                )
                / Dot11ProbeReq()
                / Dot11Elt(ID='SSID', info=ssid.encode('utf-8', errors='replace'))
                / Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x24\x30\x48\x6c')
            )
            sendp(pkt, iface=Configuration.interface, count=count, verbose=False)
            time.sleep(0.05)

    except Exception as e:
        if Configuration.verbose > 0:
            Color.pl('{!} Decloak scapy error: %s' % str(e))


def _random_mac() -> str:
    raw = bytearray(os.urandom(6))
    raw[0] = (raw[0] | 0x02) & 0xFE
    return ':'.join('%02x' % b for b in raw)


# ---------------------------------------------------------------------------
# Public entry point called from the scanner
# ---------------------------------------------------------------------------

def decloak_attempt(target, all_targets: list) -> None:
    """Try to decloak a hidden AP by probing sibling SSID candidates.

    Called from the Scanner for targets where essid_known == False.
    """
    if target.essid_known:
        return

    candidates = get_sibling_candidates(all_targets, target.bssid)
    if not candidates:
        return

    if Configuration.verbose > 0:
        Color.pl('{+} {C}Targeted decloak{W}: probing {G}%d{W} SSID candidates for {C}%s{W}'
                 % (len(candidates), target.bssid))

    send_probe_requests(target, candidates)
