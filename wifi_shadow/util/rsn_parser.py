#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""RSN (Robust Security Network) Information Element parser.

Parses the RSN IE (tag 48) from 802.11 beacon or probe-response frames to
extract AKM suites, cipher suites, PMF (802.11w) capability, and WPA3/SAE
detection.

This is a pure-Python parser that works on raw beacon bytes produced by
airodump-ng's Kismet-format CSV (the `Information Elements` field) or the
raw bytes from tshark/scapy.  No external dependencies required.

Usage (from airodump / tshark output):
    info = parse_rsn_ie(raw_ie_bytes)
    info.has_wpa3   → bool
    info.pmf_required → bool
    info.has_psk_akm  → bool
    info.akm_suites   → list of AKM suite OUI+type as ints
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional


# IEEE 802.11-2020 Table 9-151 AKM Suite Selectors (00-0F-AC OUI)
AKM_PSK          = 0x02   # WPA2-Personal (PSK)
AKM_SAE          = 0x08   # WPA3-Personal (SAE / Dragonfly)
AKM_PSK_SHA256   = 0x06   # PSK-SHA256
AKM_FT_PSK       = 0x04   # FT-PSK
AKM_1X           = 0x01   # 802.1X (Enterprise)
AKM_FT_1X        = 0x03   # FT-802.1X

# Capability bit positions (RSN Capabilities field)
RSN_CAP_PMF_REQUIRED  = 1 << 6   # bit 6: MFPR (Management Frame Protection Required)
RSN_CAP_PMF_CAPABLE   = 1 << 7   # bit 7: MFPC (Management Frame Protection Capable)

CISCO_CCX_OUI = b'\x00\x40\x96'
MICROSOFT_OUI = b'\x00\x50\xf2'
IEEE_OUI      = b'\x00\x0f\xac'


@dataclass
class RSNInfo:
    """Parsed content of an RSN IE."""
    group_cipher: Optional[int] = None         # group cipher suite type (00-0F-AC)
    pairwise_ciphers: List[int] = field(default_factory=list)
    akm_suites: List[int] = field(default_factory=list)
    pmf_capable: bool = False
    pmf_required: bool = False
    # Derived flags (set after parsing)
    has_psk_akm: bool = False
    has_sae_akm: bool = False
    has_wpa3: bool = False
    has_wpa3_transition: bool = False   # Both SAE and PSK offered


def parse_rsn_ie(data: bytes) -> Optional[RSNInfo]:
    """Parse an RSN IE body (tag 48, without the tag+length header).

    Returns RSNInfo, or None if the data is too short or malformed.
    """
    # RSN IE minimum: version(2) + group(4) + pairwise count(2) ≥ 8 bytes
    if not data or len(data) < 8:
        return None

    info = RSNInfo()
    pos = 0

    try:
        # Version (must be 1)
        _version = int.from_bytes(data[pos:pos+2], 'little')
        pos += 2

        # Group Cipher Suite (OUI[3] + type[1])
        if pos + 4 > len(data):
            return info
        _oui = data[pos:pos+3]
        info.group_cipher = data[pos+3]
        pos += 4

        # Pairwise Cipher Suite Count
        if pos + 2 > len(data):
            return info
        pw_count = int.from_bytes(data[pos:pos+2], 'little')
        pos += 2

        # Pairwise Cipher Suites
        for _ in range(pw_count):
            if pos + 4 > len(data):
                return info
            _oui = data[pos:pos+3]
            info.pairwise_ciphers.append(data[pos+3])
            pos += 4

        # AKM Suite Count
        if pos + 2 > len(data):
            return info
        akm_count = int.from_bytes(data[pos:pos+2], 'little')
        pos += 2

        # AKM Suites
        for _ in range(akm_count):
            if pos + 4 > len(data):
                return info
            oui = data[pos:pos+3]
            akm_type = data[pos+3]
            pos += 4
            # Only record standard IEEE AKMs (00-0F-AC)
            if oui == bytes([0x00, 0x0f, 0xac]):
                info.akm_suites.append(akm_type)

        # RSN Capabilities (2 bytes)
        if pos + 2 <= len(data):
            caps = int.from_bytes(data[pos:pos+2], 'little')
            info.pmf_capable  = bool(caps & RSN_CAP_PMF_CAPABLE)
            info.pmf_required = bool(caps & RSN_CAP_PMF_REQUIRED)

    except (IndexError, ValueError):
        pass  # Return what we have so far

    # Derive convenience flags
    info.has_psk_akm = any(a in (AKM_PSK, AKM_PSK_SHA256, AKM_FT_PSK)
                            for a in info.akm_suites)
    info.has_sae_akm = AKM_SAE in info.akm_suites
    info.has_wpa3 = info.has_sae_akm
    info.has_wpa3_transition = info.has_sae_akm and info.has_psk_akm

    return info


# ---------------------------------------------------------------------------
# Convenience: parse from the hex string that tshark outputs
# ---------------------------------------------------------------------------

def parse_rsn_ie_hex(hex_str: str) -> Optional[RSNInfo]:
    """Parse an RSN IE from a hex string (e.g. '30140100000fac040100...')."""
    try:
        raw = bytes.fromhex(hex_str.replace(':', '').replace(' ', ''))
    except ValueError:
        return None

    # Strip tag (0x30) and length byte if present
    if raw and raw[0] == 0x30 and len(raw) > 2:
        raw = raw[2:]

    return parse_rsn_ie(raw)


# ---------------------------------------------------------------------------
# Target enrichment — call this from airodump parsing or tshark integration
# ---------------------------------------------------------------------------

def enrich_target(target, rsn_info: RSNInfo) -> None:
    """Set WPA3 / PMF / AKM attributes on a wifi-shadow Target object.

    The target object is modified in-place. New attributes are set only if the
    target doesn't already have them, so partial data doesn't overwrite good data.
    """
    if rsn_info is None:
        return

    target.akm_suites   = getattr(target, 'akm_suites', []) or rsn_info.akm_suites
    target.pmf_capable  = getattr(target, 'pmf_capable', False) or rsn_info.pmf_capable
    target.pmf_required = getattr(target, 'pmf_required', False) or rsn_info.pmf_required
    target.has_wpa3     = getattr(target, 'has_wpa3', False) or rsn_info.has_wpa3
    target.has_wpa3_transition = (
        getattr(target, 'has_wpa3_transition', False) or rsn_info.has_wpa3_transition
    )
    target.has_psk_akm  = getattr(target, 'has_psk_akm', False) or rsn_info.has_psk_akm
    target.has_sae_akm  = getattr(target, 'has_sae_akm', False) or rsn_info.has_sae_akm


def wpa3_label(target) -> str:
    """Short display label for WPA3 state (for the scanner table)."""
    has_wpa3 = getattr(target, 'has_wpa3', False)
    transition = getattr(target, 'has_wpa3_transition', False)
    pmf_req = getattr(target, 'pmf_required', False)

    if not has_wpa3:
        return ''
    if transition:
        return 'WPA3-T'  # Transition mode (SAE+PSK)
    if pmf_req:
        return 'WPA3'
    return 'WPA3'


def attack_notes(target) -> list:
    """Return a list of warning strings for targets that limit attack options."""
    notes = []
    pmf_req = getattr(target, 'pmf_required', False)
    has_sae = getattr(target, 'has_sae_akm', False)
    has_psk = getattr(target, 'has_psk_akm', False)
    transition = getattr(target, 'has_wpa3_transition', False)

    if pmf_req and not transition:
        notes.append('PMF required — PMKID harvest skipped')
    if has_sae and not has_psk:
        notes.append('SAE-only (WPA3) — no PSK AKM to harvest')
    return notes
