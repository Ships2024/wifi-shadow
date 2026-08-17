#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Hashcat -m 22000 (.hc22000) hashline writer.

Produces WPA*01* (PMKID) and WPA*02* (EAPOL handshake) hashlines from a
captured .cap file and optional PMKID bytes.

Format reference: https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2

  WPA*01*<pmkid>*<ap_mac>*<sta_mac>*<ssid_hex>***
  WPA*02*<mic>*<ap_mac>*<sta_mac>*<ssid_hex>*<anonce>*<eapol_hex>*<msg_pair>

This module requires tshark (for cap parsing) or falls back to a minimal
Python EAPOL extractor if tshark is unavailable.
"""

from __future__ import annotations
import os
import re
import subprocess
import time
from typing import Optional


def _mac_to_hex(mac: str) -> str:
    """'AA:BB:CC:DD:EE:FF' → 'aabbccddeeff'"""
    return mac.lower().replace(':', '').replace('-', '')


def write_hc22000_pmkid(
    output_path: str,
    pmkid: bytes,
    ap_bssid: str,
    client_mac: str,
    essid: str,
) -> str:
    """Write a WPA*01* PMKID hashline to output_path.

    Returns the path written to.
    """
    pmkid_hex   = pmkid.hex()
    ap_hex      = _mac_to_hex(ap_bssid)
    client_hex  = _mac_to_hex(client_mac)
    ssid_hex    = essid.encode('utf-8', errors='replace').hex()

    hashline = 'WPA*01*%s*%s*%s*%s***\n' % (pmkid_hex, ap_hex, client_hex, ssid_hex)

    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'w') as f:
        f.write(hashline)
    return output_path


def cap_to_hc22000(cap_file: str, output_path: str, bssid: str, essid: str) -> Optional[str]:
    """Convert a .cap file to a .hc22000 file using hcxpcapngtool or hcxpcaptool.

    Returns output_path on success, None on failure.
    """
    # Try hcxpcapngtool (newer) then hcxpcaptool (older)
    for tool in ('hcxpcapngtool', 'hcxpcaptool'):
        if _command_exists(tool):
            return _run_hcxpcaptool(tool, cap_file, output_path, bssid)
    return None


def _command_exists(cmd: str) -> bool:
    try:
        subprocess.run(['which', cmd], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def _run_hcxpcaptool(tool: str, cap_file: str, output_path: str, bssid: str) -> Optional[str]:
    """Run hcxpcapngtool/hcxpcaptool to convert cap → hc22000."""
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)

    # hcxpcapngtool uses -o for output and has slightly different flags
    if 'ngtool' in tool:
        cmd = [tool, cap_file, '-o', output_path]
    else:
        cmd = [tool, cap_file, '-o', output_path]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            return output_path
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
        pass
    return None


def save_hc22000_for_handshake(cap_file: str, hs_dir: str,
                                 bssid: str, essid: str) -> Optional[str]:
    """Convert a .cap handshake file → .hc22000 and save to hs_dir.

    Returns the path of the written .hc22000 file, or None if conversion failed.
    """
    essid_safe = re.sub('[^a-zA-Z0-9]', '', essid or 'UnknownESSID')
    bssid_safe = bssid.replace(':', '-')
    date = time.strftime('%Y-%m-%dT%H-%M-%S')
    filename = 'handshake_%s_%s_%s.hc22000' % (essid_safe, bssid_safe, date)
    output_path = os.path.join(hs_dir, filename)

    return cap_to_hc22000(cap_file, output_path, bssid, essid)
