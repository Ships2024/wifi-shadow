#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""WPA/WPA2-PSK key derivation — pure Python, no external tools.

PMK  = PBKDF2-HMAC-SHA1(password, ssid, 4096, 32)
PTK  = PRF-512 over sorted MACs + sorted nonces
MIC  = HMAC-SHA1-128 over EAPOL payload (MIC field zeroed), keyed by KCK (PTK[:16])

Key descriptor version 2 (standard PSK/CCMP). Version 3 (PSK-SHA256 / AES-CMAC)
is not implemented.

Ported from wifit3/crack/wpa_psk.py (GPLv2).
"""

import hashlib
import hmac

_KCK_LEN = 16   # Key Confirmation Key: first 16 bytes of the 48-byte PTK


def pmk(psk: str, ssid: str) -> bytes:
    """Pairwise Master Key: PBKDF2-HMAC-SHA1 with 4096 iterations."""
    return hashlib.pbkdf2_hmac('sha1', psk.encode(), ssid.encode(), 4096, 32)


def _prf(key: bytes, label: bytes, data: bytes, nbytes: int) -> bytes:
    """IEEE 802.11 PRF (SHA1-based), output 'nbytes' bytes."""
    out = b''
    i = 0
    while len(out) < nbytes:
        out += hmac.new(key, label + b'\x00' + data + bytes([i]),
                        hashlib.sha1).digest()
        i += 1
    return out[:nbytes]


def ptk(pmk_bytes: bytes, aa: bytes, spa: bytes,
        anonce: bytes, snonce: bytes, nbytes: int = 48) -> bytes:
    """Pairwise Transient Key.

    AA  = AP MAC (6 bytes), SPA = client MAC (6 bytes).
    Both the MAC pair and the nonce pair are sorted so both sides derive the
    same PTK regardless of who speaks first.
    """
    data = min(aa, spa) + max(aa, spa) + min(anonce, snonce) + max(anonce, snonce)
    return _prf(pmk_bytes, b'Pairwise key expansion', data, nbytes)


def kck(ptk_bytes: bytes) -> bytes:
    return ptk_bytes[:_KCK_LEN]


def eapol_mic(kck_bytes: bytes, eapol_payload_mic_zeroed: bytes) -> bytes:
    """HMAC-SHA1-128 MIC (key descriptor version 2)."""
    return hmac.new(kck_bytes, eapol_payload_mic_zeroed, hashlib.sha1).digest()[:16]


def mic_for(psk: str, ssid: str,
            aa: bytes, spa: bytes,
            anonce: bytes, snonce: bytes,
            eapol_payload_mic_zeroed: bytes) -> bytes:
    """The M2 MIC a client with this PSK would produce."""
    k = kck(ptk(pmk(psk, ssid), aa, spa, anonce, snonce))
    return eapol_mic(k, eapol_payload_mic_zeroed)


def verify_psk(psk: str, ssid: str,
               ap_mac: str, client_mac: str,
               anonce: bytes, snonce: bytes,
               eapol_m2: bytes, mic_offset: int = 77) -> bool:
    """Verify a candidate PSK against a captured 4-way EAPOL M2.

    Args:
        psk:          Candidate passphrase.
        ssid:         Network name.
        ap_mac:       AP BSSID string ('AA:BB:CC:DD:EE:FF').
        client_mac:   Client station MAC string.
        anonce:       ANonce from M1 (32 bytes).
        snonce:       SNonce from M2 (32 bytes).
        eapol_m2:     Raw EAPOL M2 bytes.
        mic_offset:   Byte offset of the 16-byte MIC field in eapol_m2 (77 for standard EAPOL).

    Returns:
        True if the candidate PSK produces the correct MIC.
    """
    def _mac(s: str) -> bytes:
        return bytes(int(b, 16) for b in s.replace('-', ':').split(':'))

    aa  = _mac(ap_mac)
    spa = _mac(client_mac)

    # Zero the MIC field for verification
    zeroed = bytearray(eapol_m2)
    if len(zeroed) < mic_offset + 16:
        return False
    zeroed[mic_offset:mic_offset + 16] = b'\x00' * 16

    computed = mic_for(psk, ssid, aa, spa, anonce, snonce, bytes(zeroed))
    captured = eapol_m2[mic_offset:mic_offset + 16]
    return computed == captured
