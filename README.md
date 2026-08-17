# Wifi Shadow

**Automated wireless auditor for Linux — based on [wifite2](https://github.com/derv82/wifite2), enhanced with advanced attack logic.**

> **Repository:** https://github.com/Ships2024/wifi-shadow

Wifi Shadow is a complete rewrite and enhancement of the wifite2 wireless auditing tool. It keeps the same clean CLI-driven interface everyone knows, adds active PMKID harvesting, smarter WPS PIN attacks, WPA3 detection, adaptive lockout handling, hidden-network decloaking, and WPS PBC support — all running on top of the same aircrack-ng suite wifite2 uses.

---

## What's New in Wifi Shadow 3.0

These features go beyond the original wifite2:

**Active PMKID harvesting** — Instead of waiting passively for a client to associate, Wifi Shadow crafts Auth + Association frames via scapy and pulls the PMKID from the AP's EAPOL M1 message directly. Falls back to `hcxdumptool` if scapy is unavailable.

**BSSID-derived WPS seed PINs** — Before starting the full 11,000-guess WPS PIN sweep, Wifi Shadow computes up to 6 candidate PINs from the AP's BSSID using published algorithms: ComputePIN (Broadcom/Atheros/Ralink), Airocon (Realtek), D-Link (Heffner 2014), and ASUS (6-octet variant). Many routers are cracked in under a minute from a single seed guess.

**Adaptive WPS lockout detection** — A `LockTracker` tracks observed lockout durations and learns the AP's actual retry window, so wait times shrink over a session rather than always using a conservative fixed delay.

**WPA3 / Transition-mode detection** — RSN Information Elements are parsed live to detect AKM suites (PSK, SAE), PMF capability, and WPA3-Transition mode. The scan table shows WP3/WP3T labels so you know what you're targeting before you attack.

**WPS PBC (Push Button Connect) attack** — Wifi Shadow can impersonate a WPS enrollee and attempt a PBC session, which succeeds against APs advertising PBC active mode.

**Hidden AP decloaking** — For hidden networks, Wifi Shadow probes for sibling SSIDs by stripping and adding common suffixes (`-5G`, `-Guest`, `-IoT`, `-2.4`, etc.) so the real SSID is discovered without a deauth loop.

**hc22000 output** — Both PMKID captures and 4-way handshakes are saved in `.hc22000` format (hashcat `-m 22000`) in addition to the standard `.cap` format.

**Python 3.9+ / Kali-native** — All code is compatible with Python 3.9 through 3.13. No `distutils`, no `is`-with-literal warnings. Installs cleanly with `pip` or `setup.py` on the latest Kali.

---

## Supported Operating Systems

Wifi Shadow is designed and tested on the latest [**Kali Linux**](https://www.kali.org/). [ParrotSec](https://www.parrotsec.org/) is also supported.

Other distributions (BackBox, Ubuntu, Fedora) may work but are not actively tested. You need a kernel with patched wireless drivers that support monitor mode and packet injection.

---

## Required Tools

You need a wireless card that supports **monitor mode** and **packet injection**. See [Aircrack-ng's compatible cards list](https://www.aircrack-ng.org/doku.php?id=compatible_cards).

**Required:**

- `python3` (3.9 or later)
- [`iwconfig`](https://wiki.debian.org/iwconfig) — identifying wireless interfaces
- [`ifconfig`](https://en.wikipedia.org/wiki/Ifconfig) — starting and stopping interfaces
- [`airmon-ng`](https://www.aircrack-ng.org/doku.php?id=airmon-ng) — enabling monitor mode
- [`airodump-ng`](https://www.aircrack-ng.org/doku.php?id=airodump-ng) — target scanning and capture
- [`aireplay-ng`](https://www.aircrack-ng.org/doku.php?id=aireplay-ng) — deauth and replay attacks
- [`aircrack-ng`](https://www.aircrack-ng.org/doku.php?id=aircrack-ng) — cracking WEP and WPA captures
- [`packetforge-ng`](https://www.aircrack-ng.org/doku.php?id=packetforge-ng) — forging capture files for WEP attacks

**Optional, but recommended:**

- [`tshark`](https://www.wireshark.org/docs/man-pages/tshark.html) — WPS network detection and handshake validation
- [`reaver`](https://github.com/t6x/reaver-wps-fork-t6x) — WPS Pixie-Dust and PIN brute-force
- [`bully`](https://github.com/aanarchyy/bully) — WPS Pixie-Dust and PIN brute-force (alternative to reaver; use `--bully`)
- [`cowpatty`](https://github.com/joswr1ght/cowpatty) — handshake validation
- [`pyrit`](https://github.com/JPaulMora/Pyrit) — handshake validation
- [`hashcat`](https://hashcat.net/) — offline cracking of PMKID hashes and handshakes
- [`hcxdumptool`](https://github.com/ZerBea/hcxdumptool) — passive PMKID capture (fallback when scapy is unavailable)
- [`hcxtools`](https://github.com/ZerBea/hcxtools) — converting PMKID captures to hashcat format
- [`scapy`](https://scapy.net/) — active PMKID harvesting, WPS PBC, and hidden AP decloaking

Install scapy with:
```bash
sudo pip3 install scapy --break-system-packages
```

---

## Run Wifi Shadow

Clone and run directly — no install needed:

```bash
git clone https://github.com/Ships2024/wifi-shadow.git
cd wifi-shadow
sudo python3 wifi_shadow_run.py
```

For a specific interface:

```bash
sudo python3 wifi_shadow_run.py -i wlan0
```

Show all options:

```bash
sudo python3 wifi_shadow_run.py -h
```

---

## Install Wifi Shadow

Install system-wide so you can run `wifi-shadow` from any terminal:

```bash
git clone https://github.com/Ships2024/wifi-shadow.git
cd wifi-shadow
sudo pip3 install -e . --break-system-packages
```

Then run from anywhere:

```bash
sudo wifi-shadow
sudo wifi-shadow -i wlan0 --wps-only
```

To uninstall:

```bash
sudo pip3 uninstall wifi-shadow
```

---

## Attack Methods

| Method | Protocol | How it works |
|---|---|---|
| Active PMKID capture | WPA/2 | Forge Auth + Assoc frames; extract PMKID from AP's EAPOL M1 without needing a client |
| Passive PMKID capture | WPA/2 | `hcxdumptool` sniffs PMKIDs from genuine associations |
| 4-Way Handshake capture | WPA/2 | Deauth a client, capture the re-association handshake, crack offline |
| WPS Pixie-Dust | WPS | Offline attack against the AP's WPS nonces |
| WPS PIN (seed-first) | WPS | Try up to 6 BSSID-derived PINs before the full 11k sweep |
| WPS PIN (full sweep) | WPS | Online brute-force of the full WPS PIN keyspace (~11,000 guesses) |
| WPS PBC | WPS | Push-Button Connect enrollee impersonation |
| WEP replay | WEP | ARP replay, chopchop, fragment, hirte, caffe-latte |

---

## Feature List

- Active PMKID harvesting via scapy (no client required)
- BSSID-derived WPS seed PINs tried before full sweep (ComputePIN, Airocon, D-Link, ASUS)
- Adaptive WPS lockout — learns AP retry window over the session
- WPA3 / WPA3-Transition detection via live RSN IE parsing
- WPS PBC (Push Button Connect) attack support
- Hidden AP sibling-SSID decloaking via directed Probe Requests
- Saves captures as `.hc22000` (hashcat `-m 22000`) and `.cap`
- WPS Offline Pixie-Dust attack (`--wps-only --pixie`)
- WPS Online PIN brute-force (`--wps-only --no-pixie`)
- WPA/2 4-Way Handshake capture and offline crack (`--no-wps`)
- WEP attacks: replay, chopchop, fragment, hirte, p0841, caffe-latte
- Handshake validation against `pyrit`, `tshark`, `cowpatty`, and `aircrack-ng`
- 5GHz support (`-5`)
- Verbose mode to show every command being run (`-v`, `-vv`, `-vvv`)
- Stores all cracked passwords and captures to the current directory (`--cracked`)
- Offline crack mode for saved handshakes and PMKID hashes (`--crack`)

---

## Common Usage Examples

Attack all nearby targets automatically:
```bash
sudo wifi-shadow
```

Attack WPS-enabled networks only (Pixie-Dust first, then PIN):
```bash
sudo wifi-shadow --wps-only
```

Attack a specific target by BSSID:
```bash
sudo wifi-shadow --bssid AA:BB:CC:DD:EE:FF
```

PMKID attack only (no deauths):
```bash
sudo wifi-shadow --pmkid --no-deauths
```

Crack a previously captured handshake:
```bash
sudo wifi-shadow --crack --handshake path/to/handshake.cap --wordlist /usr/share/wordlists/rockyou.txt
```

Show cracked networks:
```bash
sudo wifi-shadow --cracked
```

---

## How It Compares to wifite2

Wifi Shadow is a drop-in replacement for wifite2 with all original functionality preserved. Everything new is additive:

| Feature | wifite2 | Wifi Shadow 3.0 |
|---|---|---|
| WPA handshake capture | ✓ | ✓ |
| PMKID capture (passive) | ✓ | ✓ |
| PMKID capture (active, no client) | ✗ | ✓ |
| WPS Pixie-Dust | ✓ | ✓ |
| WPS PIN brute-force | ✓ | ✓ |
| WPS seed PINs from BSSID | ✗ | ✓ |
| Adaptive WPS lockout | ✗ | ✓ |
| WPS PBC attack | ✗ | ✓ |
| WPA3 / WPA3-T detection | ✗ | ✓ |
| RSN IE parsing | ✗ | ✓ |
| Hidden AP sibling-SSID decloaking | ✗ | ✓ |
| hc22000 output format | ✗ | ✓ |
| WEP attacks | ✓ | ✓ |
| Python 3.9–3.13 | Partial | ✓ |

---

## Credits

- **wifite2** by [derv82](https://github.com/derv82/wifite2) — the foundation this project builds on
- WPS seed PIN algorithms from [bertof/WPS-pin-generator](https://github.com/nikita-yfh/WPS-pin-generator), [devttys0 write-ups](https://github.com/devttys0), and [3WiFi](https://3wifi.stascorp.com/wpspin)
- D-Link WPS PIN algorithm by Craig Heffner (devttys0), 2014
- Wifi Shadow enhancements by [Ships2024](https://github.com/Ships2024)

---

## License

GNU GPLv2 — see [LICENSE](LICENSE)
