#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .wep import AttackWEP
from .wpa import AttackWPA
from .wps import AttackWPS
from .pmkid import AttackPMKID
from ..config import Configuration
from ..util.color import Color

# Attack-mode constants (mirrors interactive.py — duplicated to avoid circular import)
_MODE_ALL       = 'all'
_MODE_PMKID     = 'pmkid'
_MODE_WPS       = 'wps'
_MODE_PIXIE     = 'pixie'
_MODE_PIN       = 'pin'
_MODE_HANDSHAKE = 'handshake'
_MODE_WEP       = 'wep'

# Optional WPS PBC attack (requires scapy)
try:
    from .wps_pbc import AttackWPSPBC
    _WPS_PBC_AVAILABLE = True
except ImportError:
    _WPS_PBC_AVAILABLE = False

class AttackAll(object):

    @classmethod
    def apply_attack_mode(cls, mode: str) -> None:
        """
        Translate a one-key mode shortcut into Configuration flag overrides.
        Called once before the attack loop so every target in the batch
        uses the same mode the user chose in the interactive picker.
        """
        if mode in (None, _MODE_ALL, ''):
            return  # Nothing to override — use whatever flags are already set

        if mode == _MODE_PMKID:
            Configuration.use_pmkid_only = True
            Configuration.wps_only       = False

        elif mode == _MODE_WPS:
            Configuration.wps_only   = True
            Configuration.wps_pixie  = True
            Configuration.wps_pin    = True

        elif mode == _MODE_PIXIE:
            Configuration.wps_only   = True
            Configuration.wps_pixie  = True
            Configuration.wps_pin    = False

        elif mode == _MODE_PIN:
            Configuration.wps_only   = True
            Configuration.wps_pixie  = False
            Configuration.wps_pin    = True

        elif mode == _MODE_HANDSHAKE:
            Configuration.wps_only        = False
            Configuration.use_pmkid_only  = False
            # Signal to attack_single to skip PMKID and WPS
            Configuration._handshake_only = True

        elif mode == _MODE_WEP:
            Configuration._wep_only = True

        label = {
            _MODE_PMKID:     'PMKID only',
            _MODE_WPS:       'WPS only (Pixie + PIN)',
            _MODE_PIXIE:     'WPS Pixie-Dust only',
            _MODE_PIN:       'WPS PIN brute-force only',
            _MODE_HANDSHAKE: 'WPA Handshake only',
            _MODE_WEP:       'WEP only',
        }.get(mode, mode)
        Color.pl('{+} Attack mode: {G}%s{W}' % label)

    @classmethod
    def attack_multiple(cls, targets, attack_mode: str = _MODE_ALL):
        '''
        Attacks all given `targets` (list[wifi_shadow.model.target]) until user interruption.
        attack_mode: one of the MODE_* constants from interactive.py / _MODE_* above.
        Returns: Number of targets that were attacked (int)
        '''
        cls.apply_attack_mode(attack_mode)

        if any(t.wps for t in targets) and not AttackWPS.can_attack_wps():
            Color.pl('{!} {O}Note: WPS attacks are not possible because you do not have {C}reaver{O} nor {C}bully{W}')

        attacked_targets = 0
        targets_remaining = len(targets)
        for index, target in enumerate(targets, start=1):
            attacked_targets += 1
            targets_remaining -= 1

            bssid = target.bssid
            essid = target.essid if target.essid_known else '{O}ESSID unknown{W}'

            Color.pl('\n{+} ({G}%d{W}/{G}%d{W})' % (index, len(targets)) +
                     ' Starting attacks against {C}%s{W} ({C}%s{W})' % (bssid, essid))

            should_continue = cls.attack_single(target, targets_remaining)
            if not should_continue:
                break

        return attacked_targets

    @classmethod
    def attack_single(cls, target, targets_remaining):
        '''
        Attacks a single `target` (wifi_shadow.model.target).
        Returns: True if attacks should continue, False otherwise.
        '''

        attacks = []

        handshake_only = getattr(Configuration, '_handshake_only', False)
        wep_only       = getattr(Configuration, '_wep_only', False)

        if Configuration.use_eviltwin:
            # TODO: EvilTwin attack
            pass

        elif 'WEP' in target.encryption:
            attacks.append(AttackWEP(target))

        elif 'WPA' in target.encryption:
            if wep_only:
                pass  # user chose WEP mode but this is a WPA target — skip

            elif handshake_only:
                # Only the 4-way handshake capture, no WPS or PMKID
                attacks.append(AttackWPA(target))

            else:
                # WPA can have multiple attack vectors:

                # WPS PBC (Push-Button) — opportunistic, only if PBC window is active
                if (not Configuration.no_wps and Configuration.wps_pbc
                        and _WPS_PBC_AVAILABLE
                        and getattr(target, 'wps_pbc_active', False)):
                    attacks.append(AttackWPSPBC(target))

                # WPS
                if not Configuration.use_pmkid_only:
                    if target.wps != False and AttackWPS.can_attack_wps():
                        # Pixie-Dust
                        if Configuration.wps_pixie:
                            attacks.append(AttackWPS(target, pixie_dust=True))

                        # PIN attack
                        if Configuration.wps_pin:
                            attacks.append(AttackWPS(target, pixie_dust=False))

                if not Configuration.wps_only:
                    # PMKID
                    attacks.append(AttackPMKID(target))

                    # Handshake capture
                    if not Configuration.use_pmkid_only:
                        attacks.append(AttackWPA(target))

        if len(attacks) == 0:
            Color.pl('{!} {R}Error: {O}Unable to attack: no attacks available')
            return True  # Keep attacking other targets (skip)

        while len(attacks) > 0:
            attack = attacks.pop(0)
            try:
                result = attack.run()
                if result:
                    break  # Attack was successful, stop other attacks.
            except Exception as e:
                Color.pexception(e)
                continue
            except KeyboardInterrupt:
                Color.pl('\n{!} {O}Interrupted{W}\n')
                answer = cls.user_wants_to_continue(targets_remaining, len(attacks))
                if answer is True:
                    continue  # Keep attacking the same target (continue)
                elif answer is None:
                    return True  # Keep attacking other targets (skip)
                else:
                    return False  # Stop all attacks (exit)

        if attack.success:
            attack.crack_result.save()

        return True  # Keep attacking other targets


    @classmethod
    def user_wants_to_continue(cls, targets_remaining, attacks_remaining=0):
        '''
        Asks user if attacks should continue onto other targets
        Returns:
            True if user wants to continue, False otherwise.
        '''
        if attacks_remaining == 0 and targets_remaining == 0:
            return  # No targets or attacksleft, drop out

        prompt_list = []
        if attacks_remaining > 0:
            prompt_list.append(Color.s('{C}%d{W} attack(s)' % attacks_remaining))
        if targets_remaining > 0:
            prompt_list.append(Color.s('{C}%d{W} target(s)' % targets_remaining))
        prompt = ' and '.join(prompt_list) + ' remain'
        Color.pl('{+} %s' % prompt)

        prompt = '{+} Do you want to'
        options = '('

        if attacks_remaining > 0:
            prompt += ' {G}continue{W} attacking,'
            options += '{G}C{W}{D}, {W}'

        if targets_remaining > 0:
            prompt += ' {O}skip{W} to the next target,'
            options += '{O}s{W}{D}, {W}'

        options += '{R}e{W})'
        prompt += ' or {R}exit{W} %s? {C}' % options

        from ..util.input import raw_input
        answer = raw_input(Color.s(prompt)).lower()

        if answer.startswith('s'):
            return None  # Skip
        elif answer.startswith('e'):
            return False  # Exit
        else:
            return True  # Continue

