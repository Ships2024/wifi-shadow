#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""WPS lockout detection and adaptive backoff.

Two lock signals:
  * Explicit: AP-Setup-Locked IE in beacons (flag passed in from outside).
  * Heuristic: N consecutive EAP/WPS rejects *before* the AP judged a PIN half
    (for APs that lock silently without setting the beacon IE).

Backoff is measured, not a blind constant: we time how long the AP stays locked
and bias the next wait toward the observed duration, so each router converges on
its own real lockout period instead of a generic 60-second flat sleep.

Ported from wifit3/campaigns/wps/lock.py (GPLv2).
"""

from __future__ import annotations
import time
from typing import List


class LockTracker:
    """Track WPS lock state and compute adaptive backoff for one AP."""

    def __init__(
        self,
        strike_threshold: int = 3,
        min_wait: float = 30.0,
        max_wait: float = 360.0,
        initial_wait: float = 60.0,
    ) -> None:
        # How many consecutive pre-half rejects before we declare a silent lock.
        self.strike_threshold = strike_threshold
        self.min_wait = min_wait
        self.max_wait = max_wait
        self.initial_wait = initial_wait

        self.strikes: int = 0
        self._locked_since: float = 0.0
        self._observed_durations: List[float] = []

    # ------------------------------------------------------------------
    # Signal methods — call these as events arrive from the WPS attack loop
    # ------------------------------------------------------------------

    def note_progress(self) -> None:
        """A PIN half was judged (M5 or NACK after a valid PIN exchange): real
        progress, not a lock. Resets the silent-lock strike counter."""
        self.strikes = 0

    def note_reject_before_pin_answer(self) -> None:
        """AP sent a reject/NACK *before* judging a PIN half — potential silent lock."""
        self.strikes += 1

    def note_setup_locked(self) -> None:
        """AP beacon shows AP-Setup-Locked IE (config error 15): immediate lock."""
        self.strikes = self.strike_threshold

    # ------------------------------------------------------------------
    # State queries
    # ------------------------------------------------------------------

    def is_locked(self, beacon_locked: bool = False) -> bool:
        """True if we should pause the PIN sweep."""
        return beacon_locked or self.strikes >= self.strike_threshold

    # ------------------------------------------------------------------
    # Lock-period accounting
    # ------------------------------------------------------------------

    def begin_lock(self) -> None:
        """Call when we first detect a lock (before sleeping)."""
        if not self._locked_since:
            self._locked_since = time.monotonic()

    def end_lock(self) -> None:
        """Call when the AP appears unlocked again (resume sweep)."""
        if self._locked_since:
            duration = time.monotonic() - self._locked_since
            self._observed_durations.append(duration)
            self._locked_since = 0.0
        self.strikes = 0

    def backoff(self) -> float:
        """Suggested sleep duration (seconds) while the AP is locked.

        - No observations → use initial_wait (conservative default).
        - Has observations → bias toward the running average, clamped to [min, max].
        """
        if not self._observed_durations:
            return self.initial_wait

        avg = sum(self._observed_durations) / len(self._observed_durations)
        # Bias: 80% of observed average + 20% of the initial conservative guess.
        suggested = avg * 0.8 + self.initial_wait * 0.2
        return max(self.min_wait, min(self.max_wait, suggested))

    # ------------------------------------------------------------------
    # Convenience: blocking wait with progress output
    # ------------------------------------------------------------------

    def wait_for_unlock(self, beacon_locked_fn=None, verbose_fn=None) -> None:
        """Block until the lock clears, printing a countdown.

        Args:
            beacon_locked_fn: callable() → bool, returns current beacon lock state.
            verbose_fn: callable(str) to print status updates (defaults to print).
        """
        self.begin_lock()
        wait = self.backoff()
        log = verbose_fn or print
        deadline = time.time() + wait

        log('[!] WPS locked — waiting %.0fs before retrying' % wait)

        while time.time() < deadline:
            remaining = deadline - time.time()
            log('\r[!] WPS locked — resuming in %.0fs...   ' % remaining)
            time.sleep(min(5.0, remaining))

            if beacon_locked_fn and not beacon_locked_fn():
                # Beacon no longer shows locked — stop waiting early.
                log('\r[+] WPS lock cleared early.          ')
                break

        self.end_lock()
        log('')
