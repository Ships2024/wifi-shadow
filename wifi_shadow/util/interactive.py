#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Interactive curses-based target picker and attack-mode selector.

Replaces the plain-text number prompt with:
  - Arrow-key navigation through the scan list
  - Space to toggle multi-select
  - Number keys to jump directly to a target
  - A to select all / deselect all
  - Enter to confirm selection
  - Q / Ctrl+C to quit

After targets are confirmed a one-key attack-mode menu is shown:
  A  All attacks        (default)
  P  PMKID only
  W  WPS only           (Pixie-Dust + PIN)
  X  Pixie-Dust only
  N  PIN brute-force only
  H  WPA Handshake only
  E  WEP only
  Enter = A

Falls back to the legacy text prompt automatically when:
  - stdout/stdin is not a real TTY
  - The terminal is too small (< 5 rows)
  - Any curses error occurs
"""

from __future__ import annotations

import curses
import os
import sys
import termios
import tty
from typing import List, Optional, Tuple

from ..util.color import Color

# ---------------------------------------------------------------------------
# Attack-mode constants — returned by pick_attack_mode()
# ---------------------------------------------------------------------------

MODE_ALL        = 'all'
MODE_PMKID      = 'pmkid'
MODE_WPS        = 'wps'
MODE_PIXIE      = 'pixie'
MODE_PIN        = 'pin'
MODE_HANDSHAKE  = 'handshake'
MODE_WEP        = 'wep'

_MODE_KEYS = {
    ord('a'): MODE_ALL,       ord('A'): MODE_ALL,
    ord('p'): MODE_PMKID,     ord('P'): MODE_PMKID,
    ord('w'): MODE_WPS,       ord('W'): MODE_WPS,
    ord('x'): MODE_PIXIE,     ord('X'): MODE_PIXIE,
    ord('n'): MODE_PIN,       ord('N'): MODE_PIN,
    ord('h'): MODE_HANDSHAKE, ord('H'): MODE_HANDSHAKE,
    ord('e'): MODE_WEP,       ord('E'): MODE_WEP,
    ord('\n'): MODE_ALL,      ord('\r'): MODE_ALL,
}

_MODE_LABELS = [
    ('[A] All attacks ', MODE_ALL),
    ('[P] PMKID only  ', MODE_PMKID),
    ('[W] WPS only    ', MODE_WPS),
    ('[X] Pixie-Dust  ', MODE_PIXIE),
    ('[N] PIN brute   ', MODE_PIN),
    ('[H] Handshake   ', MODE_HANDSHAKE),
    ('[E] WEP only    ', MODE_WEP),
]

# ---------------------------------------------------------------------------
# Column widths
# ---------------------------------------------------------------------------

_COL_NUM   = 4
_COL_ESSID = 28
_COL_BSSID = 19
_COL_CH    = 4
_COL_ENC   = 6
_COL_PWR   = 6
_COL_WPS   = 5
_COL_CLI   = 4

_MIN_WIDTH  = _COL_NUM + _COL_ESSID + _COL_BSSID + _COL_CH + _COL_ENC + _COL_PWR + _COL_WPS + 6
_MIN_HEIGHT = 7


def _is_tty() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


# ---------------------------------------------------------------------------
# Curses colour pairs
# ---------------------------------------------------------------------------

_CP_NORMAL    = 1   # white on black
_CP_HEADER    = 2   # bright cyan on black
_CP_CURSOR    = 3   # black on green (highlighted row)
_CP_SELECTED  = 4   # bright yellow on black
_CP_HINT      = 5   # dark/dim on black
_CP_WPS_YES   = 6   # bright green
_CP_ENC_WEP   = 7   # red
_CP_ENC_WPA   = 8   # yellow
_CP_ENC_WPA3  = 9   # cyan


def _init_colours() -> None:
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(_CP_NORMAL,   curses.COLOR_WHITE,  -1)
    curses.init_pair(_CP_HEADER,   curses.COLOR_CYAN,   -1)
    curses.init_pair(_CP_CURSOR,   curses.COLOR_BLACK,  curses.COLOR_GREEN)
    curses.init_pair(_CP_SELECTED, curses.COLOR_YELLOW, -1)
    curses.init_pair(_CP_HINT,     curses.COLOR_WHITE,  -1)
    curses.init_pair(_CP_WPS_YES,  curses.COLOR_GREEN,  -1)
    curses.init_pair(_CP_ENC_WEP,  curses.COLOR_RED,    -1)
    curses.init_pair(_CP_ENC_WPA,  curses.COLOR_YELLOW, -1)
    curses.init_pair(_CP_ENC_WPA3, curses.COLOR_CYAN,   -1)


# ---------------------------------------------------------------------------
# Row builder
# ---------------------------------------------------------------------------

def _fmt(s: str, width: int) -> str:
    """Truncate or pad string to exactly `width` characters."""
    s = str(s) if s else ''
    if len(s) > width:
        s = s[:width - 1] + '…'
    return s.ljust(width)


def _target_row(target, idx: int, selected: bool, cursor: bool, width: int) -> List[Tuple[str, int]]:
    """
    Return list of (text, colour_attr) segments for one target row.
    Caller writes each segment with addstr.
    """
    from ..model.target import WPSState

    sel_mark  = '[✓]' if selected else '[ ]'
    num_str   = str(idx).rjust(3)

    essid_raw = target.essid if getattr(target, 'essid_known', True) else '<hidden>'
    essid     = _fmt(essid_raw, _COL_ESSID)
    bssid     = _fmt(getattr(target, 'bssid', ''), _COL_BSSID)
    ch        = _fmt(str(getattr(target, 'channel', '?')), _COL_CH)
    enc_raw   = getattr(target, 'encryption', '???')
    enc       = _fmt(enc_raw, _COL_ENC)

    power_raw = getattr(target, 'power', 0)
    pwr       = _fmt(str(power_raw) if power_raw else '?', _COL_PWR)

    wps_state = getattr(target, 'wps', False)
    if wps_state in (True,) or str(wps_state) in ('WPSState.UNLOCKED', 'UNLOCKED'):
        wps_str = 'YES'
    elif str(wps_state) in ('WPSState.LOCKED', 'LOCKED'):
        wps_str = 'LOCK'
    else:
        wps_str = 'NO'
    wps = _fmt(wps_str, _COL_WPS)

    cli_count = len(getattr(target, 'clients', []))
    cli = _fmt(str(cli_count) if cli_count else '', _COL_CLI)

    base_attr = curses.color_pair(_CP_CURSOR) if cursor else curses.color_pair(_CP_NORMAL)
    sel_attr  = (curses.color_pair(_CP_CURSOR) | curses.A_BOLD) if cursor else \
                (curses.color_pair(_CP_SELECTED) | curses.A_BOLD) if selected else \
                curses.color_pair(_CP_NORMAL)

    # Encryption colour
    if 'WEP' in enc_raw:
        enc_attr = curses.color_pair(_CP_ENC_WEP) | curses.A_BOLD
    elif 'WPA3' in enc_raw or 'SAE' in enc_raw:
        enc_attr = curses.color_pair(_CP_ENC_WPA3) | curses.A_BOLD
    elif 'WPA' in enc_raw:
        enc_attr = curses.color_pair(_CP_ENC_WPA) | curses.A_BOLD
    else:
        enc_attr = base_attr

    if cursor:
        enc_attr = base_attr  # keep readable on green row

    wps_attr = (curses.color_pair(_CP_WPS_YES) | curses.A_BOLD) \
               if wps_str in ('YES',) and not cursor else base_attr

    return [
        (' ', base_attr),
        (sel_mark + ' ', sel_attr),
        (num_str + '  ', base_attr),
        (essid + ' ', base_attr),
        (bssid + ' ', base_attr),
        (ch + ' ', base_attr),
        (enc + ' ', enc_attr),
        (pwr + ' ', base_attr),
        (wps + ' ', wps_attr),
        (cli, base_attr),
    ]


# ---------------------------------------------------------------------------
# Main curses picker
# ---------------------------------------------------------------------------

def _curses_pick(stdscr, targets) -> Optional[List]:
    """Run inside curses.wrapper(). Returns selected targets or None (quit)."""
    _init_colours()
    curses.curs_set(0)
    stdscr.keypad(True)
    stdscr.timeout(500)  # refresh every 500ms even without keypress

    cursor    = 0
    selected  = set()
    scroll    = 0   # first visible row index

    while True:
        stdscr.erase()
        rows, cols = stdscr.getmaxyx()

        if rows < _MIN_HEIGHT or cols < 40:
            stdscr.addstr(0, 0, 'Terminal too small — resize and retry.')
            stdscr.refresh()
            k = stdscr.getch()
            if k in (ord('q'), ord('Q'), 27):
                return None
            continue

        n = len(targets)
        visible = rows - 5   # header(2) + separator(1) + hint(1) + bottom pad(1)
        if visible < 1:
            visible = 1

        # Clamp cursor
        if cursor >= n:
            cursor = max(0, n - 1)

        # Auto-scroll
        if cursor < scroll:
            scroll = cursor
        if cursor >= scroll + visible:
            scroll = cursor - visible + 1

        # ── Header ──────────────────────────────────────────────────────────
        title = ' wifi-shadow  ─  select targets  ─  %d found ' % n
        stdscr.attron(curses.color_pair(_CP_HEADER) | curses.A_BOLD)
        stdscr.addstr(0, 0, title.ljust(cols))
        stdscr.attroff(curses.color_pair(_CP_HEADER) | curses.A_BOLD)

        # ── Column headers ───────────────────────────────────────────────────
        hdr = (' SEL  NUM  ' +
               _fmt('ESSID', _COL_ESSID) + ' ' +
               _fmt('BSSID', _COL_BSSID) + ' ' +
               _fmt('CH', _COL_CH) + ' ' +
               _fmt('ENC', _COL_ENC) + ' ' +
               _fmt('PWR', _COL_PWR) + ' ' +
               _fmt('WPS', _COL_WPS) + ' CLI')
        stdscr.attron(curses.color_pair(_CP_HEADER))
        stdscr.addstr(1, 0, hdr[:cols - 1].ljust(cols - 1))
        stdscr.attroff(curses.color_pair(_CP_HEADER))

        sep = '─' * (cols - 1)
        stdscr.attron(curses.color_pair(_CP_HINT) | curses.A_DIM)
        try:
            stdscr.addstr(2, 0, sep)
        except curses.error:
            pass
        stdscr.attroff(curses.color_pair(_CP_HINT) | curses.A_DIM)

        # ── Target rows ──────────────────────────────────────────────────────
        for row_idx in range(visible):
            t_idx = scroll + row_idx
            if t_idx >= n:
                break
            target  = targets[t_idx]
            is_cur  = (t_idx == cursor)
            is_sel  = (t_idx in selected)
            segs    = _target_row(target, t_idx + 1, is_sel, is_cur, cols)
            y = 3 + row_idx
            x = 0
            for text, attr in segs:
                if x >= cols - 1:
                    break
                clip = text[:cols - 1 - x]
                try:
                    stdscr.addstr(y, x, clip, attr)
                except curses.error:
                    pass
                x += len(clip)

        # ── Scroll indicator ─────────────────────────────────────────────────
        if n > visible:
            pct = int(100 * scroll / max(1, n - visible))
            si = ' ↕ %d%% ' % pct
            try:
                stdscr.addstr(3, cols - len(si) - 1, si,
                               curses.color_pair(_CP_HINT) | curses.A_DIM)
            except curses.error:
                pass

        # ── Hint bar ─────────────────────────────────────────────────────────
        sel_count = len(selected)
        hint = (' ↑/↓ move   Space select   A all   '
                '1-9 jump   Enter confirm   Q quit')
        if sel_count:
            hint = ' %d selected —%s' % (sel_count, hint)
        stdscr.attron(curses.color_pair(_CP_HINT) | curses.A_REVERSE)
        try:
            stdscr.addstr(rows - 1, 0, hint[:cols - 1].ljust(cols - 1))
        except curses.error:
            pass
        stdscr.attroff(curses.color_pair(_CP_HINT) | curses.A_REVERSE)

        stdscr.refresh()

        # ── Input ─────────────────────────────────────────────────────────────
        k = stdscr.getch()
        if k == -1:
            continue  # timeout — just refresh

        # Quit
        if k in (ord('q'), ord('Q'), 27):  # q / Q / Esc
            return None

        # Navigate
        elif k in (curses.KEY_UP, ord('k'), ord('K')):
            cursor = (cursor - 1) % n

        elif k in (curses.KEY_DOWN, ord('j'), ord('J')):
            cursor = (cursor + 1) % n

        elif k == curses.KEY_PPAGE:
            cursor = max(0, cursor - visible)

        elif k == curses.KEY_NPAGE:
            cursor = min(n - 1, cursor + visible)

        elif k == curses.KEY_HOME:
            cursor = 0

        elif k == curses.KEY_END:
            cursor = n - 1

        # Number jump (1-9)
        elif ord('1') <= k <= ord('9'):
            idx = k - ord('1')
            if idx < n:
                cursor = idx

        # Select / deselect current
        elif k == ord(' '):
            if cursor in selected:
                selected.discard(cursor)
            else:
                selected.add(cursor)
            # Auto-advance after toggle
            if cursor < n - 1:
                cursor += 1

        # Select / deselect all
        elif k in (ord('a'), ord('A')):
            if len(selected) == n:
                selected.clear()
            else:
                selected = set(range(n))

        # Confirm
        elif k in (ord('\n'), ord('\r'), curses.KEY_ENTER):
            if not selected:
                # If nothing explicitly selected, use the highlighted row
                selected = {cursor}
            return [targets[i] for i in sorted(selected)]


# ---------------------------------------------------------------------------
# Attack-mode picker (plain terminal, no curses needed)
# ---------------------------------------------------------------------------

def _getch_raw() -> int:
    """Read a single byte from stdin in raw mode."""
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
    return ord(ch) if ch else 0


def pick_attack_mode(target_count: int) -> str:
    """
    Print one-key attack-mode menu and return a MODE_* constant.
    Falls back to MODE_ALL if not a TTY or on any error.
    """
    if not _is_tty():
        return MODE_ALL

    try:
        lines = [
            '',
            Color.s('{+} Attack mode for {G}%d{W} target(s) — press a key:' % target_count),
            '',
        ]
        # Two columns
        half = len(_MODE_LABELS) // 2 + len(_MODE_LABELS) % 2
        for i in range(half):
            left  = _MODE_LABELS[i]
            right = _MODE_LABELS[i + half] if i + half < len(_MODE_LABELS) else None
            left_s  = Color.s('  {G}%s{W}' % left[0])
            right_s = Color.s('  {G}%s{W}' % right[0]) if right else ''
            lines.append(left_s + right_s)

        lines += [
            '',
            Color.s('  {D}Enter = All attacks (default){W}'),
            '',
        ]
        for line in lines:
            print(line)

        sys.stdout.flush()
        k = _getch_raw()
        mode = _MODE_KEYS.get(k, MODE_ALL)

        # Echo choice
        label = next((lbl for lbl, m in _MODE_LABELS if m == mode), 'All attacks')
        Color.pl('{+} Mode: {G}%s{W}' % label.strip())
        print()
        return mode

    except Exception:
        return MODE_ALL


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def interactive_select(targets) -> Tuple[Optional[List], str]:
    """
    Show interactive curses picker then attack-mode menu.

    Returns:
        (chosen_targets, attack_mode)
        chosen_targets is None if the user quit.
        attack_mode is one of the MODE_* constants.
    """
    if not _is_tty() or not targets:
        return None, MODE_ALL  # caller falls back to text prompt

    try:
        chosen = curses.wrapper(_curses_pick, targets)
    except Exception:
        return None, MODE_ALL  # fall back silently

    if chosen is None:
        return None, MODE_ALL

    mode = pick_attack_mode(len(chosen))
    return chosen, mode
