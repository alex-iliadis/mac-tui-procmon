"""GUI/TUI flow-path tests — simulates every keypress sequence (the
"click paths") through the curses event loop that previous integration
tests left uncovered.

Each test follows the same shape:
    1. Put the monitor into the mode under test.
    2. Press a single key (or sequence) via handle_input.
    3. Assert observable state change.

Modes covered: main list, inspect, hidden_scan, keyscan, audit,
bulk_scan, events, traffic, plus main-mode triage / secauditor-bridge
hotkeys and the Escape-closes-special-mode chain.
"""
import curses
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import procmon
from tests.conftest import make_proc


@pytest.fixture(autouse=True)
def _mock_curses():
    with patch("curses.color_pair", side_effect=lambda n: n), \
         patch("curses.curs_set", return_value=None):
        yield


# ── Hidden-scan mode: paging keys ────────────────────────────────────────


class TestHiddenScanPaging:
    def _enter(self, monitor):
        monitor._hidden_scan_mode = True
        monitor._detail_focus = True
        monitor._hidden_scan_scroll = 0
        monitor._hidden_scan_lines = ["l%d" % i for i in range(50)]
        monitor.stdscr.getmaxyx.return_value = (30, 120)

    def test_page_down_jumps_scroll(self, monitor):
        self._enter(monitor)
        monitor.handle_input(curses.KEY_NPAGE)
        assert monitor._hidden_scan_scroll == monitor._page_size()

    def test_page_up_clamps_to_zero(self, monitor):
        self._enter(monitor)
        monitor._hidden_scan_scroll = 5
        monitor.handle_input(curses.KEY_PPAGE)
        assert monitor._hidden_scan_scroll == 0

    def test_page_up_scrolls_back(self, monitor):
        self._enter(monitor)
        monitor._hidden_scan_scroll = 50
        monitor.handle_input(curses.KEY_PPAGE)
        assert monitor._hidden_scan_scroll == 50 - monitor._page_size()


# ── Keyscan mode: scroll fallback + paging ───────────────────────────────


class TestKeyscanScrollFallback:
    """When _keyscan_findings_structured is empty, UP/DOWN fall back to
    raw scroll instead of moving a structured cursor."""

    def _enter(self, monitor, structured=False):
        monitor._keyscan_mode = True
        monitor._detail_focus = True
        monitor._keyscan_findings_structured = (
            [{"severity": "HIGH", "message": "x"}] if structured else [])
        monitor._keyscan_scroll = 0
        monitor._keyscan_cursor = 0
        monitor._keyscan_lines = ["l%d" % i for i in range(50)]
        monitor.stdscr.getmaxyx.return_value = (30, 120)

    def test_up_falls_back_to_scroll_when_unstructured(self, monitor):
        self._enter(monitor, structured=False)
        monitor._keyscan_scroll = 3
        monitor.handle_input(curses.KEY_UP)
        assert monitor._keyscan_scroll == 2

    def test_up_clamps_at_zero_in_fallback(self, monitor):
        self._enter(monitor, structured=False)
        monitor._keyscan_scroll = 0
        monitor.handle_input(curses.KEY_UP)
        assert monitor._keyscan_scroll == 0

    def test_down_falls_back_to_scroll_when_unstructured(self, monitor):
        self._enter(monitor, structured=False)
        monitor.handle_input(curses.KEY_DOWN)
        assert monitor._keyscan_scroll == 1

    def test_page_down_jumps_scroll(self, monitor):
        self._enter(monitor, structured=False)
        monitor.handle_input(curses.KEY_NPAGE)
        assert monitor._keyscan_scroll == monitor._page_size()

    def test_page_up_clamps_at_zero(self, monitor):
        self._enter(monitor, structured=False)
        monitor._keyscan_scroll = 4
        monitor.handle_input(curses.KEY_PPAGE)
        assert monitor._keyscan_scroll == 0


# ── Audit mode: every key handler ─────────────────────────────────────────


class TestAuditModeKeys:
    def _enter(self, monitor, structured=False):
        monitor._audit_mode = True
        monitor._detail_focus = True
        monitor._audit_lines = ["finding %d" % i for i in range(60)]
        monitor._audit_scroll = 0
        monitor._audit_cursor = 0
        monitor._audit_findings_structured = (
            [{"severity": "HIGH", "message": "x", "action": None}]
            if structured else [])
        monitor._audit_line_for_finding = [0] if structured else []
        monitor.stdscr.getmaxyx.return_value = (30, 120)

    def test_up_falls_back_to_scroll_when_unstructured(self, monitor):
        self._enter(monitor, structured=False)
        monitor._audit_scroll = 4
        monitor.handle_input(curses.KEY_UP)
        assert monitor._audit_scroll == 3

    def test_up_calls_move_cursor_when_structured(self, monitor):
        self._enter(monitor, structured=True)
        with patch.object(monitor, "_audit_move_cursor") as mv:
            monitor.handle_input(curses.KEY_UP)
            mv.assert_called_once_with(-1)

    def test_down_falls_back_to_scroll_when_unstructured(self, monitor):
        self._enter(monitor, structured=False)
        monitor.handle_input(curses.KEY_DOWN)
        assert monitor._audit_scroll == 1

    def test_down_calls_move_cursor_when_structured(self, monitor):
        self._enter(monitor, structured=True)
        with patch.object(monitor, "_audit_move_cursor") as mv:
            monitor.handle_input(curses.KEY_DOWN)
            mv.assert_called_once_with(1)

    def test_page_up_clamps_at_zero(self, monitor):
        self._enter(monitor)
        monitor._audit_scroll = 3
        monitor.handle_input(curses.KEY_PPAGE)
        assert monitor._audit_scroll == 0

    def test_page_down_jumps(self, monitor):
        self._enter(monitor)
        monitor.handle_input(curses.KEY_NPAGE)
        assert monitor._audit_scroll == monitor._page_size()

    def test_d_key_remediates(self, monitor):
        self._enter(monitor, structured=True)
        with patch.object(monitor, "_audit_remediate_current") as rem:
            monitor.handle_input(ord("d"))
            rem.assert_called_once()

    def test_D_key_remediates(self, monitor):
        self._enter(monitor, structured=True)
        with patch.object(monitor, "_audit_remediate_current") as rem:
            monitor.handle_input(ord("D"))
            rem.assert_called_once()

    def test_r_key_starts_rescan(self, monitor):
        self._enter(monitor)
        with patch.object(monitor, "_start_audit") as scan:
            monitor.handle_input(ord("r"))
            scan.assert_called_once()

    def test_R_key_starts_rescan(self, monitor):
        self._enter(monitor)
        with patch.object(monitor, "_start_audit") as scan:
            monitor.handle_input(ord("R"))
            scan.assert_called_once()

    def test_tab_releases_detail_focus(self, monitor):
        self._enter(monitor)
        monitor.handle_input(ord("\t"))
        assert monitor._detail_focus is False

    def test_escape_closes_audit_mode(self, monitor):
        self._enter(monitor)
        monitor.handle_input(27)
        assert monitor._audit_mode is False
        assert monitor._detail_focus is False

    def test_q_quits(self, monitor):
        self._enter(monitor)
        result = monitor.handle_input(ord("q"))
        assert result is False


# ── Bulk-scan mode: every key handler ────────────────────────────────────


class TestBulkScanModeKeys:
    def _enter(self, monitor):
        monitor._bulk_scan_mode = True
        monitor._detail_focus = True
        monitor._bulk_scan_lines = ["l%d" % i for i in range(60)]
        monitor._bulk_scan_scroll = 0
        monitor.stdscr.getmaxyx.return_value = (30, 120)

    def test_up_scrolls_up(self, monitor):
        self._enter(monitor)
        monitor._bulk_scan_scroll = 3
        monitor.handle_input(curses.KEY_UP)
        assert monitor._bulk_scan_scroll == 2

    def test_down_scrolls_down(self, monitor):
        self._enter(monitor)
        monitor.handle_input(curses.KEY_DOWN)
        assert monitor._bulk_scan_scroll == 1

    def test_page_up_clamps(self, monitor):
        self._enter(monitor)
        monitor._bulk_scan_scroll = 3
        monitor.handle_input(curses.KEY_PPAGE)
        assert monitor._bulk_scan_scroll == 0

    def test_page_down_jumps(self, monitor):
        self._enter(monitor)
        monitor.handle_input(curses.KEY_NPAGE)
        assert monitor._bulk_scan_scroll == monitor._page_size()

    def test_F_toggles_off(self, monitor):
        self._enter(monitor)
        with patch.object(monitor, "_toggle_bulk_scan_mode") as tg:
            monitor.handle_input(ord("F"))
            tg.assert_called_once()

    def test_tab_releases_focus(self, monitor):
        self._enter(monitor)
        monitor.handle_input(ord("\t"))
        assert monitor._detail_focus is False

    def test_escape_cancels_and_closes(self, monitor):
        self._enter(monitor)
        monitor.handle_input(27)
        assert monitor._bulk_scan_cancel is True
        assert monitor._bulk_scan_mode is False
        assert monitor._detail_focus is False

    def test_q_quits(self, monitor):
        self._enter(monitor)
        assert monitor.handle_input(ord("q")) is False


# ── Events mode: scroll/clear/escape (two-stage)/q ───────────────────────


class TestEventsModeKeys:
    def _enter(self, monitor, with_events=False):
        monitor._events_mode = True
        monitor._detail_focus = True
        monitor._events_scroll = 0
        monitor._events_awaiting_summary = False
        if with_events:
            monitor._events = [{"raw": "event"} for _ in range(5)]
        else:
            monitor._events = []
        monitor.stdscr.getmaxyx.return_value = (30, 120)

    def test_up_scrolls_up(self, monitor):
        self._enter(monitor)
        monitor._events_scroll = 4
        monitor.handle_input(curses.KEY_UP)
        assert monitor._events_scroll == 3

    def test_up_clamps_at_zero(self, monitor):
        self._enter(monitor)
        monitor._events_scroll = 0
        monitor.handle_input(curses.KEY_UP)
        assert monitor._events_scroll == 0

    def test_down_scrolls_down(self, monitor):
        self._enter(monitor)
        monitor.handle_input(curses.KEY_DOWN)
        assert monitor._events_scroll == 1

    def test_page_up_clamps(self, monitor):
        self._enter(monitor)
        monitor._events_scroll = 3
        monitor.handle_input(curses.KEY_PPAGE)
        assert monitor._events_scroll == 0

    def test_page_down_jumps(self, monitor):
        self._enter(monitor)
        monitor.handle_input(curses.KEY_NPAGE)
        assert monitor._events_scroll == monitor._page_size()

    def test_c_clears_buffer(self, monitor):
        self._enter(monitor, with_events=True)
        monitor.handle_input(ord("c"))
        assert monitor._events == []

    def test_tab_releases_focus(self, monitor):
        self._enter(monitor)
        monitor.handle_input(ord("\t"))
        assert monitor._detail_focus is False

    def test_escape_with_events_triggers_summary(self, monitor):
        self._enter(monitor, with_events=True)
        with patch.object(monitor, "_stop_events_stream") as stop, \
             patch.object(monitor, "_start_events_llm_summary") as start_sum:
            monitor.handle_input(27)
            stop.assert_called_once()
            start_sum.assert_called_once()
            assert monitor._events_awaiting_summary is True
            # Stays in events_mode for the second Esc
            assert monitor._events_mode is True

    def test_escape_after_summary_closes(self, monitor):
        self._enter(monitor, with_events=True)
        monitor._events_awaiting_summary = True
        with patch.object(monitor, "_stop_events_stream"):
            monitor.handle_input(27)
        assert monitor._events_mode is False
        assert monitor._detail_focus is False
        assert monitor._events_awaiting_summary is False

    def test_escape_with_no_events_closes_immediately(self, monitor):
        self._enter(monitor, with_events=False)
        with patch.object(monitor, "_stop_events_stream"):
            monitor.handle_input(27)
        assert monitor._events_mode is False
        assert monitor._detail_focus is False

    def test_q_quits(self, monitor):
        self._enter(monitor)
        with patch.object(monitor, "_stop_events_stream"):
            assert monitor.handle_input(ord("q")) is False


# ── Traffic mode: every key handler ──────────────────────────────────────


class TestTrafficModeKeys:
    def _enter(self, monitor):
        monitor._traffic_mode = True
        monitor._detail_focus = True
        monitor._traffic_flows = [{"req": "a"} for _ in range(5)]
        monitor._traffic_scroll = 0
        monitor.stdscr.getmaxyx.return_value = (30, 120)

    def test_up_scrolls_up(self, monitor):
        self._enter(monitor)
        monitor._traffic_scroll = 4
        monitor.handle_input(curses.KEY_UP)
        assert monitor._traffic_scroll == 3

    def test_down_scrolls_down(self, monitor):
        self._enter(monitor)
        monitor.handle_input(curses.KEY_DOWN)
        assert monitor._traffic_scroll == 1

    def test_page_up_clamps(self, monitor):
        self._enter(monitor)
        monitor._traffic_scroll = 3
        monitor.handle_input(curses.KEY_PPAGE)
        assert monitor._traffic_scroll == 0

    def test_page_down_jumps(self, monitor):
        self._enter(monitor)
        monitor.handle_input(curses.KEY_NPAGE)
        assert monitor._traffic_scroll == monitor._page_size()

    def test_c_clears_traffic_flows(self, monitor):
        self._enter(monitor)
        monitor.handle_input(ord("c"))
        assert monitor._traffic_flows == []

    def test_tab_releases_focus(self, monitor):
        self._enter(monitor)
        monitor.handle_input(ord("\t"))
        assert monitor._detail_focus is False

    def test_escape_stops_stream_and_closes(self, monitor):
        self._enter(monitor)
        with patch.object(monitor, "_stop_traffic_stream") as stop:
            monitor.handle_input(27)
            stop.assert_called_once()
        assert monitor._traffic_mode is False
        assert monitor._detail_focus is False

    def test_q_stops_stream_and_quits(self, monitor):
        self._enter(monitor)
        with patch.object(monitor, "_stop_traffic_stream") as stop:
            assert monitor.handle_input(ord("q")) is False
            stop.assert_called_once()


# ── Main-mode hotkeys not previously covered ─────────────────────────────


def _rows(n=3):
    rows = []
    for i in range(n):
        r = make_proc(pid=i + 1, ppid=0, cpu=float(i + 1), rss_kb=(i + 1) * 1024)
        r["depth"] = 0
        rows.append(r)
    return rows


class TestMainModeHotkeys:
    def test_T_triggers_process_triage(self, monitor):
        monitor.rows = _rows()
        monitor.selected = 0
        with patch.object(monitor, "_toggle_process_triage_mode") as t:
            monitor.handle_input(ord("T"))
            t.assert_called_once()

    def test_H_opens_secauditor_bridge(self, monitor):
        monitor.rows = _rows()
        with patch.object(monitor, "_show_secauditor_bridge") as br:
            monitor.handle_input(ord("H"))
            br.assert_called_once()

    def test_J_opens_secauditor_bridge(self, monitor):
        monitor.rows = _rows()
        with patch.object(monitor, "_show_secauditor_bridge") as br:
            monitor.handle_input(ord("J"))
            br.assert_called_once()

    def test_G_opens_secauditor_bridge(self, monitor):
        monitor.rows = _rows()
        with patch.object(monitor, "_show_secauditor_bridge") as br:
            monitor.handle_input(ord("G"))
            br.assert_called_once()

    def test_X_opens_secauditor_bridge(self, monitor):
        monitor.rows = _rows()
        with patch.object(monitor, "_show_secauditor_bridge") as br:
            monitor.handle_input(ord("X"))
            br.assert_called_once()

    def test_a_opens_audit_menu(self, monitor):
        monitor.rows = _rows()
        with patch.object(monitor, "_prompt_audit") as p:
            monitor.handle_input(ord("a"))
            p.assert_called_once()

    def test_F_opens_forensic_menu(self, monitor):
        monitor.rows = _rows()
        with patch.object(monitor, "_prompt_forensic") as p:
            monitor.handle_input(ord("F"))
            p.assert_called_once()

    def test_E_opens_telemetry_menu(self, monitor):
        monitor.rows = _rows()
        with patch.object(monitor, "_prompt_telemetry") as p:
            monitor.handle_input(ord("E"))
            p.assert_called_once()

    def test_s_opens_sort_dialog(self, monitor):
        monitor.rows = _rows()
        with patch.object(monitor, "_prompt_sort") as p:
            monitor.handle_input(ord("s"))
            p.assert_called_once()

    def test_I_toggles_inspect_mode(self, monitor):
        monitor.rows = _rows()
        monitor.selected = 0
        with patch.object(monitor, "_toggle_inspect_mode") as t:
            monitor.handle_input(ord("I"))
            t.assert_called_once()


# ── Tab from main mode: enables detail focus only when a special mode ────


class TestTabEnablesDetailFocus:
    """`Tab` only flips into detail focus if any of the special modes is on."""

    @pytest.mark.parametrize("flag", [
        "_inspect_mode", "_hidden_scan_mode", "_net_mode",
        "_bulk_scan_mode", "_events_mode", "_keyscan_mode",
        "_audit_mode", "_traffic_mode",
    ])
    def test_tab_enters_focus_in_each_mode(self, monitor, flag):
        monitor.rows = _rows()
        setattr(monitor, flag, True)
        monitor._detail_focus = False
        monitor.handle_input(ord("\t"))
        assert monitor._detail_focus is True


# ── Escape from main mode while a special mode is open closes that mode ──


class TestMainModeEscapeClosesSpecialModes:
    def test_escape_closes_inspect_mode(self, monitor):
        monitor.rows = _rows()
        monitor._inspect_mode = True
        monitor._detail_focus = False
        result = monitor.handle_input(27)
        assert result is True  # not a quit
        assert monitor._inspect_mode is False

    def test_escape_closes_hidden_scan_mode(self, monitor):
        monitor.rows = _rows()
        monitor._hidden_scan_mode = True
        result = monitor.handle_input(27)
        assert result is True
        assert monitor._hidden_scan_mode is False

    def test_escape_closes_keyscan_mode(self, monitor):
        monitor.rows = _rows()
        monitor._keyscan_mode = True
        result = monitor.handle_input(27)
        assert result is True
        assert monitor._keyscan_mode is False

    def test_escape_closes_bulk_scan_mode(self, monitor):
        monitor.rows = _rows()
        monitor._bulk_scan_mode = True
        result = monitor.handle_input(27)
        assert result is True
        assert monitor._bulk_scan_mode is False
        assert monitor._bulk_scan_cancel is True

    def test_escape_closes_events_mode(self, monitor):
        monitor.rows = _rows()
        monitor._events_mode = True
        with patch.object(monitor, "_stop_events_stream"):
            result = monitor.handle_input(27)
        assert result is True
        assert monitor._events_mode is False

    def test_escape_closes_audit_mode(self, monitor):
        monitor.rows = _rows()
        monitor._audit_mode = True
        result = monitor.handle_input(27)
        assert result is True
        assert monitor._audit_mode is False

    def test_escape_closes_traffic_mode(self, monitor):
        monitor.rows = _rows()
        monitor._traffic_mode = True
        with patch.object(monitor, "_stop_traffic_stream") as stop:
            result = monitor.handle_input(27)
            stop.assert_called_once()
        assert result is True
        assert monitor._traffic_mode is False
        assert monitor._detail_focus is False

    def test_escape_closes_net_mode(self, monitor):
        monitor.rows = _rows()
        monitor._net_mode = True
        result = monitor.handle_input(27)
        assert result is True
        assert monitor._net_mode is False


# ── Inspect mode detail-focus key paths ──────────────────────────────────


class TestInspectModeDetailKeys:
    def _enter(self, monitor):
        monitor._inspect_mode = True
        monitor._detail_focus = True
        monitor._inspect_lines = ["l%d" % i for i in range(60)]
        monitor._inspect_scroll = 0
        monitor.stdscr.getmaxyx.return_value = (30, 120)

    def test_up_clamps_at_zero(self, monitor):
        self._enter(monitor)
        monitor._inspect_scroll = 0
        monitor.handle_input(curses.KEY_UP)
        assert monitor._inspect_scroll == 0

    def test_page_up_clamps(self, monitor):
        self._enter(monitor)
        monitor._inspect_scroll = 3
        monitor.handle_input(curses.KEY_PPAGE)
        assert monitor._inspect_scroll == 0

    def test_page_down_jumps(self, monitor):
        self._enter(monitor)
        monitor.handle_input(curses.KEY_NPAGE)
        assert monitor._inspect_scroll == monitor._page_size()

    def test_I_toggles_off(self, monitor):
        self._enter(monitor)
        with patch.object(monitor, "_toggle_inspect_mode") as t:
            monitor.handle_input(ord("I"))
            t.assert_called_once()

    def test_tab_releases_focus(self, monitor):
        self._enter(monitor)
        monitor.handle_input(ord("\t"))
        assert monitor._detail_focus is False

    def test_escape_closes(self, monitor):
        self._enter(monitor)
        monitor.handle_input(27)
        assert monitor._inspect_mode is False
        assert monitor._detail_focus is False

    def test_q_quits(self, monitor):
        self._enter(monitor)
        assert monitor.handle_input(ord("q")) is False


# ── Hidden-scan mode all keys ────────────────────────────────────────────


class TestHiddenScanAllKeys:
    def _enter(self, monitor):
        monitor._hidden_scan_mode = True
        monitor._detail_focus = True
        monitor._hidden_scan_lines = ["l%d" % i for i in range(60)]
        monitor._hidden_scan_scroll = 0
        monitor.stdscr.getmaxyx.return_value = (30, 120)

    def test_H_toggles_off(self, monitor):
        self._enter(monitor)
        with patch.object(monitor, "_toggle_hidden_scan_mode") as t:
            monitor.handle_input(ord("H"))
            t.assert_called_once()

    def test_tab_releases_focus(self, monitor):
        self._enter(monitor)
        monitor.handle_input(ord("\t"))
        assert monitor._detail_focus is False

    def test_escape_closes(self, monitor):
        self._enter(monitor)
        monitor.handle_input(27)
        assert monitor._hidden_scan_mode is False
        assert monitor._detail_focus is False

    def test_q_quits(self, monitor):
        self._enter(monitor)
        assert monitor.handle_input(ord("q")) is False
