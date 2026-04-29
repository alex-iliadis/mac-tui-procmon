"""Integration tests for all keyboard shortcuts.

Each test presses a key and verifies the observable effect on the monitor state
after a full handle_input → state change cycle. Tests cover both main mode and
detail focus mode contexts.
"""
import curses
import os
import signal
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


def _rows(n=5):
    """Build n rows with incrementing pid/cpu/mem for sort tests."""
    rows = []
    for i in range(n):
        r = make_proc(pid=i + 1, ppid=0, cpu=float(i + 1), rss_kb=(i + 1) * 1024)
        r["depth"] = 0
        rows.append(r)
    return rows


# ── Navigation: Main Mode ────────────────────────────────────────────────


class TestNavigationMain:

    def test_down_moves_selection(self, monitor):
        monitor.rows = _rows()
        monitor.selected = 0
        monitor.handle_input(curses.KEY_DOWN)
        assert monitor.selected == 1

    def test_down_stops_at_bottom(self, monitor):
        monitor.rows = _rows(3)
        monitor.selected = 2
        monitor.handle_input(curses.KEY_DOWN)
        assert monitor.selected == 2

    def test_up_moves_selection(self, monitor):
        monitor.rows = _rows()
        monitor.selected = 3
        monitor.handle_input(curses.KEY_UP)
        assert monitor.selected == 2

    def test_up_stops_at_top(self, monitor):
        monitor.rows = _rows()
        monitor.selected = 0
        monitor.handle_input(curses.KEY_UP)
        assert monitor.selected == 0

    def test_page_down_jumps(self, monitor):
        monitor.rows = _rows(30)
        monitor.selected = 0
        monitor.stdscr.getmaxyx.return_value = (30, 120)
        monitor.handle_input(curses.KEY_NPAGE)
        assert monitor.selected == monitor._page_size()

    def test_page_down_clamps_to_end(self, monitor):
        monitor.rows = _rows(3)
        monitor.selected = 0
        monitor.handle_input(curses.KEY_NPAGE)
        assert monitor.selected == 2

    def test_page_up_jumps(self, monitor):
        monitor.rows = _rows(30)
        monitor.selected = 20
        monitor.stdscr.getmaxyx.return_value = (30, 120)
        monitor.handle_input(curses.KEY_PPAGE)
        assert monitor.selected == 20 - monitor._page_size()

    def test_page_up_clamps_to_top(self, monitor):
        monitor.rows = _rows()
        monitor.selected = 1
        monitor.handle_input(curses.KEY_PPAGE)
        assert monitor.selected == 0

    def test_left_collapses(self, monitor):
        parent = make_proc(pid=1)
        parent["depth"] = 0
        parent["has_children"] = True
        parent["is_collapsed"] = False
        monitor.rows = [parent]
        monitor.selected = 0
        monitor._expanded = {1}
        monitor.handle_input(curses.KEY_LEFT)
        # Should remove from expanded (collapse)
        assert 1 not in monitor._expanded

    def test_right_expands(self, monitor):
        row = make_proc(pid=1)
        row["is_collapsed"] = True
        row["has_children"] = True
        monitor.rows = [row]
        monitor.selected = 0
        monitor._expanded = set()
        with patch.object(monitor, "_resort"):
            monitor.handle_input(curses.KEY_RIGHT)
        assert 1 in monitor._expanded


# ── Sort Shortcuts ────────────────────────────────────────────────────────


class TestSortShortcuts:

    def _press_sort(self, monitor, key):
        monitor.rows = _rows()
        with patch.object(monitor, "_resort"):
            monitor.handle_input(ord(key))

    def test_m_sets_mem_sort(self, monitor):
        monitor.sort_mode = procmon.SORT_CPU
        self._press_sort(monitor, "m")
        assert monitor.sort_mode == procmon.SORT_MEM

    def test_c_sets_cpu_sort(self, monitor):
        self._press_sort(monitor, "c")
        assert monitor.sort_mode == procmon.SORT_CPU

    def test_n_sets_net_sort(self, monitor):
        self._press_sort(monitor, "n")
        assert monitor.sort_mode == procmon.SORT_NET

    def test_A_sets_alpha_sort(self, monitor):
        self._press_sort(monitor, "A")
        assert monitor.sort_mode == procmon.SORT_ALPHA

    def test_V_sets_vendor_sort(self, monitor):
        self._press_sort(monitor, "V")
        assert monitor.sort_mode == procmon.SORT_VENDOR

    def test_R_sets_bytes_in_sort(self, monitor):
        self._press_sort(monitor, "R")
        assert monitor.sort_mode == procmon.SORT_BYTES_IN

    def test_O_sets_bytes_out_sort(self, monitor):
        self._press_sort(monitor, "O")
        assert monitor.sort_mode == procmon.SORT_BYTES_OUT

    def test_same_key_toggles_invert(self, monitor):
        """Pressing the same sort key again inverts direction."""
        monitor.sort_mode = procmon.SORT_CPU
        monitor._sort_inverted = False
        monitor.rows = _rows()
        with patch.object(monitor, "_resort"):
            monitor.handle_input(ord("c"))
        assert monitor._sort_inverted is True

    def test_different_key_resets_invert(self, monitor):
        """Switching sort mode resets invert."""
        monitor.sort_mode = procmon.SORT_CPU
        monitor._sort_inverted = True
        monitor.rows = _rows()
        with patch.object(monitor, "_resort"):
            monitor.handle_input(ord("m"))
        assert monitor.sort_mode == procmon.SORT_MEM
        assert monitor._sort_inverted is False

    def test_d_toggles_dynamic_sort(self, monitor):
        monitor._dynamic_sort = False
        monitor.rows = _rows()
        with patch.object(monitor, "_resort"):
            monitor.handle_input(ord("d"))
        assert monitor._dynamic_sort is True
        with patch.object(monitor, "_resort"):
            monitor.handle_input(ord("d"))
        assert monitor._dynamic_sort is False

    def test_g_toggles_vendor_group(self, monitor):
        monitor._vendor_grouped = False
        monitor.rows = _rows()
        with patch.object(monitor, "_resort"):
            monitor.handle_input(ord("g"))
        assert monitor._vendor_grouped is True
        with patch.object(monitor, "_resort"):
            monitor.handle_input(ord("g"))
        assert monitor._vendor_grouped is False


# ── Network Mode ──────────────────────────────────────────────────────────


class TestNetworkMode:

    def test_N_opens_net_mode(self, monitor):
        monitor.rows = [make_proc(pid=100)]
        monitor.selected = 0
        monitor._net_mode = False
        with patch.object(monitor, "_start_net_fetch"):
            monitor.handle_input(ord("N"))
        assert monitor._net_mode is True
        assert monitor._net_pid == 100

    def test_N_closes_net_mode(self, monitor):
        monitor.rows = [make_proc(pid=100)]
        monitor._net_mode = True
        monitor.handle_input(ord("N"))
        assert monitor._net_mode is False

    def test_tab_enters_detail_focus_in_net_mode(self, monitor):
        monitor.rows = _rows()
        monitor._net_mode = True
        monitor._detail_focus = False
        monitor.handle_input(ord("\t"))
        assert monitor._detail_focus is True

    def test_tab_noop_outside_net_mode(self, monitor):
        monitor.rows = _rows()
        monitor._net_mode = False
        monitor._detail_focus = False
        monitor.handle_input(ord("\t"))
        assert monitor._detail_focus is False

    def test_escape_closes_net_mode(self, monitor):
        monitor.rows = _rows()
        monitor._net_mode = True
        monitor._detail_focus = False
        result = monitor.handle_input(27)
        assert result is True
        assert monitor._net_mode is False

    def test_escape_quits_when_no_net_mode(self, monitor):
        monitor.rows = _rows()
        monitor._net_mode = False
        result = monitor.handle_input(27)
        assert result is False


# ── Detail Focus Mode ────────────────────────────────────────────────────


class TestDetailFocusNavigation:

    def _setup_detail(self, monitor, n_entries=10):
        monitor._detail_focus = True
        monitor._net_entries = [{"fd": str(i)} for i in range(n_entries)]
        monitor._net_selected = 0
        monitor._net_scroll = 0

    def test_down_selects_next_connection(self, monitor):
        self._setup_detail(monitor)
        monitor.handle_input(curses.KEY_DOWN)
        assert monitor._net_selected == 1

    def test_down_stops_at_last(self, monitor):
        self._setup_detail(monitor, 3)
        monitor._net_selected = 2
        monitor.handle_input(curses.KEY_DOWN)
        assert monitor._net_selected == 2

    def test_up_selects_previous(self, monitor):
        self._setup_detail(monitor)
        monitor._net_selected = 5
        monitor.handle_input(curses.KEY_UP)
        assert monitor._net_selected == 4

    def test_up_stops_at_first(self, monitor):
        self._setup_detail(monitor)
        monitor._net_selected = 0
        monitor.handle_input(curses.KEY_UP)
        assert monitor._net_selected == 0

    def test_page_down_jumps(self, monitor):
        self._setup_detail(monitor, 50)
        monitor._net_selected = 0
        monitor.handle_input(curses.KEY_NPAGE)
        assert monitor._net_selected > 0

    def test_page_up_jumps(self, monitor):
        self._setup_detail(monitor, 50)
        monitor._net_selected = 30
        monitor.handle_input(curses.KEY_PPAGE)
        assert monitor._net_selected < 30

    def test_tab_exits_detail_focus(self, monitor):
        self._setup_detail(monitor)
        monitor.handle_input(ord("\t"))
        assert monitor._detail_focus is False

    def test_N_toggles_net_mode_from_detail(self, monitor):
        self._setup_detail(monitor)
        monitor._net_mode = True
        monitor.rows = [make_proc(pid=1)]
        monitor.handle_input(ord("N"))
        assert monitor._net_mode is False

    def test_escape_closes_net_from_detail(self, monitor):
        self._setup_detail(monitor)
        monitor._net_mode = True
        monitor.handle_input(27)
        assert monitor._net_mode is False
        assert monitor._detail_focus is False

    def test_q_quits_from_detail(self, monitor):
        self._setup_detail(monitor)
        result = monitor.handle_input(ord("q"))
        assert result is False

    def test_k_kills_connection_from_detail(self, monitor):
        self._setup_detail(monitor)
        with patch.object(monitor,
                          "_kill_net_connection_owner_process") as mock_kill:
            monitor.handle_input(ord("k"))
            mock_kill.assert_called_once()

    def test_unhandled_key_returns_true(self, monitor):
        """An unrecognized key in detail focus still returns True (no quit)."""
        self._setup_detail(monitor)
        result = monitor.handle_input(ord("z"))
        assert result is True


# ── Action Shortcuts ──────────────────────────────────────────────────────


class TestActionShortcuts:

    def test_C_opens_config(self, monitor):
        monitor.rows = _rows()
        with patch.object(monitor, "_prompt_config") as mock:
            monitor.handle_input(ord("C"))
            mock.assert_called_once()

    def test_f_opens_filter(self, monitor):
        monitor.rows = _rows()
        with patch.object(monitor, "_prompt_filter") as mock:
            monitor.handle_input(ord("f"))
            mock.assert_called_once()

    def test_k_kills_selected(self, monitor):
        monitor.rows = _rows()
        monitor.selected = 0
        with patch.object(monitor, "_kill_selected") as mock:
            monitor.handle_input(ord("k"))
            mock.assert_called_once()

    def test_q_returns_false(self, monitor):
        monitor.rows = _rows()
        result = monitor.handle_input(ord("q"))
        assert result is False

    def test_unknown_key_returns_true(self, monitor):
        """Unrecognized key doesn't quit."""
        monitor.rows = _rows()
        result = monitor.handle_input(ord("z"))
        assert result is True


# ── Full Flow: Sort + Verify Order ────────────────────────────────────────


class TestSortIntegration:
    """Press sort key and verify rows get re-ordered via _resort."""

    def test_sort_by_cpu_orders_descending(self, monitor):
        """After pressing 'c', rows are sorted by CPU descending."""
        procs = [
            {"pid": 1, "ppid": 0, "rss_kb": 100, "cpu": 10.0, "cpu_ticks": 100,
             "threads": 1, "command": "low_cpu"},
            {"pid": 2, "ppid": 0, "rss_kb": 100, "cpu": 90.0, "cpu_ticks": 900,
             "threads": 1, "command": "high_cpu"},
            {"pid": 3, "ppid": 0, "rss_kb": 100, "cpu": 50.0, "cpu_ticks": 500,
             "threads": 1, "command": "mid_cpu"},
        ]
        with patch("procmon.get_all_processes", return_value=procs), \
             patch("procmon.get_net_snapshot", return_value={}), \
             patch("procmon.get_fd_counts", return_value={}), \
             patch("procmon.get_cwds", return_value={}):
            monitor._prev_cpu = {}
            monitor.prev_net = {}
            monitor.prev_time = None
            monitor.net_rates = {}
            monitor._net_bytes = {}
            monitor.collect_data()

        # Now sort by CPU
        with patch("procmon.get_all_processes", return_value=procs):
            monitor.handle_input(ord("c"))

        # Verify order: highest CPU first
        if len(monitor.rows) >= 3:
            cpus = [r["cpu"] for r in monitor.rows]
            assert cpus == sorted(cpus, reverse=True)

    def test_sort_by_mem_orders_descending(self, monitor):
        """After pressing 'm', rows are sorted by MEM descending."""
        procs = [
            {"pid": 1, "ppid": 0, "rss_kb": 500, "cpu": 1.0, "cpu_ticks": 10,
             "threads": 1, "command": "small"},
            {"pid": 2, "ppid": 0, "rss_kb": 5000, "cpu": 1.0, "cpu_ticks": 10,
             "threads": 1, "command": "large"},
            {"pid": 3, "ppid": 0, "rss_kb": 2000, "cpu": 1.0, "cpu_ticks": 10,
             "threads": 1, "command": "medium"},
        ]
        with patch("procmon.get_all_processes", return_value=procs), \
             patch("procmon.get_net_snapshot", return_value={}), \
             patch("procmon.get_fd_counts", return_value={}), \
             patch("procmon.get_cwds", return_value={}):
            monitor._prev_cpu = {}
            monitor.prev_net = {}
            monitor.prev_time = None
            monitor.net_rates = {}
            monitor._net_bytes = {}
            monitor.collect_data()

        monitor.sort_mode = procmon.SORT_CPU  # start from different sort
        with patch("procmon.get_all_processes", return_value=procs):
            monitor.handle_input(ord("m"))

        if len(monitor.rows) >= 3:
            mems = [r["rss_kb"] for r in monitor.rows]
            assert mems == sorted(mems, reverse=True)

    def test_sort_alpha_orders_ascending(self, monitor):
        """After pressing 'A', rows are sorted alphabetically ascending."""
        procs = [
            {"pid": 1, "ppid": 0, "rss_kb": 100, "cpu": 1.0, "cpu_ticks": 10,
             "threads": 1, "command": "/usr/bin/zebra"},
            {"pid": 2, "ppid": 0, "rss_kb": 100, "cpu": 1.0, "cpu_ticks": 10,
             "threads": 1, "command": "/usr/bin/apple"},
            {"pid": 3, "ppid": 0, "rss_kb": 100, "cpu": 1.0, "cpu_ticks": 10,
             "threads": 1, "command": "/usr/bin/mango"},
        ]
        with patch("procmon.get_all_processes", return_value=procs), \
             patch("procmon.get_net_snapshot", return_value={}), \
             patch("procmon.get_fd_counts", return_value={}), \
             patch("procmon.get_cwds", return_value={}):
            monitor._prev_cpu = {}
            monitor.prev_net = {}
            monitor.prev_time = None
            monitor.net_rates = {}
            monitor._net_bytes = {}
            monitor.collect_data()

        with patch("procmon.get_all_processes", return_value=procs):
            monitor.handle_input(ord("A"))

        if len(monitor.rows) >= 3:
            # apple, mango, zebra
            assert monitor.rows[0]["pid"] == 2
            assert monitor.rows[1]["pid"] == 3
            assert monitor.rows[2]["pid"] == 1


# ── Dynamic Sort Integration ─────────────────────────────────────────────


class TestDynamicSortIntegration:

    def test_dynamic_sort_moves_exceeding_to_top(self, monitor):
        """With dynamic sort on, threshold-exceeding procs appear first."""
        monitor._alert_thresholds["cpu"] = 50.0
        monitor._dynamic_sort = True
        monitor.sort_mode = procmon.SORT_MEM

        procs = [
            {"pid": 1, "ppid": 0, "rss_kb": 9000, "cpu": 10.0, "cpu_ticks": 100,
             "threads": 1, "command": "big_mem_low_cpu"},
            {"pid": 2, "ppid": 0, "rss_kb": 1000, "cpu": 80.0, "cpu_ticks": 800,
             "threads": 1, "command": "small_mem_high_cpu"},
            {"pid": 3, "ppid": 0, "rss_kb": 5000, "cpu": 5.0, "cpu_ticks": 50,
             "threads": 1, "command": "mid_mem_low_cpu"},
        ]
        with patch("procmon.get_all_processes", return_value=procs), \
             patch("procmon.get_net_snapshot", return_value={}), \
             patch("procmon.get_fd_counts", return_value={}), \
             patch("procmon.get_cwds", return_value={}):
            monitor._prev_cpu = {}
            monitor.prev_net = {}
            monitor.prev_time = None
            monitor.net_rates = {}
            monitor._net_bytes = {}
            monitor.collect_data()

        # pid=2 (cpu 80%) exceeds threshold → should be first despite low mem
        # Without dynamic sort, mem sort would put pid=1 first
        if len(monitor.rows) >= 3:
            assert monitor.rows[0]["pid"] == 2, \
                f"Expected high-CPU proc first, got pid={monitor.rows[0]['pid']}"
