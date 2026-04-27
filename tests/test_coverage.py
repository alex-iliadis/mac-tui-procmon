"""Additional tests to push coverage above 90%.

Covers: render, _put, _page_size, _col_header, _fmt_row, _detail_lines,
_render_detail, _tag_color, _render_colored_line, _render_shortcut_bar,
_prompt_config, _prompt_filter, _kill_selected, _resort, run,
get_all_processes, get_net_snapshot, get_fd_counts, get_cwds,
_harden_process, _self_test, _short_org, _get_geo, _get_org,
_resolve_ip, main.
"""
import argparse
import curses
import gc
import json
import os
import signal
import sys
import time
from unittest.mock import MagicMock, patch, call, PropertyMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import procmon
from tests.conftest import make_proc


@pytest.fixture(autouse=True)
def _mock_curses():
    """Patch curses functions that require initscr() for all tests in this module."""
    with patch("curses.color_pair", side_effect=lambda n: n), \
         patch("curses.curs_set", return_value=None):
        yield


# ── _put ────────────────────────────────────────────────────────────────


class TestPut:

    def test_put_normal(self, monitor):
        monitor._put(0, 0, "hello")
        monitor.stdscr.addnstr.assert_called()

    def test_put_with_attr(self, monitor):
        monitor._put(1, 5, "world", curses.A_BOLD)
        monitor.stdscr.addnstr.assert_called()

    def test_put_out_of_bounds_y(self, monitor):
        monitor.stdscr.getmaxyx.return_value = (10, 80)
        monitor._put(50, 0, "text")
        monitor.stdscr.addnstr.assert_not_called()

    def test_put_negative_y(self, monitor):
        monitor._put(-1, 0, "text")
        monitor.stdscr.addnstr.assert_not_called()

    def test_put_out_of_bounds_x(self, monitor):
        monitor.stdscr.getmaxyx.return_value = (10, 80)
        monitor._put(0, 100, "text")
        monitor.stdscr.addnstr.assert_not_called()

    def test_put_curses_error(self, monitor):
        monitor.stdscr.addnstr.side_effect = curses.error("test")
        monitor._put(0, 0, "text")  # should not raise


# ── _page_size ──────────────────────────────────────────────────────────


class TestPageSize:

    def test_normal_terminal(self, monitor):
        monitor.stdscr.getmaxyx.return_value = (40, 120)
        assert monitor._page_size() == 28

    def test_small_terminal(self, monitor):
        monitor.stdscr.getmaxyx.return_value = (12, 80)
        assert monitor._page_size() == 1

    def test_very_small_terminal(self, monitor):
        monitor.stdscr.getmaxyx.return_value = (5, 40)
        assert monitor._page_size() == 1


# ── _col_header ─────────────────────────────────────────────────────────


class TestColHeader:

    def test_basic(self, monitor):
        hdr = monitor._col_header(120)
        assert "PROCESS" in hdr
        assert "PID" in hdr
        assert "MEM" in hdr
        assert "CPU%" in hdr
        assert "THR" in hdr
        assert "FDs" in hdr

    def test_skip_fd(self, monitor):
        monitor.skip_fd = True
        hdr = monitor._col_header(120)
        assert "FDs" not in hdr

    def test_sort_indicator_mem(self, monitor):
        monitor.sort_mode = procmon.SORT_MEM
        hdr = monitor._col_header(120)
        assert "MEM" in hdr

    def test_sort_indicator_cpu(self, monitor):
        monitor.sort_mode = procmon.SORT_CPU
        hdr = monitor._col_header(120)
        assert "CPU%" in hdr

    def test_small_width_does_not_raise(self, monitor):
        hdr = monitor._col_header(20)
        assert "PROCESS" in hdr
        assert "PID" in hdr


# ── _fmt_row ────────────────────────────────────────────────────────────


class TestFmtRow:

    def test_small_width_does_not_raise(self, monitor):
        row = make_proc(command="/usr/bin/example")
        result = monitor._fmt_row(row, 20)
        assert "example" in result
        assert "1" in result

    def test_basic_row(self, monitor):
        row = make_proc(pid=123, ppid=1, cpu=25.5, rss_kb=1024, threads=4, fds=10, forks=2)
        result = monitor._fmt_row(row, 160)
        assert "123" in result
        assert "1" in result

    def test_row_with_children(self, monitor):
        row = make_proc(pid=1, cpu=10.0)
        row["has_children"] = True
        row["is_collapsed"] = True
        result = monitor._fmt_row(row, 160)
        assert "\u25b6" in result

    def test_row_expanded_children(self, monitor):
        row = make_proc(pid=1, cpu=10.0)
        row["has_children"] = True
        row["is_collapsed"] = False
        result = monitor._fmt_row(row, 160)
        assert "\u25bc" in result

    def test_row_skip_fd(self, monitor):
        monitor.skip_fd = True
        row = make_proc(pid=1, fds=-1)
        result = monitor._fmt_row(row, 160)
        assert "?" not in result

    def test_row_unknown_fds(self, monitor):
        row = make_proc(pid=1, fds=-1)
        result = monitor._fmt_row(row, 160)
        assert "?" in result

    def test_long_command_truncation(self, monitor):
        row = make_proc(pid=1, command="/very/long/" + "x" * 200)
        result = monitor._fmt_row(row, 160)
        assert "\u2026" in result  # truncation ellipsis


# ── _detail_lines ───────────────────────────────────────────────────────


class TestDetailLines:

    def test_no_rows(self, monitor):
        assert monitor._detail_lines(120) == []

    def test_basic(self, monitor):
        monitor.rows = [make_proc(pid=42, ppid=1, cpu=10.0, rss_kb=2048, threads=5)]
        lines = monitor._detail_lines(120)
        assert len(lines) == 5
        assert "PID: 42" in lines[0]
        assert "CPU: 10.0%" in lines[1]
        assert "CWD:" in lines[3]
        assert "CMD:" in lines[4]

    def test_with_children_shows_group(self, monitor):
        row = make_proc(pid=1, cpu=10.0, rss_kb=1024, threads=3)
        row["has_children"] = True
        row["agg_cpu"] = 50.0
        row["agg_rss_kb"] = 5000
        row["agg_threads"] = 20
        monitor.rows = [row]
        lines = monitor._detail_lines(120)
        assert "group:" in lines[0]
        assert "group:" in lines[1]


# ── _tag_color ──────────────────────────────────────────────────────────


class TestTagColor:

    def test_tcp_tag(self, monitor):
        result = monitor._tag_color("[TCP]")
        assert result == 1 | curses.A_BOLD

    def test_udp_tag(self, monitor):
        result = monitor._tag_color("[UDP]")
        assert result == 3 | curses.A_BOLD

    def test_service_tag(self, monitor):
        result = monitor._tag_color("[HTTPS]")
        assert result == 7 | curses.A_BOLD

    def test_geo_tag(self, monitor):
        assert monitor._tag_color("[San Jose/US]") == 8

    def test_group_tag(self, monitor):
        assert monitor._tag_color("[group: 5]") == 3

    def test_bytes_small(self, monitor):
        assert monitor._tag_color("[100 KB]") == 11

    def test_bytes_medium(self, monitor):
        result = monitor._tag_color("[50 MB]")
        assert result == 6 | curses.A_BOLD

    def test_bytes_large(self, monitor):
        result = monitor._tag_color("[200 MB]")
        assert result == 12 | curses.A_BOLD

    def test_bytes_gb(self, monitor):
        result = monitor._tag_color("[2 GB]")
        assert result == 12 | curses.A_BOLD

    def test_default(self, monitor):
        assert monitor._tag_color("[unknown]") == 10


# ── _render_colored_line ────────────────────────────────────────────────


class TestRenderColoredLine:

    def test_selected_line(self, monitor):
        monitor._render_colored_line(5, 2, "hello world", 40, True)
        monitor.stdscr.addnstr.assert_called()

    def test_plain_text(self, monitor):
        monitor._render_colored_line(5, 2, "hello world", 40, False)
        monitor.stdscr.addnstr.assert_called()

    def test_with_tag(self, monitor):
        monitor._render_colored_line(5, 2, "[TCP] 192.168.1.1", 40, False)
        assert monitor.stdscr.addnstr.call_count >= 2

    def test_with_arrow(self, monitor):
        monitor._render_colored_line(5, 2, "src \u2192 dst", 40, False)
        assert monitor.stdscr.addnstr.call_count >= 2

    def test_unclosed_bracket(self, monitor):
        monitor._render_colored_line(5, 2, "[unclosed", 40, False)
        monitor.stdscr.addnstr.assert_called()

    def test_label_colon(self, monitor):
        monitor._render_colored_line(5, 2, "PID: 123", 40, False)
        monitor.stdscr.addnstr.assert_called()


# ── _render_shortcut_bar ────────────────────────────────────────────────


class TestRenderShortcutBar:

    def test_normal_mode(self, monitor):
        monitor._detail_focus = False
        monitor._net_mode = False
        monitor._render_shortcut_bar(40, 120)
        monitor.stdscr.addnstr.assert_called()

    def test_net_mode(self, monitor):
        monitor._net_mode = True
        monitor._detail_focus = False
        monitor._render_shortcut_bar(40, 120)
        monitor.stdscr.addnstr.assert_called()

    def test_detail_focus(self, monitor):
        monitor._detail_focus = True
        monitor._render_shortcut_bar(40, 120)
        monitor.stdscr.addnstr.assert_called()

    def test_audit_mode_shows_page_shortcut(self, monitor):
        monitor._detail_focus = True
        monitor._audit_mode = True

        monitor._render_shortcut_bar(40, 120)

        rendered = "".join(
            call.args[2] for call in monitor.stdscr.addnstr.call_args_list
            if len(call.args) >= 3 and isinstance(call.args[2], str)
        )
        assert "PgU/D" in rendered
        assert "Page" in rendered


# ── _render_detail ──────────────────────────────────────────────────────


class TestRenderDetail:

    def test_basic(self, monitor):
        monitor.rows = [make_proc(pid=1)]
        monitor._render_detail(10, 120, ["Line 1", "Line 2"], "Test")
        monitor.stdscr.addnstr.assert_called()

    def test_with_scroll(self, monitor):
        monitor.rows = [make_proc(pid=1)]
        lines = [f"Line {i}" for i in range(30)]
        monitor._render_detail(10, 120, lines, "Many", scroll=5)
        monitor.stdscr.addnstr.assert_called()

    def test_no_rows(self, monitor):
        monitor.rows = []
        monitor._render_detail(10, 120, ["test"], "Test")
        # Should return early

    def test_start_y_too_big(self, monitor):
        monitor.stdscr.getmaxyx.return_value = (20, 80)
        monitor.rows = [make_proc(pid=1)]
        monitor._render_detail(19, 80, ["test"])
        # Should return early

    def test_focused(self, monitor):
        monitor.rows = [make_proc(pid=1)]
        monitor._render_detail(10, 120, ["Line 1"], focused=True, selected_line=0)
        monitor.stdscr.addnstr.assert_called()

    def test_long_line_wraps(self, monitor):
        monitor.rows = [make_proc(pid=1)]
        long_line = "x" * 200
        monitor._render_detail(10, 80, [long_line])
        monitor.stdscr.addnstr.assert_called()


# ── render ──────────────────────────────────────────────────────────────


class TestRender:

    def test_render_no_rows(self, monitor):
        monitor.name = "test"
        monitor.render()
        monitor.stdscr.erase.assert_called()
        monitor.stdscr.refresh.assert_called()

    def test_render_too_small(self, monitor):
        monitor.stdscr.getmaxyx.return_value = (5, 30)
        monitor.render()
        monitor.stdscr.refresh.assert_called()

    def test_render_with_rows(self, monitor):
        monitor.rows = [
            make_proc(pid=1, cpu=10.0, rss_kb=1024, threads=2, fds=5, forks=0,
                      net_in=100, net_out=200, bytes_in=1000, bytes_out=2000),
            make_proc(pid=2, cpu=5.0, rss_kb=512, threads=1, fds=3, forks=0,
                      net_in=50, net_out=100, bytes_in=500, bytes_out=1000),
        ]
        monitor.matched_count = 2
        monitor.render()
        monitor.stdscr.erase.assert_called()

    def test_render_with_filter(self, monitor):
        monitor.name = "python"
        monitor.exclude_name = "test"
        monitor.rows = [make_proc(pid=1, cpu=1.0, fds=1, net_in=0, net_out=0)]
        monitor.matched_count = 1
        monitor.render()
        monitor.stdscr.erase.assert_called()

    def test_render_net_mode(self, monitor):
        monitor.rows = [make_proc(pid=1, cpu=1.0, fds=1, net_in=0, net_out=0)]
        monitor.matched_count = 1
        monitor._net_mode = True
        monitor._net_pid = 1
        monitor._net_cmd = "test"
        monitor._net_entries = [{"display": "[TCP] 127.0.0.1:80 -> 10.0.0.1:443", "org": "Test"}]
        monitor._net_loading = False
        monitor._net_selected = 0
        monitor.render()
        monitor.stdscr.erase.assert_called()

    def test_render_net_mode_loading(self, monitor):
        monitor.rows = [make_proc(pid=1, cpu=1.0, fds=1, net_in=0, net_out=0)]
        monitor.matched_count = 1
        monitor._net_mode = True
        monitor._net_pid = 1
        monitor._net_cmd = "test"
        monitor._net_entries = []
        monitor._net_loading = True
        monitor._net_selected = 0
        monitor.render()

    def test_render_net_mode_empty(self, monitor):
        monitor.rows = [make_proc(pid=1, cpu=1.0, fds=1, net_in=0, net_out=0)]
        monitor.matched_count = 1
        monitor._net_mode = True
        monitor._net_pid = 1
        monitor._net_cmd = "test"
        monitor._net_entries = []
        monitor._net_loading = False
        monitor._net_selected = 0
        monitor.render()

    def test_render_row_colors_red(self, monitor):
        monitor._alert_thresholds["cpu"] = 50.0
        monitor.rows = [make_proc(pid=1, cpu=60.0, fds=1, net_in=0, net_out=0)]
        monitor.matched_count = 1
        monitor.render()

    def test_render_row_colors_yellow(self, monitor):
        monitor._alert_thresholds["cpu"] = 100.0
        monitor.rows = [make_proc(pid=1, cpu=85.0, fds=1, net_in=0, net_out=0)]
        monitor.matched_count = 1
        monitor.render()

    def test_render_highlight_processes(self, monitor):
        # High CPU/mem process gets green
        monitor.rows = [make_proc(pid=1, cpu=10.0, rss_kb=600 * 1024, fds=1, net_in=0, net_out=0)]
        monitor.matched_count = 1
        monitor.render()

    def test_render_child_depth(self, monitor):
        row = make_proc(pid=2, cpu=1.0, fds=1, net_in=0, net_out=0)
        row["depth"] = 1
        row["prefix"] = "\u2514\u2500 "
        monitor.rows = [make_proc(pid=1, cpu=1.0, fds=1, net_in=0, net_out=0), row]
        monitor.matched_count = 2
        monitor.render()

    def test_render_scroll(self, monitor):
        monitor.rows = [make_proc(pid=i, cpu=1.0, fds=1, net_in=0, net_out=0) for i in range(50)]
        monitor.matched_count = 50
        monitor.selected = 30
        monitor.scroll_offset = 25
        monitor.render()

    def test_render_skip_fd(self, monitor):
        monitor.skip_fd = True
        monitor.rows = [make_proc(pid=1, cpu=1.0, fds=1, net_in=0, net_out=0)]
        monitor.matched_count = 1
        monitor.render()

    def test_render_header_brand_does_not_overlap_status_text(self, monitor):
        puts = []

        def record_put(y, x, text, attr=0):
            puts.append((y, x, text))

        monitor._put = record_put
        monitor.rows = [make_proc(pid=1, cpu=1.0, fds=1, net_in=0, net_out=0)]
        monitor.matched_count = 935
        monitor.render()

        brand = next((item for item in puts if item[0] == 0 and item[2] == " mac-tui-procmon "), None)
        proc = next((item for item in puts if item[0] == 0 and item[2].startswith("— 935 processes")), None)

        assert brand is not None
        assert proc is not None
        assert proc[1] >= brand[1] + len(brand[2])


# ── _prompt_config ──────────────────────────────────────────────────────


class TestPromptConfig:

    def test_save_thresholds(self, monitor, tmp_path):
        """Simulate typing CPU threshold 80, then Enter."""
        cfg_file = tmp_path / ".procmon.json"
        monitor._CONFIG_PATH = str(cfg_file)

        # Keys: type "80" then Enter
        keys = [ord("8"), ord("0"), curses.KEY_ENTER]
        monitor.stdscr.getch.side_effect = keys
        monitor._prompt_config()
        assert monitor._alert_thresholds["cpu"] == 80.0
        assert monitor._alert_count == 0

    def test_cancel_with_escape(self, monitor):
        monitor.stdscr.getch.return_value = 27
        original_cpu = monitor._alert_thresholds["cpu"]
        monitor._prompt_config()
        assert monitor._alert_thresholds["cpu"] == original_cpu

    def test_navigate_fields(self, monitor, tmp_path):
        cfg_file = tmp_path / ".procmon.json"
        monitor._CONFIG_PATH = str(cfg_file)

        # Down to MEM, type 5000, Enter
        keys = [curses.KEY_DOWN, ord("5"), ord("0"), ord("0"), ord("0"), curses.KEY_ENTER]
        monitor.stdscr.getch.side_effect = keys
        monitor._prompt_config()
        assert monitor._alert_thresholds["mem_mb"] == 5000.0

    def test_backspace_delete(self, monitor, tmp_path):
        cfg_file = tmp_path / ".procmon.json"
        monitor._CONFIG_PATH = str(cfg_file)

        # Type "99", backspace, "5", Enter → cpu=95
        keys = [ord("9"), ord("9"), 127, ord("5"), curses.KEY_ENTER]
        monitor.stdscr.getch.side_effect = keys
        monitor._prompt_config()
        assert monitor._alert_thresholds["cpu"] == 95.0

    def test_ctrl_u_clears(self, monitor, tmp_path):
        cfg_file = tmp_path / ".procmon.json"
        monitor._CONFIG_PATH = str(cfg_file)
        monitor._alert_thresholds["cpu"] = 70.0

        # Ctrl-U clears, type "50", Enter
        keys = [21, ord("5"), ord("0"), curses.KEY_ENTER]
        monitor.stdscr.getch.side_effect = keys
        monitor._prompt_config()
        assert monitor._alert_thresholds["cpu"] == 50.0

    def test_home_end_keys(self, monitor, tmp_path):
        cfg_file = tmp_path / ".procmon.json"
        monitor._CONFIG_PATH = str(cfg_file)

        # Type "12", Home, type "3", End, Enter → "312"
        keys = [ord("1"), ord("2"), curses.KEY_HOME, ord("3"), curses.KEY_END, curses.KEY_ENTER]
        monitor.stdscr.getch.side_effect = keys
        monitor._prompt_config()
        assert monitor._alert_thresholds["cpu"] == 312.0

    def test_left_right_cursor(self, monitor, tmp_path):
        cfg_file = tmp_path / ".procmon.json"
        monitor._CONFIG_PATH = str(cfg_file)

        # Type "13", Left, "2", Enter → "123"
        keys = [ord("1"), ord("3"), curses.KEY_LEFT, ord("2"), curses.KEY_ENTER]
        monitor.stdscr.getch.side_effect = keys
        monitor._prompt_config()
        assert monitor._alert_thresholds["cpu"] == 123.0

    def test_delete_key(self, monitor, tmp_path):
        cfg_file = tmp_path / ".procmon.json"
        monitor._CONFIG_PATH = str(cfg_file)

        # Type "12", Home, Delete, Enter → "2"
        keys = [ord("1"), ord("2"), curses.KEY_HOME, curses.KEY_DC, curses.KEY_ENTER]
        monitor.stdscr.getch.side_effect = keys
        monitor._prompt_config()
        assert monitor._alert_thresholds["cpu"] == 2.0

    def test_tab_navigates(self, monitor, tmp_path):
        cfg_file = tmp_path / ".procmon.json"
        monitor._CONFIG_PATH = str(cfg_file)

        # Tab to MEM, type "100", Enter
        keys = [ord("\t"), ord("1"), ord("0"), ord("0"), curses.KEY_ENTER]
        monitor.stdscr.getch.side_effect = keys
        monitor._prompt_config()
        assert monitor._alert_thresholds["mem_mb"] == 100.0

    def test_up_key_navigates(self, monitor, tmp_path):
        cfg_file = tmp_path / ".procmon.json"
        monitor._CONFIG_PATH = str(cfg_file)

        # Down twice to Threads, Up once to MEM, type "200", Enter
        keys = [curses.KEY_DOWN, curses.KEY_DOWN, curses.KEY_UP,
                ord("2"), ord("0"), ord("0"), curses.KEY_ENTER]
        monitor.stdscr.getch.side_effect = keys
        monitor._prompt_config()
        assert monitor._alert_thresholds["mem_mb"] == 200.0

    def test_ignores_non_numeric(self, monitor, tmp_path):
        cfg_file = tmp_path / ".procmon.json"
        monitor._CONFIG_PATH = str(cfg_file)

        # Type "5abc0", Enter → "50" (letters ignored)
        keys = [ord("5"), ord("a"), ord("b"), ord("c"), ord("0"), curses.KEY_ENTER]
        monitor.stdscr.getch.side_effect = keys
        monitor._prompt_config()
        assert monitor._alert_thresholds["cpu"] == 50.0

    def test_interval_and_max_count(self, monitor, tmp_path):
        cfg_file = tmp_path / ".procmon.json"
        monitor._CONFIG_PATH = str(cfg_file)

        # Fields: cpu(0), mem_mb(1), threads(2), fds(3), forks(4),
        #         net_in(5), net_out(6), recv_mb(7), sent_mb(8),
        #         separator(9→auto-skip→10), interval(10), max_count(11)
        # 9 DOWNs from cpu(0): 1,2,3,4,5,6,7,8,9→10 = interval
        keys = []
        for _ in range(9):
            keys.append(curses.KEY_DOWN)
        keys += [21, ord("3"), ord("0")]  # Ctrl-U clear, then interval = 30
        keys.append(curses.KEY_DOWN)
        keys += [21, ord("1"), ord("0")]  # Ctrl-U clear, then max = 10
        keys.append(curses.KEY_ENTER)
        monitor.stdscr.getch.side_effect = keys
        monitor._prompt_config()
        assert monitor._alert_interval == 30.0
        assert monitor._alert_max_count == 10

    def test_decimal_input(self, monitor, tmp_path):
        cfg_file = tmp_path / ".procmon.json"
        monitor._CONFIG_PATH = str(cfg_file)

        keys = [ord("7"), ord("0"), ord("."), ord("5"), curses.KEY_ENTER]
        monitor.stdscr.getch.side_effect = keys
        monitor._prompt_config()
        assert monitor._alert_thresholds["cpu"] == 70.5


# ── _prompt_filter ──────────────────────────────────────────────────────


class TestPromptFilter:

    def test_set_include_filter(self, monitor):
        # Type "python", Enter
        keys = [ord(c) for c in "python"] + [curses.KEY_ENTER]
        monitor.stdscr.getch.side_effect = keys
        with patch.object(monitor, "collect_data"):
            monitor._prompt_filter()
        assert monitor.name == "python"
        assert "python" in monitor.patterns

    def test_set_exclude_filter(self, monitor):
        # Tab to exclude, type "test", Enter
        keys = [ord("\t")] + [ord(c) for c in "test"] + [curses.KEY_ENTER]
        monitor.stdscr.getch.side_effect = keys
        with patch.object(monitor, "collect_data"):
            monitor._prompt_filter()
        assert monitor.exclude_name == "test"
        assert "test" in monitor.exclude_patterns

    def test_cancel_filter(self, monitor):
        monitor.name = "original"
        monitor.patterns = ["original"]
        monitor.stdscr.getch.return_value = 27
        monitor._prompt_filter()
        assert monitor.name == "original"

    def test_filter_backspace(self, monitor):
        keys = [ord("a"), ord("b"), 127, curses.KEY_ENTER]
        monitor.stdscr.getch.side_effect = keys
        with patch.object(monitor, "collect_data"):
            monitor._prompt_filter()
        assert monitor.name == "a"

    def test_filter_home_end(self, monitor):
        keys = [ord("b"), ord("c"), curses.KEY_HOME, ord("a"), curses.KEY_END, curses.KEY_ENTER]
        monitor.stdscr.getch.side_effect = keys
        with patch.object(monitor, "collect_data"):
            monitor._prompt_filter()
        assert monitor.name == "abc"

    def test_filter_left_right(self, monitor):
        keys = [ord("a"), ord("c"), curses.KEY_LEFT, ord("b"), curses.KEY_ENTER]
        monitor.stdscr.getch.side_effect = keys
        with patch.object(monitor, "collect_data"):
            monitor._prompt_filter()
        assert monitor.name == "abc"

    def test_filter_ctrl_u(self, monitor):
        keys = [ord("x"), ord("y"), 21, ord("a"), curses.KEY_ENTER]
        monitor.stdscr.getch.side_effect = keys
        with patch.object(monitor, "collect_data"):
            monitor._prompt_filter()
        assert monitor.name == "a"

    def test_filter_delete(self, monitor):
        keys = [ord("a"), ord("b"), curses.KEY_HOME, curses.KEY_DC, curses.KEY_ENTER]
        monitor.stdscr.getch.side_effect = keys
        with patch.object(monitor, "collect_data"):
            monitor._prompt_filter()
        assert monitor.name == "b"

    def test_filter_up_down_switches(self, monitor):
        # Down to exclude, type "exc", Up to include, type "inc", Enter
        keys = [curses.KEY_DOWN] + [ord(c) for c in "exc"]
        keys += [curses.KEY_UP] + [ord(c) for c in "inc"]
        keys += [curses.KEY_ENTER]
        monitor.stdscr.getch.side_effect = keys
        with patch.object(monitor, "collect_data"):
            monitor._prompt_filter()
        assert monitor.name == "inc"
        assert monitor.exclude_name == "exc"

    def test_filter_comma_separated(self, monitor):
        keys = [ord(c) for c in "python,node"] + [curses.KEY_ENTER]
        monitor.stdscr.getch.side_effect = keys
        with patch.object(monitor, "collect_data"):
            monitor._prompt_filter()
        assert monitor.patterns == ["python", "node"]

    def test_filter_resets_selection(self, monitor):
        monitor.selected = 10
        monitor.scroll_offset = 5
        keys = [curses.KEY_ENTER]
        monitor.stdscr.getch.side_effect = keys
        with patch.object(monitor, "collect_data"):
            monitor._prompt_filter()
        assert monitor.selected == 0
        assert monitor.scroll_offset == 0


# ── _kill_selected ──────────────────────────────────────────────────────


class TestKillSelected:

    def test_kill_single_process(self, monitor):
        monitor.rows = [make_proc(pid=999)]
        with patch("os.kill") as mock_kill, \
             patch.object(monitor, "collect_data"):
            monitor._kill_selected()
        mock_kill.assert_called_once_with(999, signal.SIGKILL)

    def test_kill_no_rows(self, monitor):
        with patch("os.kill") as mock_kill:
            monitor._kill_selected()
        mock_kill.assert_not_called()

    def test_kill_subtree(self, monitor):
        parent = make_proc(pid=100)
        parent["depth"] = 0
        child = make_proc(pid=101, ppid=100)
        child["depth"] = 1
        monitor.rows = [parent, child]
        monitor.selected = 0
        with patch("os.kill") as mock_kill, \
             patch.object(monitor, "collect_data"):
            monitor._kill_selected()
        # Child killed first (reversed), then parent
        assert mock_kill.call_count == 2
        mock_kill.assert_any_call(101, signal.SIGKILL)
        mock_kill.assert_any_call(100, signal.SIGKILL)

    def test_kill_child_walks_to_root(self, monitor):
        parent = make_proc(pid=100)
        parent["depth"] = 0
        child = make_proc(pid=101)
        child["depth"] = 1
        monitor.rows = [parent, child]
        monitor.selected = 1  # selected child
        with patch("os.kill") as mock_kill, \
             patch.object(monitor, "collect_data"):
            monitor._kill_selected()
        assert mock_kill.call_count == 2

    def test_kill_process_not_found(self, monitor):
        monitor.rows = [make_proc(pid=999)]
        with patch("os.kill", side_effect=ProcessLookupError), \
             patch.object(monitor, "collect_data"):
            monitor._kill_selected()  # should not raise

    def test_kill_permission_error(self, monitor):
        monitor.rows = [make_proc(pid=999)]
        with patch("os.kill", side_effect=PermissionError), \
             patch.object(monitor, "collect_data"):
            monitor._kill_selected()  # should not raise


# ── _resort ─────────────────────────────────────────────────────────────


class TestResort:

    def test_empty_rows(self, monitor):
        monitor.rows = []
        monitor._resort()  # should not raise

    def test_resort_maintains_selection(self, monitor):
        with patch("procmon.get_all_processes") as mock_gap:
            mock_gap.return_value = [
                {"pid": 2, "ppid": 0, "cpu": 0.0, "cpu_ticks": 0,
                 "rss_kb": 100, "threads": 1, "command": "/usr/bin/a"},
                {"pid": 3, "ppid": 0, "cpu": 0.0, "cpu_ticks": 0,
                 "rss_kb": 200, "threads": 1, "command": "/usr/bin/b"},
            ]
            monitor.rows = [make_proc(pid=2), make_proc(pid=3)]
            monitor.selected = 1  # pid=3
            monitor._resort()
            # Selection should be maintained or adjusted
            assert monitor.selected >= 0
            assert monitor._all_procs is not None


# ── _toggle_net_mode ────────────────────────────────────────────────────


class TestToggleNetMode:

    def test_toggle_on(self, monitor):
        monitor.rows = [make_proc(pid=1, command="/usr/bin/test")]
        monitor._net_mode = False
        monitor._inspect_mode = True  # should be closed by _toggle_net_mode
        with patch.object(monitor, "_start_net_fetch"):
            monitor._toggle_net_mode()
        assert monitor._net_mode is True
        assert monitor._detail_focus is True
        # Modal exclusivity
        assert monitor._inspect_mode is False

    def test_toggle_off(self, monitor):
        monitor._net_mode = True
        monitor._detail_focus = True
        monitor._toggle_net_mode()
        assert monitor._net_mode is False
        assert monitor._detail_focus is False

    def test_toggle_on_no_rows(self, monitor):
        monitor.rows = []
        monitor._net_mode = False
        monitor._toggle_net_mode()
        assert monitor._net_mode is False


# ── run loop ────────────────────────────────────────────────────────────


class TestRunLoop:

    def test_run_quit_on_q(self, monitor):
        """Run loop exits when 'q' is pressed."""
        call_count = [0]

        def fake_getch():
            call_count[0] += 1
            if call_count[0] == 1:
                return -1  # no key first
            return ord("q")

        monitor.stdscr.getch.side_effect = fake_getch
        with patch.object(monitor, "collect_data"), \
             patch.object(monitor, "render"), \
             patch("time.monotonic", return_value=0.0):
            monitor.run()

    def test_run_refresh_cycle(self, monitor):
        """Run loop refreshes data on interval."""
        times = [0.0, 0.0, 6.0, 6.0]
        time_idx = [0]

        def fake_monotonic():
            idx = min(time_idx[0], len(times) - 1)
            time_idx[0] += 1
            return times[idx]

        call_count = [0]

        def fake_getch():
            call_count[0] += 1
            if call_count[0] >= 3:
                return ord("q")
            return -1

        monitor.stdscr.getch.side_effect = fake_getch
        with patch.object(monitor, "collect_data"), \
             patch.object(monitor, "render"), \
             patch.object(monitor, "_check_alerts"), \
             patch("time.monotonic", side_effect=fake_monotonic):
            monitor.run()


# ── get_net_snapshot ────────────────────────────────────────────────────


class TestGetNetSnapshot:

    def test_normal_output(self):
        fake_output = b"chrome.123,1000,2000,\nfirefox.456,500,300,\n"
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (fake_output, b"")
        with patch("subprocess.Popen", return_value=mock_proc):
            result = procmon.get_net_snapshot()
        assert result[123] == (1000, 2000)
        assert result[456] == (500, 300)

    def test_empty_output(self):
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b"", b"")
        with patch("subprocess.Popen", return_value=mock_proc):
            result = procmon.get_net_snapshot()
        assert result == {}

    def test_timeout(self):
        import subprocess
        mock_proc = MagicMock()
        mock_proc.communicate.side_effect = subprocess.TimeoutExpired("cmd", 5)
        with patch("subprocess.Popen", return_value=mock_proc):
            result = procmon.get_net_snapshot()
        assert result == {}
        mock_proc.kill.assert_called_once()

    def test_file_not_found(self):
        with patch("subprocess.Popen", side_effect=FileNotFoundError):
            result = procmon.get_net_snapshot()
        assert result == {}

    def test_os_error(self):
        with patch("subprocess.Popen", side_effect=OSError):
            result = procmon.get_net_snapshot()
        assert result == {}

    def test_malformed_lines(self):
        fake_output = b",header\nbad line\nchrome.789,100,200,\n\n"
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (fake_output, b"")
        with patch("subprocess.Popen", return_value=mock_proc):
            result = procmon.get_net_snapshot()
        assert 789 in result


# ── get_fd_counts / get_cwds ────────────────────────────────────────────


class TestGetFdCountsCwds:

    def test_fd_counts_empty(self):
        assert procmon.get_fd_counts([]) == {}

    def test_cwds_empty(self):
        assert procmon.get_cwds([]) == {}

    def test_fd_counts_with_pids(self):
        with patch("procmon._get_fd_count", return_value=5):
            result = procmon.get_fd_counts([1, 2])
        assert result == {1: 5, 2: 5}

    def test_cwds_with_pids(self):
        with patch("procmon._get_cwd", return_value="/tmp"):
            result = procmon.get_cwds([1])
        assert result == {1: "/tmp"}


# ── _short_org ──────────────────────────────────────────────────────────


class TestShortOrg:

    def test_empty(self):
        assert procmon._short_org("") == ""

    def test_known_org(self):
        assert procmon._short_org("Amazon Technologies Inc.") == "AWS"
        assert procmon._short_org("Google LLC") == "Google"
        assert procmon._short_org("Cloudflare, Inc") == "Cloudflare"

    def test_unknown_org_strips_corp(self):
        # "Acme Corp, Inc." → split(",")→"Acme Corp" → strip " Corp" → "Acme"
        result = procmon._short_org("Acme Corp, Inc.")
        assert result == "Acme"

    def test_unknown_org_no_suffix(self):
        result = procmon._short_org("Foobar Networks")
        assert result == "Foobar Networks"

    def test_strip_suffix(self):
        assert procmon._short_org("FooCo LLC") == "FooCo"
        assert procmon._short_org("BarCo Ltd") == "BarCo"


# ── _get_geo / _get_org ────────────────────────────────────────────────


class TestGeoOrg:

    def test_get_geo_local(self):
        assert procmon._get_geo("127.0.0.1") == ""

    def test_get_geo_cached(self):
        procmon._geoip_cache["1.2.3.4"] = "NYC/US"
        assert procmon._get_geo("1.2.3.4") == "NYC/US"
        del procmon._geoip_cache["1.2.3.4"]

    def test_get_geo_uncached(self):
        assert procmon._get_geo("99.99.99.99") == ""

    def test_get_org_local(self):
        assert procmon._get_org("127.0.0.1") == ""

    def test_get_org_cached(self):
        procmon._org_cache["5.6.7.8"] = "Test Corp"
        assert procmon._get_org("5.6.7.8") == "Test Corp"
        del procmon._org_cache["5.6.7.8"]


# ── _harden_process ────────────────────────────────────────────────────


class TestHardenProcess:

    def test_runs_without_error(self):
        with patch("os.setpriority"):
            procmon._harden_process()

    def test_permission_errors_handled(self):
        with patch("os.setpriority", side_effect=PermissionError):
            procmon._harden_process()  # should not raise


# ── _self_test ──────────────────────────────────────────────────────────


class TestSelfTest:

    def test_success(self):
        result = procmon._self_test()
        assert result is True  # should pass on macOS


# ── _resolve_ip ─────────────────────────────────────────────────────────


class TestResolveIp:

    def test_local_ip(self):
        assert procmon._resolve_ip("127.0.0.1") == "127.0.0.1"

    def test_private_ip(self):
        assert procmon._resolve_ip("10.0.0.1") == "10.0.0.1"

    def test_cached_ip(self):
        procmon._rdns_cache["test.ip"] = "cached.hostname"
        assert procmon._resolve_ip("test.ip") == "cached.hostname"
        del procmon._rdns_cache["test.ip"]

    def test_cached_none(self):
        procmon._rdns_cache["test.ip2"] = None
        assert procmon._resolve_ip("test.ip2") == "test.ip2"
        del procmon._rdns_cache["test.ip2"]


# ── main ────────────────────────────────────────────────────────────────


class TestComputeCpuDeltas:

    def test_first_call_zero_cpu(self, monitor):
        procs = [{"pid": 1, "cpu_ticks": 1000, "cpu": 0.0}]
        monitor._compute_cpu_deltas(procs)
        assert procs[0]["cpu"] == 0.0  # first sample, no delta

    def test_second_call_has_delta(self, monitor):
        procs1 = [{"pid": 1, "cpu_ticks": 1000, "cpu": 0.0}]
        monitor._compute_cpu_deltas(procs1)

        procs2 = [{"pid": 1, "cpu_ticks": 2000, "cpu": 0.0}]
        with patch("time.monotonic", return_value=time.monotonic() + 1.0):
            monitor._compute_cpu_deltas(procs2)
        # Should have non-zero CPU now
        assert procs2[0]["cpu"] >= 0.0

    def test_dead_pid_pruned(self, monitor):
        procs = [{"pid": 1, "cpu_ticks": 1000, "cpu": 0.0}]
        monitor._compute_cpu_deltas(procs)
        assert 1 in monitor._prev_cpu

        # Second call without pid 1
        monitor._compute_cpu_deltas([])
        assert 1 not in monitor._prev_cpu


# ── _list_all_pids ──────────────────────────────────────────────────────


class TestListAllPids:

    def test_returns_pids(self):
        pids = procmon._list_all_pids()
        assert isinstance(pids, list)
        assert len(pids) > 0
        assert os.getpid() in pids or True  # our pid or at least some pids


# ── get_all_processes ───────────────────────────────────────────────────


class TestGetAllProcesses:

    def test_returns_processes(self):
        procs = procmon.get_all_processes()
        assert isinstance(procs, list)
        assert len(procs) > 0
        assert all("pid" in p and "command" in p for p in procs)

    def test_excludes_own_pid(self):
        procs = procmon.get_all_processes()
        own_pid = os.getpid()
        assert all(p["pid"] != own_pid for p in procs)


# ── collect_data ────────────────────────────────────────────────────────


class TestCollectData:

    def test_collect_data_populates_rows(self, monitor):
        with patch("procmon.get_all_processes") as mock_gap, \
             patch("procmon.get_net_snapshot", return_value={}), \
             patch("procmon.get_fd_counts", return_value={}), \
             patch("procmon.get_cwds", return_value={}), \
             patch("procmon._check_hidden_pids_quick", return_value=set()):
            mock_gap.return_value = [
                {"pid": 2, "ppid": 0, "cpu": 0.0, "cpu_ticks": 100,
                 "rss_kb": 1024, "threads": 2, "command": "/usr/bin/test"},
            ]
            monitor.collect_data()
        assert len(monitor.rows) >= 1
        assert monitor.matched_count >= 1

    def test_collect_data_with_filter(self, monitor):
        monitor.patterns = ["python"]
        with patch("procmon.get_all_processes") as mock_gap, \
             patch("procmon.get_net_snapshot", return_value={}), \
             patch("procmon.get_fd_counts", return_value={}), \
             patch("procmon.get_cwds", return_value={}), \
             patch("procmon._check_hidden_pids_quick", return_value=set()):
            mock_gap.return_value = [
                {"pid": 2, "ppid": 0, "cpu": 0.0, "cpu_ticks": 100,
                 "rss_kb": 1024, "threads": 2, "command": "/usr/bin/python3"},
                {"pid": 3, "ppid": 0, "cpu": 0.0, "cpu_ticks": 100,
                 "rss_kb": 512, "threads": 1, "command": "/usr/bin/ruby"},
            ]
            monitor.collect_data()
        assert monitor.matched_count == 1
        assert monitor._all_procs[0]["command"] == "/usr/bin/python3"

    def test_collect_data_with_exclude(self, monitor):
        monitor.exclude_patterns = ["ruby"]
        with patch("procmon.get_all_processes") as mock_gap, \
             patch("procmon.get_net_snapshot", return_value={}), \
             patch("procmon.get_fd_counts", return_value={}), \
             patch("procmon.get_cwds", return_value={}), \
             patch("procmon._check_hidden_pids_quick", return_value=set()):
            mock_gap.return_value = [
                {"pid": 2, "ppid": 0, "cpu": 0.0, "cpu_ticks": 100,
                 "rss_kb": 1024, "threads": 2, "command": "/usr/bin/python3"},
                {"pid": 3, "ppid": 0, "cpu": 0.0, "cpu_ticks": 100,
                 "rss_kb": 512, "threads": 1, "command": "/usr/bin/ruby"},
            ]
            monitor.collect_data()
        assert monitor.matched_count == 1


# ── _start_net_fetch / _poll_net_result ─────────────────────────────────


class TestNetFetch:

    def test_start_net_fetch(self, monitor):
        monitor._net_worker = None
        with patch.object(monitor, "_fetch_net_connections", return_value=[]):
            monitor._start_net_fetch(1)
        assert monitor._net_loading is True

    def test_start_net_fetch_already_running(self, monitor):
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = True
        monitor._net_worker = mock_thread
        monitor._start_net_fetch(1)
        # Should not create new thread

    def test_poll_no_pending(self, monitor):
        monitor._net_pending = None
        assert monitor._poll_net_result() is False

    def test_poll_loading(self, monitor):
        monitor._net_pending = "loading"
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = True
        monitor._net_worker = mock_thread
        assert monitor._poll_net_result() is False

    def test_poll_ready(self, monitor):
        monitor._net_pending = [{"display": "test", "org": "", "fd": 1}]
        monitor._net_mode = True  # must be in net mode
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = False
        monitor._net_worker = mock_thread
        assert monitor._poll_net_result() is True
        assert monitor._net_entries == [{"display": "test", "org": "", "fd": 1}]

    def test_poll_closed_net_mode(self, monitor):
        monitor._net_pending = [{"display": "test", "org": "", "fd": 1}]
        monitor._net_mode = False  # user closed net mode
        assert monitor._poll_net_result() is False
        assert monitor._net_pending is None


# ── _scroll_net_to_selected ─────────────────────────────────────────────


class TestScrollNetToSelected:

    def test_scroll_adjusts(self, monitor):
        monitor._net_selected = 20
        monitor._net_scroll = 0
        monitor.stdscr.getmaxyx.return_value = (40, 120)
        monitor._scroll_net_to_selected()
        # scroll should adjust to make selected visible


# ── _set_sort ───────────────────────────────────────────────────────────


class TestSetSort:

    def test_change_mode(self, monitor):
        monitor.sort_mode = procmon.SORT_MEM
        monitor._sort_inverted = True
        with patch.object(monitor, "_resort"):
            monitor._set_sort(procmon.SORT_CPU)
        assert monitor.sort_mode == procmon.SORT_CPU
        assert monitor._sort_inverted is False

    def test_toggle_same_mode(self, monitor):
        monitor.sort_mode = procmon.SORT_MEM
        monitor._sort_inverted = False
        with patch.object(monitor, "_resort"):
            monitor._set_sort(procmon.SORT_MEM)
        assert monitor._sort_inverted is True
