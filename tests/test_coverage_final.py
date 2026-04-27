"""Final coverage push — target small scattered uncovered regions.

Focuses on rendering branches, handle_input paths, and leftover helpers
that are reachable with cheap curses-mocked tests.
"""
import os
import sys
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import procmon
from tests.conftest import make_proc


# ── Render guard + header extras ──────────────────────────────────────────


class TestRenderGuards:
    def test_tiny_terminal_shows_message(self, monitor):
        monitor.stdscr.getmaxyx.return_value = (5, 30)  # too small
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put") as put:
            monitor.render()
        # "Terminal too small" was drawn
        assert any("Terminal too small" in str(c) for c in put.call_args_list)

    def test_header_hidden_alert_banner(self, monitor):
        monitor.stdscr.getmaxyx.return_value = (40, 160)
        monitor.rows = [make_proc(pid=1, command="/bin/test")]
        monitor._hidden_alert_count = 3
        monitor._detail_focus = False
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put") as put, \
             patch.object(monitor, "_render_detail"):
            monitor.render()
        # HIDDEN: 3 banner was rendered
        assert any("HIDDEN: 3" in str(c) for c in put.call_args_list)

    def test_filter_tags_in_header(self, monitor):
        monitor.stdscr.getmaxyx.return_value = (40, 160)
        monitor.rows = [make_proc(pid=1, command="/bin/test")]
        monitor.name = "chrome"
        monitor.exclude_name = "helper"
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put") as put, \
             patch.object(monitor, "_render_detail"):
            monitor.render()
        s = " ".join(str(c) for c in put.call_args_list)
        assert "+'chrome'" in s
        assert "-'helper'" in s


# ── Input handler for audit / keyscan ≤ 4 chars edge ──────────────────────


class TestAuditMoveCursorEdge:
    def test_move_cursor_without_structured_scrolls_audit(self, monitor):
        monitor._audit_mode = True
        monitor._detail_focus = True
        monitor._audit_findings_structured = []
        monitor._audit_scroll = 5
        import curses
        monitor.handle_input(curses.KEY_UP)
        assert monitor._audit_scroll == 4

    def test_move_cursor_up_below_zero_clamps(self, monitor):
        monitor._audit_mode = True
        monitor._detail_focus = True
        monitor._audit_findings_structured = []
        monitor._audit_scroll = 0
        import curses
        monitor.handle_input(curses.KEY_UP)
        assert monitor._audit_scroll == 0


# ── _collect_chat_context: inspect + hidden-scan + bulk-scan ───────────────


class TestCollectChatContextExtras:

    def test_inspect_mode_context(self, monitor):
        monitor._inspect_mode = True
        monitor._inspect_lines = ["inspect report line"]
        monitor._inspect_pid = 1234
        monitor._inspect_cmd = "/bin/target"
        monitor.rows = []
        monitor.selected = 0
        label, text = monitor._collect_chat_context()
        assert "1234" in label
        assert "inspect report line" in text

    def test_events_mode_context(self, monitor):
        monitor._events_mode = True
        monitor._events_lock = threading.Lock()
        monitor._events_source = "eslogger"
        with monitor._events_lock:
            monitor._events = [{"pid": 1, "ppid": 0, "cmd": "/bin/sh",
                                 "ts": 0, "kind": "exec", "extra": {}}]
        label, text = monitor._collect_chat_context()
        assert "Security timeline" in label
        assert "eslogger" in text

    def test_net_mode_context(self, monitor):
        monitor._net_mode = True
        monitor._net_entries = [{"display": "tcp *:22"}]
        monitor._net_pid = 99
        monitor._net_cmd = "sshd"
        label, text = monitor._collect_chat_context()
        assert "99" in label
        assert "tcp *:22" in text

    def test_main_list_context_with_selected_process(self, monitor):
        monitor.rows = [make_proc(pid=42, command="/Applications/Thing")]
        monitor.selected = 0
        label, text = monitor._collect_chat_context()
        assert "42" in label
        assert "command: /Applications/Thing" in text

    def test_main_list_empty_falls_through(self, monitor):
        monitor.rows = []
        label, text = monitor._collect_chat_context()
        assert label == "Process list"


# ── _prompt_audit / _prompt_forensic — click through once ────────────────


class TestPromptAuditTopEntry:
    pass

class TestPromptForensicTopEntry:
    def test_enter_runs_inspect(self, monitor):
        monitor.stdscr.getmaxyx.return_value = (40, 120)
        monitor.stdscr.getch.side_effect = [10]  # Enter on first action row
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put"), \
             patch.object(monitor, "_toggle_inspect_mode") as tog:
            monitor._prompt_forensic()
        tog.assert_called_once()


class TestPromptTelemetryTopEntry:
    def test_enter_runs_security_timeline(self, monitor):
        monitor.stdscr.getmaxyx.return_value = (40, 120)
        monitor.stdscr.getch.side_effect = [10]
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put"), \
             patch.object(monitor, "_toggle_events_mode") as tog:
            monitor._prompt_telemetry()
        tog.assert_called_once()


# ── _render_sectioned_menu PageUp ────────────────────────────────────────


class TestSectionedMenuPageUp:
    def test_page_up_navigation(self, monitor):
        import curses
        rows = [
            ("H1", "header", None),
            ("A", "action", "a"),
            ("H2", "header", None),
            ("B", "action", "b"),
        ]
        monitor.stdscr.getmaxyx.return_value = (40, 120)
        # Go down, then PageUp, then Enter
        monitor.stdscr.getch.side_effect = [
            curses.KEY_DOWN, curses.KEY_PPAGE, 10]
        picked = []
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put"):
            monitor._run_sectioned_menu(
                rows, title="T", footer="f",
                on_select=picked.append)
        assert picked  # selected something


# ── Dispatch action: keyscan permission/lookup errors ────────────────────


class TestDispatchKeyscanErrorPaths:
    def _ready(self, monitor):
        monitor._log_messages = []
        monitor._log_lock = threading.Lock()
        monitor._log_max = 100
        return monitor






# ── Log messages panel (toggle + scroll) ──────────────────────────────────


class TestLogToggle:
    def test_log_toggle_opens(self, monitor):
        monitor._log_mode = False
        monitor._detail_focus = False
        monitor.handle_input(ord("L"))
        assert monitor._log_mode is True

    def test_log_toggle_closes(self, monitor):
        monitor._log_mode = True
        monitor.handle_input(ord("L"))
        assert monitor._log_mode is False


# ── Chat mode open/close ──────────────────────────────────────────────────


class TestChatToggle:
    def test_question_mark_opens_chat(self, monitor):
        monitor._chat_mode = False
        monitor._detail_focus = False
        monitor.rows = []
        with patch.object(monitor, "_chat_send") as send:
            monitor.handle_input(ord("?"))
        assert monitor._chat_mode is True
        send.assert_called_once_with("Tell me more about this item.",
                                     auto_open=True)

    def test_exit_chat_clears_flag(self, monitor):
        monitor._chat_mode = True
        monitor._exit_chat_mode()
        assert monitor._chat_mode is False


# ── UI: toggle-close paths when re-pressing the same audit type ──────────


class TestWrapText:
    def test_wraps_long_line(self, monitor):
        # Word-boundary wrap: supply a line that has spaces.
        text = "word " * 30  # 150 chars with spaces
        result = monitor._wrap_text(text, 20)
        assert len(result) > 1

    def test_preserves_hard_newlines(self, monitor):
        result = monitor._wrap_text("line1\nline2\nline3", 50)
        assert result == ["line1", "line2", "line3"]

    def test_word_boundary_wrap(self, monitor):
        result = monitor._wrap_text(
            "one two three four five six seven eight nine ten", 15)
        assert all(len(l) <= 15 for l in result)


# ── Action panel render ───────────────────────────────────────────────────


class TestFormatActionPanel:
    def test_renders_ok(self, monitor):
        panel = monitor._format_action_panel({
            "level": "ok", "summary": "it worked", "detail_text": ""}, 80)
        joined = "\n".join(panel)
        assert "Success" in joined
        assert "it worked" in joined

    def test_renders_error_with_detail(self, monitor):
        panel = monitor._format_action_panel({
            "level": "error", "summary": "broke",
            "detail_text": "see log\nfor more"}, 80)
        joined = "\n".join(panel)
        assert "Failed" in joined
        assert "broke" in joined
        assert "see log" in joined

    def test_renders_info(self, monitor):
        panel = monitor._format_action_panel({
            "level": "info", "summary": "cancelled", "detail_text": ""}, 80)
        joined = "\n".join(panel)
        assert "cancelled" in joined


# ── _detail_lines (main list detail) ──────────────────────────────────────


class TestDetailLines:
    def test_detail_lines_for_selected_row(self, monitor):
        monitor.rows = [make_proc(pid=1, command="/bin/test", cpu=10.0,
                                   rss_kb=1024)]
        monitor.selected = 0
        monitor.skip_fd = False
        lines = monitor._detail_lines(w=120)
        joined = "\n".join(lines)
        assert "PID: 1" in joined
        assert "/bin/test" in joined

    def test_detail_lines_empty_when_no_rows(self, monitor):
        monitor.rows = []
        assert monitor._detail_lines(w=120) == []


# ── Page size helper ─────────────────────────────────────────────────────


class TestPageSize:
    def test_returns_positive(self, monitor):
        monitor.stdscr.getmaxyx.return_value = (40, 120)
        assert monitor._page_size() >= 1

    def test_small_screen_returns_at_least_one(self, monitor):
        monitor.stdscr.getmaxyx.return_value = (5, 40)
        assert monitor._page_size() >= 1
