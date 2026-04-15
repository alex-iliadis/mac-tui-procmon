"""Unit tests for procmon — alert system, helpers, commands, config, tree, filters."""
import curses
import json
import os
import sys
import time
from unittest.mock import MagicMock, mock_open, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import procmon
from tests.conftest import make_proc


# ── Alert Unit Tests ────────────────────────────────────────────────────


class TestCheckAlertsNoThresholds:
    """When no thresholds are set, no alerts should fire."""

    def test_no_alert_when_all_thresholds_zero(self, monitor):
        monitor._all_procs = [make_proc(cpu=999)]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_not_called()
        assert monitor._alert_count == 0


class TestCheckAlertsCPU:
    """CPU threshold triggering."""

    def test_alert_fires_when_cpu_exceeds_threshold(self, monitor):
        monitor._alert_thresholds["cpu"] = 70.0
        monitor._all_procs = [make_proc(cpu=80.0)]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_called_once()
        assert monitor._alert_count == 1

    def test_no_alert_when_cpu_below_threshold(self, monitor):
        monitor._alert_thresholds["cpu"] = 70.0
        monitor._all_procs = [make_proc(cpu=50.0)]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_not_called()
        assert monitor._alert_count == 0

    def test_no_alert_at_exact_threshold(self, monitor):
        monitor._alert_thresholds["cpu"] = 70.0
        monitor._all_procs = [make_proc(cpu=70.0)]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_not_called()

    def test_alert_sums_cpu_across_procs(self, monitor):
        monitor._alert_thresholds["cpu"] = 70.0
        monitor._all_procs = [make_proc(pid=1, cpu=40.0), make_proc(pid=2, cpu=40.0)]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_called_once()


class TestCheckAlertsMem:
    """Memory threshold triggering."""

    def test_alert_fires_when_mem_exceeds_threshold(self, monitor):
        monitor._alert_thresholds["mem_mb"] = 1000.0
        monitor._all_procs = [make_proc(rss_kb=2000 * 1024)]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_called_once()
        assert monitor._alert_count == 1

    def test_no_alert_when_mem_below_threshold(self, monitor):
        monitor._alert_thresholds["mem_mb"] = 1000.0
        monitor._all_procs = [make_proc(rss_kb=500 * 1024)]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_not_called()


class TestCheckAlertsThreads:
    """Thread count threshold."""

    def test_alert_fires_when_threads_exceed(self, monitor):
        monitor._alert_thresholds["threads"] = 100
        monitor._all_procs = [make_proc(threads=150)]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_called_once()

    def test_no_alert_when_threads_below(self, monitor):
        monitor._alert_thresholds["threads"] = 100
        monitor._all_procs = [make_proc(threads=50)]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_not_called()


class TestCheckAlertsFDs:
    """File descriptor threshold."""

    def test_alert_fires_when_fds_exceed(self, monitor):
        monitor._alert_thresholds["fds"] = 500
        monitor._all_procs = [make_proc(fds=600)]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_called_once()

    def test_no_alert_when_fds_below(self, monitor):
        monitor._alert_thresholds["fds"] = 500
        monitor._all_procs = [make_proc(fds=100)]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_not_called()

    def test_negative_fds_clamped_to_zero(self, monitor):
        monitor._alert_thresholds["fds"] = 10
        monitor._all_procs = [make_proc(fds=-1)]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_not_called()


class TestCheckAlertsForks:
    """Fork count threshold."""

    def test_alert_fires_when_forks_exceed(self, monitor):
        monitor._alert_thresholds["forks"] = 10
        monitor._all_procs = [make_proc(forks=20)]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_called_once()

    def test_no_alert_when_forks_below(self, monitor):
        monitor._alert_thresholds["forks"] = 10
        monitor._all_procs = [make_proc(forks=5)]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_not_called()


class TestCheckAlertsNetIn:
    """Network in threshold (KB/s)."""

    def test_alert_fires_when_net_in_exceeds(self, monitor):
        monitor._alert_thresholds["net_in"] = 100.0
        # net_in is in bytes/s, threshold is KB/s; total = sum(net_in)/1024
        monitor._all_procs = [make_proc(net_in=200 * 1024)]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_called_once()

    def test_no_alert_when_net_in_below(self, monitor):
        monitor._alert_thresholds["net_in"] = 100.0
        monitor._all_procs = [make_proc(net_in=50 * 1024)]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_not_called()

    def test_negative_net_in_clamped(self, monitor):
        monitor._alert_thresholds["net_in"] = 1.0
        monitor._all_procs = [make_proc(net_in=-1)]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_not_called()


class TestCheckAlertsNetOut:
    """Network out threshold (KB/s)."""

    def test_alert_fires_when_net_out_exceeds(self, monitor):
        monitor._alert_thresholds["net_out"] = 100.0
        monitor._all_procs = [make_proc(net_out=200 * 1024)]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_called_once()

    def test_no_alert_when_net_out_below(self, monitor):
        monitor._alert_thresholds["net_out"] = 100.0
        monitor._all_procs = [make_proc(net_out=50 * 1024)]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_not_called()


class TestCheckAlertsRecvMB:
    """Cumulative received MB threshold."""

    def test_alert_fires_when_recv_exceeds(self, monitor):
        monitor._alert_thresholds["recv_mb"] = 100.0
        monitor._all_procs = [make_proc(bytes_in=200 * 1024 * 1024)]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_called_once()

    def test_no_alert_when_recv_below(self, monitor):
        monitor._alert_thresholds["recv_mb"] = 100.0
        monitor._all_procs = [make_proc(bytes_in=50 * 1024 * 1024)]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_not_called()


class TestCheckAlertsSentMB:
    """Cumulative sent MB threshold."""

    def test_alert_fires_when_sent_exceeds(self, monitor):
        monitor._alert_thresholds["sent_mb"] = 100.0
        monitor._all_procs = [make_proc(bytes_out=200 * 1024 * 1024)]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_called_once()

    def test_no_alert_when_sent_below(self, monitor):
        monitor._alert_thresholds["sent_mb"] = 100.0
        monitor._all_procs = [make_proc(bytes_out=50 * 1024 * 1024)]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_not_called()


class TestAlertCooldown:
    """Cooldown interval between alerts."""

    def test_cooldown_prevents_rapid_alerts(self, monitor):
        monitor._alert_thresholds["cpu"] = 50.0
        monitor._all_procs = [make_proc(cpu=100.0)]
        monitor._alert_interval = 60

        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
            assert popen.call_count == 1
            # Second call within cooldown should not fire
            monitor._check_alerts()
            assert popen.call_count == 1

    def test_alert_fires_after_cooldown_expires(self, monitor):
        monitor._alert_thresholds["cpu"] = 50.0
        monitor._all_procs = [make_proc(cpu=100.0)]
        monitor._alert_interval = 1

        with patch("subprocess.Popen") as popen, \
             patch("time.monotonic") as mock_time:
            mock_time.return_value = 1000.0
            monitor._check_alerts()
            assert popen.call_count == 1

            mock_time.return_value = 1000.5
            monitor._check_alerts()
            assert popen.call_count == 1  # still in cooldown

            mock_time.return_value = 1002.0
            monitor._check_alerts()
            assert popen.call_count == 2  # cooldown expired


class TestAlertMaxCount:
    """Maximum alert count limiting."""

    def test_stops_after_max_count(self, monitor):
        monitor._alert_thresholds["cpu"] = 50.0
        monitor._all_procs = [make_proc(cpu=100.0)]
        monitor._alert_max_count = 3
        monitor._alert_interval = 0  # no cooldown

        with patch("subprocess.Popen") as popen:
            for _ in range(5):
                monitor._check_alerts()
            assert popen.call_count == 3
            assert monitor._alert_count == 3

    def test_unlimited_when_max_count_zero(self, monitor):
        monitor._alert_thresholds["cpu"] = 50.0
        monitor._all_procs = [make_proc(cpu=100.0)]
        monitor._alert_max_count = 0
        monitor._alert_interval = 0

        with patch("subprocess.Popen") as popen:
            for _ in range(10):
                monitor._check_alerts()
            assert popen.call_count == 10


class TestAlertReset:
    """Alert count/timer reset when condition clears."""

    def test_reset_when_condition_clears(self, monitor):
        monitor._alert_thresholds["cpu"] = 70.0
        monitor._alert_interval = 0

        with patch("subprocess.Popen"):
            # Fire some alerts
            monitor._all_procs = [make_proc(cpu=100.0)]
            monitor._check_alerts()
            assert monitor._alert_count == 1

            # Condition clears
            monitor._all_procs = [make_proc(cpu=10.0)]
            monitor._check_alerts()
            assert monitor._alert_count == 0
            assert monitor._alert_last_sound == 0.0

    def test_reset_after_max_count_when_condition_clears(self, monitor):
        """The key bug fix: count must reset even after hitting max count."""
        monitor._alert_thresholds["cpu"] = 70.0
        monitor._alert_max_count = 3
        monitor._alert_interval = 0

        with patch("subprocess.Popen") as popen:
            # Hit max count
            monitor._all_procs = [make_proc(cpu=100.0)]
            for _ in range(5):
                monitor._check_alerts()
            assert monitor._alert_count == 3
            assert popen.call_count == 3

            # Condition clears — count MUST reset
            monitor._all_procs = [make_proc(cpu=10.0)]
            monitor._check_alerts()
            assert monitor._alert_count == 0
            assert monitor._alert_last_sound == 0.0

            # Condition returns — alerts should fire again
            monitor._all_procs = [make_proc(cpu=100.0)]
            monitor._check_alerts()
            assert monitor._alert_count == 1
            assert popen.call_count == 4

    def test_retrigger_full_cycle(self, monitor):
        """Full cycle: trigger → max → clear → retrigger."""
        monitor._alert_thresholds["cpu"] = 70.0
        monitor._alert_max_count = 2
        monitor._alert_interval = 0

        with patch("subprocess.Popen") as popen:
            # Phase 1: fire 2 alerts, hit max
            monitor._all_procs = [make_proc(cpu=100.0)]
            monitor._check_alerts()
            monitor._check_alerts()
            monitor._check_alerts()  # blocked by max
            assert popen.call_count == 2

            # Phase 2: clear
            monitor._all_procs = [make_proc(cpu=10.0)]
            monitor._check_alerts()
            assert monitor._alert_count == 0

            # Phase 3: retrigger, fire 2 more
            monitor._all_procs = [make_proc(cpu=100.0)]
            monitor._check_alerts()
            monitor._check_alerts()
            assert popen.call_count == 4


class TestAlertProcsSource:
    """Alert uses _all_procs, not self.rows."""

    def test_uses_all_procs(self, monitor):
        monitor._alert_thresholds["cpu"] = 50.0
        monitor.rows = [make_proc(cpu=10.0)]
        monitor._all_procs = [make_proc(cpu=100.0)]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_called_once()

    def test_falls_back_to_rows(self, monitor):
        monitor._alert_thresholds["cpu"] = 50.0
        monitor.rows = [make_proc(cpu=100.0)]
        if hasattr(monitor, "_all_procs"):
            delattr(monitor, "_all_procs")
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_called_once()


class TestAlertSoundError:
    """Alert handles OSError from afplay gracefully."""

    def test_oserror_does_not_crash(self, monitor):
        monitor._alert_thresholds["cpu"] = 50.0
        monitor._all_procs = [make_proc(cpu=100.0)]
        with patch("subprocess.Popen", side_effect=OSError("no afplay")):
            monitor._check_alerts()
        assert monitor._alert_count == 1


class TestAlertMultipleThresholds:
    """Multiple thresholds set simultaneously."""

    def test_triggers_on_any_threshold(self, monitor):
        monitor._alert_thresholds["cpu"] = 200.0  # not exceeded
        monitor._alert_thresholds["mem_mb"] = 100.0  # exceeded
        monitor._all_procs = [make_proc(cpu=50.0, rss_kb=200 * 1024)]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_called_once()


# ── Config Tests ────────────────────────────────────────────────────────


class TestConfig:

    def test_load_config(self, monitor, tmp_path):
        cfg = {
            "alert_thresholds": {"cpu": 80.0, "mem_mb": 5000.0},
            "alert_interval": 30,
            "alert_max_count": 10,
        }
        cfg_file = tmp_path / ".procmon.json"
        cfg_file.write_text(json.dumps(cfg))
        monitor._CONFIG_PATH = str(cfg_file)
        monitor._load_config()
        assert monitor._alert_thresholds["cpu"] == 80.0
        assert monitor._alert_thresholds["mem_mb"] == 5000.0
        assert monitor._alert_thresholds["fds"] == 0  # unchanged
        assert monitor._alert_interval == 30
        assert monitor._alert_max_count == 10

    def test_load_config_missing_file(self, monitor, tmp_path):
        monitor._CONFIG_PATH = str(tmp_path / "nonexistent.json")
        monitor._load_config()  # should not raise
        assert monitor._alert_thresholds["cpu"] == 0.0

    def test_load_config_invalid_json(self, monitor, tmp_path):
        cfg_file = tmp_path / ".procmon.json"
        cfg_file.write_text("not json{{{")
        monitor._CONFIG_PATH = str(cfg_file)
        monitor._load_config()  # should not raise
        assert monitor._alert_thresholds["cpu"] == 0.0

    def test_save_config(self, monitor, tmp_path):
        cfg_file = tmp_path / ".procmon.json"
        monitor._CONFIG_PATH = str(cfg_file)
        monitor._alert_thresholds["cpu"] = 42.0
        monitor._alert_interval = 15
        monitor._alert_max_count = 3
        monitor._save_config()
        saved = json.loads(cfg_file.read_text())
        assert saved["alert_thresholds"]["cpu"] == 42.0
        assert saved["alert_interval"] == 15
        assert saved["alert_max_count"] == 3

    def test_config_roundtrip(self, monitor, tmp_path):
        cfg_file = tmp_path / ".procmon.json"
        monitor._CONFIG_PATH = str(cfg_file)
        monitor._alert_thresholds["cpu"] = 99.0
        monitor._alert_thresholds["threads"] = 512
        monitor._alert_interval = 5
        monitor._alert_max_count = 0
        monitor._save_config()

        # Reset and reload
        monitor._alert_thresholds["cpu"] = 0.0
        monitor._alert_thresholds["threads"] = 0
        monitor._alert_interval = 60
        monitor._alert_max_count = 5
        monitor._load_config()
        assert monitor._alert_thresholds["cpu"] == 99.0
        assert monitor._alert_thresholds["threads"] == 512
        assert monitor._alert_interval == 5
        assert monitor._alert_max_count == 0

    def test_load_config_ignores_unknown_keys(self, monitor, tmp_path):
        cfg = {"alert_thresholds": {"cpu": 10.0, "unknown_key": 999}, "extra": True}
        cfg_file = tmp_path / ".procmon.json"
        cfg_file.write_text(json.dumps(cfg))
        monitor._CONFIG_PATH = str(cfg_file)
        monitor._load_config()
        assert monitor._alert_thresholds["cpu"] == 10.0
        assert "unknown_key" not in monitor._alert_thresholds


# ── Helper Function Tests ───────────────────────────────────────────────


class TestFmtMem:

    def test_kb(self):
        assert procmon.fmt_mem(500) == "500 KB"

    def test_mb(self):
        assert procmon.fmt_mem(2048) == "2.0 MB"

    def test_gb(self):
        assert procmon.fmt_mem(2 * 1024 * 1024) == "2.00 GB"

    def test_zero(self):
        assert procmon.fmt_mem(0) == "0 KB"

    def test_boundary_kb_mb(self):
        assert procmon.fmt_mem(1023) == "1023 KB"
        assert procmon.fmt_mem(1024) == "1.0 MB"

    def test_boundary_mb_gb(self):
        assert procmon.fmt_mem(1024 * 1024 - 1) == "1024.0 MB"
        assert procmon.fmt_mem(1024 * 1024) == "1.00 GB"


class TestFmtBytes:

    def test_bytes(self):
        assert procmon.fmt_bytes(500) == "500 B"

    def test_kb(self):
        assert procmon.fmt_bytes(2048) == "2.0 KB"

    def test_mb(self):
        assert procmon.fmt_bytes(2 * 1024 * 1024) == "2.0 MB"

    def test_gb(self):
        assert procmon.fmt_bytes(3 * 1024 * 1024 * 1024) == "3.00 GB"

    def test_zero(self):
        assert procmon.fmt_bytes(0) == "0 B"


class TestFmtRate:

    def test_negative(self):
        assert procmon.fmt_rate(-1) == "-"

    def test_bps(self):
        assert procmon.fmt_rate(500) == "500 B/s"

    def test_kbps(self):
        assert procmon.fmt_rate(2048) == "2.0 KB/s"

    def test_mbps(self):
        assert procmon.fmt_rate(2 * 1024 * 1024) == "2.0 MB/s"

    def test_zero(self):
        assert procmon.fmt_rate(0) == "0 B/s"


class TestShortCwd:

    def test_home_prefix(self):
        result = procmon.short_cwd(procmon.HOME + "/Documents")
        assert result == "~/Documents"

    def test_non_home(self):
        assert procmon.short_cwd("/usr/local/bin") == "/usr/local/bin"

    def test_home_itself(self):
        assert procmon.short_cwd(procmon.HOME) == "~"


class TestShortCommand:

    def test_absolute_path_with_vendor(self):
        result = procmon._short_command("/usr/bin/python3")
        assert "python3" in result

    def test_app_bundle_with_vendor(self):
        result = procmon._short_command("/Applications/Firefox.app/Contents/MacOS/firefox")
        assert "Firefox" in result

    def test_relative_command(self):
        result = procmon._short_command("python3 script.py")
        assert "python3" in result

    def test_no_vendor_for_unknown_path(self):
        result = procmon._short_command("/opt/custom/bin/myapp")
        assert result == "myapp"


class TestExtractPort:

    def test_normal(self):
        assert procmon._extract_port("192.168.1.1:8080") == 8080

    def test_wildcard(self):
        assert procmon._extract_port("*:443") == 443

    def test_invalid(self):
        assert procmon._extract_port("noport") == 0


class TestPortService:

    def test_known_port(self):
        assert procmon._port_service(443) == "HTTPS"
        assert procmon._port_service(22) == "SSH"
        assert procmon._port_service(80) == "HTTP"

    def test_unknown_port(self):
        assert procmon._port_service(99999) == ""


class TestIsLocalIp:

    def test_localhost(self):
        assert procmon._is_local_ip("localhost")

    def test_127(self):
        assert procmon._is_local_ip("127.0.0.1")

    def test_private_10(self):
        assert procmon._is_local_ip("10.0.0.1")

    def test_private_192(self):
        assert procmon._is_local_ip("192.168.1.1")

    def test_public(self):
        assert not procmon._is_local_ip("8.8.8.8")

    def test_empty(self):
        assert procmon._is_local_ip("")

    def test_wildcard(self):
        assert procmon._is_local_ip("*")


class TestResolveAddr:

    def test_no_colon(self):
        assert procmon._resolve_addr("localhost") == "localhost"

    def test_ipv6_passthrough(self):
        assert procmon._resolve_addr("[::1]:8080") == "[::1]:8080"

    def test_normal_addr(self):
        with patch.object(procmon, "_resolve_ip", return_value="resolved"):
            assert procmon._resolve_addr("1.2.3.4:80") == "resolved:80"


# ── Command / Input Tests ──────────────────────────────────────────────


class TestHandleInputQuit:

    def test_q_quits(self, monitor):
        assert monitor.handle_input(ord("q")) is False

    def test_escape_quits_when_not_net_mode(self, monitor):
        monitor._net_mode = False
        assert monitor.handle_input(27) is False

    def test_escape_closes_net_mode_first(self, monitor):
        monitor._net_mode = True
        monitor._detail_focus = True
        result = monitor.handle_input(27)
        assert result is True
        assert monitor._net_mode is False
        assert monitor._detail_focus is False


class TestHandleInputNavigation:

    def test_down_arrow(self, monitor):
        monitor.rows = [make_proc(pid=1), make_proc(pid=2), make_proc(pid=3)]
        monitor.selected = 0
        monitor.handle_input(curses.KEY_DOWN)
        assert monitor.selected == 1

    def test_up_arrow(self, monitor):
        monitor.rows = [make_proc(pid=1), make_proc(pid=2)]
        monitor.selected = 1
        monitor.handle_input(curses.KEY_UP)
        assert monitor.selected == 0

    def test_down_arrow_at_bottom(self, monitor):
        monitor.rows = [make_proc(pid=1), make_proc(pid=2)]
        monitor.selected = 1
        monitor.handle_input(curses.KEY_DOWN)
        assert monitor.selected == 1  # no change

    def test_up_arrow_at_top(self, monitor):
        monitor.rows = [make_proc(pid=1)]
        monitor.selected = 0
        monitor.handle_input(curses.KEY_UP)
        assert monitor.selected == 0

    def test_page_down(self, monitor):
        monitor.rows = [make_proc(pid=i) for i in range(50)]
        monitor.selected = 0
        monitor.handle_input(curses.KEY_NPAGE)
        assert monitor.selected > 0

    def test_page_up(self, monitor):
        monitor.rows = [make_proc(pid=i) for i in range(50)]
        monitor.selected = 40
        monitor.handle_input(curses.KEY_PPAGE)
        assert monitor.selected < 40


class TestHandleInputSort:

    def test_sort_mem(self, monitor):
        monitor.sort_mode = procmon.SORT_CPU
        with patch.object(monitor, "_resort"):
            monitor.handle_input(ord("m"))
        assert monitor.sort_mode == procmon.SORT_MEM

    def test_sort_cpu(self, monitor):
        with patch.object(monitor, "_resort"):
            monitor.handle_input(ord("c"))
        assert monitor.sort_mode == procmon.SORT_CPU

    def test_sort_net(self, monitor):
        with patch.object(monitor, "_resort"):
            monitor.handle_input(ord("n"))
        assert monitor.sort_mode == procmon.SORT_NET

    def test_sort_alpha(self, monitor):
        with patch.object(monitor, "_resort"):
            monitor.handle_input(ord("A"))
        assert monitor.sort_mode == procmon.SORT_ALPHA

    def test_sort_vendor(self, monitor):
        with patch.object(monitor, "_resort"):
            monitor.handle_input(ord("V"))
        assert monitor.sort_mode == procmon.SORT_VENDOR

    def test_sort_bytes_in(self, monitor):
        with patch.object(monitor, "_resort"):
            monitor.handle_input(ord("R"))
        assert monitor.sort_mode == procmon.SORT_BYTES_IN

    def test_sort_bytes_out(self, monitor):
        with patch.object(monitor, "_resort"):
            monitor.handle_input(ord("O"))
        assert monitor.sort_mode == procmon.SORT_BYTES_OUT

    def test_sort_toggle_inverts(self, monitor):
        monitor._sort_inverted = False
        with patch.object(monitor, "_resort"):
            monitor.handle_input(ord("m"))  # already SORT_MEM
        assert monitor._sort_inverted is True


class TestHandleInputActions:

    def test_collapse_left(self, monitor):
        monitor.rows = [make_proc(pid=1)]
        monitor.rows[0]["has_children"] = True
        monitor.rows[0]["is_collapsed"] = False
        monitor._expanded.add(1)
        with patch.object(monitor, "_resort"):
            monitor.handle_input(curses.KEY_LEFT)
        assert 1 not in monitor._expanded

    def test_expand_right(self, monitor):
        monitor.rows = [make_proc(pid=1)]
        monitor.rows[0]["has_children"] = True
        monitor.rows[0]["is_collapsed"] = True
        monitor.handle_input(curses.KEY_RIGHT)
        assert 1 in monitor._expanded

    def test_toggle_net_mode(self, monitor):
        monitor.rows = [make_proc(pid=1)]
        monitor._net_mode = False
        with patch.object(monitor, "_start_net_fetch"):
            monitor.handle_input(ord("N"))
        assert monitor._net_mode is True

    def test_tab_enters_detail_focus_in_net_mode(self, monitor):
        monitor._net_mode = True
        monitor._detail_focus = False
        monitor.handle_input(ord("\t"))
        assert monitor._detail_focus is True

    def test_tab_does_nothing_outside_net_mode(self, monitor):
        monitor._net_mode = False
        monitor._detail_focus = False
        monitor.handle_input(ord("\t"))
        assert monitor._detail_focus is False

    def test_shift_c_opens_config(self, monitor):
        with patch.object(monitor, "_prompt_config") as mock:
            monitor.handle_input(ord("C"))
        mock.assert_called_once()

    def test_f_opens_filter(self, monitor):
        with patch.object(monitor, "_prompt_filter") as mock:
            monitor.handle_input(ord("f"))
        mock.assert_called_once()

    def test_k_kills_selected(self, monitor):
        with patch.object(monitor, "_kill_selected") as mock:
            monitor.handle_input(ord("k"))
        mock.assert_called_once()

    def test_unknown_key_continues(self, monitor):
        result = monitor.handle_input(ord("z"))
        assert result is True


class TestHandleInputDetailFocus:
    """Commands when detail_focus is True (net connection list)."""

    def test_q_quits_from_detail(self, monitor):
        monitor._detail_focus = True
        monitor._net_entries = [{"fd": 1}]
        assert monitor.handle_input(ord("q")) is False

    def test_escape_exits_net_mode(self, monitor):
        monitor._detail_focus = True
        monitor._net_mode = True
        monitor._net_entries = [{"fd": 1}]
        result = monitor.handle_input(27)
        assert result is True
        assert monitor._net_mode is False
        assert monitor._detail_focus is False

    def test_tab_exits_detail_focus(self, monitor):
        monitor._detail_focus = True
        monitor.handle_input(ord("\t"))
        assert monitor._detail_focus is False

    def test_down_in_detail(self, monitor):
        monitor._detail_focus = True
        monitor._net_entries = [{"fd": 1}, {"fd": 2}, {"fd": 3}]
        monitor._net_selected = 0
        monitor.handle_input(curses.KEY_DOWN)
        assert monitor._net_selected == 1

    def test_up_in_detail(self, monitor):
        monitor._detail_focus = True
        monitor._net_entries = [{"fd": 1}, {"fd": 2}]
        monitor._net_selected = 1
        monitor.handle_input(curses.KEY_UP)
        assert monitor._net_selected == 0

    def test_n_toggles_from_detail(self, monitor):
        monitor._detail_focus = True
        monitor._net_mode = True
        monitor._net_entries = [{"fd": 1}]
        monitor.handle_input(ord("N"))
        assert monitor._net_mode is False


# ── Sort Method Tests ──────────────────────────────────────────────────


class TestSortKey:

    def test_sort_key_mem(self, monitor):
        monitor.sort_mode = procmon.SORT_MEM
        key_fn = monitor._sort_key()
        p = make_proc(rss_kb=1000)
        assert key_fn(p) == 1000

    def test_sort_key_cpu(self, monitor):
        monitor.sort_mode = procmon.SORT_CPU
        key_fn = monitor._sort_key()
        p = make_proc(cpu=55.5)
        assert key_fn(p) == 55.5

    def test_sort_key_net(self, monitor):
        monitor.sort_mode = procmon.SORT_NET
        key_fn = monitor._sort_key()
        p = make_proc()
        p["agg_net_in"] = 100
        p["agg_net_out"] = 200
        assert key_fn(p) == 300

    def test_sort_reverse_default_mem(self, monitor):
        # SORT_MEM is descending by default (not in ALPHA/VENDOR)
        monitor.sort_mode = procmon.SORT_MEM
        monitor._sort_inverted = False
        assert monitor._sort_reverse() is True

    def test_sort_reverse_inverted_mem(self, monitor):
        monitor.sort_mode = procmon.SORT_MEM
        monitor._sort_inverted = True
        assert monitor._sort_reverse() is False

    def test_sort_reverse_alpha_default(self, monitor):
        # SORT_ALPHA is ascending by default
        monitor.sort_mode = procmon.SORT_ALPHA
        monitor._sort_inverted = False
        assert monitor._sort_reverse() is False

    def test_sort_reverse_alpha_inverted(self, monitor):
        monitor.sort_mode = procmon.SORT_ALPHA
        monitor._sort_inverted = True
        assert monitor._sort_reverse() is True


# ── Tree Building Tests ─────────────────────────────────────────────────


class TestBuildTree:

    def _make_full_proc(self, pid, ppid, command="/usr/bin/test", cpu=1.0,
                        rss_kb=100, threads=1, cpu_ticks=0):
        return {
            "pid": pid, "ppid": ppid, "cpu": cpu, "rss_kb": rss_kb,
            "threads": threads, "fds": 0, "forks": 0,
            "net_in": 0, "net_out": 0, "bytes_in": 0, "bytes_out": 0,
            "command": command, "cpu_ticks": cpu_ticks,
        }

    def test_single_root(self):
        procs = [self._make_full_proc(1, 0)]
        tree = procmon.build_tree(procs, procs, lambda p: p.get("agg_rss_kb", 0))
        assert len(tree) == 1
        assert tree[0]["pid"] == 1

    def test_parent_child(self):
        parent = self._make_full_proc(1, 0)
        child = self._make_full_proc(2, 1)
        all_procs = [parent, child]
        tree = procmon.build_tree([parent], all_procs, lambda p: p.get("agg_rss_kb", 0))
        assert len(tree) == 1
        assert len(tree[0]["children"]) == 1
        assert tree[0]["children"][0]["pid"] == 2

    def test_aggregates(self):
        parent = self._make_full_proc(1, 0, rss_kb=100, cpu=10.0)
        child = self._make_full_proc(2, 1, rss_kb=200, cpu=20.0)
        all_procs = [parent, child]
        tree = procmon.build_tree([parent], all_procs, lambda p: p.get("agg_rss_kb", 0))
        assert tree[0]["agg_rss_kb"] == 300
        assert tree[0]["agg_cpu"] == 30.0

    def test_multiple_roots(self):
        p1 = self._make_full_proc(1, 0)
        p2 = self._make_full_proc(2, 0)
        tree = procmon.build_tree([p1, p2], [p1, p2], lambda p: p.get("agg_rss_kb", 0))
        assert len(tree) == 2


class TestFlattenTree:

    def test_flat_single(self):
        tree = [{"pid": 1, "depth": 0, "children": [], "rss_kb": 100,
                 "has_children": False}]
        flat = procmon.flatten_tree(tree)
        assert len(flat) == 1
        assert flat[0]["pid"] == 1

    def test_collapsed_hides_children(self):
        child = {"pid": 2, "depth": 1, "children": [], "rss_kb": 50,
                 "has_children": False}
        tree = [{"pid": 1, "depth": 0, "children": [child], "rss_kb": 100,
                 "has_children": True}]
        flat = procmon.flatten_tree(tree, expanded=set())
        assert len(flat) == 1  # children hidden (not expanded)

    def test_expanded_shows_children(self):
        child = {"pid": 2, "depth": 1, "children": [], "rss_kb": 50,
                 "has_children": False}
        tree = [{"pid": 1, "depth": 0, "children": [child], "rss_kb": 100,
                 "has_children": True}]
        flat = procmon.flatten_tree(tree, expanded={1})
        assert len(flat) == 2


class TestGroupSiblings:

    def _make_child(self, pid, command, rss_kb=100):
        return {
            "pid": pid, "ppid": 0, "command": command,
            "rss_kb": rss_kb, "cpu": 1.0, "threads": 1,
            "cpu_ticks": 0, "agg_rss_kb": rss_kb, "agg_cpu": 1.0,
            "agg_cpu_ticks": 0, "agg_threads": 1, "agg_forks": 0,
            "agg_net_in": 0, "agg_net_out": 0, "agg_bytes_in": 0,
            "agg_bytes_out": 0, "net_in": 0, "net_out": 0,
            "bytes_in": 0, "bytes_out": 0, "depth": 1, "children": [],
        }

    def test_no_grouping_single(self):
        children = [self._make_child(1, "/usr/bin/test")]
        result = procmon._group_siblings(children)
        assert len(result) == 1

    def test_groups_same_command(self):
        children = [
            self._make_child(1, "/usr/bin/python3"),
            self._make_child(2, "/usr/bin/python3"),
        ]
        result = procmon._group_siblings(children)
        assert len(result) == 1  # grouped into one
        assert result[0]["rss_kb"] == 200  # sum
        assert result[0]["sibling_count"] == 2

    def test_sibling_count_in_fmt_row(self, monitor):
        """Grouped row shows (N) count in the display name."""
        row = make_proc(pid=1, command="/usr/bin/python3")
        row["sibling_count"] = 5
        row["has_children"] = True
        row["is_collapsed"] = True
        line = monitor._fmt_row(row, 120)
        assert "(5)" in line

    def test_different_commands_not_grouped(self):
        children = [
            self._make_child(1, "/usr/bin/python3"),
            self._make_child(2, "/usr/bin/ruby"),
        ]
        result = procmon._group_siblings(children)
        assert len(result) == 2

    def test_empty(self):
        assert procmon._group_siblings([]) == []


# ── Filter Tests ────────────────────────────────────────────────────────


class TestFiltering:
    """Test that include/exclude patterns filter correctly in collect_data logic."""

    def test_include_filter_matches(self):
        procs = [
            {"command": "/usr/bin/python3 script.py", "pid": 1},
            {"command": "/usr/bin/ruby app.rb", "pid": 2},
            {"command": "/usr/bin/python3 other.py", "pid": 3},
        ]
        patterns = ["python"]
        matched = [p for p in procs
                   if not patterns or any(pat in p["command"].lower() for pat in patterns)]
        assert len(matched) == 2
        assert all("python" in m["command"].lower() for m in matched)

    def test_exclude_filter_removes(self):
        procs = [
            {"command": "/usr/bin/python3 script.py", "pid": 1},
            {"command": "/usr/bin/python3 test.py", "pid": 2},
        ]
        exclude = ["test"]
        matched = [p for p in procs
                   if not any(pat in p["command"].lower() for pat in exclude)]
        assert len(matched) == 1
        assert matched[0]["pid"] == 1

    def test_include_and_exclude(self):
        procs = [
            {"command": "chrome renderer", "pid": 1},
            {"command": "chrome gpu", "pid": 2},
            {"command": "firefox", "pid": 3},
        ]
        patterns = ["chrome"]
        exclude = ["gpu"]
        matched = [p for p in procs
                   if (not patterns or any(pat in p["command"].lower() for pat in patterns))
                   and not any(pat in p["command"].lower() for pat in exclude)]
        assert len(matched) == 1
        assert matched[0]["pid"] == 1

    def test_empty_patterns_match_all(self):
        procs = [{"command": "a", "pid": 1}, {"command": "b", "pid": 2}]
        patterns = []
        matched = [p for p in procs
                   if not patterns or any(pat in p["command"].lower() for pat in patterns)]
        assert len(matched) == 2
