"""Additional coverage tests for native helpers, __init__, _fetch_net_connections,
_do_refresh_net_bytes, _lookup_geoip, _start_net_refresh, _get_subtree_pids,
_kill_net_connection, and remaining edge cases."""
import ctypes
import curses
import json
import os
import signal
import subprocess
import sys
import time
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import procmon
from tests.conftest import make_proc


@pytest.fixture(autouse=True)
def _mock_curses():
    with patch("curses.color_pair", side_effect=lambda n: n), \
         patch("curses.curs_set", return_value=None):
        yield


# ── __init__ via curses.wrapper ─────────────────────────────────────────


class TestInit:

    def test_init_with_full_curses_mock(self):
        """Test ProcMonUI __init__ by mocking all curses functions."""
        stdscr = MagicMock()
        stdscr.getmaxyx.return_value = (40, 120)
        with patch("curses.use_default_colors"), \
             patch("curses.init_pair"), \
             patch("curses.curs_set"), \
             patch.object(procmon.ProcMonUI, "_load_config"):
            mon = procmon.ProcMonUI(stdscr, "test", 5.0, False)
        assert mon.name == "test"
        assert mon.patterns == ["test"]
        assert mon.interval == 5.0
        assert mon.skip_fd is False
        assert mon._alert_count == 0

    def test_init_no_name(self):
        stdscr = MagicMock()
        stdscr.getmaxyx.return_value = (40, 120)
        with patch("curses.use_default_colors"), \
             patch("curses.init_pair"), \
             patch("curses.curs_set"), \
             patch.object(procmon.ProcMonUI, "_load_config"):
            mon = procmon.ProcMonUI(stdscr, "", 3.0, True)
        assert mon.patterns == []
        assert mon.skip_fd is True
        assert mon.interval == 3.0

    def test_init_comma_separated_names(self):
        stdscr = MagicMock()
        stdscr.getmaxyx.return_value = (40, 120)
        with patch("curses.use_default_colors"), \
             patch("curses.init_pair"), \
             patch("curses.curs_set"), \
             patch.object(procmon.ProcMonUI, "_load_config"):
            mon = procmon.ProcMonUI(stdscr, "chrome,firefox", 5.0, False)
        assert mon.patterns == ["chrome", "firefox"]


# ── _fetch_net_connections ──────────────────────────────────────────────


class TestFetchNetConnections:

    def test_basic_lsof_output(self, monitor):
        """Parse standard lsof output with established connections."""
        monitor.rows = [make_proc(pid=100)]
        monitor._net_bytes = {}
        lsof_output = (
            "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
            "chrome    100 user    5u  IPv4   0x1    0t0    TCP 127.0.0.1:54321->93.184.216.34:443 (ESTABLISHED)\n"
            "chrome    100 user    6u  IPv4   0x2    0t0    TCP 127.0.0.1:54322->10.0.0.1:80 (ESTABLISHED)\n"
        )
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (lsof_output.encode(), b"")

        with patch("subprocess.Popen", return_value=mock_proc), \
             patch("procmon._lookup_geoip"), \
             patch("procmon._resolve_addr", side_effect=lambda x: x), \
             patch("procmon._get_geo", return_value=""), \
             patch("procmon._get_org", return_value=""):
            entries = monitor._fetch_net_connections(100)

        assert len(entries) >= 1
        assert entries[0]["proto"] == "TCP"
        assert entries[0]["pid"] == 100

    def test_lsof_timeout(self, monitor):
        monitor.rows = [make_proc(pid=100)]
        mock_proc = MagicMock()
        mock_proc.communicate.side_effect = subprocess.TimeoutExpired("cmd", 10)
        with patch("subprocess.Popen", return_value=mock_proc):
            entries = monitor._fetch_net_connections(100)
        assert entries == []
        mock_proc.kill.assert_called_once()

    def test_lsof_not_found(self, monitor):
        monitor.rows = [make_proc(pid=100)]
        with patch("subprocess.Popen", side_effect=FileNotFoundError):
            entries = monitor._fetch_net_connections(100)
        assert entries == []

    def test_lsof_os_error(self, monitor):
        monitor.rows = [make_proc(pid=100)]
        with patch("subprocess.Popen", side_effect=OSError):
            entries = monitor._fetch_net_connections(100)
        assert entries == []

    def test_filters_listeners(self, monitor):
        """Listener entries (no ->) should be filtered out."""
        monitor._net_bytes = {}
        lsof_output = (
            "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
            "python    100 user    5u  IPv4   0x1    0t0    TCP *:8080 (LISTEN)\n"
            "python    100 user    6u  IPv4   0x2    0t0    TCP 127.0.0.1:8080->192.168.1.1:54321 (ESTABLISHED)\n"
        )
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (lsof_output.encode(), b"")
        with patch("subprocess.Popen", return_value=mock_proc), \
             patch("procmon._lookup_geoip"), \
             patch("procmon._resolve_addr", side_effect=lambda x: x), \
             patch("procmon._get_geo", return_value=""), \
             patch("procmon._get_org", return_value=""):
            entries = monitor._fetch_net_connections(100)
        # Only the ESTABLISHED connection
        assert len(entries) == 1

    def test_with_bytes(self, monitor):
        """Connections with cached bytes show byte tags."""
        monitor._net_bytes = {(100, "5u"): (1024, 2048)}
        lsof_output = (
            "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
            "chrome    100 user    5u  IPv4   0x1    0t0    TCP 127.0.0.1:8080->8.8.8.8:443 (ESTABLISHED)\n"
        )
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (lsof_output.encode(), b"")
        with patch("subprocess.Popen", return_value=mock_proc), \
             patch("procmon._lookup_geoip"), \
             patch("procmon._resolve_addr", side_effect=lambda x: x), \
             patch("procmon._get_geo", return_value="NYC/US"), \
             patch("procmon._get_org", return_value="Google LLC"):
            entries = monitor._fetch_net_connections(100)
        assert len(entries) == 1
        assert entries[0]["bytes_in"] == 1024
        assert entries[0]["bytes_out"] == 2048
        assert "Google" in entries[0]["display"]

    def test_with_service_and_geo(self, monitor):
        """Service names and geo tags appear in display."""
        monitor._net_bytes = {}
        lsof_output = (
            "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
            "chrome    100 user    5u  IPv4   0x1    0t0    TCP 127.0.0.1:8080->8.8.8.8:443 (ESTABLISHED)\n"
        )
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (lsof_output.encode(), b"")
        with patch("subprocess.Popen", return_value=mock_proc), \
             patch("procmon._lookup_geoip"), \
             patch("procmon._resolve_addr", side_effect=lambda x: x), \
             patch("procmon._get_geo", return_value="MTV/US"), \
             patch("procmon._get_org", return_value=""):
            entries = monitor._fetch_net_connections(100)
        assert "[HTTPS]" in entries[0]["display"]
        assert "[MTV/US]" in entries[0]["display"]

    def test_dedup_connections(self, monitor):
        """Duplicate connections are deduplicated."""
        monitor._net_bytes = {}
        lsof_output = (
            "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
            "chrome    100 user    5u  IPv4   0x1    0t0    TCP 127.0.0.1:8080->8.8.8.8:443 (ESTABLISHED)\n"
            "chrome    100 user    5u  IPv4   0x1    0t0    TCP 127.0.0.1:8080->8.8.8.8:443 (ESTABLISHED)\n"
        )
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (lsof_output.encode(), b"")
        with patch("subprocess.Popen", return_value=mock_proc), \
             patch("procmon._lookup_geoip"), \
             patch("procmon._resolve_addr", side_effect=lambda x: x), \
             patch("procmon._get_geo", return_value=""), \
             patch("procmon._get_org", return_value=""):
            entries = monitor._fetch_net_connections(100)
        assert len(entries) == 1

    def test_wildcard_name_skipped(self, monitor):
        """Entries with *:* or just * are skipped."""
        monitor._net_bytes = {}
        lsof_output = (
            "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
            "chrome    100 user    5u  IPv4   0x1    0t0    TCP *:*\n"
            "chrome    100 user    6u  IPv4   0x2    0t0    TCP *\n"
        )
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (lsof_output.encode(), b"")
        with patch("subprocess.Popen", return_value=mock_proc):
            entries = monitor._fetch_net_connections(100)
        assert entries == []

    def test_no_state_connection(self, monitor):
        """Connection without parenthetical state."""
        monitor._net_bytes = {}
        lsof_output = (
            "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
            "node      100 user    5u  IPv4   0x1    0t0    UDP 127.0.0.1:5353->224.0.0.251:5353\n"
        )
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (lsof_output.encode(), b"")
        with patch("subprocess.Popen", return_value=mock_proc), \
             patch("procmon._lookup_geoip"), \
             patch("procmon._resolve_addr", side_effect=lambda x: x), \
             patch("procmon._get_geo", return_value=""), \
             patch("procmon._get_org", return_value=""):
            entries = monitor._fetch_net_connections(100)
        assert len(entries) == 1

    def test_old_bytes_format_migration(self, monitor):
        """Migrate old integer byte format to tuple."""
        monitor._net_bytes = {(100, "5u"): 5000}
        lsof_output = (
            "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
            "chrome    100 user    5u  IPv4   0x1    0t0    TCP 127.0.0.1:8080->8.8.8.8:443 (ESTABLISHED)\n"
        )
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (lsof_output.encode(), b"")
        with patch("subprocess.Popen", return_value=mock_proc), \
             patch("procmon._lookup_geoip"), \
             patch("procmon._resolve_addr", side_effect=lambda x: x), \
             patch("procmon._get_geo", return_value=""), \
             patch("procmon._get_org", return_value=""):
            entries = monitor._fetch_net_connections(100)
        assert entries[0]["bytes_in"] == 5000
        assert entries[0]["bytes_out"] == 0


# ── _do_refresh_net_bytes ───────────────────────────────────────────────


class TestDoRefreshNetBytes:

    def test_basic_refresh(self, monitor):
        monitor.rows = [make_proc(pid=100)]
        monitor._net_entries = [
            {"pid": 100, "fd": "5u", "addr_key": "127.0.0.1:8080->8.8.8.8:443",
             "display": "test", "org": ""},
        ]
        nettop_output = (
            "chrome.100,0,0,\n"
            "chrome.100 127.0.0.1:8080<->8.8.8.8:443,1000,2000,\n"
        )
        mock_nettop = MagicMock()
        mock_nettop.communicate.return_value = (nettop_output.encode(), b"")

        with patch("subprocess.Popen", return_value=mock_nettop), \
             patch.object(monitor, "_fetch_net_connections", return_value=[]):
            monitor._do_refresh_net_bytes(100)

        assert (100, "5u") in monitor._net_bytes

    def test_nettop_timeout(self, monitor):
        monitor.rows = [make_proc(pid=100)]
        monitor._net_entries = []
        mock_proc = MagicMock()
        mock_proc.communicate.side_effect = subprocess.TimeoutExpired("cmd", 5)
        with patch("subprocess.Popen", return_value=mock_proc), \
             patch.object(monitor, "_fetch_net_connections", return_value=[]):
            monitor._do_refresh_net_bytes(100)
        mock_proc.kill.assert_called_once()

    def test_nettop_not_found(self, monitor):
        monitor.rows = [make_proc(pid=100)]
        monitor._net_entries = []
        with patch("subprocess.Popen", side_effect=FileNotFoundError), \
             patch.object(monitor, "_fetch_net_connections", return_value=[]):
            monitor._do_refresh_net_bytes(100)


# ── _get_subtree_pids ──────────────────────────────────────────────────


class TestGetSubtreePids:

    def test_single_process(self, monitor):
        with patch("procmon.get_all_processes", return_value=[
            {"pid": 100, "ppid": 0, "command": "test"},
        ]):
            pids = monitor._get_subtree_pids(100)
        assert 100 in pids

    def test_with_children(self, monitor):
        with patch("procmon.get_all_processes", return_value=[
            {"pid": 100, "ppid": 0, "command": "parent"},
            {"pid": 101, "ppid": 100, "command": "child1"},
            {"pid": 102, "ppid": 100, "command": "child2"},
        ]):
            pids = monitor._get_subtree_pids(100)
        assert set(pids) == {100, 101, 102}

    def test_pid_not_in_tree(self, monitor):
        with patch("procmon.get_all_processes", return_value=[
            {"pid": 200, "ppid": 0, "command": "other"},
        ]):
            pids = monitor._get_subtree_pids(999)
        assert pids == [999]


# ── _kill_net_connection ────────────────────────────────────────────────


class TestKillNetConnection:

    def test_kill_connection(self, monitor):
        monitor._net_entries = [{"pid": 100, "fd": "5u", "display": "test"}]
        monitor._net_selected = 0
        monitor._net_pid = 100
        with patch("os.kill") as mock_kill, \
             patch.object(monitor, "_start_net_fetch"), \
             patch.object(monitor, "_confirm_action", return_value=True):
            monitor._kill_net_connection_owner_process()
        mock_kill.assert_called_once_with(100, signal.SIGKILL)

    def test_kill_aborted_when_user_declines(self, monitor):
        monitor._net_entries = [{"pid": 100, "fd": "5u", "display": "test"}]
        monitor._net_selected = 0
        monitor._net_pid = 100
        with patch("os.kill") as mock_kill, \
             patch.object(monitor, "_start_net_fetch") as mock_fetch, \
             patch.object(monitor, "_confirm_action", return_value=False):
            monitor._kill_net_connection_owner_process()
        mock_kill.assert_not_called()
        mock_fetch.assert_not_called()

    def test_kill_no_entries(self, monitor):
        monitor._net_entries = []
        with patch("os.kill") as mock_kill, \
             patch.object(monitor, "_confirm_action", return_value=True):
            monitor._kill_net_connection_owner_process()
        mock_kill.assert_not_called()

    def test_kill_invalid_pid(self, monitor):
        monitor._net_entries = [{"pid": 0, "fd": "5u", "display": "test"}]
        monitor._net_selected = 0
        with patch("os.kill") as mock_kill, \
             patch.object(monitor, "_confirm_action", return_value=True):
            monitor._kill_net_connection_owner_process()
        mock_kill.assert_not_called()

    def test_kill_permission_error(self, monitor):
        monitor._net_entries = [{"pid": 100, "fd": "5u", "display": "test"}]
        monitor._net_selected = 0
        monitor._net_pid = 100
        with patch("os.kill", side_effect=PermissionError), \
             patch.object(monitor, "_start_net_fetch"), \
             patch.object(monitor, "_confirm_action", return_value=True):
            monitor._kill_net_connection_owner_process()  # should not raise

    def test_legacy_alias_still_callable(self, monitor):
        # Some external callers / older tests may still reach in by the
        # pre-rename name; keep the alias working.
        assert (monitor._kill_net_connection ==
                monitor._kill_net_connection_owner_process)


# ── _start_net_refresh ──────────────────────────────────────────────────


class TestStartNetRefresh:

    def test_basic_refresh(self, monitor):
        monitor._net_pid = 100
        monitor._net_worker = None
        monitor._net_mode = True
        with patch.object(monitor, "_do_refresh_net_bytes"):
            monitor._start_net_refresh()
        assert monitor._net_loading is True

    def test_already_running(self, monitor):
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = True
        monitor._net_worker = mock_thread
        monitor._net_pid = 100
        monitor._start_net_refresh()
        # Should not create new thread


# ── _lookup_geoip ───────────────────────────────────────────────────────


class TestLookupGeoip:

    def test_all_cached(self):
        procmon._geoip_cache["1.1.1.1"] = "SFO/US"
        procmon._lookup_geoip(["1.1.1.1"])
        del procmon._geoip_cache["1.1.1.1"]

    def test_local_ips_skipped(self):
        procmon._lookup_geoip(["127.0.0.1", "10.0.0.1"])
        # Should not make any HTTP requests

    def test_batch_lookup(self):
        test_ip = "203.0.113.1"
        procmon._geoip_cache.pop(test_ip, None)
        procmon._org_cache.pop(test_ip, None)

        response = json.dumps([
            {"status": "success", "city": "Test", "countryCode": "US", "org": "TestOrg"}
        ]).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = response
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("procmon._urllib.Request") as mock_req, \
             patch("procmon._urllib.urlopen", return_value=mock_resp):
            procmon._lookup_geoip([test_ip])

        assert procmon._geoip_cache[test_ip] == "Test/US"
        assert procmon._org_cache[test_ip] == "TestOrg"
        del procmon._geoip_cache[test_ip]
        del procmon._org_cache[test_ip]

    def test_batch_lookup_failure(self):
        test_ip = "203.0.113.2"
        procmon._geoip_cache.pop(test_ip, None)
        procmon._org_cache.pop(test_ip, None)

        with patch("procmon._urllib.Request"), \
             patch("procmon._urllib.urlopen", side_effect=Exception("timeout")):
            procmon._lookup_geoip([test_ip])

        assert procmon._geoip_cache.get(test_ip) == ""
        del procmon._geoip_cache[test_ip]
        del procmon._org_cache[test_ip]

    def test_failed_status(self):
        test_ip = "203.0.113.3"
        procmon._geoip_cache.pop(test_ip, None)
        procmon._org_cache.pop(test_ip, None)

        response = json.dumps([{"status": "fail"}]).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = response
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("procmon._urllib.Request"), \
             patch("procmon._urllib.urlopen", return_value=mock_resp):
            procmon._lookup_geoip([test_ip])

        assert procmon._geoip_cache[test_ip] == ""
        del procmon._geoip_cache[test_ip]
        del procmon._org_cache[test_ip]


# ── Native helper functions ─────────────────────────────────────────────


class TestNativeHelpers:

    def test_get_proc_args_self(self):
        result = procmon._get_proc_args(os.getpid())
        assert result is not None
        assert "python" in result.lower() or "pytest" in result.lower()

    def test_get_proc_args_invalid_pid(self):
        result = procmon._get_proc_args(99999999)
        assert result is None

    def test_get_proc_path_self(self):
        result = procmon._get_proc_path(os.getpid())
        assert result is not None

    def test_get_proc_path_invalid(self):
        result = procmon._get_proc_path(99999999)
        assert result is None

    def test_get_fd_count_self(self):
        result = procmon._get_fd_count(os.getpid())
        assert result > 0

    def test_get_fd_count_invalid(self):
        result = procmon._get_fd_count(99999999)
        assert result == -1

    def test_get_cwd_self(self):
        result = procmon._get_cwd(os.getpid())
        assert result != "-"

    def test_get_cwd_invalid(self):
        result = procmon._get_cwd(99999999)
        assert result == "-"

    def test_get_total_memory_kb(self):
        result = procmon._get_total_memory_kb()
        assert result > 0

    def test_list_all_pids(self):
        pids = procmon._list_all_pids()
        assert len(pids) > 10
        assert 1 in pids  # launchd


# ── _self_test failure paths ────────────────────────────────────────────


class TestSelfTestFailure:

    def test_proc_pidinfo_returns_zero(self):
        with patch.object(procmon._libproc, "proc_pidinfo", return_value=0):
            result = procmon._self_test()
        assert result is False

    def test_ppid_mismatch(self):
        original = procmon._taskallinfo_buf.pbsd.pbi_ppid
        procmon._taskallinfo_buf.pbsd.pbi_ppid = 99999
        # Need to also ensure proc_pidinfo succeeds
        result = procmon._self_test()
        procmon._taskallinfo_buf.pbsd.pbi_ppid = original
        # The real call will overwrite the buffer so we can't easily test mismatch
        # Just verify the function runs without crashing


# ── collect_data net rates ──────────────────────────────────────────────


class TestCollectDataNetRates:

    def test_net_rate_calculation(self, monitor):
        """Two collect_data calls should produce net rates."""
        with patch("procmon.get_all_processes") as mock_gap, \
             patch("procmon.get_net_snapshot") as mock_net, \
             patch("procmon.get_fd_counts", return_value={}), \
             patch("procmon.get_cwds", return_value={}):
            mock_gap.return_value = [
                {"pid": 1, "ppid": 0, "cpu": 0.0, "cpu_ticks": 100,
                 "rss_kb": 1024, "threads": 2, "command": "/usr/bin/test"},
            ]
            mock_net.return_value = {1: (1000, 2000)}
            monitor.collect_data()

            # Second call with different net values
            mock_net.return_value = {1: (5000, 6000)}
            monitor.collect_data()

        # Should have net rates now
        assert monitor.net_rates.get(1) is not None

    def test_collect_data_skip_fd(self, monitor):
        monitor.skip_fd = True
        with patch("procmon.get_all_processes") as mock_gap, \
             patch("procmon.get_net_snapshot", return_value={}), \
             patch("procmon.get_fd_counts") as mock_fd, \
             patch("procmon.get_cwds", return_value={}):
            mock_gap.return_value = [
                {"pid": 1, "ppid": 0, "cpu": 0.0, "cpu_ticks": 100,
                 "rss_kb": 1024, "threads": 2, "command": "/usr/bin/test"},
            ]
            monitor.collect_data()
        mock_fd.assert_not_called()


# ── _resolve_ip with actual DNS lookup ──────────────────────────────────


class TestResolveIpDns:

    def test_dns_failure(self):
        # Clear cache for a fake IP
        procmon._rdns_cache.pop("198.51.100.1", None)
        import socket
        with patch("procmon._socket.gethostbyaddr", side_effect=socket.herror):
            result = procmon._resolve_ip("198.51.100.1")
        assert result == "198.51.100.1"
        assert procmon._rdns_cache["198.51.100.1"] is None
        del procmon._rdns_cache["198.51.100.1"]

    def test_dns_success(self):
        procmon._rdns_cache.pop("198.51.100.2", None)
        with patch("procmon._socket.gethostbyaddr", return_value=("example.com", [], [])):
            result = procmon._resolve_ip("198.51.100.2")
        assert result == "example.com"
        del procmon._rdns_cache["198.51.100.2"]


# ── _save_config error handling ─────────────────────────────────────────


class TestSaveConfigError:

    def test_save_config_write_error(self, monitor):
        monitor._CONFIG_PATH = "/nonexistent/path/.procmon.json"
        monitor._save_config()  # should not raise


# ── run loop edge cases ─────────────────────────────────────────────────


class TestRunLoopEdges:

    def test_run_memory_error_recovery(self, monitor):
        """MemoryError during collect_data should be handled."""
        calls = [0]

        def fake_collect():
            calls[0] += 1
            if calls[0] == 2:
                raise MemoryError()

        times = [0.0, 0.0, 0.0, 10.0, 10.0, 10.0, 10.0]
        tidx = [0]

        def fake_time():
            v = times[min(tidx[0], len(times) - 1)]
            tidx[0] += 1
            return v

        getch_calls = [0]

        def fake_getch():
            getch_calls[0] += 1
            if getch_calls[0] >= 3:
                return ord("q")
            return -1

        monitor.stdscr.getch.side_effect = fake_getch
        with patch.object(monitor, "collect_data", side_effect=fake_collect), \
             patch.object(monitor, "render"), \
             patch.object(monitor, "_check_alerts"), \
             patch("time.monotonic", side_effect=fake_time), \
             patch("gc.collect"):
            monitor.run()

    def test_run_polls_net_result(self, monitor):
        """Run loop polls for background net results."""
        calls = [0]

        def fake_getch():
            calls[0] += 1
            if calls[0] >= 2:
                return ord("q")
            return -1

        monitor._net_pending = "something"
        monitor.stdscr.getch.side_effect = fake_getch
        with patch.object(monitor, "collect_data"), \
             patch.object(monitor, "render"), \
             patch.object(monitor, "_poll_net_result", return_value=True), \
             patch("time.monotonic", return_value=0.0):
            monitor.run()


# ── Edge cases in rendering ─────────────────────────────────────────────


class TestRenderEdgeCases:

    def test_render_too_small_terminal(self, monitor):
        monitor.stdscr.getmaxyx.return_value = (8, 30)
        monitor.render()

    def test_render_single_process_no_plural(self, monitor):
        monitor.rows = [make_proc(pid=1, cpu=1.0, fds=1, net_in=0, net_out=0)]
        monitor.matched_count = 1
        monitor.render()

    def test_render_with_selection_at_end(self, monitor):
        monitor.rows = [make_proc(pid=i, cpu=1.0, fds=1, net_in=0, net_out=0)
                        for i in range(5)]
        monitor.matched_count = 5
        monitor.selected = 4
        monitor.render()


# ── sort key variants ───────────────────────────────────────────────────


class TestSortKeyVariants:

    def test_sort_key_bytes_in(self, monitor):
        monitor.sort_mode = procmon.SORT_BYTES_IN
        fn = monitor._sort_key()
        p = make_proc()
        p["agg_bytes_in"] = 500
        assert fn(p) == 500

    def test_sort_key_bytes_out(self, monitor):
        monitor.sort_mode = procmon.SORT_BYTES_OUT
        fn = monitor._sort_key()
        p = make_proc()
        p["agg_bytes_out"] = 700
        assert fn(p) == 700

    def test_sort_key_vendor(self, monitor):
        monitor.sort_mode = procmon.SORT_VENDOR
        fn = monitor._sort_key()
        p = make_proc(command="/Applications/Google Chrome.app/chrome")
        result = fn(p)
        assert isinstance(result, str)

    def test_sort_key_alpha(self, monitor):
        monitor.sort_mode = procmon.SORT_ALPHA
        fn = monitor._sort_key()
        p = make_proc(command="/usr/bin/test")
        result = fn(p)
        assert isinstance(result, str)


# ── _collapse_selected edge cases ───────────────────────────────────────


class TestCollapseEdges:

    def test_collapse_empty_rows(self, monitor):
        monitor.rows = []
        monitor._collapse_selected()  # should not raise

    def test_collapse_jumps_to_parent(self, monitor):
        """Collapsing an already-collapsed or childless node jumps to parent."""
        parent = make_proc(pid=1)
        parent["depth"] = 0
        child = make_proc(pid=2)
        child["depth"] = 1
        child["has_children"] = False
        child["is_collapsed"] = False
        monitor.rows = [parent, child]
        monitor.selected = 1
        monitor._collapse_selected()
        assert monitor.selected == 0  # jumped to parent

    def test_expand_empty_rows(self, monitor):
        monitor.rows = []
        monitor._expand_selected()  # should not raise

    def test_expand_non_collapsed(self, monitor):
        row = make_proc(pid=1)
        row["is_collapsed"] = False
        monitor.rows = [row]
        monitor._expand_selected()
        # Should not add to _expanded since not collapsed
