"""Tests for vendor grouping feature ('g' key).

Covers: build_vendor_tree, _get_vendor, 'g' toggle, header/shortcut bar
indicators, config persistence, and integration with sort/dynamic sort.
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


# ── _get_vendor ──────────────────────────────────────────────────────────


class TestGetVendor:

    def test_apple_system(self):
        assert procmon._get_vendor("/System/Library/foo") == "Apple"

    def test_apple_usr_bin(self):
        assert procmon._get_vendor("/usr/bin/python3") == "Apple"

    def test_google_chrome(self):
        assert procmon._get_vendor("/Applications/Google Chrome.app/chrome") == "Google"

    def test_mozilla_firefox(self):
        assert procmon._get_vendor("/Applications/Firefox.app/firefox") == "Mozilla"

    def test_microsoft_vscode(self):
        assert procmon._get_vendor("/Applications/Visual Studio Code.app/code") == "Microsoft"

    def test_docker(self):
        assert procmon._get_vendor("/Applications/Docker.app/docker") == "Docker"

    def test_apple_rdns(self):
        assert procmon._get_vendor("com.apple.weather.menu") == "Apple"

    def test_apple_rdns_passwords(self):
        assert procmon._get_vendor("com.apple.Passwords.MenuBarExtra") == "Apple"

    def test_microsoft_rdns(self):
        assert procmon._get_vendor("com.microsoft.teams2.agent") == "Microsoft"

    def test_microsoft_rdns_in_path(self):
        assert procmon._get_vendor("Contents/Library/LaunchAgents/com.microsoft.teams2.agent") == "Microsoft"

    def test_google_rdns(self):
        assert procmon._get_vendor("com.google.Chrome.helper") == "Google"

    def test_docker_rdns(self):
        assert procmon._get_vendor("com.docker.backend") == "Docker"

    def test_mozilla_rdns(self):
        assert procmon._get_vendor("org.mozilla.firefox") == "Mozilla"

    def test_unknown_returns_no_vendor(self):
        assert procmon._get_vendor("/opt/custom/myapp") == "No Vendor"

    def test_relative_path_no_vendor(self):
        assert procmon._get_vendor("myapp --flag") == "No Vendor"


class TestShortCommandRdns:

    def test_rdns_gets_vendor_tag(self):
        result = procmon._short_command("com.apple.weather.menu")
        assert "[Apple]" in result

    def test_microsoft_rdns_gets_tag(self):
        result = procmon._short_command("com.microsoft.teams2.agent")
        assert "[Microsoft]" in result


# ── build_vendor_tree ────────────────────────────────────────────────────


class TestBuildVendorTree:

    def _proc(self, pid, command, cpu=1.0, rss_kb=100):
        return {
            "pid": pid, "ppid": 0, "command": command,
            "rss_kb": rss_kb, "cpu": cpu, "cpu_ticks": int(cpu * 100),
            "threads": 1,
        }

    def test_groups_by_vendor(self):
        """Processes from the same vendor are grouped under one root."""
        procs = [
            self._proc(1, "/System/Library/daemon1"),
            self._proc(2, "/usr/bin/daemon2"),
            self._proc(3, "/Applications/Google Chrome.app/chrome"),
        ]
        sort_key = lambda p: p.get("agg_rss_kb", p["rss_kb"])
        tree = procmon.build_vendor_tree(procs, procs, sort_key, reverse=True)
        vendors = [n["command"] for n in tree]
        assert "Apple" in vendors
        # Chrome is alone but still under Google
        assert "Google" in vendors

    def test_vendor_node_has_sibling_count(self):
        """Vendor group node shows count of children."""
        procs = [
            self._proc(1, "/System/Library/daemon1"),
            self._proc(2, "/usr/bin/daemon2"),
            self._proc(3, "/usr/sbin/syslogd"),
        ]
        sort_key = lambda p: p.get("agg_rss_kb", p["rss_kb"])
        tree = procmon.build_vendor_tree(procs, procs, sort_key, reverse=True)
        apple = [n for n in tree if n["command"] == "Apple"][0]
        assert apple["sibling_count"] == 3

    def test_vendor_node_aggregates(self):
        """Vendor group node has correct aggregated metrics."""
        procs = [
            self._proc(1, "/System/Library/a", cpu=10.0, rss_kb=1000),
            self._proc(2, "/usr/bin/b", cpu=5.0, rss_kb=2000),
        ]
        sort_key = lambda p: p.get("agg_rss_kb", p["rss_kb"])
        tree = procmon.build_vendor_tree(procs, procs, sort_key, reverse=True)
        apple = [n for n in tree if n["command"] == "Apple"][0]
        assert apple["agg_cpu"] == 15.0
        assert apple["agg_rss_kb"] == 3000

    def test_no_vendor_single_not_wrapped(self):
        """A single unvendored process is NOT wrapped in a 'No Vendor' group."""
        procs = [
            self._proc(1, "/opt/custom/myapp"),
        ]
        sort_key = lambda p: p.get("agg_rss_kb", p["rss_kb"])
        tree = procmon.build_vendor_tree(procs, procs, sort_key, reverse=True)
        # Should be the process itself, not a "No Vendor" wrapper
        assert tree[0]["command"] == "/opt/custom/myapp"

    def test_no_vendor_multiple_grouped(self):
        """Multiple unvendored processes are grouped under 'No Vendor'."""
        procs = [
            self._proc(1, "/opt/custom/app1"),
            self._proc(2, "/opt/custom/app2"),
        ]
        sort_key = lambda p: p.get("agg_rss_kb", p["rss_kb"])
        tree = procmon.build_vendor_tree(procs, procs, sort_key, reverse=True)
        assert tree[0]["command"] == "No Vendor"
        assert tree[0]["sibling_count"] == 2

    def test_sorting_applies_at_vendor_level(self):
        """Vendors are sorted by the aggregate sort key."""
        procs = [
            self._proc(1, "/System/Library/a", rss_kb=100),
            self._proc(2, "/Applications/Google Chrome.app/chrome", rss_kb=5000),
        ]
        sort_key = lambda p: p.get("agg_rss_kb", p["rss_kb"])
        tree = procmon.build_vendor_tree(procs, procs, sort_key, reverse=True)
        # Google (5000) should come before Apple (100) in descending sort
        assert tree[0]["command"] == "Google"
        assert tree[1]["command"] == "Apple"

    def test_mixed_vendors_and_no_vendor(self):
        """Mix of vendored and unvendored processes."""
        procs = [
            self._proc(1, "/System/Library/a"),
            self._proc(2, "/Applications/Google Chrome.app/chrome"),
            self._proc(3, "/opt/custom/myapp1"),
            self._proc(4, "/opt/custom/myapp2"),
        ]
        sort_key = lambda p: p.get("agg_rss_kb", p["rss_kb"])
        tree = procmon.build_vendor_tree(procs, procs, sort_key, reverse=True)
        commands = [n["command"] for n in tree]
        assert "Apple" in commands
        assert "Google" in commands
        assert "No Vendor" in commands

    def test_flatten_vendor_tree(self):
        """Vendor tree flattens correctly — vendor is root, processes are children."""
        procs = [
            self._proc(1, "/System/Library/a"),
            self._proc(2, "/usr/bin/b"),
        ]
        sort_key = lambda p: p.get("agg_rss_kb", p["rss_kb"])
        tree = procmon.build_vendor_tree(procs, procs, sort_key, reverse=True)
        # Expand the Apple vendor group
        apple = [n for n in tree if n["command"] == "Apple"][0]
        flat = procmon.flatten_tree(tree, expanded={apple["pid"]})
        # First row: Apple group. Then its children.
        assert flat[0]["command"] == "Apple"
        assert len(flat) == 3  # Apple + 2 children


# ── 'g' Key Toggle ──────────────────────────────────────────────────────


class TestVendorGroupToggle:

    def test_g_enables(self, monitor):
        monitor._vendor_grouped = False
        monitor.rows = [make_proc(pid=1)]
        with patch.object(monitor, "_resort"):
            monitor.handle_input(ord("g"))
        assert monitor._vendor_grouped is True

    def test_g_disables(self, monitor):
        monitor._vendor_grouped = True
        monitor.rows = [make_proc(pid=1)]
        with patch.object(monitor, "_resort"):
            monitor.handle_input(ord("g"))
        assert monitor._vendor_grouped is False

    def test_g_triggers_resort(self, monitor):
        monitor.rows = [make_proc(pid=1)]
        with patch.object(monitor, "_resort") as mock:
            monitor.handle_input(ord("g"))
            mock.assert_called_once()


# ── Header and Shortcut Bar ─────────────────────────────────────────────


class TestVendorGroupUI:

    def test_header_shows_vendor_tag(self, monitor):
        monitor._vendor_grouped = True
        monitor.rows = [make_proc(pid=1)]
        monitor.stdscr.getmaxyx.return_value = (30, 140)
        monitor.render()
        calls = monitor.stdscr.addnstr.call_args_list
        found = any("[vendor]" in str(c) for c in calls)
        assert found

    def test_header_no_vendor_tag_when_off(self, monitor):
        monitor._vendor_grouped = False
        monitor.rows = [make_proc(pid=1)]
        monitor.stdscr.getmaxyx.return_value = (30, 140)
        monitor.render()
        calls = monitor.stdscr.addnstr.call_args_list
        found = any("[vendor]" in str(c) for c in calls)
        assert not found

    def test_shortcut_bar_shows_grp(self, monitor):
        monitor._vendor_grouped = False
        monitor.rows = [make_proc(pid=1)]
        monitor.stdscr.getmaxyx.return_value = (30, 140)
        monitor.render()
        calls = monitor.stdscr.addnstr.call_args_list
        found = any("Grp" in str(c) for c in calls)
        assert found

    def test_shortcut_bar_shows_grp_check_when_on(self, monitor):
        monitor._vendor_grouped = True
        monitor.rows = [make_proc(pid=1)]
        monitor.stdscr.getmaxyx.return_value = (30, 140)
        monitor.render()
        calls = monitor.stdscr.addnstr.call_args_list
        found = any("Grp\u2713" in str(c) for c in calls)
        assert found


# ── Config Persistence ───────────────────────────────────────────────────


class TestVendorGroupConfig:

    def test_save_includes_vendor_grouped(self, monitor):
        monitor._vendor_grouped = True
        with patch("builtins.open", MagicMock()) as mock_file:
            monitor._save_config()
            written = mock_file().__enter__().write.call_args[0][0]
            import json
            cfg = json.loads(written)
            assert cfg["vendor_grouped"] is True

    def test_load_restores_vendor_grouped(self, monitor):
        import json
        cfg_data = json.dumps({
            "vendor_grouped": True,
            "alert_thresholds": {},
            "alert_interval": 60,
            "alert_max_count": 5,
        })
        with patch("builtins.open", MagicMock(return_value=MagicMock(
            __enter__=MagicMock(return_value=MagicMock(read=MagicMock(return_value=cfg_data))),
            __exit__=MagicMock(return_value=False)
        ))):
            monitor._load_config()
        assert monitor._vendor_grouped is True


# ── Integration with collect_data ────────────────────────────────────────


class TestVendorGroupCollectData:

    def test_collect_data_uses_vendor_tree(self, monitor):
        """When _vendor_grouped is on, collect_data uses build_vendor_tree."""
        monitor._vendor_grouped = True
        procs = [
            {"pid": 1, "ppid": 0, "rss_kb": 100, "cpu": 1.0, "cpu_ticks": 100,
             "threads": 1, "command": "/System/Library/daemon1"},
            {"pid": 2, "ppid": 0, "rss_kb": 200, "cpu": 2.0, "cpu_ticks": 200,
             "threads": 1, "command": "/usr/bin/daemon2"},
            {"pid": 3, "ppid": 0, "rss_kb": 300, "cpu": 3.0, "cpu_ticks": 300,
             "threads": 1, "command": "/Applications/Google Chrome.app/chrome"},
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

        # Root rows should be vendor groups
        root_commands = [r["command"] for r in monitor.rows if r["depth"] == 0]
        assert "Apple" in root_commands or "Google" in root_commands

    def test_collect_data_normal_when_off(self, monitor):
        """When _vendor_grouped is off, uses normal build_tree."""
        monitor._vendor_grouped = False
        procs = [
            {"pid": 1, "ppid": 0, "rss_kb": 100, "cpu": 1.0, "cpu_ticks": 100,
             "threads": 1, "command": "/System/Library/daemon1"},
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

        # Should be the actual process, not a vendor wrapper
        if monitor.rows:
            assert "daemon1" not in monitor.rows[0].get("vendor_group", "")


# ── Integration with dynamic sort ───────────────────────────────────────


class TestVendorGroupWithDynamicSort:

    def test_vendor_group_with_dynamic_sort(self, monitor):
        """Both features active: vendor groups sorted with threshold priority."""
        monitor._vendor_grouped = True
        monitor._dynamic_sort = True
        monitor._alert_thresholds["cpu"] = 50.0

        procs = [
            {"pid": 1, "ppid": 0, "rss_kb": 5000, "cpu": 10.0, "cpu_ticks": 100,
             "threads": 1, "command": "/System/Library/heavy_mem"},
            {"pid": 2, "ppid": 0, "rss_kb": 100, "cpu": 80.0, "cpu_ticks": 800,
             "threads": 1, "command": "/Applications/Google Chrome.app/chrome"},
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

        # Google (cpu 80% > threshold 50%) should be first despite lower mem
        if len(monitor.rows) >= 2:
            assert monitor.rows[0]["command"] == "Google"


# ── Selection and expansion persistence across refresh ───────────────────


class TestSelectionPersistence:

    def _procs(self):
        return [
            {"pid": 1, "ppid": 0, "rss_kb": 100, "cpu": 1.0, "cpu_ticks": 100,
             "threads": 1, "command": "/System/Library/daemon1"},
            {"pid": 2, "ppid": 0, "rss_kb": 200, "cpu": 2.0, "cpu_ticks": 200,
             "threads": 1, "command": "/usr/bin/daemon2"},
            {"pid": 3, "ppid": 0, "rss_kb": 300, "cpu": 3.0, "cpu_ticks": 300,
             "threads": 1, "command": "/Applications/Google Chrome.app/chrome"},
        ]

    def _setup(self, monitor):
        monitor._prev_cpu = {}
        monitor.prev_net = {}
        monitor.prev_time = None
        monitor.net_rates = {}
        monitor._net_bytes = {}

    def test_selection_preserved_on_refresh(self, monitor):
        """Selected PID stays selected after collect_data refresh."""
        procs = self._procs()
        self._setup(monitor)
        with patch("procmon.get_all_processes", return_value=procs), \
             patch("procmon.get_net_snapshot", return_value={}), \
             patch("procmon.get_fd_counts", return_value={}), \
             patch("procmon.get_cwds", return_value={}):
            monitor.collect_data()

        # Select second row and note its PID
        monitor.selected = 1
        sel_pid = monitor.rows[1]["pid"]

        # Refresh
        with patch("procmon.get_all_processes", return_value=procs), \
             patch("procmon.get_net_snapshot", return_value={}), \
             patch("procmon.get_fd_counts", return_value={}), \
             patch("procmon.get_cwds", return_value={}):
            monitor.collect_data()

        assert monitor.rows[monitor.selected]["pid"] == sel_pid

    def test_selection_preserved_vendor_mode(self, monitor):
        """Selected vendor group stays selected after refresh."""
        monitor._vendor_grouped = True
        procs = self._procs()
        self._setup(monitor)
        with patch("procmon.get_all_processes", return_value=procs), \
             patch("procmon.get_net_snapshot", return_value={}), \
             patch("procmon.get_fd_counts", return_value={}), \
             patch("procmon.get_cwds", return_value={}):
            monitor.collect_data()

        # Select a vendor group
        monitor.selected = 1
        sel_pid = monitor.rows[1]["pid"]

        # Refresh — same procs, vendor group PIDs should be stable
        with patch("procmon.get_all_processes", return_value=procs), \
             patch("procmon.get_net_snapshot", return_value={}), \
             patch("procmon.get_fd_counts", return_value={}), \
             patch("procmon.get_cwds", return_value={}):
            monitor.collect_data()

        assert monitor.rows[monitor.selected]["pid"] == sel_pid

    def test_expansion_preserved_on_refresh(self, monitor):
        """Expanded nodes stay expanded after refresh."""
        procs = self._procs()
        self._setup(monitor)
        with patch("procmon.get_all_processes", return_value=procs), \
             patch("procmon.get_net_snapshot", return_value={}), \
             patch("procmon.get_fd_counts", return_value={}), \
             patch("procmon.get_cwds", return_value={}):
            monitor.collect_data()

        # Expand a node
        if monitor.rows:
            pid_to_expand = monitor.rows[0]["pid"]
            monitor._expanded.add(pid_to_expand)

        # Refresh
        with patch("procmon.get_all_processes", return_value=procs), \
             patch("procmon.get_net_snapshot", return_value={}), \
             patch("procmon.get_fd_counts", return_value={}), \
             patch("procmon.get_cwds", return_value={}):
            monitor.collect_data()

        assert pid_to_expand in monitor._expanded

    def test_vendor_group_stable_pid(self):
        """Vendor group PID is stable across rebuilds regardless of sort order."""
        procs = [
            {"pid": 1, "ppid": 0, "rss_kb": 100, "cpu": 1.0, "cpu_ticks": 100,
             "threads": 1, "command": "/System/Library/a"},
            {"pid": 2, "ppid": 0, "rss_kb": 200, "cpu": 2.0, "cpu_ticks": 200,
             "threads": 1, "command": "/usr/bin/b"},
        ]
        sort_key = lambda p: p.get("agg_rss_kb", p["rss_kb"])
        tree1 = procmon.build_vendor_tree(procs, procs, sort_key, reverse=True)
        tree2 = procmon.build_vendor_tree(procs, procs, sort_key, reverse=False)
        # Apple group should have the same PID in both
        apple1 = [n for n in tree1 if n["command"] == "Apple"][0]
        apple2 = [n for n in tree2 if n["command"] == "Apple"][0]
        assert apple1["pid"] == apple2["pid"]

    def test_selection_clamped_when_process_disappears(self, monitor):
        """If the selected process dies, selection is clamped to last row."""
        procs = self._procs()
        self._setup(monitor)
        with patch("procmon.get_all_processes", return_value=procs), \
             patch("procmon.get_net_snapshot", return_value={}), \
             patch("procmon.get_fd_counts", return_value={}), \
             patch("procmon.get_cwds", return_value={}):
            monitor.collect_data()
        monitor.selected = 2  # select third row

        # Refresh with fewer processes
        with patch("procmon.get_all_processes", return_value=procs[:1]), \
             patch("procmon.get_net_snapshot", return_value={}), \
             patch("procmon.get_fd_counts", return_value={}), \
             patch("procmon.get_cwds", return_value={}):
            monitor.collect_data()

        assert monitor.selected < len(monitor.rows)
