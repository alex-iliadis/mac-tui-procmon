import sys
import os
import pytest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import procmon


def make_proc(pid=1, ppid=0, cpu=0.0, rss_kb=0, threads=1, fds=0, forks=0,
              net_in=-1, net_out=-1, bytes_in=0, bytes_out=0,
              command="/usr/bin/test", cpu_ticks=0):
    """Create a minimal process dict for testing."""
    return {
        "pid": pid, "ppid": ppid, "cpu": cpu, "rss_kb": rss_kb,
        "threads": threads, "fds": fds, "forks": forks,
        "net_in": net_in, "net_out": net_out,
        "bytes_in": bytes_in, "bytes_out": bytes_out,
        "command": command, "depth": 0, "children": [],
        "agg_cpu": cpu, "agg_rss_kb": rss_kb, "agg_threads": threads,
        "agg_forks": 0, "agg_net_in": max(net_in, 0),
        "agg_net_out": max(net_out, 0), "agg_bytes_in": bytes_in,
        "agg_bytes_out": bytes_out, "agg_cpu_ticks": cpu_ticks,
        "cpu_ticks": cpu_ticks, "prefix": "", "has_children": False,
        "is_collapsed": False, "cwd": "~",
    }


@pytest.fixture
def monitor():
    """Create a ProcMonUI instance with mocked curses, bypassing __init__."""
    mon = object.__new__(procmon.ProcMonUI)
    mon.stdscr = MagicMock()
    mon.stdscr.getmaxyx.return_value = (40, 120)
    mon.stdscr.getch.return_value = -1
    mon.name = ""
    mon.patterns = []
    mon.exclude_name = ""
    mon.exclude_patterns = []
    mon.interval = 5.0
    mon.skip_fd = False
    mon.selected = 0
    mon.scroll_offset = 0
    mon.rows = []
    mon.matched_count = 0
    mon.prev_net = {}
    mon.prev_time = None
    mon.net_rates = {}
    mon.sort_mode = procmon.SORT_MEM
    mon._sort_inverted = False
    mon._dynamic_sort = False
    mon._vendor_grouped = False
    mon._prev_cpu = {}
    mon._collapsed = set()
    mon._expanded = set()
    mon._detail_focus = False
    mon._net_mode = False
    mon._net_entries = []
    mon._net_selected = 0
    mon._net_scroll = 0
    mon._net_pid = None
    mon._net_bytes = {}
    mon._total_mem_kb = 16 * 1024 * 1024
    mon._alert_thresholds = {
        "cpu": 0.0, "mem_mb": 0.0, "threads": 0, "fds": 0,
        "forks": 0, "net_in": 0.0, "net_out": 0.0,
        "recv_mb": 0.0, "sent_mb": 0.0,
    }
    mon._alert_last_sound = 0.0
    mon._alert_interval = 60
    mon._alert_max_count = 5
    mon._alert_count = 0
    mon._net_worker = None
    mon._net_pending = None
    mon._net_loading = False
    mon._all_procs = []
    return mon
