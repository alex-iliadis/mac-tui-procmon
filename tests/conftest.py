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
    # Inspect mode
    mon._inspect_mode = False
    mon._inspect_pid = None
    mon._inspect_cmd = ""
    mon._inspect_lines = []
    mon._inspect_scroll = 0
    mon._inspect_worker = None
    mon._inspect_pending = None
    mon._inspect_loading = False
    mon._inspect_phase = ""
    # Hidden process detection (passive header badge only)
    mon._hidden_pids = set()
    mon._hidden_alert_count = 0
    mon._last_hidden_check = 0.0
    # Debug log
    import threading as _threading
    import threading as _t
    mon._log_messages = []
    mon._log_lock = _t.Lock()
    mon._log_max = 500
    mon._log_mode = False
    mon._log_scroll = 0
    # Chat overlay
    mon._chat_mode = False
    mon._chat_messages = []
    mon._chat_input = ""
    mon._chat_cursor = 0
    mon._chat_scroll = 0
    mon._chat_loading = False
    mon._chat_worker = None
    mon._chat_pending = None
    mon._chat_context_label = ""
    mon._chat_context_text = ""
    # LLM executive-summary state (per-scope)
    mon._llm_summary = {"audit": None,
                        "inspect": None, "events": None}
    mon._llm_summary_pending = {"audit": None,
                                 "inspect": None,
                                 "events": None}
    mon._llm_summary_loading = {"audit": False,
                                 "inspect": False,
                                 "events": False}
    mon._llm_summary_worker = {"audit": None,
                                "inspect": None,
                                "events": None}
    # Host security audits
    mon._audit_mode = False
    mon._audit_type = None
    mon._audit_lines = []
    mon._audit_scroll = 0
    mon._audit_worker = None
    mon._audit_pending = None
    mon._audit_loading = False
    mon._audit_progress_lines = []
    mon._audit_progress_lock = _threading.Lock()
    mon._audit_findings_structured = []
    mon._audit_line_for_finding = []
    mon._audit_cursor = 0
    mon._audit_action_result = None
    mon._audit_context_pid = None
    mon._audit_context_cmd = ""
    mon._audit_title_override = ""
    # Live events
    import threading
    mon._events_mode = False
    mon._events = []
    mon._events_scroll = 0
    mon._events_worker = None
    mon._events_proc = None
    mon._events_cancel = False
    mon._events_source = ""
    mon._events_filter = ""
    mon._events_lock = threading.Lock()
    mon._events_max = 500
    mon._events_awaiting_summary = False
    # Traffic Inspector
    mon._traffic_mode = False
    mon._traffic_proc = None
    mon._traffic_flows = []
    import threading as _t_traffic
    mon._traffic_flows_lock = _t_traffic.Lock()
    mon._traffic_flows_max = 500
    mon._traffic_scroll = 0
    mon._traffic_reader_thread = None
    mon._traffic_port = 8080
    mon._traffic_loading = False
    mon._traffic_error = ""
    mon._traffic_shim_path = ""
    mon._test_select_pid = 0
    return mon
