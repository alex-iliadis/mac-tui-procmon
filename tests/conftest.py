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
    mon._prev_disk_io = {}
    mon._disk_io_rates = {}
    # Per-PID metric ring buffer (sparklines)
    import threading as _th_metric
    mon._metric_history = {}
    mon._metric_history_lock = _th_metric.Lock()
    mon._metric_history_max_age = 300
    mon._metric_history_seen = {}
    mon._metric_history_max = 60
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
    mon._chat_status = None
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
    # GPU / Metal per-process utilization
    import threading as _t_gpu
    mon._gpu_supported = False
    mon._gpu_supported_probed = False
    mon._gpu_samples = {}
    mon._gpu_samples_lock = _t_gpu.Lock()
    mon._gpu_worker = None
    mon._gpu_pending = None
    mon._gpu_loading = False
    mon._gpu_status = ""
    mon._gpu_last_sample_ts = 0.0
    mon._gpu_sample_interval = 5.0
    # Unified Logging per-process stream
    import collections as _c_unified
    import threading as _t_unified
    mon._unified_log_mode = False
    mon._unified_log_pid = None
    mon._unified_log_cmd = ""
    mon._unified_log_lines = _c_unified.deque(maxlen=2000)
    mon._unified_log_lock = _t_unified.Lock()
    mon._unified_log_proc = None
    mon._unified_log_worker = None
    mon._unified_log_loading = False
    mon._unified_log_cancel = False
    mon._unified_log_scroll = 0
    mon._unified_log_max = 2000
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
    # Feature 1: Process Event Ripples
    mon._row_pulses = {}
    mon._pulse_thresholds = {
        "cpu_delta": 20.0,
        "net_delta_mbps": 1.0,
        "io_delta_mbps": 5.0,
    }
    mon._pulse_frames = 4
    mon._pulse_prev = {}
    # Feature 2: AI Narrator
    import threading as _t_narrator
    mon._narrator_enabled = False
    mon._narrator_last_tick = 0.0
    mon._narrator_interval = 15.0
    mon._narrator_caption = ""
    mon._narrator_target_pid = None
    mon._narrator_target_cmd = ""
    mon._narrator_speak = True
    mon._narrator_worker = None
    mon._narrator_pending = None
    mon._narrator_loading = False
    mon._narrator_seen_pids = {}
    mon._narrator_history = []
    mon._narrator_history_max = 20
    mon._narrator_speak_lock = _t_narrator.Lock()
    # Feature 3: Resource Oscilloscope
    mon._oscilloscope_mode = False
    mon._oscilloscope_pid = None
    mon._oscilloscope_scroll = 0
    # Feature 4: Three-Model Consensus Race
    import threading as _t_consensus
    mon._consensus_lanes = {"claude": [], "codex": [], "gemini": []}
    mon._consensus_lane_lock = _t_consensus.Lock()
    mon._consensus_lane_done = {"claude": False, "codex": False, "gemini": False}
    mon._consensus_risk_bar = 0
    mon._consensus_running = False
    mon._consensus_lane_max_lines = 60
    # Feature 5: Attack Chain Replay
    mon._events_persist_on_close = True
    mon._replay_mode = False
    mon._replay_events = []
    mon._replay_cursor = 0
    mon._replay_playing = False
    mon._replay_speed = 1.0
    mon._replay_driveby_pairs = set()
    mon._replay_driveby_window_secs = 5.0
    # Feature 6: Network Orbit / Constellation
    mon._orbit_mode = False
    mon._orbit_tick = 0
    # Feature 7: Process Galaxy
    mon._galaxy_mode = False
    mon._galaxy_positions = {}
    mon._galaxy_velocity = {}
    mon._galaxy_glow = {}
    mon._galaxy_known_pids = set()
    mon._galaxy_node_cap = 80
    mon._galaxy_iter_step = 0.5
    # Feature 8: Process Lifecycle DVR
    import collections as _c_lifecycle
    mon._lifecycle_mode = False
    mon._lifecycle_snapshots = _c_lifecycle.deque(maxlen=300)
    mon._lifecycle_cursor = -1
    mon._lifecycle_playing = True
    mon._lifecycle_max_rows = 60
    mon._lifecycle_min_alive_cells = 1
    mon._test_select_pid = 0
    return mon
