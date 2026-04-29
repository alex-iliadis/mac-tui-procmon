"""Tests for the four new features:
1. Memory-dump indicator on the Inspect report
2. Traffic Inspector (experimental mitmproxy wrapper)
3. LLM executive summary across audits / keyscan / hidden / inspect
4. Events → LLM analysis on stop
"""
import ctypes
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import procmon


# ── 1. Memory-dump indicator ──────────────────────────────────────────────


class TestInspectMemoryBadges:
    def test_dumped_badge_when_core_succeeds(self, monitor):
        artifacts = {
            "pid": 42, "exe_path": "/bin/x",
            "yara_memory": {"success": True, "matches": ["rule_a"],
                            "core_size": 5 * 1024 * 1024},
            "yara_file": [],
        }
        lines = monitor._format_inspect_report(artifacts)
        joined = "\n".join(lines[:10])
        assert "[MEMORY-DUMPED]" in joined
        assert "5.0 MB" in joined
        assert "1 YARA hit" in joined

    def test_skipped_badge_when_no_root(self, monitor):
        artifacts = {
            "pid": 42, "exe_path": "/bin/x",
            "yara_memory": {"success": False,
                            "error": "skipped — requires root"},
            "yara_file": [],
        }
        lines = monitor._format_inspect_report(artifacts)
        joined = "\n".join(lines[:10])
        assert "[MEMORY-SKIPPED]" in joined
        assert "requires root" in joined

    def test_disk_yara_badge_present(self, monitor):
        artifacts = {
            "pid": 1, "exe_path": "/bin/x",
            "yara_memory": {"success": False, "error": "not attempted"},
            "yara_file": ["rule_one", "rule_two"],
        }
        lines = monitor._format_inspect_report(artifacts)
        joined = "\n".join(lines[:10])
        assert "[DISK-YARA] 2 hits" in joined



# ── 2. LLM summary infrastructure ─────────────────────────────────────────


class TestLlmSummaryInfrastructure:
    def test_build_findings_summary_body_includes_counts(self, monitor):
        findings = [
            {"severity": "CRITICAL", "message": "c1", "action": None},
            {"severity": "HIGH", "message": "h1", "action": None},
            {"severity": "HIGH", "message": "h2", "action": None},
        ]
        body = monitor._build_findings_summary_body("Test Audit", findings)
        assert "SCAN: Test Audit" in body
        assert "TOTAL FINDINGS: 3" in body
        assert "CRITICAL" in body
        assert "c1" in body
        assert "h1" in body

    def test_build_findings_caps_at_40(self, monitor):
        findings = [{"severity": "INFO", "message": f"m{i}",
                     "action": None} for i in range(60)]
        body = monitor._build_findings_summary_body("T", findings)
        assert "more findings omitted" in body

    def test_summary_panel_renders_bullets(self, monitor):
        resp = ("TOP_CONCERN: ALF is disabled.\n"
                "SIGNAL: VNC exposed externally.\n"
                "ACTION: Run procmon --audit network --fix-first.\n")
        panel = monitor._format_llm_summary_panel(resp)
        joined = "\n".join(panel)
        assert "AI SUMMARY" in joined
        assert "[CRITICAL]" in joined
        assert "[HIGH]" in joined
        assert "ALF is disabled" in joined
        assert "Fix first:" in joined

    def test_loading_banner_has_thinking_indicator(self, monitor):
        monitor._llm_summary_loading["audit"] = True
        banner = monitor._llm_summary_loading_banner("audit")
        joined = "\n".join(banner)
        assert "AI SUMMARY" in joined
        assert "Generating" in joined

    def test_loading_banner_empty_when_not_loading(self, monitor):
        monitor._llm_summary_loading["audit"] = False
        assert monitor._llm_summary_loading_banner("audit") == []

    def test_start_noop_on_empty_findings(self, monitor):
        monitor._llm_summary_loading["audit"] = True
        monitor._start_llm_summary("audit", "T", [])
        assert monitor._llm_summary_loading["audit"] is False

    def test_start_noop_when_worker_in_flight(self, monitor):
        mock_worker = MagicMock()
        mock_worker.is_alive.return_value = True
        monitor._llm_summary_worker["audit"] = mock_worker
        with patch.object(monitor, "_run_llm") as run:
            monitor._start_llm_summary(
                "audit", "T",
                [{"severity": "HIGH", "message": "x", "action": None}])
        run.assert_not_called()

    def test_start_completes_populates_pending(self, monitor):
        monitor._llm_summary_worker["audit"] = None
        with patch.object(monitor, "_run_llm",
                          return_value="TOP_CONCERN: bad"):
            monitor._start_llm_summary(
                "audit", "T",
                [{"severity": "HIGH", "message": "x", "action": None}])
            for _ in range(50):
                if monitor._llm_summary_pending["audit"] is not None:
                    break
                time.sleep(0.01)
        assert monitor._llm_summary_pending["audit"] is not None

    def test_start_error_response_still_produces_panel(self, monitor):
        monitor._llm_summary_worker["audit"] = None
        with patch.object(monitor, "_run_llm",
                          return_value="[claude CLI not found]"):
            monitor._start_llm_summary(
                "audit", "T",
                [{"severity": "HIGH", "message": "x", "action": None}])
            for _ in range(50):
                if monitor._llm_summary_pending["audit"] is not None:
                    break
                time.sleep(0.01)
        pending = monitor._llm_summary_pending["audit"]
        assert pending is not None
        assert any("unavailable" in l for l in pending)

    def test_poll_applies_pending_summary(self, monitor):
        monitor._llm_summary_pending["audit"] = ["line1", "line2"]
        assert monitor._poll_llm_summary("audit") is True
        assert monitor._llm_summary["audit"] == ["line1", "line2"]
        assert monitor._llm_summary_pending["audit"] is None

    def test_poll_no_pending_returns_false(self, monitor):
        monitor._llm_summary_pending["audit"] = None
        assert monitor._poll_llm_summary("audit") is False


# ── Audit mode kicks off summary on scan complete ─────────────────────────




# ── 3. Keyscan summary trigger ───────────────────────────────────────────




# ── 5. Inspect summary trigger ───────────────────────────────────────────


class TestInspectSummaryTrigger:
    def test_inspect_worker_calls_summary_after_consensus(self, monitor):
        # Stub everything the worker calls so we only exercise the
        # end-of-worker summary trigger.
        monitor._inspect_pid = 42
        monitor._inspect_phase = ""
        artifacts = {"pid": 42, "exe_path": "/bin/x"}
        analyses = {"claude": "RISK: CRITICAL\nDetails here.",
                    "codex": "RISK: HIGH\n",
                    "gemini": "RISK: MEDIUM\n"}
        with patch.object(monitor, "_collect_inspect_artifacts",
                          return_value=artifacts), \
             patch.object(monitor, "_format_inspect_report",
                          return_value=["report"]), \
             patch.object(monitor, "_run_llms_parallel",
                          return_value=analyses), \
             patch.object(monitor, "_run_llms_parallel_streaming",
                          return_value=analyses), \
             patch.object(monitor, "_synthesize_analyses",
                          return_value=("claude",
                                        "CONSENSUS_RISK: CRITICAL\nBad.")), \
             patch.object(monitor, "_start_llm_summary") as start:
            monitor._inspect_worker_fn(42, "/bin/x")
        # Among other calls, at least one should be scope="inspect"
        inspect_calls = [c for c in start.call_args_list
                         if c.args[0] == "inspect"]
        assert len(inspect_calls) == 1
        _, title, findings = inspect_calls[0].args
        assert "PID 42" in title
        # Pseudo findings elevated CRITICAL for consensus + CRITICAL claude
        assert any(f["severity"] == "CRITICAL" for f in findings)


# ── 6. Events → LLM summary on stop ───────────────────────────────────────


class TestEventsLlmOnStop:
    def test_first_escape_starts_summary_second_closes(self, monitor):
        monitor._detail_focus = True
        monitor._events_mode = True
        monitor._events_awaiting_summary = False
        # Seed events so the two-stage flow kicks in
        with monitor._events_lock:
            monitor._events.append({"pid": 1, "ppid": 0, "cmd": "x",
                                     "ts": "0", "kind": "exec", "extra": {}})
        with patch.object(monitor, "_stop_events_stream"), \
             patch.object(monitor, "_start_events_llm_summary") as start:
            monitor.handle_input(27)  # first Esc
        assert monitor._events_mode is True
        assert monitor._events_awaiting_summary is True
        start.assert_called_once()

        # Second Esc actually closes.
        with patch.object(monitor, "_stop_events_stream"):
            monitor.handle_input(27)
        assert monitor._events_mode is False
        assert monitor._events_awaiting_summary is False

    def test_escape_with_no_events_closes_immediately(self, monitor):
        monitor._detail_focus = True
        monitor._events_mode = True
        monitor._events_awaiting_summary = False
        # No events — no summary trigger
        with patch.object(monitor, "_stop_events_stream"), \
             patch.object(monitor, "_start_events_llm_summary") as start:
            monitor.handle_input(27)
        start.assert_not_called()
        assert monitor._events_mode is False

    def test_start_events_summary_populates_pending(self, monitor):
        with monitor._events_lock:
            monitor._events.append({"pid": 1, "ppid": 0, "cmd": "/bin/evil",
                                     "ts": "0", "kind": "exec"})
        monitor._events_source = "eslogger"
        monitor._llm_summary_worker["events"] = None
        with patch.object(monitor, "_run_llm",
                          return_value="TOP_CONCERN: /bin/evil spawned"):
            monitor._start_events_llm_summary()
            for _ in range(50):
                if monitor._llm_summary_pending["events"] is not None:
                    break
                time.sleep(0.01)
        pending = monitor._llm_summary_pending["events"]
        assert pending is not None
        assert any("evil" in l for l in pending)

    def test_start_events_summary_noop_on_empty(self, monitor):
        with monitor._events_lock:
            monitor._events.clear()
        with patch.object(monitor, "_run_llm") as run:
            monitor._start_events_llm_summary()
        run.assert_not_called()


# ── 7. Traffic Inspector ─────────────────────────────────────────────────


class TestTrafficInspector:
    def test_toggle_without_mitmdump_shows_error(self, monitor):
        monitor._traffic_mode = False
        with patch("shutil.which", return_value=None):
            monitor._toggle_traffic_mode()
        assert monitor._traffic_mode is True  # opens in error state
        assert "experimental backend unavailable" in monitor._traffic_error
        assert "mitmdump not found" in monitor._traffic_error

    def test_toggle_with_mitmdump_launches_subprocess(self, monitor, tmp_path):
        fake_path = str(tmp_path / "mitmdump")
        # Make a fake binary so shutil.which finds it
        open(fake_path, "w").close()
        os.chmod(fake_path, 0o755)

        fake_proc = MagicMock()
        fake_proc.stdout = iter([])  # no flows
        with patch("shutil.which", return_value=fake_path), \
             patch("subprocess.Popen", return_value=fake_proc) as popen:
            monitor._toggle_traffic_mode()
        popen.assert_called_once()
        argv = popen.call_args[0][0]
        assert argv[0] == fake_path
        assert "--listen-port" in argv
        assert monitor._traffic_mode is True
        assert monitor._traffic_loading is False
        assert monitor._detail_ready_state() == ("ready", True)
        # Shim written to a predictable location
        assert os.path.exists(monitor._traffic_shim_path)
        # Teardown
        with patch("os.unlink"):
            monitor._stop_traffic_stream()

    def test_toggle_twice_closes(self, monitor, tmp_path):
        fake_path = str(tmp_path / "mitmdump")
        open(fake_path, "w").close()
        fake_proc = MagicMock()
        fake_proc.stdout = iter([])
        with patch("shutil.which", return_value=fake_path), \
             patch("subprocess.Popen", return_value=fake_proc):
            monitor._toggle_traffic_mode()
        # Re-toggle → close
        monitor._toggle_traffic_mode()
        assert monitor._traffic_mode is False
        fake_proc.terminate.assert_called()

    def test_reader_parses_json_flows(self, monitor, tmp_path):
        fake_path = str(tmp_path / "mitmdump")
        open(fake_path, "w").close()
        os.chmod(fake_path, 0o755)

        fake_proc = MagicMock()
        # Two valid JSON flow lines + a non-JSON noise line
        fake_proc.stdout = iter([
            json.dumps({"method": "GET", "url": "https://a/",
                        "host": "a", "scheme": "https", "status": 200,
                        "req_size": 0, "resp_size": 1234,
                        "content_type": "text/html"}) + "\n",
            "warning: not json\n",
            json.dumps({"method": "POST", "url": "https://b/",
                        "host": "b", "scheme": "https", "status": 500,
                        "req_size": 42, "resp_size": 99,
                        "content_type": "application/json"}) + "\n",
        ])
        with patch("shutil.which", return_value=fake_path), \
             patch("subprocess.Popen", return_value=fake_proc):
            monitor._toggle_traffic_mode()
        # Wait for the reader thread to drain the iterator
        for _ in range(50):
            with monitor._traffic_flows_lock:
                if len(monitor._traffic_flows) == 2:
                    break
            time.sleep(0.02)
        with monitor._traffic_flows_lock:
            assert len(monitor._traffic_flows) == 2
            assert monitor._traffic_flows[0]["host"] == "a"
            assert monitor._traffic_flows[1]["status"] == 500

        # Cleanup
        with patch("os.unlink"):
            monitor._stop_traffic_stream()

    def test_format_traffic_view_shows_error(self, monitor):
        monitor._traffic_error = (
            "experimental backend unavailable: mitmdump not found. "
            "Install via: brew"
        )
        lines = monitor._format_traffic_view()
        joined = "\n".join(lines)
        assert "Traffic Inspector (experimental)" in joined
        assert "mitmdump not found" in joined

    def test_format_traffic_view_shows_flows(self, monitor):
        monitor._traffic_error = ""
        with monitor._traffic_flows_lock:
            monitor._traffic_flows.extend([
                {"method": "GET", "url": "https://e/", "host": "e",
                 "status": 200, "req_size": 0, "resp_size": 1,
                 "content_type": "text/html"},
                {"method": "CONNECT", "url": "", "host": "p.com",
                 "status": -1, "error": "certificate verify failed"},
            ])
        lines = monitor._format_traffic_view()
        joined = "\n".join(lines)
        assert "e/" in joined
        assert "certificate verify failed" in joined

    def test_traffic_input_clear(self, monitor):
        monitor._detail_focus = True
        monitor._traffic_mode = True
        with monitor._traffic_flows_lock:
            monitor._traffic_flows.extend([{"method": "GET"}])
        monitor.handle_input(ord("c"))
        with monitor._traffic_flows_lock:
            assert monitor._traffic_flows == []

    def test_traffic_input_escape_stops(self, monitor):
        monitor._detail_focus = True
        monitor._traffic_mode = True
        with patch.object(monitor, "_stop_traffic_stream") as stop:
            monitor.handle_input(27)
        stop.assert_called_once()
        assert monitor._traffic_mode is False

    def test_traffic_input_up_down(self, monitor):
        import curses
        monitor._detail_focus = True
        monitor._traffic_mode = True
        monitor._traffic_scroll = 5
        monitor.handle_input(curses.KEY_UP)
        assert monitor._traffic_scroll == 4
        monitor.handle_input(curses.KEY_DOWN)
        assert monitor._traffic_scroll == 5

    def test_traffic_in_telemetry_menu(self, monitor):
        payloads = {r[2] for r in monitor._TELEMETRY_ROWS if r[1] == "action"}
        assert "traffic" in payloads

    def test_telemetry_dispatch_traffic(self, monitor):
        with patch.object(monitor, "_toggle_traffic_mode") as tog:
            monitor._dispatch_telemetry_action("traffic")
        tog.assert_called_once()

    def test_shutdown_kills_traffic_proc(self, monitor):
        fake_proc = MagicMock()
        monitor._traffic_proc = fake_proc
        monitor._shutdown()
        # _shutdown() calls _stop_traffic_stream, which calls terminate()
        # (and falls through to kill only on timeout). Either counts.
        assert fake_proc.terminate.called or fake_proc.kill.called


# ── 5. Per-process disk I/O bytes (proc_pid_rusage) ─────────────────────


class TestDiskIoHelper:
    def test_get_disk_io_returns_pair_on_success(self):
        # Simulate libproc filling in disk byte counts. We swap the struct
        # constructor for one that pre-populates the diskio fields, then
        # have proc_pid_rusage just return 0 (success). The "as if filled
        # by the kernel" approximation is faithful enough — we're testing
        # that _get_disk_io correctly propagates ri_diskio_* into a tuple.
        class _Prefilled(procmon.rusage_info_v4):
            def __init__(self):
                super().__init__()
                self.ri_diskio_bytesread = 1024
                self.ri_diskio_byteswritten = 2048
        with patch.object(procmon, "rusage_info_v4", _Prefilled), \
             patch.object(procmon._libproc, "proc_pid_rusage",
                          return_value=0):
            br, bw = procmon._get_disk_io(1234)
        assert br == 1024
        assert bw == 2048

    def test_get_disk_io_returns_none_on_failure(self):
        with patch.object(procmon._libproc, "proc_pid_rusage",
                          return_value=-1):
            br, bw = procmon._get_disk_io(1234)
        assert br is None
        assert bw is None

    def test_get_disk_io_invalid_pid(self):
        br, bw = procmon._get_disk_io(0)
        assert br is None and bw is None

    def test_get_disk_io_handles_oserror(self):
        with patch.object(procmon._libproc, "proc_pid_rusage",
                          side_effect=OSError("boom")):
            br, bw = procmon._get_disk_io(1234)
        assert br is None and bw is None


class TestDiskIoCollect:
    def test_collect_data_populates_disk_fields(self, monitor):
        # First refresh: cumulative snapshot only, no rate yet (no prior).
        proc_a = {"pid": 100, "ppid": 1, "cpu": 0.0, "rss_kb": 0,
                  "threads": 1, "command": "/bin/x", "cpu_ticks": 0}
        with patch("procmon.get_all_processes", return_value=[proc_a]), \
             patch("procmon.get_net_snapshot", return_value={}), \
             patch("procmon.get_fd_counts", return_value={}), \
             patch("procmon.get_cwds", return_value={}), \
             patch("procmon._get_disk_io", return_value=(1000, 2000)):
            monitor.collect_data()
        assert proc_a["disk_bytes_in"] == 1000
        assert proc_a["disk_bytes_out"] == 2000
        # First sample → no rate yet
        assert proc_a["disk_in"] == -1

    def test_collect_data_computes_disk_rate(self, monitor):
        # Two refreshes 1s apart → rate = (new - old) / dt.
        monitor.prev_time = 100.0
        monitor._prev_disk_io = {100: (1000, 2000)}
        proc_a = {"pid": 100, "ppid": 1, "cpu": 0.0, "rss_kb": 0,
                  "threads": 1, "command": "/bin/x", "cpu_ticks": 0}
        with patch("procmon.get_all_processes", return_value=[proc_a]), \
             patch("procmon.get_net_snapshot", return_value={}), \
             patch("procmon.get_fd_counts", return_value={}), \
             patch("procmon.get_cwds", return_value={}), \
             patch("procmon.time.monotonic", return_value=101.0), \
             patch("procmon._get_disk_io", return_value=(2000, 4000)):
            monitor.collect_data()
        # 1000 bytes read in 1s → 1000 B/s
        assert abs(proc_a["disk_in"] - 1000.0) < 0.5
        assert abs(proc_a["disk_out"] - 2000.0) < 0.5

    def test_collect_data_handles_disk_io_unavailable(self, monitor):
        proc_a = {"pid": 100, "ppid": 1, "cpu": 0.0, "rss_kb": 0,
                  "threads": 1, "command": "/bin/x", "cpu_ticks": 0}
        with patch("procmon.get_all_processes", return_value=[proc_a]), \
             patch("procmon.get_net_snapshot", return_value={}), \
             patch("procmon.get_fd_counts", return_value={}), \
             patch("procmon.get_cwds", return_value={}), \
             patch("procmon._get_disk_io", return_value=(None, None)):
            monitor.collect_data()
        assert proc_a["disk_bytes_in"] == 0
        assert proc_a["disk_bytes_out"] == 0
        assert proc_a["disk_in"] == -1
        assert proc_a["disk_out"] == -1


class TestDiskIoDisplay:
    def test_detail_lines_includes_disk_when_present(self, monitor):
        from tests.conftest import make_proc
        r = make_proc(pid=100)
        r["disk_in"] = 1024.0
        r["disk_out"] = 2048.0
        r["disk_bytes_in"] = 1_048_576
        r["disk_bytes_out"] = 2_097_152
        monitor.rows = [r]
        monitor.selected = 0
        lines = monitor._detail_lines(120)
        joined = "\n".join(lines)
        assert "Disk:" in joined

    def test_detail_lines_omits_disk_when_unavailable(self, monitor):
        from tests.conftest import make_proc
        r = make_proc(pid=100)
        # No disk fields set → helper should suppress the line.
        monitor.rows = [r]
        monitor.selected = 0
        lines = monitor._detail_lines(120)
        joined = "\n".join(lines)
        assert "Disk:" not in joined

    def test_chat_context_includes_disk_for_selected_proc(self, monitor):
        from tests.conftest import make_proc
        r = make_proc(pid=100)
        r["disk_in"] = 1024.0
        r["disk_out"] = 2048.0
        r["disk_bytes_in"] = 1_048_576
        r["disk_bytes_out"] = 2_097_152
        monitor.rows = [r]
        monitor.selected = 0
        label, text = monitor._collect_chat_context()
        assert "disk_io_rate" in text or "disk_io_total" in text


# ── 6. Per-PID metric ring buffer + sparklines ───────────────────────────


class TestSparklineHelper:
    def test_empty_returns_empty_string(self):
        assert procmon._sparkline([]) == ""
        assert procmon._sparkline([], width=10) == ""

    def test_all_zeros_uses_lowest_block(self):
        s = procmon._sparkline([0, 0, 0, 0])
        assert s == procmon._SPARK_BLOCKS[0] * 4

    def test_single_value(self):
        s = procmon._sparkline([7.5])
        # max==value → top block
        assert s == procmon._SPARK_BLOCKS[-1]

    def test_normalizes_to_peak(self):
        s = procmon._sparkline([0, 50, 100])
        assert len(s) == 3
        assert s[0] == procmon._SPARK_BLOCKS[0]
        assert s[2] == procmon._SPARK_BLOCKS[-1]

    def test_truncates_to_width(self):
        s = procmon._sparkline(list(range(100)), width=24)
        assert len(s) == 24
        # most-recent samples kept (last value should be top block)
        assert s[-1] == procmon._SPARK_BLOCKS[-1]

    def test_handles_large_values(self):
        s = procmon._sparkline([1e9, 2e9, 4e9])
        assert len(s) == 3
        assert s[-1] == procmon._SPARK_BLOCKS[-1]

    def test_negative_values_clamped(self):
        s = procmon._sparkline([-5, 10, 20])
        # Negative coerced to 0 → first block at 0/20=0
        assert s[0] == procmon._SPARK_BLOCKS[0]


class TestMetricHistoryCollect:
    def test_history_populates_after_collect(self, monitor):
        proc_a = {"pid": 100, "ppid": 1, "cpu": 5.0, "rss_kb": 1024,
                  "threads": 1, "command": "/bin/x", "cpu_ticks": 0}
        with patch("procmon.get_all_processes", return_value=[proc_a]), \
             patch("procmon.get_net_snapshot", return_value={}), \
             patch("procmon.get_fd_counts", return_value={}), \
             patch("procmon.get_cwds", return_value={}), \
             patch("procmon._get_disk_io", return_value=(0, 0)):
            monitor.collect_data()
            monitor.collect_data()
            monitor.collect_data()
        hist = monitor._metric_history.get(100, {})
        assert "cpu" in hist
        assert len(hist["cpu"]) == 3
        # Last sample retained the live value
        assert hist["cpu"][-1] == 5.0

    def test_history_evicts_dead_pids(self, monitor):
        # Pre-seed history for a PID we'll never see again, then advance time
        # past _metric_history_max_age and run collect_data once.
        monitor._metric_history[999] = {
            "cpu": __import__("collections").deque([1.0]),
        }
        monitor._metric_history_seen[999] = 0.0
        monitor._metric_history_max_age = 1
        proc_b = {"pid": 200, "ppid": 1, "cpu": 1.0, "rss_kb": 1024,
                  "threads": 1, "command": "/bin/y", "cpu_ticks": 0}
        # time.monotonic returns ~now (large) so 999 is way past max_age
        with patch("procmon.get_all_processes", return_value=[proc_b]), \
             patch("procmon.get_net_snapshot", return_value={}), \
             patch("procmon.get_fd_counts", return_value={}), \
             patch("procmon.get_cwds", return_value={}), \
             patch("procmon._get_disk_io", return_value=(0, 0)):
            monitor.collect_data()
        assert 999 not in monitor._metric_history
        assert 200 in monitor._metric_history


class TestTrendSection:
    def test_empty_when_no_history(self, monitor):
        assert monitor._build_trend_section(123) == []
        assert monitor._build_trend_section(None) == []

    def test_renders_section_when_history_present(self, monitor):
        import collections as _c
        monitor._metric_history[100] = {
            "cpu": _c.deque([1.0, 2.0, 3.0]),
            "rss_kb": _c.deque([100.0, 200.0, 300.0]),
            "net_in": _c.deque([0.0, 0.0, 0.0]),
            "net_out": _c.deque([0.0, 0.0, 0.0]),
        }
        lines = monitor._build_trend_section(100)
        joined = "\n".join(lines)
        assert "TREND" in joined
        assert "CPU%" in joined
        assert "MEM" in joined
        assert "peak" in joined

    def test_inspect_report_includes_trend(self, monitor):
        import collections as _c
        monitor._metric_history[42] = {
            "cpu": _c.deque([1.0, 2.0]),
            "rss_kb": _c.deque([100.0, 200.0]),
            "net_in": _c.deque([0.0, 0.0]),
            "net_out": _c.deque([0.0, 0.0]),
        }
        artifacts = {"pid": 42, "exe_path": "/bin/x",
                     "yara_memory": {"success": False, "error": "skipped"},
                     "yara_file": []}
        lines = monitor._format_inspect_report(artifacts)
        joined = "\n".join(lines)
        assert "TREND" in joined


# ── 7. Unified Logging per-process stream ────────────────────────────────


class TestUnifiedLogMode:
    def test_toggle_starts_subprocess_with_correct_argv(self, monitor):
        from tests.conftest import make_proc
        monitor.rows = [make_proc(pid=42, command="/usr/bin/foo")]
        monitor.selected = 0
        fake_proc = MagicMock()
        fake_proc.stdout = MagicMock()
        fake_proc.stdout.readline = MagicMock(return_value=b"")
        fake_proc.stderr = MagicMock()
        fake_proc.stderr.readline = MagicMock(return_value=b"")
        with patch("procmon.subprocess.Popen",
                   return_value=fake_proc) as mock_popen:
            monitor._toggle_unified_log_mode()
        argv = mock_popen.call_args[0][0]
        assert argv[:2] == ["log", "stream"]
        assert "--process" in argv
        assert "42" in argv
        assert "--style" in argv
        assert "compact" in argv
        assert monitor._unified_log_mode is True
        assert monitor._unified_log_pid == 42

    def test_toggle_off_kills_subprocess(self, monitor):
        # Simulate an active stream; second toggle should stop it.
        fake_proc = MagicMock()
        monitor._unified_log_mode = True
        monitor._unified_log_proc = fake_proc
        monitor._toggle_unified_log_mode()
        assert monitor._unified_log_mode is False
        assert fake_proc.terminate.called or fake_proc.kill.called
        assert monitor._unified_log_proc is None

    def test_lines_appended_under_lock(self, monitor):
        monitor._append_unified_log_line("hello")
        monitor._append_unified_log_line("world")
        with monitor._unified_log_lock:
            snap = list(monitor._unified_log_lines)
        assert snap == ["hello", "world"]

    def test_format_view_shows_recent_lines(self, monitor):
        monitor._unified_log_pid = 42
        monitor._append_unified_log_line("2026-04-27 12:00:00 foo[42]: alive")
        out = monitor._format_unified_log_view()
        joined = "\n".join(out)
        assert "log stream" in joined
        assert "alive" in joined

    def test_format_view_loading_message_when_empty(self, monitor):
        monitor._unified_log_pid = 1
        monitor._unified_log_loading = True
        out = monitor._format_unified_log_view()
        joined = "\n".join(out)
        assert "Connecting" in joined

    def test_escape_in_detail_focus_closes_mode(self, monitor):
        fake_proc = MagicMock()
        monitor._detail_focus = True
        monitor._unified_log_mode = True
        monitor._unified_log_proc = fake_proc
        monitor.handle_input(27)
        assert monitor._unified_log_mode is False
        assert fake_proc.terminate.called or fake_proc.kill.called

    def test_main_U_key_triggers_toggle(self, monitor):
        from tests.conftest import make_proc
        monitor.rows = [make_proc(pid=42)]
        monitor.selected = 0
        with patch.object(monitor, "_toggle_unified_log_mode") as tog:
            monitor.handle_input(ord("U"))
        tog.assert_called_once()

    def test_shutdown_kills_unified_log_proc(self, monitor):
        fake_proc = MagicMock()
        monitor._unified_log_proc = fake_proc
        monitor._shutdown()
        assert fake_proc.terminate.called or fake_proc.kill.called

    def test_chat_context_includes_unified_log_tail(self, monitor):
        monitor._unified_log_mode = True
        monitor._unified_log_pid = 42
        monitor._unified_log_cmd = "foo"
        for i in range(5):
            monitor._append_unified_log_line(f"sample-line-{i}")
        label, text = monitor._collect_chat_context()
        assert "Unified Log" in label
        assert "sample-line-4" in text

    def test_subprocess_failure_surfaced_as_error_line(self, monitor):
        from tests.conftest import make_proc
        monitor.rows = [make_proc(pid=42)]
        monitor.selected = 0
        with patch("procmon.subprocess.Popen",
                   side_effect=FileNotFoundError("log not found")):
            monitor._toggle_unified_log_mode()
        snap = list(monitor._unified_log_lines)
        assert any("failed to start" in l for l in snap)


# ── 8. GPU per-process utilization ───────────────────────────────────────


SAMPLE_POWERMETRICS_JSON = b"""{
  "tasks": [
    {"pid": 100, "name": "renderer", "gputime_ms_per_s": 250.0},
    {"pid": 200, "name": "worker", "gputime_ms_per_s": 50.0},
    {"pid": 300, "name": "no_gpu", "gputime_ms_per_s": 0.0}
  ]
}"""


class TestPowerMetricsParse:
    def test_parses_tasks_to_gpu_pct(self, monitor):
        out = monitor._parse_powermetrics_gpu_json(SAMPLE_POWERMETRICS_JSON)
        # 250 ms per 1000 ms → 25.0%
        assert abs(out[100] - 25.0) < 0.01
        assert abs(out[200] - 5.0) < 0.01
        assert out[300] == 0.0

    def test_clamps_to_0_100(self, monitor):
        # Synthetic: a task that somehow says 1500 ms/s
        blob = b'{"tasks": [{"pid": 5, "gputime_ms_per_s": 1500.0}]}'
        out = monitor._parse_powermetrics_gpu_json(blob)
        assert out[5] == 100.0

    def test_empty_input_returns_empty_dict(self, monitor):
        assert monitor._parse_powermetrics_gpu_json(b"") == {}
        assert monitor._parse_powermetrics_gpu_json(None) == {}

    def test_malformed_json_returns_empty_dict(self, monitor):
        assert monitor._parse_powermetrics_gpu_json(b"not json") == {}

    def test_missing_tasks_key_returns_empty_dict(self, monitor):
        assert monitor._parse_powermetrics_gpu_json(b"{}") == {}

    def test_skips_invalid_pid(self, monitor):
        blob = b'{"tasks": [{"pid": "x", "gputime_ms_per_s": 5}]}'
        out = monitor._parse_powermetrics_gpu_json(blob)
        assert out == {}


class TestGpuProbe:
    def test_probe_disabled_when_not_root(self, monitor):
        monitor._gpu_supported_probed = False
        with patch("procmon.os.geteuid", return_value=501):
            monitor._probe_gpu_supported()
        assert monitor._gpu_supported is False
        assert monitor._gpu_status == "needs root"

    def test_probe_disabled_when_powermetrics_missing(self, monitor):
        monitor._gpu_supported_probed = False
        with patch("procmon.os.geteuid", return_value=0), \
             patch("procmon.shutil.which", return_value=None):
            monitor._probe_gpu_supported()
        assert monitor._gpu_supported is False
        assert monitor._gpu_status == "unsupported"

    def test_probe_enabled_when_root_and_powermetrics(self, monitor):
        monitor._gpu_supported_probed = False
        with patch("procmon.os.geteuid", return_value=0), \
             patch("procmon.shutil.which",
                   return_value="/usr/bin/powermetrics"):
            monitor._probe_gpu_supported()
        assert monitor._gpu_supported is True

    def test_probe_is_idempotent(self, monitor):
        monitor._gpu_supported_probed = True
        # Even with root + powermetrics, a second call should be a no-op
        # because the probe flag is already set.
        with patch("procmon.os.geteuid", return_value=501):
            monitor._probe_gpu_supported()
        # _gpu_supported keeps whatever it was before (default False)
        assert monitor._gpu_supported is False


class TestGpuSamplerWorker:
    def test_worker_populates_pending(self, monitor):
        fake_proc = MagicMock()
        fake_proc.communicate.return_value = (
            SAMPLE_POWERMETRICS_JSON, b"")
        with patch("procmon.subprocess.Popen", return_value=fake_proc):
            monitor._gpu_sampler_worker()
        assert monitor._gpu_pending is not None
        assert 100 in monitor._gpu_pending

    def test_worker_handles_timeout(self, monitor):
        fake_proc = MagicMock()
        fake_proc.communicate.side_effect = subprocess.TimeoutExpired(
            cmd="powermetrics", timeout=8)
        with patch("procmon.subprocess.Popen", return_value=fake_proc):
            monitor._gpu_sampler_worker()
        assert monitor._gpu_pending == {}
        fake_proc.kill.assert_called_once()

    def test_worker_disables_supported_on_oserror(self, monitor):
        monitor._gpu_supported = True
        with patch("procmon.subprocess.Popen",
                   side_effect=FileNotFoundError("no powermetrics")):
            monitor._gpu_sampler_worker()
        assert monitor._gpu_supported is False
        assert monitor._gpu_pending == {}

    def test_poll_swaps_pending_into_samples(self, monitor):
        monitor._gpu_pending = {42: 17.5}
        ok = monitor._poll_gpu_result()
        assert ok is True
        assert monitor._gpu_samples[42] == 17.5
        assert monitor._gpu_pending is None

    def test_poll_returns_false_when_no_pending(self, monitor):
        monitor._gpu_pending = None
        assert monitor._poll_gpu_result() is False


class TestGpuMaybeStart:
    def test_skipped_when_unsupported(self, monitor):
        monitor._gpu_supported = False
        with patch("procmon.threading.Thread") as mock_th:
            monitor._maybe_start_gpu_sampler()
        mock_th.assert_not_called()

    def test_skipped_when_already_running(self, monitor):
        monitor._gpu_supported = True
        running = MagicMock()
        running.is_alive.return_value = True
        monitor._gpu_worker = running
        with patch("procmon.threading.Thread") as mock_th:
            monitor._maybe_start_gpu_sampler()
        mock_th.assert_not_called()

    def test_skipped_when_within_interval(self, monitor):
        monitor._gpu_supported = True
        monitor._gpu_worker = None
        monitor._gpu_last_sample_ts = 1e15  # far future
        monitor._gpu_sample_interval = 5.0
        with patch("procmon.threading.Thread") as mock_th:
            monitor._maybe_start_gpu_sampler()
        mock_th.assert_not_called()


class TestGpuChatContext:
    def test_chat_context_includes_gpu_when_present(self, monitor):
        from tests.conftest import make_proc
        r = make_proc(pid=100)
        r["gpu_pct"] = 42.0
        monitor.rows = [r]
        monitor.selected = 0
        label, text = monitor._collect_chat_context()
        assert "gpu" in text.lower()

    def test_chat_context_omits_gpu_when_absent(self, monitor):
        from tests.conftest import make_proc
        r = make_proc(pid=100)
        # gpu_pct not set
        monitor.rows = [r]
        monitor.selected = 0
        label, text = monitor._collect_chat_context()
        # No 'gpu:' line should be present
        assert "  gpu:" not in text


# ── 9. Mach file-port count (IPC enumeration) ────────────────────────────


class TestMachPortCount:
    def test_count_from_proc_pidinfo_byte_total(self):
        # proc_pidinfo returns total bytes that *would* be written —
        # 8 bytes per proc_fileportinfo struct.
        with patch.object(procmon._libproc, "proc_pidinfo",
                          return_value=24):
            assert procmon._get_mach_port_count(123) == 3

    def test_zero_count(self):
        with patch.object(procmon._libproc, "proc_pidinfo",
                          return_value=0):
            assert procmon._get_mach_port_count(123) == 0

    def test_negative_return_means_failure(self):
        with patch.object(procmon._libproc, "proc_pidinfo",
                          return_value=-1):
            assert procmon._get_mach_port_count(123) == -1

    def test_invalid_pid_returns_minus_one(self):
        assert procmon._get_mach_port_count(0) == -1
        assert procmon._get_mach_port_count(-5) == -1

    def test_oserror_returns_minus_one(self):
        with patch.object(procmon._libproc, "proc_pidinfo",
                          side_effect=OSError("boom")):
            assert procmon._get_mach_port_count(123) == -1


class TestMachPortInspectIntegration:
    def test_inspect_toggle_samples_mach_ports(self, monitor):
        from tests.conftest import make_proc
        monitor.rows = [make_proc(pid=42)]
        monitor.selected = 0
        with patch("procmon._get_mach_port_count", return_value=7), \
             patch("procmon._get_proc_path", return_value="/bin/x"), \
             patch.object(monitor, "_start_inspect_fetch"):
            monitor._toggle_inspect_mode()
        assert monitor.rows[0].get("mach_ports") == 7

    def test_inspect_report_shows_mach_port_count(self, monitor):
        artifacts = {"pid": 42, "exe_path": "/bin/x",
                     "yara_memory": {"success": False, "error": "no"},
                     "yara_file": [],
                     "mach_ports": 12}
        lines = monitor._format_inspect_report(artifacts)
        joined = "\n".join(lines)
        assert "IPC: 12 Mach file ports" in joined

    def test_inspect_report_omits_ipc_when_unavailable(self, monitor):
        artifacts = {"pid": 42, "exe_path": "/bin/x",
                     "yara_memory": {"success": False, "error": "no"},
                     "yara_file": [],
                     "mach_ports": -1}
        lines = monitor._format_inspect_report(artifacts)
        joined = "\n".join(lines)
        assert "IPC:" not in joined

    def test_chat_context_includes_mach_port_count(self, monitor):
        from tests.conftest import make_proc
        r = make_proc(pid=100)
        r["mach_ports"] = 5
        monitor.rows = [r]
        monitor.selected = 0
        label, text = monitor._collect_chat_context()
        assert "mach_file_ports: 5" in text

    def test_chat_context_omits_mach_ports_when_minus_one(self, monitor):
        from tests.conftest import make_proc
        r = make_proc(pid=100)
        r["mach_ports"] = -1
        monitor.rows = [r]
        monitor.selected = 0
        label, text = monitor._collect_chat_context()
        assert "mach_file_ports" not in text

    def test_singular_label_for_one_port(self, monitor):
        artifacts = {"pid": 1, "exe_path": "/bin/x",
                     "yara_memory": {"success": False, "error": "no"},
                     "yara_file": [],
                     "mach_ports": 1}
        lines = monitor._format_inspect_report(artifacts)
        joined = "\n".join(lines)
        assert "1 Mach file port " in joined  # singular
