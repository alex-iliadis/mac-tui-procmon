"""Tests for the four new features:
1. Memory-dump indicator on the Inspect report
2. Traffic Inspector (experimental mitmproxy wrapper)
3. LLM executive summary across audits / keyscan / hidden / inspect
4. Events → LLM analysis on stop
"""
import json
import os
import shutil
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

    def test_vt_badge_when_found(self, monitor):
        artifacts = {
            "pid": 1, "exe_path": "/bin/x",
            "yara_memory": {"success": False, "error": "skip"},
            "yara_file": [],
            "virustotal": {"found": True, "malicious": 7, "suspicious": 2},
        }
        lines = monitor._format_inspect_report(artifacts)
        joined = "\n".join(lines[:10])
        assert "[VT] 7 malicious" in joined


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


class TestAuditModeTriggersSummary:
    def test_poll_audit_result_starts_summary(self, monitor):
        monitor._audit_mode = True
        monitor._audit_type = "network"
        monitor._audit_pending = ["line"]
        monitor._audit_findings_structured = [
            {"severity": "HIGH", "message": "x", "action": None}]
        with patch.object(monitor, "_start_llm_summary") as start:
            monitor._poll_audit_result()
        start.assert_called_once()
        scope, title, findings = start.call_args[0]
        assert scope == "audit"
        assert "Network" in title
        assert len(findings) == 1

    def test_toggle_audit_mode_clears_stale_summary(self, monitor):
        monitor._llm_summary["audit"] = ["stale", "summary"]
        monitor._llm_summary_pending["audit"] = ["pending"]
        with patch.object(monitor, "_start_audit"):
            monitor._toggle_audit_mode("network")
        assert monitor._llm_summary["audit"] is None
        assert monitor._llm_summary_pending["audit"] is None


# ── 3. Keyscan summary trigger ───────────────────────────────────────────


class TestKeyscanSummaryTrigger:
    def test_poll_keyscan_starts_summary(self, monitor):
        monitor._keyscan_mode = True
        monitor._keyscan_pending = ["line"]
        monitor._keyscan_findings_structured = [
            {"severity": "HIGH", "message": "x",
             "action": {"type": "delete_tcc"}}]
        monitor._keyscan_line_for_finding = [0]
        with patch.object(monitor, "_start_llm_summary") as start:
            monitor._poll_keyscan_result()
        start.assert_called_once()
        assert start.call_args[0][0] == "keyscan"


# ── 4. Hidden-scan summary trigger ───────────────────────────────────────


class TestHiddenScanSummaryTrigger:
    def test_poll_hidden_starts_summary_with_pseudo_findings(self, monitor):
        monitor._hidden_scan_mode = True
        monitor._hidden_scan_pending = [
            "── PID brute-force ──",
            "  [!] PID 999: /tmp/evil",
            "",
            "  Apple kext not in /Library/Extensions (ignored)",
        ]
        with patch.object(monitor, "_start_llm_summary") as start:
            monitor._poll_hidden_scan_result()
        start.assert_called_once()
        scope, title, findings = start.call_args[0]
        assert scope == "hidden"
        # Non-blank lines are pseudo-findings; severity HIGH for [!] lines
        assert any(f["severity"] == "HIGH" for f in findings)


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
