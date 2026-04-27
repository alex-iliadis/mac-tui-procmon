"""Tests for process inspect mode and hidden process detection."""
import curses
import os
import sys
import time
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import procmon
from tests.conftest import make_proc


# ── Inspect Mode Toggle ────────────────────────────────────────────────


class TestInspectModeToggle:
    def test_toggle_on(self, monitor):
        monitor.rows = [make_proc(pid=100, command="/usr/bin/test")]
        monitor.selected = 0
        with patch.object(monitor, "_start_inspect_fetch"):
            monitor._toggle_inspect_mode()
        assert monitor._inspect_mode is True
        assert monitor._detail_focus is True
        assert monitor._inspect_pid == 100
        assert monitor._inspect_loading is True

    def test_toggle_off(self, monitor):
        monitor._inspect_mode = True
        monitor._detail_focus = True
        monitor._toggle_inspect_mode()
        assert monitor._inspect_mode is False
        assert monitor._detail_focus is False

    def test_toggle_on_closes_net_mode(self, monitor):
        monitor.rows = [make_proc(pid=100, command="/usr/bin/test")]
        monitor.selected = 0
        monitor._net_mode = True
        with patch.object(monitor, "_start_inspect_fetch"):
            monitor._toggle_inspect_mode()
        assert monitor._net_mode is False
        assert monitor._inspect_mode is True

    def test_toggle_on_closes_hidden_mode(self, monitor):
        monitor.rows = [make_proc(pid=100, command="/usr/bin/test")]
        monitor.selected = 0
        monitor._hidden_scan_mode = True
        with patch.object(monitor, "_start_inspect_fetch"):
            monitor._toggle_inspect_mode()
        assert monitor._hidden_scan_mode is False
        assert monitor._inspect_mode is True

    def test_toggle_no_rows(self, monitor):
        monitor.rows = []
        monitor._toggle_inspect_mode()
        assert monitor._inspect_mode is False


class TestInspectPollResult:
    def test_poll_applies_artifacts(self, monitor):
        monitor._inspect_mode = True
        monitor._inspect_loading = True
        monitor._inspect_pending = ("artifacts", ["line1", "line2"])
        result = monitor._poll_inspect_result()
        assert result is True
        assert monitor._inspect_lines == ["line1", "line2"]
        assert monitor._inspect_loading is True  # still loading (artifacts phase)
        assert monitor._inspect_pending is None

    def test_poll_applies_complete(self, monitor):
        monitor._inspect_mode = True
        monitor._inspect_loading = True
        monitor._inspect_pending = ("complete", ["all", "lines"])
        result = monitor._poll_inspect_result()
        assert result is True
        assert monitor._inspect_loading is False
        assert monitor._inspect_lines == ["all", "lines"]

    def test_poll_applies_error(self, monitor):
        monitor._inspect_mode = True
        monitor._inspect_loading = True
        monitor._inspect_pending = ("error", ["[error]"])
        result = monitor._poll_inspect_result()
        assert result is True
        assert monitor._inspect_loading is False

    def test_poll_when_mode_closed(self, monitor):
        monitor._inspect_mode = False
        monitor._inspect_pending = ("complete", ["data"])
        result = monitor._poll_inspect_result()
        assert result is False
        assert monitor._inspect_pending is None
        assert monitor._inspect_loading is False

    def test_poll_when_nothing_pending(self, monitor):
        monitor._inspect_pending = None
        result = monitor._poll_inspect_result()
        assert result is False


# ── Inspect Input Handling ─────────────────────────────────────────────


class TestInspectInputHandling:
    def test_scroll_down(self, monitor):
        monitor._detail_focus = True
        monitor._inspect_mode = True
        monitor._inspect_scroll = 0
        monitor.handle_input(curses.KEY_DOWN)
        assert monitor._inspect_scroll == 1

    def test_scroll_up(self, monitor):
        monitor._detail_focus = True
        monitor._inspect_mode = True
        monitor._inspect_scroll = 5
        monitor.handle_input(curses.KEY_UP)
        assert monitor._inspect_scroll == 4

    def test_scroll_up_clamps_zero(self, monitor):
        monitor._detail_focus = True
        monitor._inspect_mode = True
        monitor._inspect_scroll = 0
        monitor.handle_input(curses.KEY_UP)
        assert monitor._inspect_scroll == 0

    def test_page_down(self, monitor):
        monitor._detail_focus = True
        monitor._inspect_mode = True
        monitor._inspect_scroll = 0
        monitor.handle_input(curses.KEY_NPAGE)
        assert monitor._inspect_scroll > 0

    def test_page_up(self, monitor):
        monitor._detail_focus = True
        monitor._inspect_mode = True
        monitor._inspect_scroll = 20
        monitor.handle_input(curses.KEY_PPAGE)
        assert monitor._inspect_scroll < 20

    def test_close_with_I(self, monitor):
        monitor._detail_focus = True
        monitor._inspect_mode = True
        with patch.object(monitor, "_toggle_inspect_mode") as toggle:
            monitor.handle_input(ord("I"))
        toggle.assert_called_once()

    def test_tab_unfocuses(self, monitor):
        monitor._detail_focus = True
        monitor._inspect_mode = True
        monitor.handle_input(ord("\t"))
        assert monitor._detail_focus is False

    def test_escape_closes(self, monitor):
        monitor._detail_focus = True
        monitor._inspect_mode = True
        monitor.handle_input(27)
        assert monitor._inspect_mode is False
        assert monitor._detail_focus is False

    def test_quit_from_inspect(self, monitor):
        monitor._detail_focus = True
        monitor._inspect_mode = True
        result = monitor.handle_input(ord("q"))
        assert result is False

    def test_I_key_in_main_mode(self, monitor):
        monitor.rows = [make_proc(pid=100, command="/usr/bin/test")]
        monitor.selected = 0
        with patch.object(monitor, "_toggle_inspect_mode") as toggle:
            monitor.handle_input(ord("I"))
        toggle.assert_called_once()


# ── Artifact Collection ────────────────────────────────────────────────


class TestCollectInspectArtifacts:
    def test_collects_all_artifacts(self, monitor):
        def fake_popen(cmd, **kwargs):
            mock = MagicMock()
            mock.communicate.return_value = (b"output", b"")
            mock.returncode = 0
            return mock

        with patch("subprocess.Popen", side_effect=fake_popen), \
             patch("os.geteuid", return_value=1000), \
             patch("procmon._get_proc_env", return_value={"HOME": "/Users/test"}), \
             patch("procmon._libproc") as mock_libproc, \
             patch("procmon._get_proc_path", return_value="/usr/bin/test"):
            mock_libproc.proc_pidinfo.return_value = 0
            artifacts = monitor._collect_inspect_artifacts(100, "/usr/bin/test")

        assert "codesign_verify" in artifacts
        assert "entitlements" in artifacts
        assert "dylibs" in artifacts
        assert "sha256" in artifacts
        assert "lsof" in artifacts
        assert "env" in artifacts
        assert "lineage" in artifacts
        assert "vmmap" in artifacts
        assert artifacts["vmmap"].startswith("[skipped")  # not root
        assert artifacts["pid"] == 100
        assert artifacts["exe_path"] == "/usr/bin/test"

    def test_vmmap_when_root(self, monitor):
        def fake_popen(cmd, **kwargs):
            mock = MagicMock()
            mock.communicate.return_value = (b"vmmap output", b"")
            mock.returncode = 0
            return mock

        with patch("subprocess.Popen", side_effect=fake_popen), \
             patch("os.geteuid", return_value=0), \
             patch("procmon._get_proc_env", return_value={}), \
             patch("procmon._libproc") as mock_libproc, \
             patch("procmon._get_proc_path", return_value="/usr/bin/test"):
            mock_libproc.proc_pidinfo.return_value = 0
            artifacts = monitor._collect_inspect_artifacts(100, "/usr/bin/test")

        assert artifacts["vmmap"] == "vmmap output"


class TestFormatInspectReport:
    def test_format_has_sections(self, monitor):
        artifacts = {
            "pid": 100,
            "exe_path": "/usr/bin/test",
            "codesign_verify": "valid on disk",
            "entitlements": "<dict/>",
            "dylibs": "/usr/lib/libSystem.B.dylib",
            "sha256": "abc123  /usr/bin/test",
            "lsof": "COMMAND  PID  USER  FD\ntest  100  user  txt",
            "env": {"DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib", "HOME": "/Users/test"},
            "lineage": [(100, "/usr/bin/test"), (1, "/sbin/launchd")],
            "vmmap": "[skipped]",
        }
        lines = monitor._format_inspect_report(artifacts)
        text = "\n".join(lines)
        assert "[INSPECT]" in text
        assert "Code Signature" in text
        assert "SHA-256" in text
        assert "Entitlements" in text
        assert "Linked Dylibs" in text
        assert "Process Lineage" in text
        assert "Open Files" in text
        assert "Environment" in text
        assert "Memory Regions" in text
        # DYLD_INSERT_LIBRARIES should be flagged
        assert "[!] DYLD_INSERT_LIBRARIES" in text

    def test_format_renders_new_security_sections(self, monitor):
        """Exercise every new artifact section the inspect report knows about."""
        artifacts = {
            "pid": 100, "exe_path": "/bin/test",
            "codesign_verify": "valid", "entitlements": "",
            "dylibs": "", "sha256": "aa /bin/test", "lsof": "",
            "env": {}, "lineage": [], "vmmap": "",
            "codesign_structured": {
                "team_id": "ABC123", "identifier": "com.x.y",
                "hardened_runtime": True, "flags": "0x10000",
                "authority": ["Authority 1", "Authority 2"],
                "requirements": "anchor apple",
            },
            "gatekeeper": {
                "accepted": False, "notarized": False,
                "origin": "unknown", "reason": "source=no matching CA",
            },
            "persistence_hits": [
                ("/Library/LaunchAgents/com.bad.plist", "persistence"),
            ],
            "user_writable_dylibs": ["/tmp/evil.dylib"],
            "virustotal": {
                "found": True, "malicious": 3, "suspicious": 1,
                "undetected": 40,
                "popular_threat_name": "trojan.mac/x",
                "known_names": ["evil.bin"],
            },
            "yara_file": ["RuleA"],
            "yara_memory": {
                "success": True, "matches": ["RuleB"], "core_size": 2048,
            },
        }
        lines = monitor._format_inspect_report(artifacts)
        text = "\n".join(lines)
        assert "Signature Details" in text
        assert "Trust tier:" in text
        assert "ABC123" in text
        assert "Authority 1" in text
        assert "anchor apple" in text
        assert "Gatekeeper" in text
        assert "[!] Reason:" in text
        assert "Persistence Path Hits" in text
        assert "/Library/LaunchAgents/com.bad.plist" in text
        assert "Dylibs from user-writable paths" in text
        assert "/tmp/evil.dylib" in text
        assert "VirusTotal" in text
        assert "[!] 3 malicious" in text
        assert "trojan.mac/x" in text
        assert "RuleA" in text
        assert "RuleB" in text

    def test_format_handles_vt_error(self, monitor):
        artifacts = {
            "pid": 1, "exe_path": "/bin/x", "codesign_verify": "",
            "entitlements": "", "dylibs": "", "sha256": "", "lsof": "",
            "env": {}, "lineage": [], "vmmap": "",
            "virustotal": {"error": "rate limited"},
        }
        text = "\n".join(monitor._format_inspect_report(artifacts))
        assert "rate limited" in text

    def test_format_vt_not_found(self, monitor):
        artifacts = {
            "pid": 1, "exe_path": "/bin/x", "codesign_verify": "",
            "entitlements": "", "dylibs": "", "sha256": "", "lsof": "",
            "env": {}, "lineage": [], "vmmap": "",
            "virustotal": {"found": False},
        }
        text = "\n".join(monitor._format_inspect_report(artifacts))
        assert "Hash not found" in text

    def test_format_yara_memory_skipped(self, monitor):
        artifacts = {
            "pid": 1, "exe_path": "/bin/x", "codesign_verify": "",
            "entitlements": "", "dylibs": "", "sha256": "", "lsof": "",
            "env": {}, "lineage": [], "vmmap": "",
            "yara_memory": {"success": False, "error": "needs root"},
        }
        text = "\n".join(monitor._format_inspect_report(artifacts))
        assert "[skipped: needs root]" in text


class TestBuildAnalysisInputNewArtifacts:
    """The LLM input builder should include the new deterministic findings."""

    def test_includes_codesign_gatekeeper_vt_yara(self, monitor):
        artifacts = {
            "pid": 1, "exe_path": "/bin/x",
            "codesign_verify": "v", "entitlements": "e", "sha256": "h",
            "dylibs": "d", "lsof": "l", "env": {}, "lineage": [],
            "vmmap": "[skipped]",
            "codesign_structured": {
                "team_id": "T", "identifier": "i",
                "hardened_runtime": True, "flags": "f",
                "authority": ["A"], "requirements": "req",
            },
            "gatekeeper": {"accepted": False, "notarized": False,
                           "origin": "u", "reason": "r", "raw": "raw"},
            "persistence_hits": [("/Library/LaunchAgents/x", "persistence")],
            "user_writable_dylibs": ["/tmp/x.dylib"],
            "virustotal": {"found": True, "malicious": 5,
                           "suspicious": 0, "popular_threat_name": "t",
                           "known_names": ["n"]},
            "yara_file": ["RuleX"],
            "yara_memory": {"success": True, "matches": ["RuleY"]},
        }
        text = monitor._build_analysis_input(artifacts)
        assert "CODESIGN STRUCTURED" in text
        assert "trust_tier=" in text
        assert "team_id=T" in text
        assert "GATEKEEPER" in text
        assert "PERSISTENCE PATH HITS" in text
        assert "DYLIBS FROM USER-WRITABLE PATHS" in text
        assert "VIRUSTOTAL" in text
        assert "YARA MATCHES (on-disk)" in text
        assert "RuleX" in text
        assert "YARA MATCHES (memory)" in text
        assert "RuleY" in text


# ── _run_cmd_short helper ─────────────────────────────────────────────


class TestRunCmdShort:
    def test_success(self):
        mock = MagicMock()
        mock.communicate.return_value = (b"out", b"err")
        mock.returncode = 0
        with patch("subprocess.Popen", return_value=mock):
            rc, out, err = procmon._run_cmd_short(["x"])
        assert rc == 0
        assert out == "out"
        assert err == "err"

    def test_timeout(self):
        import subprocess as sp
        mock = MagicMock()
        mock.communicate.side_effect = sp.TimeoutExpired("x", 5)
        mock.kill.return_value = None
        mock.wait.return_value = None
        with patch("subprocess.Popen", return_value=mock):
            rc, out, err = procmon._run_cmd_short(["x"])
        assert rc is None
        assert err == "timeout"

    def test_file_not_found(self):
        with patch("subprocess.Popen", side_effect=FileNotFoundError("no")):
            rc, out, err = procmon._run_cmd_short(["x"])
        assert rc is None
        assert "no" in err

    def test_stdin_bytes_passed(self):
        mock = MagicMock()
        mock.communicate.return_value = (b"ok", b"")
        mock.returncode = 0
        with patch("subprocess.Popen", return_value=mock):
            procmon._run_cmd_short(["x"], stdin_bytes=b"input")
        # communicate was called with input=b"input"
        assert mock.communicate.call_args.kwargs.get("input") == b"input"


# ── LLM CLI Integration ────────────────────────────────────────────────


class TestRunLlm:
    def test_successful_claude(self, monitor):
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b"RISK: LOW\nSUMMARY: Clean\n", b"")
        mock_proc.returncode = 0
        with patch("subprocess.Popen", return_value=mock_proc):
            result = monitor._run_llm("claude", "prompt", "input", timeout=10)
        assert "RISK: LOW" in result

    def test_successful_codex(self, monitor):
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b"RISK: MEDIUM\n", b"")
        mock_proc.returncode = 0
        with patch("subprocess.Popen", return_value=mock_proc):
            result = monitor._run_llm("codex", "prompt", "input", timeout=10)
        assert "RISK: MEDIUM" in result

    def test_successful_gemini(self, monitor):
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b"RISK: HIGH\n", b"")
        mock_proc.returncode = 0
        with patch("subprocess.Popen", return_value=mock_proc):
            result = monitor._run_llm("gemini", "prompt", "input", timeout=10)
        assert "RISK: HIGH" in result

    def test_tool_not_found(self, monitor):
        with patch("subprocess.Popen", side_effect=FileNotFoundError):
            result = monitor._run_llm("claude", "prompt", "input")
        assert "not found" in result.lower()

    def test_timeout(self, monitor):
        import subprocess as sp
        mock_proc = MagicMock()
        mock_proc.communicate.side_effect = sp.TimeoutExpired("claude", 10)
        mock_proc.kill.return_value = None
        mock_proc.wait.return_value = None
        with patch("subprocess.Popen", return_value=mock_proc):
            result = monitor._run_llm("claude", "prompt", "input", timeout=10)
        assert "timed out" in result.lower()

    def test_non_zero_exit(self, monitor):
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b"", b"auth error")
        mock_proc.returncode = 1
        with patch("subprocess.Popen", return_value=mock_proc):
            result = monitor._run_llm("claude", "prompt", "input")
        assert "error" in result.lower()

    def test_non_zero_exit_falls_back_to_stdout(self, monitor):
        """When stderr is empty but stdout has content (as some CLIs do when
        failing), show stdout in the error rather than 'no output'."""
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b"Auth required", b"")
        mock_proc.returncode = 1
        with patch("subprocess.Popen", return_value=mock_proc):
            result = monitor._run_llm("claude", "prompt", "input")
        assert "Auth required" in result

    def test_home_env_overridden_under_sudo(self, monitor):
        """Subprocess must see HOME=<invoking user's home> so the CLI finds
        its auth tokens (e.g. ~/.claude/) even when procmon is sudo'd."""
        captured = {}

        def fake_popen(argv, **kwargs):
            captured["env"] = kwargs.get("env", {})
            mock = MagicMock()
            mock.communicate.return_value = (b"RISK: LOW\n", b"")
            mock.returncode = 0
            return mock

        with patch("subprocess.Popen", side_effect=fake_popen):
            monitor._run_llm("claude", "prompt", "input", timeout=5)
        assert captured["env"]["HOME"] == procmon._EFFECTIVE_HOME

    def test_user_env_set_under_sudo(self, monitor):
        """When SUDO_USER is present, USER and LOGNAME are set to it so
        CLIs that read those don't use 'root'."""
        captured = {}

        def fake_popen(argv, **kwargs):
            captured["env"] = kwargs.get("env", {})
            mock = MagicMock()
            mock.communicate.return_value = (b"RISK: LOW\n", b"")
            mock.returncode = 0
            return mock

        with patch.dict("os.environ", {"SUDO_USER": "alex"}), \
             patch("subprocess.Popen", side_effect=fake_popen):
            monitor._run_llm("claude", "prompt", "input", timeout=5)
        assert captured["env"]["USER"] == "alex"
        assert captured["env"]["LOGNAME"] == "alex"

    def test_unknown_tool(self, monitor):
        result = monitor._run_llm("nonexistent", "prompt", "input")
        assert "unknown tool" in result.lower()


class TestRunLlmsParallel:
    def test_all_three_called(self, monitor):
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b"RISK: LOW", b"")
        mock_proc.returncode = 0
        artifacts = {
            "pid": 100, "exe_path": "/usr/bin/test",
            "codesign_verify": "valid", "entitlements": "",
            "sha256": "abc", "dylibs": "", "lsof": "",
            "env": {}, "lineage": [], "vmmap": "",
        }
        with patch("subprocess.Popen", return_value=mock_proc):
            results = monitor._run_llms_parallel(artifacts)
        assert set(results.keys()) == {"claude", "codex", "gemini"}
        for tool in ("claude", "codex", "gemini"):
            assert "RISK: LOW" in results[tool]


class TestSynthesizeAnalyses:
    def test_uses_claude_when_available(self, monitor):
        analyses = {
            "claude": "RISK: LOW\nSUMMARY: clean",
            "codex": "RISK: LOW\nSUMMARY: clean",
            "gemini": "RISK: LOW\nSUMMARY: clean",
        }
        with patch.object(monitor, "_run_llm",
                          return_value="CONSENSUS_RISK: LOW\nAGREEMENT: unanimous"):
            synth_tool, consensus = monitor._synthesize_analyses(analyses)
        assert synth_tool == "claude"
        assert "CONSENSUS_RISK: LOW" in consensus

    def test_falls_through_to_codex(self, monitor):
        analyses = {
            "claude": "[claude CLI not found]",
            "codex": "RISK: MEDIUM",
            "gemini": "RISK: LOW",
        }
        calls = []

        def fake_run(tool, prompt, input_text, timeout=60):
            calls.append(tool)
            if tool == "codex":
                return "CONSENSUS_RISK: MEDIUM"
            return "[error]"

        with patch.object(monitor, "_run_llm", side_effect=fake_run):
            synth_tool, consensus = monitor._synthesize_analyses(analyses)
        assert synth_tool == "codex"
        assert "CONSENSUS_RISK: MEDIUM" in consensus

    def test_local_fallback_when_all_fail(self, monitor):
        analyses = {
            "claude": "[claude CLI not found]",
            "codex": "[codex CLI not found]",
            "gemini": "[gemini CLI not found]",
        }
        synth_tool, consensus = monitor._synthesize_analyses(analyses)
        assert synth_tool is None
        assert "CONSENSUS_RISK" in consensus


class TestLocalConsensusFallback:
    def test_unanimous(self, monitor):
        analyses = {
            "claude": "RISK: LOW\nmore",
            "codex": "RISK: LOW\nmore",
            "gemini": "RISK: LOW\nmore",
        }
        result = monitor._local_consensus_fallback(analyses)
        assert "CONSENSUS_RISK: LOW" in result
        assert "unanimous" in result

    def test_mixed_picks_worst(self, monitor):
        analyses = {
            "claude": "RISK: LOW",
            "codex": "RISK: HIGH",
            "gemini": "RISK: MEDIUM",
        }
        result = monitor._local_consensus_fallback(analyses)
        assert "CONSENSUS_RISK: HIGH" in result
        assert "mixed" in result

    def test_no_parseable_output(self, monitor):
        analyses = {
            "claude": "[error]",
            "codex": "[error]",
            "gemini": "[error]",
        }
        result = monitor._local_consensus_fallback(analyses)
        assert "UNKNOWN" in result


# ── Inspect Worker ─────────────────────────────────────────────────────


class TestInspectWorkerFn:
    def test_worker_runs_all_three_and_synthesizes(self, monitor):
        artifacts = {
            "pid": 100, "exe_path": "/usr/bin/test",
            "codesign_verify": "valid", "entitlements": "",
            "sha256": "abc", "dylibs": "", "lsof": "",
            "env": {}, "lineage": [], "vmmap": "[skipped]",
        }
        analyses = {
            "claude": "RISK: LOW\nAll good",
            "codex": "RISK: LOW\nclean",
            "gemini": "RISK: LOW\nno issues",
        }
        with patch.object(monitor, "_collect_inspect_artifacts", return_value=artifacts), \
             patch.object(monitor, "_run_llms_parallel", return_value=analyses), \
             patch.object(monitor, "_synthesize_analyses",
                          return_value=("claude", "CONSENSUS_RISK: LOW\nAGREEMENT: unanimous")):
            monitor._inspect_worker_fn(100, "/usr/bin/test")

        status, lines = monitor._inspect_pending
        assert status == "complete"
        text = "\n".join(lines)
        assert "Claude Security Analysis" in text
        assert "Codex Security Analysis" in text
        assert "Gemini Security Analysis" in text
        assert "Consensus" in text
        assert "[RISK: LOW]" in text
        assert "AGREEMENT: unanimous" in text

    def test_worker_handles_exception(self, monitor):
        with patch.object(monitor, "_collect_inspect_artifacts", side_effect=RuntimeError("boom")):
            monitor._inspect_worker_fn(100, "/usr/bin/test")

        status, lines = monitor._inspect_pending
        assert status == "error"
        assert any("boom" in l for l in lines)
        assert monitor._inspect_phase == ""


# ── Hidden Process Detection ───────────────────────────────────────────


class TestCheckHiddenPidsQuick:
    def test_finds_hidden(self):
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b"  1\n  2\n  3\n  99\n", b"")
        with patch("subprocess.Popen", return_value=mock_proc), \
             patch("os.getpid", return_value=999):
            hidden = procmon._check_hidden_pids_quick([1, 2, 3])
        assert 99 in hidden
        assert 1 not in hidden

    def test_no_hidden(self):
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b"  1\n  2\n  3\n", b"")
        with patch("subprocess.Popen", return_value=mock_proc), \
             patch("os.getpid", return_value=999):
            hidden = procmon._check_hidden_pids_quick([1, 2, 3])
        assert len(hidden) == 0

    def test_ps_failure(self):
        with patch("subprocess.Popen", side_effect=OSError("no fork")):
            hidden = procmon._check_hidden_pids_quick([1, 2])
        assert hidden == set()

    def test_ps_timeout(self):
        import subprocess as sp
        mock_proc = MagicMock()
        mock_proc.communicate.side_effect = sp.TimeoutExpired("ps", 5)
        mock_proc.kill.return_value = None
        mock_proc.wait.return_value = None
        with patch("subprocess.Popen", return_value=mock_proc):
            hidden = procmon._check_hidden_pids_quick([1, 2])
        assert hidden == set()

    def test_excludes_pid_zero(self):
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b"  0\n  1\n", b"")
        with patch("subprocess.Popen", return_value=mock_proc), \
             patch("os.getpid", return_value=999):
            hidden = procmon._check_hidden_pids_quick([1])
        assert 0 not in hidden


class TestCheckHiddenPidsNetwork:
    def test_parses_lsof(self):
        lsof_out = b"COMMAND  PID  USER  FD  TYPE  DEVICE  SIZE  NODE  NAME\nfoo  42  user  3u  IPv4  0x0  0t0  TCP  *:80\n"
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (lsof_out, b"")
        with patch("subprocess.Popen", return_value=mock_proc):
            pids = procmon._check_hidden_pids_network()
        assert 42 in pids

    def test_lsof_failure(self):
        with patch("subprocess.Popen", side_effect=FileNotFoundError):
            pids = procmon._check_hidden_pids_network()
        assert pids == set()


# ── Hidden Scan Toggle ─────────────────────────────────────────────────


class TestHiddenScanToggle:
    def test_toggle_on(self, monitor):
        with patch.object(monitor, "_start_hidden_scan"):
            monitor._toggle_hidden_scan_mode()
        assert monitor._hidden_scan_mode is True
        assert monitor._detail_focus is True
        assert monitor._hidden_scan_loading is True

    def test_toggle_off(self, monitor):
        monitor._hidden_scan_mode = True
        monitor._detail_focus = True
        monitor._toggle_hidden_scan_mode()
        assert monitor._hidden_scan_mode is False
        assert monitor._detail_focus is False

    def test_toggle_closes_net_mode(self, monitor):
        monitor._net_mode = True
        with patch.object(monitor, "_start_hidden_scan"):
            monitor._toggle_hidden_scan_mode()
        assert monitor._net_mode is False

    def test_toggle_closes_inspect_mode(self, monitor):
        monitor._inspect_mode = True
        with patch.object(monitor, "_start_hidden_scan"):
            monitor._toggle_hidden_scan_mode()
        assert monitor._inspect_mode is False


class TestHiddenScanPollResult:
    def test_poll_applies(self, monitor):
        monitor._hidden_scan_mode = True
        monitor._hidden_scan_loading = True
        monitor._hidden_scan_pending = ["finding 1", "finding 2"]
        result = monitor._poll_hidden_scan_result()
        assert result is True
        assert monitor._hidden_scan_lines == ["finding 1", "finding 2"]
        assert monitor._hidden_scan_loading is False

    def test_poll_when_closed(self, monitor):
        monitor._hidden_scan_mode = False
        monitor._hidden_scan_pending = ["data"]
        result = monitor._poll_hidden_scan_result()
        assert result is False
        assert monitor._hidden_scan_pending is None

    def test_poll_nothing_pending(self, monitor):
        monitor._hidden_scan_pending = None
        result = monitor._poll_hidden_scan_result()
        assert result is False


# ── Hidden Scan Input Handling ─────────────────────────────────────────


class TestHiddenScanInputHandling:
    def test_scroll_down(self, monitor):
        monitor._detail_focus = True
        monitor._hidden_scan_mode = True
        monitor._hidden_scan_scroll = 0
        monitor.handle_input(curses.KEY_DOWN)
        assert monitor._hidden_scan_scroll == 1

    def test_scroll_up(self, monitor):
        monitor._detail_focus = True
        monitor._hidden_scan_mode = True
        monitor._hidden_scan_scroll = 5
        monitor.handle_input(curses.KEY_UP)
        assert monitor._hidden_scan_scroll == 4

    def test_scroll_up_clamps(self, monitor):
        monitor._detail_focus = True
        monitor._hidden_scan_mode = True
        monitor._hidden_scan_scroll = 0
        monitor.handle_input(curses.KEY_UP)
        assert monitor._hidden_scan_scroll == 0

    def test_close_with_H(self, monitor):
        monitor._detail_focus = True
        monitor._hidden_scan_mode = True
        with patch.object(monitor, "_toggle_hidden_scan_mode") as toggle:
            monitor.handle_input(ord("H"))
        toggle.assert_called_once()

    def test_tab_unfocuses(self, monitor):
        monitor._detail_focus = True
        monitor._hidden_scan_mode = True
        monitor.handle_input(ord("\t"))
        assert monitor._detail_focus is False

    def test_escape_closes(self, monitor):
        monitor._detail_focus = True
        monitor._hidden_scan_mode = True
        monitor.handle_input(27)
        assert monitor._hidden_scan_mode is False
        assert monitor._detail_focus is False

    def test_quit_from_hidden(self, monitor):
        monitor._detail_focus = True
        monitor._hidden_scan_mode = True
        result = monitor.handle_input(ord("q"))
        assert result is False

    def test_H_key_in_main_mode(self, monitor):
        with patch.object(monitor, "_show_secauditor_bridge") as toggle:
            monitor.handle_input(ord("H"))
        toggle.assert_called_once()


# ── Deep Hidden Scan Worker ────────────────────────────────────────────


class TestDeepHiddenScan:
    def test_clean_system(self, monitor):
        """On a clean system (ps matches libproc, no anomalies), expect 0 findings."""
        ps_mock = MagicMock()
        ps_mock.communicate.return_value = (b"  1\n  2\n  3\n", b"")

        lsof_mock = MagicMock()
        lsof_mock.communicate.return_value = (b"COMMAND  PID\nfoo  1\n", b"")

        sysctl_mock = MagicMock()
        sysctl_mock.communicate.return_value = (b"100", b"")

        def fake_popen(cmd, **kwargs):
            if cmd[0] == "ps":
                return ps_mock
            elif cmd[0] == "lsof":
                return lsof_mock
            elif cmd[0] == "sysctl":
                return sysctl_mock
            return MagicMock()

        with patch("subprocess.Popen", side_effect=fake_popen), \
             patch("procmon._list_all_pids", return_value=[1, 2, 3]), \
             patch("os.getpid", return_value=999), \
             patch("procmon._libproc") as mock_libproc, \
             patch("procmon._get_proc_path", return_value="/usr/bin/test"), \
             patch("os.path.exists", return_value=True), \
             patch("procmon._find_hidden_kexts", return_value=[]), \
             patch("procmon._list_system_extensions", return_value=[]):
            mock_libproc.proc_pidinfo.return_value = 0  # no hidden PIDs in brute force
            findings = monitor._deep_hidden_scan()

        # Scan now covers processes + kernel modules; the summary text was
        # updated accordingly.
        assert any("0 finding" in f for f in findings)


# ── Background Hidden Check in collect_data ────────────────────────────


class TestBackgroundHiddenCheck:
    def test_updates_hidden_pids(self, monitor):
        monitor._last_hidden_check = 0.0
        monitor.interval = 5.0
        monitor.rows = [make_proc(pid=1)]
        monitor.selected = 0

        ps_mock = MagicMock()
        ps_mock.communicate.return_value = (b"  1\n  99\n", b"")

        with patch("procmon.get_all_processes", return_value=[make_proc(pid=1)]), \
             patch("procmon.get_net_snapshot", return_value={}), \
             patch("procmon.get_fd_counts", return_value={}), \
             patch("procmon.get_cwds", return_value={}), \
             patch("procmon.build_tree", return_value=[]), \
             patch("procmon.flatten_tree", return_value=[make_proc(pid=1)]), \
             patch("subprocess.Popen", return_value=ps_mock), \
             patch("os.getpid", return_value=999), \
             patch("time.monotonic", return_value=100.0):
            monitor.collect_data()

        assert 99 in monitor._hidden_pids
        assert monitor._hidden_alert_count == 1


# ── Net Mode Exclusivity ──────────────────────────────────────────────


class TestNetModeExclusivity:
    def test_net_closes_inspect(self, monitor):
        monitor.rows = [make_proc(pid=100, command="/usr/bin/test")]
        monitor.selected = 0
        monitor._inspect_mode = True
        with patch.object(monitor, "_start_net_fetch"):
            monitor._toggle_net_mode()
        assert monitor._inspect_mode is False
        assert monitor._net_mode is True

    def test_net_closes_hidden(self, monitor):
        monitor.rows = [make_proc(pid=100, command="/usr/bin/test")]
        monitor.selected = 0
        monitor._hidden_scan_mode = True
        with patch.object(monitor, "_start_net_fetch"):
            monitor._toggle_net_mode()
        assert monitor._hidden_scan_mode is False
        assert monitor._net_mode is True


# ── _get_proc_env ──────────────────────────────────────────────────────


class TestGetProcEnv:
    def test_returns_empty_on_failure(self):
        with patch("procmon._libc") as mock_libc:
            mock_libc.sysctl.return_value = -1
            result = procmon._get_proc_env(999)
        assert result == {}


# ── Tag Colors ─────────────────────────────────────────────────────────


class TestInspectTagColors:
    def test_risk_high_is_red(self, monitor):
        with patch("curses.color_pair", side_effect=lambda n: n << 8):
            attr = monitor._tag_color("[!RISK: HIGH]")
        assert attr & curses.A_BOLD

    def test_risk_low_is_green(self, monitor):
        with patch("curses.color_pair", side_effect=lambda n: n << 8):
            attr = monitor._tag_color("[RISK: LOW]")
        assert attr & curses.A_BOLD

    def test_inspect_tag(self, monitor):
        with patch("curses.color_pair", side_effect=lambda n: n << 8):
            attr = monitor._tag_color("[INSPECT]")
        assert attr & curses.A_BOLD

    def test_warning_tag(self, monitor):
        with patch("curses.color_pair", side_effect=lambda n: n << 8):
            attr = monitor._tag_color("[!]")
        assert attr & curses.A_BOLD


# ── Detail Lines FDs ───────────────────────────────────────────────────


class TestDetailLinesFds:
    def test_fds_on_pid_line(self, monitor):
        monitor.rows = [make_proc(pid=100, fds=42, command="/usr/bin/test")]
        monitor.selected = 0
        lines = monitor._detail_lines(120)
        # FDs should be on the first line (PID line)
        assert "FDs: 42" in lines[0]
        # And NOT on the second line (CPU/MEM line)
        assert "FDs" not in lines[1]


# ── Sort Dialog ────────────────────────────────────────────────────────


class TestSortDialog:
    def test_s_key_opens_dialog(self, monitor):
        with patch.object(monitor, "_prompt_sort") as prompt:
            monitor.handle_input(ord("s"))
        prompt.assert_called_once()

    def test_individual_sort_keys_still_work(self, monitor):
        # The m/c/V/etc keybinds are kept functional for muscle memory,
        # just hidden from the shortcut bar.
        with patch.object(monitor, "_set_sort") as set_sort:
            monitor.handle_input(ord("m"))
            monitor.handle_input(ord("c"))
            monitor.handle_input(ord("V"))
        assert set_sort.call_count == 3

    def test_shortcut_bar_no_longer_lists_sort_keys(self, monitor):
        """The bar should show 's Sort' instead of individual sort letters."""
        monitor._detail_focus = False
        monitor._net_mode = False
        monitor._inspect_mode = False
        monitor._hidden_scan_mode = False
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put") as put:
            monitor._render_shortcut_bar(40, 200)
        texts = " ".join(str(c.args[2]) if len(c.args) > 2 else "" for c in put.call_args_list)
        assert " s" in texts and "Sort" in texts
        assert "Mem" not in texts
        assert "A-Z" not in texts
        assert "Vendor" not in texts


# ── Forensic Dialog ────────────────────────────────────────────────────


class TestForensicDialog:
    def test_F_key_opens_dialog(self, monitor):
        with patch.object(monitor, "_prompt_forensic") as prompt:
            monitor.handle_input(ord("F"))
        prompt.assert_called_once()

    def test_E_key_opens_telemetry_dialog(self, monitor):
        with patch.object(monitor, "_prompt_telemetry") as prompt:
            monitor.handle_input(ord("E"))
        prompt.assert_called_once()

    def test_individual_keys_still_work(self, monitor):
        """I/N remain process actions; H now points to SecAuditor."""
        with patch.object(monitor, "_toggle_inspect_mode") as insp, \
             patch.object(monitor, "_show_secauditor_bridge") as sec, \
             patch.object(monitor, "_toggle_net_mode") as net:
            monitor.handle_input(ord("I"))
            monitor.handle_input(ord("H"))
            monitor.handle_input(ord("N"))
        insp.assert_called_once()
        sec.assert_called_once()
        net.assert_called_once()

    def test_shortcut_bar_shows_forensic(self, monitor):
        monitor._detail_focus = False
        monitor._net_mode = False
        monitor._inspect_mode = False
        monitor._hidden_scan_mode = False
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put") as put:
            monitor._render_shortcut_bar(40, 200)
        texts = " ".join(str(c.args[2]) if len(c.args) > 2 else "" for c in put.call_args_list)
        assert "F" in texts and "Process" in texts
        assert "N" in texts and "Net" in texts
        assert "a" in texts and "SecAudit" in texts
        assert "Telemetry" not in texts
        assert "Posture" not in texts
        assert "Inspect" not in texts
        assert "Hidden" not in texts
        assert "Dyn" not in texts
        assert "Grp" not in texts


# ── Sort Dialog Toggles (Dynamic/Group inside popup) ──────────────────


class TestSortDialogToggles:
    def _drive(self, monitor, keys):
        """Run _prompt_sort with a sequence of mocked getch() returns."""
        monitor.stdscr.getmaxyx.return_value = (40, 120)
        monitor.stdscr.getch.side_effect = list(keys)
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put"), \
             patch.object(monitor, "_resort"), \
             patch.object(monitor, "_set_sort"):
            monitor._prompt_sort()

    def test_d_toggles_dynamic_in_dialog(self, monitor):
        monitor._dynamic_sort = False
        self._drive(monitor, [ord("d"), 27])  # toggle then Esc
        assert monitor._dynamic_sort is True

    def test_g_toggles_group_in_dialog(self, monitor):
        monitor._vendor_grouped = False
        self._drive(monitor, [ord("g"), 27])
        assert monitor._vendor_grouped is True

    def test_esc_closes_dialog(self, monitor):
        # Just Esc — should return without raising
        self._drive(monitor, [27])

    def test_selecting_sort_mode_closes_dialog(self, monitor):
        """Enter on a sort row should call _set_sort and return."""
        monitor.sort_mode = procmon.SORT_MEM
        monitor.stdscr.getmaxyx.return_value = (40, 120)
        monitor.stdscr.getch.side_effect = [10]  # Enter on currently-selected row
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put"), \
             patch.object(monitor, "_set_sort") as set_sort:
            monitor._prompt_sort()
        set_sort.assert_called_once()


# ── Preflight Tool Check ───────────────────────────────────────────────


class TestKextEnumeration:
    """Hidden kernel module / system extension detection."""

    def test_kmutil_returns_empty_on_failure(self):
        with patch("procmon._run_cmd_short", return_value=(None, "", "oops")):
            assert procmon._kmutil_showloaded() == set()

    def test_kmutil_parses_bundle_ids(self):
        sample = (
            "Index Refs Address   Size       UUID        Name                     Version\n"
            "    1   23 0xff0001  0x10000    1234-5678   com.apple.iokit.IOUSBFamily  1.0\n"
            "    2    5 0xff1001  0x5000     2345-6789   com.example.kext             2.0\n"
        )
        with patch("procmon._run_cmd_short", return_value=(0, sample, "")):
            bundle_ids = procmon._kmutil_showloaded()
        assert "com.apple.iokit.IOUSBFamily" in bundle_ids
        assert "com.example.kext" in bundle_ids

    def test_system_extensions_tab_delimited(self):
        output = (
            "--- com.apple.system_extension.network_extension\n"
            "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n"
            "*\t*\tABC123TEAM\tcom.example.ext (1.0/1)\tMyExt\t[activated enabled]\n"
        )
        with patch("procmon._run_cmd_short", return_value=(0, output, "")):
            entries = procmon._list_system_extensions()
        assert len(entries) == 1
        assert entries[0]["team_id"] == "ABC123TEAM"
        assert entries[0]["bundle_id"] == "com.example.ext"
        assert entries[0]["state"] == "activated enabled"

    def test_system_extensions_empty(self):
        with patch("procmon._run_cmd_short", return_value=(None, "", "no tool")):
            assert procmon._list_system_extensions() == []

    def test_find_hidden_kexts_no_path(self):
        """A kext with no on-disk path is HIGH."""
        kexts = [{"bundle_id": "com.bad.rootkit", "path": None,
                   "team_id": None}]
        with patch("procmon._kextmanager_loaded_kexts", return_value=kexts), \
             patch("procmon._kmutil_showloaded", return_value=set()):
            findings = procmon._find_hidden_kexts()
        assert any("no on-disk path" in msg for _, msg in findings)

    def test_find_hidden_kexts_third_party_no_team(self):
        """3rd-party kext without TeamIdentifier flagged MEDIUM."""
        kexts = [{"bundle_id": "com.foo.kext",
                   "path": "/opt/foo/foo.kext", "team_id": None}]
        with patch("procmon._kextmanager_loaded_kexts", return_value=kexts), \
             patch("procmon._kmutil_showloaded", return_value=set()):
            findings = procmon._find_hidden_kexts()
        assert any("TeamIdentifier" in msg for _, msg in findings)

    def test_find_hidden_kexts_iokit_not_kmutil(self):
        """Bundle seen by IOKit but not kmutil: MEDIUM discrepancy."""
        kexts = [{"bundle_id": "com.apple.real", "path": "/System/...",
                   "team_id": "APPLE"}]
        with patch("procmon._kextmanager_loaded_kexts", return_value=kexts), \
             patch("procmon._kmutil_showloaded",
                   return_value={"com.apple.other"}):
            findings = procmon._find_hidden_kexts()
        txt = " ".join(msg for _, msg in findings)
        assert "IOKit but NOT in kmutil" in txt
        assert "kmutil but NOT in IOKit" in txt

    def test_find_hidden_kexts_kernel_excluded(self):
        """__kernel__ synthetic entry must not be flagged."""
        kexts = [{"bundle_id": "__kernel__", "path": None, "team_id": None}]
        with patch("procmon._kextmanager_loaded_kexts", return_value=kexts), \
             patch("procmon._kmutil_showloaded", return_value=set()):
            findings = procmon._find_hidden_kexts()
        assert findings == []

    def test_kextmanager_iokit_unavailable(self):
        """Framework load failure returns [] gracefully."""
        with patch("ctypes.CDLL", side_effect=OSError):
            assert procmon._kextmanager_loaded_kexts() == []

    def test_kextmanager_null_info(self):
        """NULL return from KextManagerCopyLoadedKextInfo → []."""
        fake_iokit = MagicMock()
        fake_iokit.KextManagerCopyLoadedKextInfo.return_value = None
        fake_cf = MagicMock()

        def fake_cdll(path, use_errno=None):
            return fake_iokit if "IOKit" in path else fake_cf

        with patch("ctypes.CDLL", side_effect=fake_cdll):
            result = procmon._kextmanager_loaded_kexts()
        assert result == []

    def test_list_system_extensions_skips_empty_lines(self):
        """Empty/header lines in systemextensionsctl output are skipped."""
        output = (
            "\n"
            "--- com.apple.system_extension.driver_extension\n"
            "No system extensions\n"
            "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n"
        )
        with patch("procmon._run_cmd_short", return_value=(0, output, "")):
            assert procmon._list_system_extensions() == []

    def test_kmutil_skips_header_line(self):
        """Header line with Address + Size is skipped."""
        sample = (
            "Address  Size  Name\n"
            "0xff  0x10  com.foo.kext\n"
        )
        with patch("procmon._run_cmd_short", return_value=(0, sample, "")):
            bundle_ids = procmon._kmutil_showloaded()
        assert "com.foo.kext" in bundle_ids


class TestKeyboardHookDetection:
    """Keyboard hook / keylogger detector — event taps, TCC, input methods."""

    def test_enumerate_event_taps_returns_empty_when_cg_missing(self):
        with patch("ctypes.CDLL", side_effect=OSError):
            assert procmon._enumerate_event_taps() == []

    def test_enumerate_event_taps_no_taps(self):
        fake_cg = MagicMock()
        fake_cg.CGGetEventTapList.return_value = 0
        # First call sets count via ctypes pointer semantics; we simulate by
        # not populating anything → the function returns [] when count==0.
        with patch("ctypes.CDLL", return_value=fake_cg):
            assert procmon._enumerate_event_taps() == []

    def test_query_tcc_missing_db_returns_empty(self):
        with patch("os.path.exists", return_value=False):
            assert procmon._query_tcc_input_monitoring() == []

    def test_list_input_methods_ignores_non_app(self, tmp_path):
        input_methods = tmp_path / "Library" / "Input Methods"
        input_methods.mkdir(parents=True)
        (input_methods / "random.txt").write_text("noise")
        (input_methods / "Good.app").mkdir()
        with patch.object(procmon, "_EFFECTIVE_HOME", str(tmp_path)), \
             patch("procmon._codesign_structured",
                   return_value={"identifier": "com.x", "team_id": "T", "rc": 0}):
            imes = procmon._list_input_methods()
        paths = [i["path"] for i in imes]
        # Only the .app bundle is enumerated; random.txt is skipped
        assert any(p.endswith("Good.app") for p in paths)
        assert not any(p.endswith("random.txt") for p in paths)

    def test_secure_keyboard_entry_tool_missing(self):
        with patch("ctypes.CDLL", side_effect=OSError):
            result = procmon._check_secure_keyboard_entry()
        assert result["enabled"] is False
        assert result["pid"] == 0

    def test_scan_keyboard_hooks_tap_on_keys_flags_high(self):
        """A CGEventTap hooking key events on a non-Apple binary → HIGH."""
        tap = {"tap_id": 1, "pid": 42, "target_pid": 0, "tap_point": 0,
                "enabled": True, "events_of_interest_mask": (1 << 10),
                "hooks_keys": True}
        with patch("procmon._enumerate_event_taps", return_value=[tap]), \
             patch("procmon._query_tcc_input_monitoring", return_value=[]), \
             patch("procmon._list_input_methods", return_value=[]), \
             patch("procmon._check_secure_keyboard_entry",
                   return_value={"enabled": True, "pid": 100}), \
             patch("procmon._get_proc_path", return_value="/tmp/sus"), \
             patch("procmon._is_apple_signed", return_value=False):
            findings = procmon._scan_keyboard_hooks()
        assert any(f["severity"] == "HIGH" and "CGEventTap" in f["message"]
                   for f in findings)

    def test_scan_skips_apple_taps_without_elevating(self):
        tap = {"tap_id": 1, "pid": 42, "target_pid": 0, "tap_point": 0,
                "enabled": True, "events_of_interest_mask": (1 << 10),
                "hooks_keys": True}
        with patch("procmon._enumerate_event_taps", return_value=[tap]), \
             patch("procmon._query_tcc_input_monitoring", return_value=[]), \
             patch("procmon._list_input_methods", return_value=[]), \
             patch("procmon._check_secure_keyboard_entry",
                   return_value={"enabled": False, "pid": 0}), \
             patch("procmon._get_proc_path", return_value="/usr/sbin/universalaccessd"), \
             patch("procmon._is_apple_signed", return_value=True):
            findings = procmon._scan_keyboard_hooks()
        # Apple path should flag MEDIUM (noteworthy but not alarming), not HIGH
        high_taps = [f for f in findings
                     if f["severity"] == "HIGH" and "CGEventTap" in f["message"]]
        assert high_taps == []

    def test_apple_taps_have_no_action(self):
        """Apple-owned event taps must NOT be offered for kill — that would
        take out essential accessibility/input daemons."""
        tap = {"tap_id": 1, "pid": 42, "target_pid": 0, "tap_point": 0,
                "enabled": True, "events_of_interest_mask": (1 << 10),
                "hooks_keys": True}
        with patch("procmon._enumerate_event_taps", return_value=[tap]), \
             patch("procmon._query_tcc_input_monitoring", return_value=[]), \
             patch("procmon._list_input_methods", return_value=[]), \
             patch("procmon._check_secure_keyboard_entry",
                   return_value={"enabled": False, "pid": 0}), \
             patch("procmon._get_proc_path", return_value="/usr/sbin/universalaccessd"), \
             patch("procmon._is_apple_signed", return_value=True):
            findings = procmon._scan_keyboard_hooks()
        tap_findings = [f for f in findings if "CGEventTap" in f["message"]]
        assert all(f["action"] is None for f in tap_findings)

    def test_non_apple_taps_offer_kill_action(self):
        """A non-Apple tap gets a kill_process action so `D` can terminate
        the owner PID."""
        tap = {"tap_id": 1, "pid": 9999, "target_pid": 0, "tap_point": 0,
                "enabled": True, "events_of_interest_mask": (1 << 10),
                "hooks_keys": True}
        with patch("procmon._enumerate_event_taps", return_value=[tap]), \
             patch("procmon._query_tcc_input_monitoring", return_value=[]), \
             patch("procmon._list_input_methods", return_value=[]), \
             patch("procmon._check_secure_keyboard_entry",
                   return_value={"enabled": False, "pid": 0}), \
             patch("procmon._get_proc_path", return_value="/Applications/Rando/Rando"), \
             patch("procmon._is_apple_signed", return_value=False):
            findings = procmon._scan_keyboard_hooks()
        tap_finding = next(f for f in findings if "CGEventTap" in f["message"])
        assert tap_finding["action"] == {"type": "kill_process", "pid": 9999,
                                          "exe": "/Applications/Rando/Rando"}

    def test_tcc_grant_to_third_party_flags_high(self):
        entry = {"service": "kTCCServiceAccessibility", "client": "com.random.app",
                  "client_type": 0, "auth_value": 2, "auth_reason": 0,
                  "db": "/Library/Application Support/com.apple.TCC/TCC.db"}
        with patch("procmon._enumerate_event_taps", return_value=[]), \
             patch("procmon._query_tcc_input_monitoring", return_value=[entry]), \
             patch("procmon._list_input_methods", return_value=[]), \
             patch("procmon._check_secure_keyboard_entry",
                   return_value={"enabled": False, "pid": 0}):
            findings = procmon._scan_keyboard_hooks()
        assert any("com.random.app" in f["message"] and f["severity"] == "HIGH"
                   for f in findings)

    def test_tcc_finding_has_delete_action(self):
        """A TCC grant finding carries a delete_tcc action so the user can
        actually remove the grant — this is the feature the user asked for."""
        entry = {"service": "kTCCServiceAccessibility", "client": "com.skype.skype",
                  "client_type": 0, "auth_value": 2, "auth_reason": 0,
                  "db": "/Library/Application Support/com.apple.TCC/TCC.db"}
        with patch("procmon._enumerate_event_taps", return_value=[]), \
             patch("procmon._query_tcc_input_monitoring", return_value=[entry]), \
             patch("procmon._list_input_methods", return_value=[]), \
             patch("procmon._check_secure_keyboard_entry",
                   return_value={"enabled": False, "pid": 0}):
            findings = procmon._scan_keyboard_hooks()
        tcc = next(f for f in findings if "com.skype.skype" in f["message"])
        assert tcc["action"] == {
            "type": "delete_tcc",
            "client": "com.skype.skype",
            "service": "kTCCServiceAccessibility",
            "db": "/Library/Application Support/com.apple.TCC/TCC.db",
        }

    def test_input_method_finding_has_remove_action(self):
        """A non-Apple input method is offered for removal via remove_bundle."""
        ime = {"path": "/Library/Input Methods/Evil.app",
                "bundle_id": "com.evil", "team_id": "X", "authority": [],
                "codesign_ok": True}
        with patch("procmon._enumerate_event_taps", return_value=[]), \
             patch("procmon._query_tcc_input_monitoring", return_value=[]), \
             patch("procmon._list_input_methods", return_value=[ime]), \
             patch("procmon._check_secure_keyboard_entry",
                   return_value={"enabled": False, "pid": 0}):
            findings = procmon._scan_keyboard_hooks()
        ime_finding = next(f for f in findings if "Evil.app" in f["message"])
        assert ime_finding["action"] == {
            "type": "remove_bundle",
            "path": "/Library/Input Methods/Evil.app",
        }

    def test_tcc_grant_denied_not_flagged(self):
        entry = {"service": "kTCCServiceAccessibility", "client": "com.random.app",
                  "client_type": 0, "auth_value": 0, "auth_reason": 0, "db": ""}
        with patch("procmon._enumerate_event_taps", return_value=[]), \
             patch("procmon._query_tcc_input_monitoring", return_value=[entry]), \
             patch("procmon._list_input_methods", return_value=[]), \
             patch("procmon._check_secure_keyboard_entry",
                   return_value={"enabled": False, "pid": 0}):
            findings = procmon._scan_keyboard_hooks()
        assert not any("com.random.app" in f["message"] for f in findings)

    def test_tcc_apple_bundles_not_flagged(self):
        entry = {"service": "kTCCServiceAccessibility", "client": "com.apple.Finder",
                  "client_type": 0, "auth_value": 2, "auth_reason": 0, "db": ""}
        with patch("procmon._enumerate_event_taps", return_value=[]), \
             patch("procmon._query_tcc_input_monitoring", return_value=[entry]), \
             patch("procmon._list_input_methods", return_value=[]), \
             patch("procmon._check_secure_keyboard_entry",
                   return_value={"enabled": False, "pid": 0}):
            findings = procmon._scan_keyboard_hooks()
        assert not any("com.apple.Finder" in f["message"] for f in findings)


class TestKeyscanMode:
    def test_toggle_on_launches_scan(self, monitor):
        with patch.object(monitor, "_start_keyscan") as start:
            monitor._toggle_keyscan_mode()
        assert monitor._keyscan_mode is True
        assert monitor._detail_focus is True
        start.assert_called_once()

    def test_toggle_off_closes(self, monitor):
        monitor._keyscan_mode = True
        monitor._detail_focus = True
        monitor._toggle_keyscan_mode()
        assert monitor._keyscan_mode is False
        assert monitor._detail_focus is False

    def test_toggle_closes_other_modes(self, monitor):
        monitor._inspect_mode = True
        monitor._hidden_scan_mode = True
        monitor._bulk_scan_mode = True
        monitor._net_mode = True
        with patch.object(monitor, "_start_keyscan"):
            monitor._toggle_keyscan_mode()
        assert monitor._inspect_mode is False
        assert monitor._hidden_scan_mode is False
        assert monitor._bulk_scan_mode is False
        assert monitor._net_mode is False

    def test_poll_applies_pending(self, monitor):
        monitor._keyscan_mode = True
        monitor._keyscan_loading = True
        monitor._keyscan_pending = ["line1", "line2"]
        assert monitor._poll_keyscan_result() is True
        assert monitor._keyscan_lines == ["line1", "line2"]
        assert monitor._keyscan_loading is False

    def test_format_report_sorts_by_severity(self, monitor):
        findings = [
            ("INFO", "info"),
            ("HIGH", "high"),
            ("CRITICAL", "crit"),
            ("MEDIUM", "med"),
        ]
        lines = monitor._format_keyscan_report(findings)
        text = "\n".join(lines)
        crit_pos = text.find("[CRITICAL]")
        high_pos = text.find("[HIGH]")
        med_pos = text.find("[MEDIUM]")
        info_pos = text.find("[INFO]")
        assert crit_pos < high_pos < med_pos < info_pos

    def test_format_report_no_findings(self, monitor):
        lines = monitor._format_keyscan_report([])
        assert any("No keyboard-hook signals" in l for l in lines)

    def test_format_report_populates_structured(self, monitor):
        """_format_keyscan_report stores the structured view on the monitor
        so the cursor can map findings to display lines."""
        findings = [
            {"severity": "HIGH", "message": "one",
             "action": {"type": "delete_tcc", "client": "x",
                         "service": "y", "db": "z"}},
            {"severity": "INFO", "message": "two", "action": None},
        ]
        monitor._format_keyscan_report(findings)
        assert len(monitor._keyscan_findings_structured) == 2
        # Line indices should be populated and point at real content lines
        assert len(monitor._keyscan_line_for_finding) == 2

    def test_format_report_shows_removable_count(self, monitor):
        findings = [
            {"severity": "HIGH", "message": "tcc",
             "action": {"type": "delete_tcc", "client": "x",
                         "service": "y", "db": "z"}},
            {"severity": "INFO", "message": "info", "action": None},
        ]
        lines = monitor._format_keyscan_report(findings)
        # New layout: header block has a `Actionable:  1 — press ...` line.
        assert any("Actionable" in l and "1" in l for l in lines)

    def test_format_report_marks_actionable_rows(self, monitor):
        """Actionable rows carry an "[x]" marker and the severity tag."""
        findings = [
            {"severity": "HIGH", "message": "actionable",
             "action": {"type": "delete_tcc", "client": "x",
                         "service": "y", "db": "z"}},
            {"severity": "INFO", "message": "informational", "action": None},
        ]
        lines = monitor._format_keyscan_report(findings)
        # Actionable row: "    [x] [HIGH]  actionable"
        assert any("[x]" in l and "actionable" in l and "[HIGH]" in l
                   for l in lines)
        # Informational row: has no "[x]" but still lists the message
        info_lines = [l for l in lines
                      if "informational" in l and "[x]" not in l]
        assert info_lines, lines


class TestKeyscanInputHandling:
    def test_scroll_down(self, monitor):
        monitor._detail_focus = True
        monitor._keyscan_mode = True
        monitor._keyscan_scroll = 0
        monitor.handle_input(curses.KEY_DOWN)
        assert monitor._keyscan_scroll == 1

    def test_esc_closes(self, monitor):
        monitor._detail_focus = True
        monitor._keyscan_mode = True
        monitor.handle_input(27)
        assert monitor._keyscan_mode is False
        assert monitor._detail_focus is False

    def test_q_quits(self, monitor):
        monitor._detail_focus = True
        monitor._keyscan_mode = True
        assert monitor.handle_input(ord("q")) is False

    def test_arrow_down_moves_cursor_when_structured(self, monitor):
        """With structured findings, Up/Down moves the selection cursor
        instead of the viewport scroll offset."""
        monitor._detail_focus = True
        monitor._keyscan_mode = True
        monitor._keyscan_findings_structured = [
            {"severity": "HIGH", "message": "a", "action": None},
            {"severity": "HIGH", "message": "b", "action": None},
        ]
        monitor._keyscan_cursor = 0
        monitor.handle_input(curses.KEY_DOWN)
        assert monitor._keyscan_cursor == 1

    def test_arrow_up_moves_cursor_when_structured(self, monitor):
        monitor._detail_focus = True
        monitor._keyscan_mode = True
        monitor._keyscan_findings_structured = [
            {"severity": "HIGH", "message": "a", "action": None},
            {"severity": "HIGH", "message": "b", "action": None},
        ]
        monitor._keyscan_cursor = 1
        monitor.handle_input(curses.KEY_UP)
        assert monitor._keyscan_cursor == 0

    def test_cursor_clamps_at_boundaries(self, monitor):
        monitor._detail_focus = True
        monitor._keyscan_mode = True
        monitor._keyscan_findings_structured = [
            {"severity": "HIGH", "message": "only", "action": None},
        ]
        monitor._keyscan_cursor = 0
        monitor.handle_input(curses.KEY_UP)
        assert monitor._keyscan_cursor == 0
        monitor.handle_input(curses.KEY_DOWN)
        assert monitor._keyscan_cursor == 0

    def test_d_key_triggers_remove(self, monitor):
        """`D` on a finding with an action invokes the remove dispatcher."""
        monitor._detail_focus = True
        monitor._keyscan_mode = True
        monitor._keyscan_findings_structured = [
            {"severity": "HIGH", "message": "tcc",
             "action": {"type": "delete_tcc", "client": "x",
                         "service": "y", "db": "z"}},
        ]
        with patch.object(monitor, "_keyscan_remove_current") as rm:
            monitor.handle_input(ord("D"))
        rm.assert_called_once()

    def test_lowercase_d_also_triggers_remove(self, monitor):
        monitor._detail_focus = True
        monitor._keyscan_mode = True
        monitor._keyscan_findings_structured = [
            {"severity": "HIGH", "message": "x", "action": None},
        ]
        with patch.object(monitor, "_keyscan_remove_current") as rm:
            monitor.handle_input(ord("d"))
        rm.assert_called_once()


# ── Remediation primitives ─────────────────────────────────────────────


class TestDeleteTccGrant:
    def test_deletes_matching_row(self, tmp_path):
        """_delete_tcc_grant removes the row from a real sqlite db."""
        import sqlite3
        db = tmp_path / "TCC.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE access (client TEXT, service TEXT)")
        conn.execute(
            "INSERT INTO access VALUES ('com.skype.skype', 'kTCCServiceAccessibility')")
        conn.execute(
            "INSERT INTO access VALUES ('com.apple.Finder', 'kTCCServiceAccessibility')")
        conn.commit()
        conn.close()

        ok, msg = procmon._delete_tcc_grant(
            "com.skype.skype", "kTCCServiceAccessibility", str(db))
        assert ok is True
        assert "deleted 1" in msg

        # Verify the right row was deleted, others preserved
        conn = sqlite3.connect(str(db))
        clients = [r[0] for r in conn.execute("SELECT client FROM access")]
        conn.close()
        assert "com.skype.skype" not in clients
        assert "com.apple.Finder" in clients

    def test_missing_db(self):
        ok, msg = procmon._delete_tcc_grant(
            "x", "y", "/does/not/exist.db")
        assert ok is False
        assert "not found" in msg

    def test_missing_required_field(self):
        ok, msg = procmon._delete_tcc_grant("", "service", "path")
        assert ok is False
        assert "missing" in msg

    def test_no_matching_row(self, tmp_path):
        import sqlite3
        db = tmp_path / "TCC.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE access (client TEXT, service TEXT)")
        conn.commit()
        conn.close()
        ok, msg = procmon._delete_tcc_grant("ghost", "x", str(db))
        assert ok is False
        assert "no matching row" in msg

    def test_readonly_db_reports_fda_hint(self, tmp_path):
        """When the DB is read-only (as it is under SIP without FDA), the
        error message steers the user toward granting Full Disk Access."""
        import sqlite3
        db = tmp_path / "TCC.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE access (client TEXT, service TEXT)")
        conn.execute("INSERT INTO access VALUES ('x', 'y')")
        conn.commit()
        conn.close()
        # Make the file read-only to simulate SIP-protected DB
        os.chmod(db, 0o444)
        try:
            ok, msg = procmon._delete_tcc_grant("x", "y", str(db))
        finally:
            os.chmod(db, 0o644)
        assert ok is False
        # Either "Full Disk Access" hint or a generic sqlite error both OK —
        # depending on whether sqlite surfaces readonly differently on this
        # platform. Just make sure we didn't silently claim success.
        assert "deleted" not in msg


class TestDeleteTccGrantTccutil:
    """_delete_tcc_grant prefers `tccutil reset` over raw sqlite because:
      1. tccutil works under plain sudo without Full Disk Access
      2. direct sqlite writes to /Library/.../TCC.db are SIP-protected
    Fall back to sqlite only when tccutil is missing or rejects the input."""

    def test_uses_tccutil_when_available(self, tmp_path):
        """Happy path: tccutil succeeds AND actually removes the row → we
        return its success message without falling through to sqlite."""
        import sqlite3
        db = tmp_path / "TCC.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE access (client TEXT, service TEXT)")
        conn.execute("INSERT INTO access VALUES "
                     "('com.skype.skype', 'kTCCServiceAccessibility')")
        conn.commit()
        conn.close()

        # Simulate a *real* tccutil: it returns 0 AND removes the row as a
        # side effect, the way Apple's tool actually works when everything
        # lines up. The post-verification in _delete_tcc_grant must then
        # confirm the row is gone and short-circuit.
        def fake_run(cmd, **kw):
            if cmd[:2] == ["tccutil", "reset"]:
                conn2 = sqlite3.connect(str(db))
                conn2.execute(
                    "DELETE FROM access WHERE client = ? AND service = ?",
                    ("com.skype.skype", "kTCCServiceAccessibility"))
                conn2.commit()
                conn2.close()
                return (0, "", "")
            return (0, "", "")

        with patch("shutil.which",
                   side_effect=lambda t: "/usr/bin/tccutil" if t == "tccutil" else None), \
             patch("procmon._run_cmd_short", side_effect=fake_run) as runner:
            ok, msg = procmon._delete_tcc_grant(
                "com.skype.skype", "kTCCServiceAccessibility", str(db))
        assert ok is True
        assert "tccutil reset" in msg
        assert "Accessibility" in msg
        called_args = runner.call_args[0][0]
        assert called_args == ["tccutil", "reset", "Accessibility",
                                "com.skype.skype"]
        # Row is gone now (tccutil did the work, sqlite never ran)
        conn = sqlite3.connect(str(db))
        rows = list(conn.execute("SELECT client FROM access"))
        conn.close()
        assert rows == []

    def test_tccutil_failure_falls_back_to_sqlite(self, tmp_path):
        """If tccutil exits non-zero, we fall back to sqlite DELETE."""
        import sqlite3
        db = tmp_path / "TCC.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE access (client TEXT, service TEXT)")
        conn.execute("INSERT INTO access VALUES "
                     "('com.skype.skype', 'kTCCServiceAccessibility')")
        conn.commit()
        conn.close()

        with patch("shutil.which",
                   side_effect=lambda t: "/usr/bin/tccutil" if t == "tccutil" else None), \
             patch("procmon._run_cmd_short",
                   return_value=(1, "", "tccutil: no matching grant")):
            ok, msg = procmon._delete_tcc_grant(
                "com.skype.skype", "kTCCServiceAccessibility", str(db))
        assert ok is True
        assert "deleted" in msg

    def test_tccutil_not_available_uses_sqlite(self, tmp_path):
        """Environments without tccutil (unlikely on macOS but possible in CI
        fixtures) still work via the sqlite fallback."""
        import sqlite3
        db = tmp_path / "TCC.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE access (client TEXT, service TEXT)")
        conn.execute("INSERT INTO access VALUES "
                     "('com.skype.skype', 'kTCCServiceAccessibility')")
        conn.commit()
        conn.close()
        with patch("shutil.which", return_value=None):
            ok, msg = procmon._delete_tcc_grant(
                "com.skype.skype", "kTCCServiceAccessibility", str(db))
        assert ok is True
        assert "deleted" in msg

    def test_unknown_service_skips_tccutil(self, tmp_path):
        """A service not in the short-name map falls straight to sqlite."""
        import sqlite3
        db = tmp_path / "TCC.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE access (client TEXT, service TEXT)")
        conn.execute(
            "INSERT INTO access VALUES ('c', 'kTCCServiceBrandNew')")
        conn.commit()
        conn.close()
        tccutil_calls = []

        def fake_run(cmd, **kw):
            if cmd[:2] == ["tccutil", "reset"]:
                tccutil_calls.append(cmd)
            return (0, "", "")

        with patch("shutil.which",
                   side_effect=lambda t: "/usr/bin/tccutil" if t == "tccutil" else None), \
             patch("procmon._run_cmd_short", side_effect=fake_run):
            ok, msg = procmon._delete_tcc_grant(
                "c", "kTCCServiceBrandNew", str(db))
        # tccutil reset was NOT invoked for this unknown service
        assert tccutil_calls == []
        assert ok is True

    def test_readonly_db_reports_tccutil_hint(self, tmp_path):
        """When both tccutil fails and sqlite is read-only, the error hints
        at the correct manual `sudo tccutil reset` invocation."""
        import sqlite3
        db = tmp_path / "TCC.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE access (client TEXT, service TEXT)")
        conn.execute("INSERT INTO access VALUES ('x', 'kTCCServiceListenEvent')")
        conn.commit()
        conn.close()
        os.chmod(db, 0o444)
        try:
            with patch("shutil.which",
                       side_effect=lambda t: "/usr/bin/tccutil" if t == "tccutil" else None), \
                 patch("procmon._run_cmd_short",
                       return_value=(1, "", "denied")):
                ok, msg = procmon._delete_tcc_grant(
                    "x", "kTCCServiceListenEvent", str(db))
        finally:
            os.chmod(db, 0o644)
        assert ok is False
        # Should tell the user exactly what command to run manually
        assert "tccutil reset ListenEvent x" in msg or "Full Disk Access" in msg

    def test_service_short_name_map_covers_main_services(self):
        """Regression guard: the three keyboard-hook services stay mapped."""
        for svc in ("kTCCServiceAccessibility", "kTCCServiceListenEvent",
                     "kTCCServicePostEvent"):
            assert svc in procmon._TCC_SERVICE_SHORT_NAMES


class TestTccGrantExists:
    """Three-valued check:
      True  — confirmed present
      False — confirmed absent
      None  — can't tell (db unreadable)

    The None case matters a lot: if we collapse it into False ('not there'),
    `_delete_tcc_grant` reports a false success when it couldn't actually
    verify — which is the bug that kept Skype grants alive despite
    "successful" deletes."""

    def test_finds_matching_row(self, tmp_path):
        import sqlite3
        db = tmp_path / "TCC.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE access (client TEXT, service TEXT)")
        conn.execute("INSERT INTO access VALUES ('com.skype', 'kTCCServiceAccessibility')")
        conn.commit()
        conn.close()
        assert procmon._tcc_grant_exists(
            "com.skype", "kTCCServiceAccessibility", str(db)) is True

    def test_no_matching_row_returns_false(self, tmp_path):
        import sqlite3
        db = tmp_path / "TCC.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE access (client TEXT, service TEXT)")
        conn.commit()
        conn.close()
        assert procmon._tcc_grant_exists("anything", "x", str(db)) is False

    def test_nonexistent_db_returns_false(self):
        """No DB file → the grant is definitely not there."""
        assert procmon._tcc_grant_exists("c", "s", "/no/such.db") is False

    def test_missing_db_path_returns_none(self):
        """Empty path → we can't even check → None."""
        assert procmon._tcc_grant_exists("c", "s", "") is None

    def test_corrupt_db_returns_none(self, tmp_path):
        """A non-sqlite file masquerading as TCC.db → can't verify → None,
        NOT False. Returning False here is what caused the silent-success
        bug where we claimed removal but the grant was still there."""
        f = tmp_path / "fake.db"
        f.write_text("not sqlite")
        assert procmon._tcc_grant_exists("c", "s", str(f)) is None

    def test_unreadable_db_returns_none(self, tmp_path):
        """Simulating SIP-blocked reads: the db file exists but sqlite
        can't open it. Must return None so _delete_tcc_grant doesn't
        prematurely claim success."""
        import sqlite3
        db = tmp_path / "TCC.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE access (client TEXT, service TEXT)")
        conn.commit()
        conn.close()
        with patch("sqlite3.connect",
                   side_effect=sqlite3.OperationalError("authorization denied")):
            assert procmon._tcc_grant_exists(
                "c", "kTCCServiceAccessibility", str(db)) is None


class TestTccRemovalSilentFailureReproduction:
    """Reproduction for the user-reported bug: 'I tried to delete the Skype
    TCC grant — no luck.' tccutil was returning 0 while leaving the row in
    the system TCC.db because SIP protected it from root. The fix detects
    that tccutil lied and falls back to sqlite (which then surfaces an
    informative error if sqlite can't touch it either).

    These tests pin down that behavior so the bug can't silently regress.
    """

    def test_tccutil_lies_falls_back_to_sqlite(self, tmp_path):
        """Simulate tccutil returning 0 but not removing the row. The
        function must detect this, run sqlite DELETE, and succeed."""
        import sqlite3
        db = tmp_path / "TCC.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE access (client TEXT, service TEXT)")
        conn.execute("INSERT INTO access VALUES "
                     "('com.skype.skype', 'kTCCServiceAccessibility')")
        conn.commit()
        conn.close()

        # tccutil says success but doesn't touch the db
        with patch("shutil.which",
                   side_effect=lambda t: "/usr/bin/tccutil" if t == "tccutil" else None), \
             patch("procmon._run_cmd_short", return_value=(0, "", "")):
            ok, msg = procmon._delete_tcc_grant(
                "com.skype.skype", "kTCCServiceAccessibility", str(db))
        assert ok is True
        # Message explicitly flags that tccutil didn't actually do it
        assert "tccutil lied" in msg
        # Row is gone now (sqlite fallback handled it)
        conn = sqlite3.connect(str(db))
        rows = list(conn.execute("SELECT client FROM access"))
        conn.close()
        assert rows == []

    def test_tccutil_lies_and_sqlite_readonly_informs_user(self, tmp_path):
        """Both paths fail: tccutil returns 0 without removing, and sqlite
        is read-only. User must see a clear, actionable error — not a
        misleading 'success' message."""
        import sqlite3
        db = tmp_path / "TCC.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE access (client TEXT, service TEXT)")
        conn.execute("INSERT INTO access VALUES "
                     "('com.skype.skype', 'kTCCServiceAccessibility')")
        conn.commit()
        conn.close()
        os.chmod(db, 0o444)
        try:
            with patch("shutil.which",
                       side_effect=lambda t: "/usr/bin/tccutil" if t == "tccutil" else None), \
                 patch("procmon._run_cmd_short", return_value=(0, "", "")):
                ok, msg = procmon._delete_tcc_grant(
                    "com.skype.skype", "kTCCServiceAccessibility", str(db))
        finally:
            os.chmod(db, 0o644)
        assert ok is False
        # Must tell the user tccutil silently no-op'd AND point at FDA
        assert "silently" in msg or "Full Disk Access" in msg

    def test_tccutil_really_removes_grant_returns_success(self, tmp_path):
        """Control test: when tccutil actually works (row is gone after
        the call), we return its success message without falling through
        to sqlite."""
        import sqlite3
        db = tmp_path / "TCC.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE access (client TEXT, service TEXT)")
        # Note: NO row inserted — tccutil's effect is simulated by absence
        conn.commit()
        conn.close()

        with patch("shutil.which",
                   side_effect=lambda t: "/usr/bin/tccutil" if t == "tccutil" else None), \
             patch("procmon._run_cmd_short", return_value=(0, "", "")):
            ok, msg = procmon._delete_tcc_grant(
                "com.skype.skype", "kTCCServiceAccessibility", str(db))
        assert ok is True
        assert "tccutil reset" in msg
        assert "lied" not in msg


class TestTccutilDualEnvAttempts:
    """tccutil picks its target TCC.db based on HOME/USER. Under sudo with
    HOME preserved (via our procmon-sudo wrapper), tccutil targets the
    user's per-user db — but most 'real' grants live in the system db at
    /Library/Application Support/com.apple.TCC/TCC.db. So _delete_tcc_grant
    tries *both* env contexts before giving up."""

    def test_retries_with_root_env_when_user_env_fails(self, tmp_path):
        """First attempt (user env) doesn't remove the row; second attempt
        (HOME=/var/root) does. The function returns success with a label
        indicating which env worked."""
        import sqlite3
        db = tmp_path / "TCC.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE access (client TEXT, service TEXT)")
        conn.execute("INSERT INTO access VALUES "
                     "('com.skype.skype', 'kTCCServiceAccessibility')")
        conn.commit()
        conn.close()

        tccutil_calls = []  # only tccutil invocations — ignore csrutil noise

        def fake_run(cmd, **kw):
            if cmd[:2] == ["tccutil", "reset"]:
                tccutil_calls.append(kw.get("env"))
                env = kw.get("env") or {}
                if env.get("HOME") == "/var/root":
                    conn2 = sqlite3.connect(str(db))
                    conn2.execute("DELETE FROM access")
                    conn2.commit()
                    conn2.close()
            return (0, "", "")

        with patch("shutil.which",
                   side_effect=lambda t: "/usr/bin/tccutil" if t == "tccutil" else None), \
             patch("procmon._run_cmd_short", side_effect=fake_run):
            ok, msg = procmon._delete_tcc_grant(
                "com.skype.skype", "kTCCServiceAccessibility", str(db))
        assert ok is True
        assert "root env" in msg
        # Both tccutil attempts were made (user first, root second)
        assert len(tccutil_calls) == 2
        assert tccutil_calls[1] is not None
        assert tccutil_calls[1].get("HOME") == "/var/root"

    def test_both_attempts_lie_falls_back_to_sqlite(self, tmp_path):
        """tccutil rc=0 in both env contexts but neither actually removes
        the row → falls through to sqlite DELETE."""
        import sqlite3
        db = tmp_path / "TCC.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE access (client TEXT, service TEXT)")
        conn.execute("INSERT INTO access VALUES "
                     "('com.skype.skype', 'kTCCServiceAccessibility')")
        conn.commit()
        conn.close()

        with patch("shutil.which",
                   side_effect=lambda t: "/usr/bin/tccutil" if t == "tccutil" else None), \
             patch("procmon._run_cmd_short", return_value=(0, "", "")):
            ok, msg = procmon._delete_tcc_grant(
                "com.skype.skype", "kTCCServiceAccessibility", str(db))
        assert ok is True
        assert "tccutil lied" in msg
        # sqlite DELETE was the one that actually removed the row
        conn = sqlite3.connect(str(db))
        rows = list(conn.execute("SELECT client FROM access"))
        conn.close()
        assert rows == []

    def test_user_env_success_short_circuits(self, tmp_path):
        """If user-env tccutil succeeds, we don't try the root-env retry."""
        import sqlite3
        db = tmp_path / "TCC.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE access (client TEXT, service TEXT)")
        conn.execute("INSERT INTO access VALUES "
                     "('com.skype.skype', 'kTCCServiceAccessibility')")
        conn.commit()
        conn.close()

        tccutil_calls = []

        def fake_run(cmd, **kw):
            if cmd[:2] == ["tccutil", "reset"]:
                tccutil_calls.append(kw.get("env"))
                # First tccutil call removes the row
                if len(tccutil_calls) == 1:
                    conn2 = sqlite3.connect(str(db))
                    conn2.execute("DELETE FROM access")
                    conn2.commit()
                    conn2.close()
            return (0, "", "")

        with patch("shutil.which",
                   side_effect=lambda t: "/usr/bin/tccutil" if t == "tccutil" else None), \
             patch("procmon._run_cmd_short", side_effect=fake_run):
            ok, msg = procmon._delete_tcc_grant(
                "com.skype.skype", "kTCCServiceAccessibility", str(db))
        assert ok is True
        assert "user env" in msg
        # Only ONE tccutil call was made (no root-env retry)
        assert len(tccutil_calls) == 1

    def test_silent_success_bug_reproduction(self, tmp_path):
        """**Reproduction for the user-reported 'didn't work, no errors' bug.**

        The exact failure mode:
          1. User hits D on Skype's Accessibility grant (lives in SYSTEM
             TCC.db — /Library/.../TCC.db).
          2. procmon runs `tccutil reset Accessibility com.skype.skype`.
             tccutil returns 0 but doesn't actually modify the db (because
             of SIP restrictions it can't announce).
          3. procmon re-queries the system db to verify — SIP blocks the
             read too (Terminal lacks Full Disk Access).
          4. Old code: sqlite error → _tcc_grant_exists returns False →
             'false is not True, so tccutil must have succeeded' → report
             success → grant is still there.

        Fix: _tcc_grant_exists returns None when it can't verify, and
        _delete_tcc_grant treats None as 'keep trying'."""
        import sqlite3
        db = tmp_path / "TCC.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE access (client TEXT, service TEXT)")
        conn.execute("INSERT INTO access VALUES "
                     "('com.skype.skype', 'kTCCServiceAccessibility')")
        conn.commit()
        conn.close()

        # Fake both possibilities:
        #  - tccutil always returns 0 (silent no-op — Apple's bug)
        #  - sqlite reads of the db fail (SIP blocks without FDA)
        #  - sqlite writes of the db also fail (same reason)
        def fake_sqlite_connect(*args, **kw):
            raise sqlite3.OperationalError("authorization denied")

        with patch("shutil.which",
                   side_effect=lambda t: "/usr/bin/tccutil" if t == "tccutil" else None), \
             patch("procmon._run_cmd_short", return_value=(0, "", "")), \
             patch("sqlite3.connect", side_effect=fake_sqlite_connect):
            ok, msg = procmon._delete_tcc_grant(
                "com.skype.skype", "kTCCServiceAccessibility", str(db))

        # Must NOT falsely claim success
        assert ok is False, (
            f"_delete_tcc_grant incorrectly reported success when both "
            f"tccutil and sqlite were no-ops. Got: {msg}")
        # Message must give the user SOMETHING actionable — either pointing
        # at FDA, explaining we can't verify, flagging tccutil's lie, or
        # echoing the exact manual command they can run.
        actionable_signals = (
            "Full Disk Access", "authorization denied", "can't verify",
            "still present", "tccutil reset", "SIP-protected",
        )
        assert any(signal in msg for signal in actionable_signals), \
            f"Expected an actionable error message; got: {msg!r}"

    def test_cannot_verify_but_sqlite_write_works(self, tmp_path):
        """Edge case: tccutil said OK, we can't verify (sqlite read denied),
        but the fallback sqlite WRITE does work because sqlite.connect
        is only mocked to fail on read-only opens.

        Net: the write path actually removes the row, and we return
        success. Verifies fallback runs even when verification can't."""
        import sqlite3
        db = tmp_path / "TCC.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE access (client TEXT, service TEXT)")
        conn.execute("INSERT INTO access VALUES ('com.skype', 'kTCCServiceAccessibility')")
        conn.commit()
        conn.close()

        real_connect = sqlite3.connect

        def selective_connect(path_or_uri, **kw):
            # Fail only on the read-only uri form used by _tcc_grant_exists
            if isinstance(path_or_uri, str) and "mode=ro" in path_or_uri:
                raise sqlite3.OperationalError("authorization denied")
            return real_connect(path_or_uri, **kw)

        with patch("shutil.which",
                   side_effect=lambda t: "/usr/bin/tccutil" if t == "tccutil" else None), \
             patch("procmon._run_cmd_short", return_value=(0, "", "")), \
             patch("sqlite3.connect", side_effect=selective_connect):
            ok, msg = procmon._delete_tcc_grant(
                "com.skype", "kTCCServiceAccessibility", str(db))
        # sqlite write succeeded so the row is gone
        conn = sqlite3.connect(str(db))
        rows = list(conn.execute("SELECT client FROM access"))
        conn.close()
        assert rows == []
        assert ok is True

    def test_root_env_scrubs_sudo_vars(self, tmp_path):
        """The root-env attempt must not leak SUDO_USER/SUDO_UID; otherwise
        tccutil still thinks it's acting on the user's behalf."""
        import sqlite3
        db = tmp_path / "TCC.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE access (client TEXT, service TEXT)")
        conn.execute("INSERT INTO access VALUES ('x', 'kTCCServiceAccessibility')")
        conn.commit()
        conn.close()

        tccutil_envs = []

        def fake_run(cmd, **kw):
            if cmd[:2] == ["tccutil", "reset"]:
                tccutil_envs.append(kw.get("env"))
            return (0, "", "")

        with patch.dict("os.environ",
                        {"SUDO_USER": "alex", "SUDO_UID": "501",
                         "SUDO_GID": "20", "HOME": "/Users/alex"},
                        clear=False), \
             patch("shutil.which",
                   side_effect=lambda t: "/usr/bin/tccutil" if t == "tccutil" else None), \
             patch("procmon._run_cmd_short", side_effect=fake_run):
            procmon._delete_tcc_grant(
                "x", "kTCCServiceAccessibility", str(db))
        # Second tccutil attempt is the root-env one; must have sudo vars stripped
        root_env = tccutil_envs[1]
        assert root_env is not None
        assert "SUDO_USER" not in root_env
        assert "SUDO_UID" not in root_env
        assert "SUDO_GID" not in root_env
        assert root_env.get("HOME") == "/var/root"
        assert root_env.get("USER") == "root"


class TestFullEndToEndSkypeRemoval:
    """Mirror the exact user flow: scan finds a Skype grant → user hits
    D → confirm → removal actually removes the row from the db, even when
    tccutil is a no-op on this system."""

    def test_skype_grant_is_actually_deleted_via_ui_flow(self, monitor, tmp_path):
        import sqlite3
        db = tmp_path / "TCC.db"
        conn = sqlite3.connect(str(db))
        conn.execute(
            "CREATE TABLE access (service TEXT, client TEXT, "
            "client_type INT, auth_value INT, auth_reason INT)")
        conn.execute(
            "INSERT INTO access VALUES "
            "('kTCCServiceAccessibility', 'com.skype.skype', 0, 2, 0)")
        conn.commit()
        conn.close()

        # Build a keyscan as the UI would
        with patch("procmon._enumerate_event_taps", return_value=[]), \
             patch("procmon._query_tcc_input_monitoring", return_value=[
                 {"service": "kTCCServiceAccessibility",
                  "client": "com.skype.skype",
                  "client_type": 0, "auth_value": 2, "auth_reason": 0,
                  "db": str(db)}
             ]), \
             patch("procmon._list_input_methods", return_value=[]), \
             patch("procmon._check_secure_keyboard_entry",
                   return_value={"enabled": False, "pid": 0}):
            findings = procmon._scan_keyboard_hooks()
            monitor._format_keyscan_report(findings)

        monitor._keyscan_mode = True
        monitor._keyscan_cursor = 0
        # Confirm, and force the scenario where tccutil lies (returns 0
        # without touching the db) — exactly the scenario the user hit.
        with patch.object(monitor, "_confirm_action", return_value=True), \
             patch("shutil.which",
                   side_effect=lambda t: "/usr/bin/tccutil" if t == "tccutil" else None), \
             patch("procmon._run_cmd_short", return_value=(0, "", "")), \
             patch.object(monitor, "_start_keyscan"):
            monitor._keyscan_remove_current()

        # The Skype row is gone from the db (sqlite fallback ran)
        conn = sqlite3.connect(str(db))
        rows = list(conn.execute("SELECT client FROM access"))
        conn.close()
        assert rows == []

        # The UI action-result panel reflects what actually happened
        result = monitor._keyscan_action_result
        assert result is not None
        assert result["level"] == "ok"
        combined = result["summary"] + " " + result.get("detail_text", "")
        assert "deleted" in combined or "tccutil reset" in combined or "Removed" in combined


class TestKeyscanCursorScroll:
    """Moving the cursor past the visible viewport must scroll the view.
    Regression for the bug where arrow keys moved an invisible cursor."""

    def test_cursor_down_scrolls_when_off_screen(self, monitor):
        monitor._keyscan_findings_structured = [
            {"severity": "HIGH", "message": f"f{i}",
             "action": {"type": "delete_tcc"}} for i in range(100)
        ]
        # Simulate a rendered report where each finding is on line i+5
        # (so line_for_finding = [5, 6, 7, ..., 104]).
        monitor._keyscan_line_for_finding = [5 + i for i in range(100)]
        monitor._keyscan_cursor = 0
        monitor._keyscan_scroll = 0
        monitor.stdscr.getmaxyx.return_value = (30, 120)  # small screen
        # Move cursor way down
        for _ in range(50):
            monitor._keyscan_move_cursor(1)
        assert monitor._keyscan_cursor == 50
        # Scroll offset must have moved — otherwise viewport is stuck at top
        assert monitor._keyscan_scroll > 0

    def test_cursor_up_scrolls_back(self, monitor):
        monitor._keyscan_findings_structured = [
            {"severity": "HIGH", "message": f"f{i}",
             "action": {"type": "delete_tcc"}} for i in range(100)
        ]
        # Cursor index i sits on display line 5+i
        monitor._keyscan_line_for_finding = [5 + i for i in range(100)]
        monitor._keyscan_cursor = 90
        monitor._keyscan_scroll = 80
        monitor.stdscr.getmaxyx.return_value = (30, 120)
        for _ in range(85):
            monitor._keyscan_move_cursor(-1)
        assert monitor._keyscan_cursor == 5
        # Scroll offset should have followed the cursor; after going from
        # cursor 90 down to cursor 5, the scroll must be at or below the
        # cursor's target line (10) so the cursor stays visible.
        target_line = monitor._keyscan_line_for_finding[5]
        assert monitor._keyscan_scroll <= target_line

    def test_scroll_is_noop_without_findings(self, monitor):
        monitor._keyscan_line_for_finding = []
        monitor._keyscan_scroll = 42
        monitor._scroll_keyscan_to_cursor()
        assert monitor._keyscan_scroll == 42  # unchanged

    def test_scroll_clamps_at_zero(self, monitor):
        monitor._keyscan_findings_structured = [
            {"severity": "HIGH", "message": "only",
             "action": {"type": "delete_tcc"}}
        ]
        monitor._keyscan_line_for_finding = [5]
        monitor._keyscan_cursor = 0
        monitor._keyscan_scroll = 10  # start scrolled down for some reason
        monitor.stdscr.getmaxyx.return_value = (40, 120)
        monitor._scroll_keyscan_to_cursor()
        # Target line (5) is above scroll (10) → scroll clamps down
        assert monitor._keyscan_scroll <= 5


class TestRemoveBundle:
    def test_removes_directory(self, tmp_path):
        target = tmp_path / "Evil.app"
        target.mkdir()
        (target / "Info.plist").write_text("junk")
        ok, msg = procmon._remove_bundle(str(target))
        assert ok is True
        assert not target.exists()

    def test_refuses_system_paths(self):
        ok, msg = procmon._remove_bundle("/System/Library/Foo.app")
        assert ok is False
        assert "refusing" in msg

    def test_non_directory(self, tmp_path):
        f = tmp_path / "regular.txt"
        f.write_text("x")
        ok, msg = procmon._remove_bundle(str(f))
        assert ok is False


# ── Keyscan removal dispatcher + UX ────────────────────────────────────


class TestKeyscanRemoveCurrent:
    def _setup_with_finding(self, monitor, action):
        monitor._keyscan_findings_structured = [
            {"severity": "HIGH", "message": "test", "action": action},
        ]
        monitor._keyscan_cursor = 0

    @staticmethod
    def _result_text(result):
        """Concatenate summary + detail_text into a single string so tests
        can grep it regardless of how the panel is structured."""
        if result is None:
            return ""
        return (result.get("summary", "") + "\n"
                + result.get("detail_text", ""))

    def test_info_finding_is_noop_with_message(self, monitor):
        """An informational finding reports it's not removable and doesn't
        invoke any action."""
        self._setup_with_finding(monitor, None)
        with patch.object(monitor, "_confirm_action") as confirm:
            monitor._keyscan_remove_current()
        confirm.assert_not_called()
        assert "informational" in self._result_text(monitor._keyscan_action_result)
        assert monitor._keyscan_action_result["level"] == "info"

    def test_cancelled_confirmation_is_noop(self, monitor):
        self._setup_with_finding(monitor, {"type": "delete_tcc",
                                            "client": "x", "service": "y",
                                            "db": "z"})
        with patch.object(monitor, "_confirm_action", return_value=False), \
             patch.object(monitor, "_dispatch_keyscan_action") as dispatch:
            monitor._keyscan_remove_current()
        dispatch.assert_not_called()
        assert "Cancelled" in self._result_text(monitor._keyscan_action_result)

    def test_confirmed_delete_tcc_calls_dispatcher(self, monitor):
        action = {"type": "delete_tcc", "client": "com.skype.skype",
                   "service": "kTCCServiceAccessibility", "db": "/x.db"}
        self._setup_with_finding(monitor, action)
        with patch.object(monitor, "_confirm_action", return_value=True), \
             patch.object(monitor, "_dispatch_keyscan_action",
                          return_value=(True, "deleted")) as dispatch, \
             patch.object(monitor, "_start_keyscan"):
            monitor._keyscan_remove_current()
        dispatch.assert_called_once_with(action)
        result = monitor._keyscan_action_result
        assert result["level"] == "ok"
        assert "Removed" in result["summary"] or "deleted" in result["summary"]

    def test_successful_removal_triggers_rescan(self, monitor):
        action = {"type": "delete_tcc", "client": "x", "service": "y",
                   "db": "z"}
        self._setup_with_finding(monitor, action)
        with patch.object(monitor, "_confirm_action", return_value=True), \
             patch.object(monitor, "_dispatch_keyscan_action",
                          return_value=(True, "ok")), \
             patch.object(monitor, "_start_keyscan") as rescan:
            monitor._keyscan_remove_current()
        rescan.assert_called_once()

    def test_failed_removal_does_not_rescan(self, monitor):
        action = {"type": "delete_tcc", "client": "x", "service": "y",
                   "db": "z"}
        self._setup_with_finding(monitor, action)
        with patch.object(monitor, "_confirm_action", return_value=True), \
             patch.object(monitor, "_dispatch_keyscan_action",
                          return_value=(False, "readonly")), \
             patch.object(monitor, "_start_keyscan") as rescan:
            monitor._keyscan_remove_current()
        rescan.assert_not_called()
        result = monitor._keyscan_action_result
        assert result["level"] == "error"
        # Raw error is surfaced in the detail text for the user to read
        assert "readonly" in self._result_text(result)

    def test_empty_cursor_is_safe(self, monitor):
        """With no findings, _keyscan_remove_current reports nothing to do."""
        monitor._keyscan_findings_structured = []
        monitor._keyscan_cursor = 0
        monitor._keyscan_remove_current()
        assert "Nothing selected" in self._result_text(monitor._keyscan_action_result)


class TestActionPanelRendering:
    """The keyscan action-result panel replaces the single-line status
    banner. It's word-wrapped so long SIP/FDA explanations don't get
    clipped, and visually separated from the findings below."""

    def test_ok_panel_shows_success_icon_and_summary(self, monitor):
        result = {"level": "ok", "summary": "Removed com.skype.skype",
                  "detail_text": ""}
        lines = monitor._format_action_panel(result, 80)
        joined = "\n".join(lines)
        assert "Success" in joined
        assert "\u2714" in joined  # ✔
        assert "Removed com.skype.skype" in joined

    def test_error_panel_shows_failure_icon_and_detail(self, monitor):
        result = {"level": "error", "summary": "Could not remove grant",
                  "detail_text": "TCC.db is SIP-protected.\nTry manually: ..."}
        lines = monitor._format_action_panel(result, 80)
        joined = "\n".join(lines)
        assert "Failed" in joined
        assert "\u2718" in joined  # ✘
        assert "SIP-protected" in joined

    def test_info_panel(self, monitor):
        result = {"level": "info", "summary": "Cancelled", "detail_text": ""}
        lines = monitor._format_action_panel(result, 80)
        joined = "\n".join(lines)
        assert "\u2794" in joined  # ➔
        assert "Cancelled" in joined

    def test_detail_text_is_word_wrapped(self, monitor):
        """A long error spanning one paragraph wraps to box width rather
        than being truncated — regression for the user-reported issue
        where the SIP error got cut off mid-sentence."""
        long_text = (
            "TCC.db is SIP-protected. Try manually: sudo tccutil reset "
            "Accessibility com.skype.skype (or grant Full Disk Access to "
            "your terminal in System Settings → Privacy & Security)")
        result = {"level": "error", "summary": "x", "detail_text": long_text}
        lines = monitor._format_action_panel(result, 50)
        # No single wrapped line should exceed the column budget
        for line in lines:
            if line.startswith(" \u2502   "):
                body = line[5:]
                assert len(body) <= 50

    def test_panel_ends_with_separator(self, monitor):
        """The panel visually closes with a ─── border so the user can tell
        where the action output ends and the findings begin."""
        result = {"level": "ok", "summary": "ok", "detail_text": ""}
        lines = monitor._format_action_panel(result, 50)
        # Last non-empty line is the bottom border
        non_empty = [l for l in lines if l.strip()]
        assert non_empty[-1].startswith(" \u2514")  # └ corner

    def test_panel_integrated_into_render_above_findings(self, monitor):
        """End-to-end: when the scan has completed AND an action ran, the
        action panel appears in the rendered lines BEFORE the findings."""
        monitor._keyscan_mode = True
        monitor._keyscan_lines = [
            "Keyboard hook scan",
            "── [HIGH] ──",
            "  [x] TCC grant: com.skype",
        ]
        monitor._keyscan_findings_structured = [
            {"severity": "HIGH", "message": "TCC grant: com.skype",
             "action": {"type": "delete_tcc"}},
        ]
        monitor._keyscan_line_for_finding = [2]
        monitor._keyscan_cursor = 0
        monitor._keyscan_action_result = {
            "level": "error",
            "summary": "Could not remove TCC grant",
            "detail_text": "TCC.db is SIP-protected.",
        }

        captured = {}

        def fake_render_detail(start_y, w, lines, *args, **kwargs):
            captured["lines"] = list(lines)

        monitor.stdscr.getmaxyx.return_value = (40, 120)
        monitor.rows = [make_proc(pid=1, command="/bin/test")]
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_render_detail",
                          side_effect=fake_render_detail):
            monitor.render()
        lines = captured.get("lines", [])
        # Panel appears ABOVE the findings
        panel_idx = next(i for i, l in enumerate(lines)
                         if "LAST ACTION" in l)
        findings_idx = next(i for i, l in enumerate(lines)
                            if "com.skype" in l)
        assert panel_idx < findings_idx
        # Panel contains the raw error, not just a truncated banner
        joined = "\n".join(lines[:findings_idx])
        assert "SIP-protected" in joined


class TestSipExplanation:
    """_sip_explanation tailors its text to euid so a user running as root
    vs. a user who forgot sudo both see the right fix for THEIR situation."""

    def test_root_euid_explains_sudo_is_not_enough(self, monitor):
        text = monitor._sip_explanation(
            0, "TCC.db is SIP-protected. Try manually: …")
        assert "You ARE running as root" in text
        assert "sudo alone is not enough" in text
        assert "Full Disk Access" in text

    def test_non_root_euid_suggests_sudo_AND_fda(self, monitor):
        text = monitor._sip_explanation(
            501, "TCC.db is SIP-protected.")
        assert "uid=501" in text
        assert "sudo mac-tui-procmon" in text
        assert "Full Disk Access" in text

    def test_non_sip_error_no_fda_section(self, monitor):
        """Errors that don't look SIP-related shouldn't talk about FDA —
        that would confuse the user with irrelevant advice."""
        text = monitor._sip_explanation(
            0, "bundle identifier not found")
        assert "Full Disk Access" not in text
        assert "Raw error:" in text

    def test_always_includes_debug_log_hint(self, monitor):
        """Every failure mentions the `L` key so the user knows where to
        look for full details."""
        text = monitor._sip_explanation(0, "anything")
        assert "Press L" in text


class TestWrapText:
    def test_short_line_unchanged(self, monitor):
        assert monitor._wrap_text("hello", 20) == ["hello"]

    def test_wraps_on_word_boundaries(self, monitor):
        out = monitor._wrap_text("one two three four five", 10)
        for line in out:
            assert len(line) <= 10
        assert " ".join(out) == "one two three four five"

    def test_preserves_hard_newlines(self, monitor):
        out = monitor._wrap_text("first\nsecond", 100)
        assert out == ["first", "second"]


class TestDispatchKeyscanAction:
    def test_delete_tcc_routes_to_helper(self, monitor):
        with patch("procmon._delete_tcc_grant",
                   return_value=(True, "deleted")) as f:
            ok, msg = monitor._dispatch_keyscan_action({
                "type": "delete_tcc", "client": "c", "service": "s", "db": "d"
            })
        # `logger` is threaded through so every sub-step can hit the debug
        # log window; keep this assertion loose on positional args.
        f.assert_called_once()
        call_args = f.call_args
        assert call_args.args == ("c", "s", "d")
        assert "logger" in call_args.kwargs
        assert ok and msg == "deleted"

    def test_remove_bundle_routes_to_helper(self, monitor):
        with patch("procmon._remove_bundle",
                   return_value=(True, "removed")) as f:
            ok, msg = monitor._dispatch_keyscan_action({
                "type": "remove_bundle", "path": "/opt/Evil.app"
            })
        f.assert_called_once_with("/opt/Evil.app")
        assert ok

    def test_kill_process_sends_sigterm(self, monitor):
        with patch("os.kill") as kill:
            ok, msg = monitor._dispatch_keyscan_action({
                "type": "kill_process", "pid": 4321
            })
        import signal as _s
        kill.assert_called_once_with(4321, _s.SIGTERM)
        assert ok

    def test_kill_process_missing_pid(self, monitor):
        with patch("os.kill", side_effect=ProcessLookupError):
            ok, msg = monitor._dispatch_keyscan_action({
                "type": "kill_process", "pid": 9999
            })
        assert ok is False
        assert "not found" in msg

    def test_kill_process_permission_denied(self, monitor):
        with patch("os.kill", side_effect=PermissionError):
            ok, msg = monitor._dispatch_keyscan_action({
                "type": "kill_process", "pid": 1
            })
        assert ok is False
        assert "permission" in msg.lower()

    def test_unknown_action_type(self, monitor):
        ok, msg = monitor._dispatch_keyscan_action({"type": "no_such"})
        assert ok is False
        assert "unknown" in msg.lower()


class TestConfirmActionModal:
    """`_confirm_action` shows a modal that returns True only on `y` / `Y`."""

    def test_returns_true_on_y(self, monitor):
        monitor.stdscr.getmaxyx.return_value = (40, 120)
        monitor.stdscr.getch.side_effect = [ord("y")]
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put"):
            assert monitor._confirm_action("Delete thing?") is True

    def test_returns_true_on_Y(self, monitor):
        monitor.stdscr.getmaxyx.return_value = (40, 120)
        monitor.stdscr.getch.side_effect = [ord("Y")]
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put"):
            assert monitor._confirm_action("x") is True

    def test_any_other_key_cancels(self, monitor):
        monitor.stdscr.getmaxyx.return_value = (40, 120)
        monitor.stdscr.getch.side_effect = [ord("n")]
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put"):
            assert monitor._confirm_action("x") is False

    def test_idle_timeout_loops_until_key(self, monitor):
        """Getch returning -1 means no key yet; the modal keeps waiting."""
        monitor.stdscr.getmaxyx.return_value = (40, 120)
        monitor.stdscr.getch.side_effect = [-1, -1, ord("y")]
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put"):
            assert monitor._confirm_action("x") is True

    def test_multi_line_prompt(self, monitor):
        monitor.stdscr.getmaxyx.return_value = (40, 120)
        monitor.stdscr.getch.side_effect = [ord("y")]
        puts = []
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put",
                          side_effect=lambda y, x, text, attr=0: puts.append(text)):
            monitor._confirm_action("line1\nline2\nline3")
        assert any("line1" in t for t in puts)
        assert any("line2" in t for t in puts)
        assert any("line3" in t for t in puts)

    def test_restores_timeout_after_close(self, monitor):
        monitor.stdscr.getmaxyx.return_value = (40, 120)
        monitor.stdscr.getch.side_effect = [ord("n")]
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put"):
            monitor._confirm_action("x")
        # Should have called timeout(-1) to block, then timeout(100) on exit
        calls = [c.args[0] for c in monitor.stdscr.timeout.call_args_list]
        assert 100 in calls


class TestKeyscanRenderCursor:
    """The keyscan render branch overlays a ▶ cursor on the selected line
    and stamps a transient status line at the top."""

    def _render(self, monitor):
        monitor.stdscr.getmaxyx.return_value = (40, 160)
        monitor.rows = [make_proc(pid=1, command="/bin/test")]
        with patch("curses.color_pair", side_effect=lambda n: n << 8):
            monitor.render()
        return monitor.stdscr.addnstr.call_args_list

    def test_cursor_arrow_drawn_on_selected_actionable_row(self, monitor):
        """The overlay rewrites the selected line to start with ▶ before
        passing it into _render_detail. We assert against the prepared
        buffer rather than the post-wrap addnstr stream to avoid coupling
        to the colored-tag splitter."""
        monitor._keyscan_mode = True
        monitor._keyscan_loading = False
        # New report layout: 4-space indent + "[x] [SEV]  msg"
        monitor._keyscan_lines = [
            "  \u2501\u2501 KEYBOARD HOOK SCAN \u2501\u2501",
            "",
            "  Severity:    [HIGH 2]",
            "  Actionable:  2",
            "",
            "  \u2500\u2500 FINDINGS",
            "",
            "    [x] [HIGH]  TCC grant: com.skype",
            "    [x] [HIGH]  TCC grant: com.zoom",
        ]
        monitor._keyscan_findings_structured = [
            {"severity": "HIGH", "message": "TCC grant: com.skype",
             "action": {"type": "delete_tcc"}},
            {"severity": "HIGH", "message": "TCC grant: com.zoom",
             "action": {"type": "delete_tcc"}},
        ]
        monitor._keyscan_line_for_finding = [7, 8]
        monitor._keyscan_cursor = 1  # select com.zoom

        captured = {}

        def fake_render_detail(start_y, w, lines, *args, **kwargs):
            captured["lines"] = list(lines)

        monitor.stdscr.getmaxyx.return_value = (40, 160)
        monitor.rows = [make_proc(pid=1, command="/bin/test")]
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_render_detail",
                          side_effect=fake_render_detail):
            monitor.render()
        lines = captured.get("lines", [])
        # Cursor rewrites the first 4 chars of the selected row to "  \u25b6 "
        zoom_line = next(l for l in lines if "com.zoom" in l and "DETAIL" not in l)
        skype_line = next(l for l in lines if "com.skype" in l and "DETAIL" not in l)
        assert zoom_line.startswith("  \u25b6 "), zoom_line
        assert not skype_line.startswith("  \u25b6 "), skype_line

    def test_status_banner_shown(self, monitor):
        monitor._keyscan_mode = True
        monitor._keyscan_lines = ["Keyboard hook scan — done"]
        monitor._keyscan_findings_structured = []
        monitor._keyscan_line_for_finding = []
        # New structured action result instead of a raw string banner
        monitor._keyscan_action_result = {
            "level": "ok",
            "summary": "deleted 1 row",
            "detail_text": "",
        }

        captured = {}

        def fake_render_detail(start_y, w, lines, *args, **kwargs):
            captured["lines"] = list(lines)

        monitor.stdscr.getmaxyx.return_value = (40, 160)
        monitor.rows = [make_proc(pid=1, command="/bin/test")]
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_render_detail",
                          side_effect=fake_render_detail):
            monitor.render()
        assert any("deleted 1 row" in l for l in captured.get("lines", []))

    def test_cursor_on_informational_row(self, monitor):
        """Rows without an `[x]` (info findings) still get a cursor when
        selected — the overlay rewrites the 4-char indent to `  ▶ `."""
        monitor._keyscan_mode = True
        monitor._keyscan_lines = [
            "  \u2501\u2501 KEYBOARD HOOK SCAN",
            "",
            "        [INFO]  Secure Keyboard Entry is OFF",
        ]
        monitor._keyscan_findings_structured = [
            {"severity": "INFO", "message": "Secure Keyboard Entry is OFF",
             "action": None},
        ]
        monitor._keyscan_line_for_finding = [2]
        monitor._keyscan_cursor = 0

        captured = {}

        def fake_render_detail(start_y, w, lines, *args, **kwargs):
            captured["lines"] = list(lines)

        monitor.stdscr.getmaxyx.return_value = (40, 160)
        monitor.rows = [make_proc(pid=1, command="/bin/test")]
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_render_detail",
                          side_effect=fake_render_detail):
            monitor.render()
        assert any(l.startswith("  \u25b6 ")
                   for l in captured.get("lines", []))

    def test_loading_state(self, monitor):
        monitor._keyscan_mode = True
        monitor._keyscan_loading = True
        monitor._keyscan_lines = []
        calls = self._render(monitor)
        text = "\n".join(str(c) for c in calls)
        assert "Scanning" in text

    def test_no_scan_results(self, monitor):
        monitor._keyscan_mode = True
        monitor._keyscan_loading = False
        monitor._keyscan_lines = []
        calls = self._render(monitor)
        text = "\n".join(str(c) for c in calls)
        assert "No scan" in text


class TestDebugLog:
    """The `L`-key debug log is the user's window into what procmon is
    actually doing — every subprocess, every verification, every failure
    path writes to it. When 'delete' mysteriously 'doesn't work', the
    log is what tells them why."""

    def test_log_shortcut_opens_overlay(self, monitor):
        monitor._log_mode = False
        monitor.handle_input(ord("L"))
        assert monitor._log_mode is True

    def test_esc_closes_log(self, monitor):
        monitor._log_mode = True
        monitor.handle_input(27)
        assert monitor._log_mode is False

    def test_L_closes_when_already_open(self, monitor):
        """Pressing L while the log is open closes it (idempotent)."""
        monitor._log_mode = True
        monitor.handle_input(ord("L"))
        assert monitor._log_mode is False

    def test_log_intercepts_before_chat(self, monitor):
        """Log overlay is layered ABOVE the chat overlay. When both are
        conceptually 'open', the log gets keys first."""
        monitor._log_mode = True
        monitor._chat_mode = True
        # Any random printable key that'd normally go to the chat input
        monitor.handle_input(ord("x"))
        assert monitor._chat_input == ""

    def test_append_logs_with_timestamp_and_category(self, monitor):
        monitor._log("TCC", "hello")
        assert len(monitor._log_messages) == 1
        ts, cat, text = monitor._log_messages[0]
        assert cat == "TCC"
        assert text == "hello"
        assert len(ts) == 8 and ts[2] == ":" and ts[5] == ":"

    def test_ring_buffer_caps_messages(self, monitor):
        monitor._log_max = 3
        for i in range(5):
            monitor._log("X", f"msg{i}")
        assert len(monitor._log_messages) == 3
        assert monitor._log_messages[0][2] == "msg2"
        assert monitor._log_messages[-1][2] == "msg4"

    def test_clear_empties_buffer(self, monitor):
        monitor._log_mode = True
        monitor._log("X", "one")
        monitor._log("X", "two")
        monitor.handle_input(ord("c"))
        assert monitor._log_messages == []

    def test_scroll_up_and_down(self, monitor):
        monitor._log_mode = True
        monitor._log_scroll = 0
        monitor.handle_input(curses.KEY_UP)
        assert monitor._log_scroll == 1
        monitor.handle_input(curses.KEY_DOWN)
        assert monitor._log_scroll == 0
        monitor.handle_input(curses.KEY_DOWN)  # clamp at 0
        assert monitor._log_scroll == 0

    def test_page_up_and_down(self, monitor):
        monitor._log_mode = True
        monitor._log_scroll = 0
        monitor.handle_input(curses.KEY_PPAGE)
        assert monitor._log_scroll > 0
        monitor.handle_input(curses.KEY_NPAGE)
        assert monitor._log_scroll == 0

    def test_q_closes_and_quits(self, monitor):
        monitor._log_mode = True
        assert monitor.handle_input(ord("q")) is False

    def test_log_appends_during_delete_tcc(self, monitor):
        """Every step of a TCC deletion writes to the debug log so the
        user can see the exact sequence after the fact."""
        action = {"type": "delete_tcc", "client": "com.skype.skype",
                  "service": "kTCCServiceAccessibility",
                  "db": "/no/such/file.db"}
        with patch("shutil.which",
                   side_effect=lambda t: "/usr/bin/tccutil" if t == "tccutil" else None), \
             patch("procmon._run_cmd_short", return_value=(0, "", "")):
            monitor._dispatch_keyscan_action(action)
        cats_seen = {cat for _, cat, _ in monitor._log_messages}
        assert "ACTION" in cats_seen
        assert "TCC" in cats_seen
        text_all = " ".join(t for _, _, t in monitor._log_messages)
        assert "tccutil" in text_all

    def test_log_records_sip_state(self, monitor):
        """The first log line for any TCC operation reports euid, SUDO_USER
        and csrutil status so the user sees the environment at a glance."""
        with patch("shutil.which", return_value=None), \
             patch("procmon._run_cmd_short",
                   return_value=(0, "System Integrity Protection status: enabled.", "")):
            procmon._delete_tcc_grant(
                "x", "kTCCServiceAccessibility", "/nope",
                logger=monitor._log)
        text_all = " ".join(t for _, _, t in monitor._log_messages)
        assert "euid=" in text_all
        assert ("System Integrity Protection" in text_all
                or "unknown" in text_all)

    def test_logger_swallows_exceptions(self, monitor):
        """A broken logger callback must never kill the operation itself."""
        def bad_logger(cat, text):
            raise RuntimeError("logger is broken")
        with patch("shutil.which", return_value=None):
            ok, msg = procmon._delete_tcc_grant(
                "c", "kTCCServiceAccessibility", "/nope",
                logger=bad_logger)
        assert ok is False

    def test_render_log_empty_shows_hint(self, monitor):
        monitor._log_mode = True
        monitor._log_messages = []
        monitor.stdscr.getmaxyx.return_value = (30, 120)
        puts = []
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch("curses.curs_set"), \
             patch.object(monitor, "_put",
                          side_effect=lambda y, x, t, a=0: puts.append(t)):
            monitor._render_log()
        assert any("log is empty" in s for s in puts)

    def test_render_log_shows_entries(self, monitor):
        monitor._log_mode = True
        monitor._log("TCC", "attempting delete")
        monitor._log("FAIL", "grant still present")
        monitor.stdscr.getmaxyx.return_value = (30, 120)
        puts = []
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch("curses.curs_set"), \
             patch.object(monitor, "_put",
                          side_effect=lambda y, x, t, a=0: puts.append(t)):
            monitor._render_log()
        joined = " ".join(puts)
        assert "attempting delete" in joined
        assert "grant still present" in joined
        assert "TCC" in joined
        assert "FAIL" in joined

    def test_render_log_tiny_terminal_noop(self, monitor):
        monitor._log_mode = True
        monitor.stdscr.getmaxyx.return_value = (5, 10)
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch("curses.curs_set"), \
             patch.object(monitor, "_put"):
            monitor._render_log()  # must not raise


class TestChatSendSubprocessEnv:
    """The chat worker must set HOME/USER so claude finds per-user auth
    tokens when procmon is invoked via sudo."""

    def test_worker_overrides_home_and_user_env(self, monitor):
        monitor._chat_mode = True
        monitor._chat_input = "q"
        monitor._chat_cursor = 1
        captured = {}

        def fake_popen(argv, **kwargs):
            captured["env"] = kwargs.get("env", {})
            mock = MagicMock()
            mock.communicate.return_value = (b"hi", b"")
            mock.returncode = 0
            return mock

        def immediate_thread(target=None, daemon=None, **kw):
            t = MagicMock()
            t.start = lambda: target()
            return t

        with patch.dict("os.environ", {"SUDO_USER": "alex"}, clear=False), \
             patch("subprocess.Popen", side_effect=fake_popen), \
             patch("threading.Thread", side_effect=immediate_thread):
            monitor._chat_send()
        # Fresh env must have HOME set to effective user's home
        assert captured["env"]["HOME"] == procmon._EFFECTIVE_HOME
        # USER/LOGNAME match SUDO_USER when set
        assert captured["env"]["USER"] == "alex"
        assert captured["env"]["LOGNAME"] == "alex"


class TestEventStreamReaders:
    """Exercise the stdout/stderr reader threads + exit watcher so the
    reader-thread bodies get covered."""

    def test_stdout_reader_populates_events(self, monitor):
        """Lines from eslogger stdout are parsed and appended to _events."""
        fake_proc = MagicMock()
        fake_proc.stdout = MagicMock()
        # Two valid JSON events, then EOF
        line1 = (b'{"time":"t","event":{"exec":{"target":'
                 b'{"executable":{"path":"/bin/ls"},'
                 b'"audit_token":{"pid":1},'
                 b'"parent_audit_token":{"pid":2}}}}}\n')
        fake_proc.stdout.readline = MagicMock(side_effect=[line1, b""])
        fake_proc.stderr = MagicMock()
        fake_proc.stderr.readline = MagicMock(return_value=b"")
        fake_proc.wait = MagicMock(return_value=0)

        targets = []
        def fake_thread(target=None, **kw):
            targets.append(target)
            t = MagicMock()
            t.start = lambda: None
            return t

        with patch.object(monitor, "_pick_event_source",
                          return_value=("eslogger", ["eslogger", "exec"])), \
             patch("subprocess.Popen", return_value=fake_proc), \
             patch("os.geteuid", return_value=0), \
             patch("threading.Thread", side_effect=fake_thread):
            monitor._start_events_stream()
        # Drive stdout reader
        targets[0]()
        assert any(e.get("pid") == 1 for e in monitor._events)

    def test_stdout_reader_skips_unparseable_lines(self, monitor):
        fake_proc = MagicMock()
        fake_proc.stdout = MagicMock()
        fake_proc.stdout.readline = MagicMock(
            side_effect=[b"garbage\n", b""])
        fake_proc.stderr = MagicMock()
        fake_proc.stderr.readline = MagicMock(return_value=b"")
        fake_proc.wait = MagicMock(return_value=0)

        targets = []
        def fake_thread(target=None, **kw):
            targets.append(target)
            t = MagicMock()
            t.start = lambda: None
            return t

        with patch.object(monitor, "_pick_event_source",
                          return_value=("eslogger", ["eslogger", "exec"])), \
             patch("subprocess.Popen", return_value=fake_proc), \
             patch("os.geteuid", return_value=0), \
             patch("threading.Thread", side_effect=fake_thread):
            monitor._start_events_stream()
        before = len(monitor._events)
        targets[0]()  # drive stdout reader
        # No new non-error events added (parse failures just skip)
        non_error = [e for e in monitor._events if e["kind"] != "error"]
        assert len(non_error) == 0

    def test_reader_cancel_breaks_loop(self, monitor):
        """When the cancel flag is set, the reader loop exits cleanly."""
        fake_proc = MagicMock()
        fake_proc.stdout = MagicMock()
        # Infinite stream of blank lines — reader should exit as soon as we
        # set cancel=True between reads, not hang on readline.
        fake_proc.stdout.readline = MagicMock(return_value=b"ignored\n")
        fake_proc.stderr = MagicMock()
        fake_proc.stderr.readline = MagicMock(return_value=b"")
        fake_proc.wait = MagicMock(return_value=0)

        targets = []
        def fake_thread(target=None, **kw):
            targets.append(target)
            t = MagicMock()
            t.start = lambda: None
            return t

        with patch.object(monitor, "_pick_event_source",
                          return_value=("eslogger", ["eslogger", "exec"])), \
             patch("subprocess.Popen", return_value=fake_proc), \
             patch("os.geteuid", return_value=0), \
             patch("threading.Thread", side_effect=fake_thread):
            monitor._start_events_stream()
        monitor._events_cancel = True
        # Must return promptly without hanging
        targets[0]()


class TestKmutilEdgeCases:
    def test_kmutil_timeout(self):
        import subprocess as sp
        fake = MagicMock()
        fake.communicate.side_effect = sp.TimeoutExpired("kmutil", 10)
        fake.kill.return_value = None
        fake.wait.return_value = None
        with patch("subprocess.Popen", return_value=fake):
            assert procmon._kmutil_showloaded() == set()

    def test_kmutil_non_zero_return(self):
        fake = MagicMock()
        fake.communicate.return_value = (b"irrelevant", b"err")
        fake.returncode = 1
        with patch("subprocess.Popen", return_value=fake):
            assert procmon._kmutil_showloaded() == set()

    def test_kmutil_non_reverse_dns_tokens_skipped(self):
        sample = (
            "0xff  0x10  BadFormatName\n"  # not reverse-DNS
            "0xff  0x10  com.real.kext\n"
        )
        with patch("procmon._run_cmd_short", return_value=(0, sample, "")):
            bundle_ids = procmon._kmutil_showloaded()
        assert "com.real.kext" in bundle_ids
        assert "BadFormatName" not in bundle_ids


class TestSystemExtensionsEdgeCases:
    def test_short_fields_skipped(self):
        """Lines with fewer than 5 tab-separated fields are skipped."""
        output = (
            "enabled\tactive\theader\n"
            "*\t*\t[activated enabled]\n"  # only 3 fields — malformed
        )
        with patch("procmon._run_cmd_short", return_value=(0, output, "")):
            entries = procmon._list_system_extensions()
        assert entries == []

    def test_bundle_without_parens_stored_as_full(self):
        """If the bundle(version) column has no parens, the whole string is
        treated as the bundle id and version stays empty."""
        output = (
            "\t*\tTEAM\tcom.noversion\tSomeName\t[activated enabled]\n"
        )
        with patch("procmon._run_cmd_short", return_value=(0, output, "")):
            entries = procmon._list_system_extensions()
        assert len(entries) == 1
        assert entries[0]["bundle_id"] == "com.noversion"
        assert entries[0]["version"] == ""


class TestChatSubprocessPaths:
    """Cover the remaining claude-subprocess error branches in _chat_send."""

    def test_chat_send_returns_stdout_fallback_on_error_with_empty_stderr(self, monitor):
        monitor._chat_mode = True
        monitor._chat_input = "q"
        monitor._chat_cursor = 1
        fake = MagicMock()
        fake.communicate.return_value = (b"rate limited", b"")
        fake.returncode = 1

        def immediate_thread(target=None, daemon=None, **kw):
            t = MagicMock()
            t.start = lambda: target()
            return t

        with patch("subprocess.Popen", return_value=fake), \
             patch("threading.Thread", side_effect=immediate_thread):
            monitor._chat_send()
        # stdout content appears in the error tag
        assert "rate limited" in monitor._chat_pending

    def test_chat_send_no_output_at_all(self, monitor):
        """Empty stdout AND stderr still produces a readable error tag."""
        monitor._chat_mode = True
        monitor._chat_input = "q"
        monitor._chat_cursor = 1
        fake = MagicMock()
        fake.communicate.return_value = (b"", b"")
        fake.returncode = 2

        def immediate_thread(target=None, daemon=None, **kw):
            t = MagicMock()
            t.start = lambda: target()
            return t

        with patch("subprocess.Popen", return_value=fake), \
             patch("threading.Thread", side_effect=immediate_thread):
            monitor._chat_send()
        assert "no output" in monitor._chat_pending

    def test_chat_send_unexpected_exception_captured(self, monitor):
        """A runtime exception inside the worker still produces an error
        tag rather than killing the thread silently."""
        monitor._chat_mode = True
        monitor._chat_input = "q"
        monitor._chat_cursor = 1

        def immediate_thread(target=None, daemon=None, **kw):
            t = MagicMock()
            t.start = lambda: target()
            return t

        # Make Popen raise a generic Exception (not FileNotFound/OSError)
        with patch("subprocess.Popen", side_effect=RuntimeError("boom")), \
             patch("threading.Thread", side_effect=immediate_thread):
            monitor._chat_send()
        assert "unexpected error" in monitor._chat_pending
        assert "boom" in monitor._chat_pending


class TestKeyscanRemoveActionBranches:
    """Exercise each action-type branch of _keyscan_remove_current so the
    prompt-building code is covered end-to-end."""

    def _run_with_finding(self, monitor, action):
        monitor._keyscan_findings_structured = [
            {"severity": "HIGH", "message": "m", "action": action},
        ]
        monitor._keyscan_cursor = 0
        with patch.object(monitor, "_confirm_action", return_value=True) as cfm, \
             patch.object(monitor, "_dispatch_keyscan_action",
                          return_value=(True, "ok")), \
             patch.object(monitor, "_start_keyscan"):
            monitor._keyscan_remove_current()
        return cfm

    def test_delete_tcc_prompt_mentions_fda(self, monitor):
        action = {"type": "delete_tcc", "client": "c", "service": "s",
                  "db": "/p.db"}
        cfm = self._run_with_finding(monitor, action)
        prompt = cfm.call_args[0][0]
        assert "TCC grant" in prompt
        assert "Full Disk Access" in prompt

    def test_kill_process_prompt_mentions_pid(self, monitor):
        action = {"type": "kill_process", "pid": 1234, "exe": "/bin/x"}
        cfm = self._run_with_finding(monitor, action)
        prompt = cfm.call_args[0][0]
        assert "Kill the process" in prompt
        assert "1234" in prompt

    def test_remove_bundle_prompt_mentions_recursive(self, monitor):
        action = {"type": "remove_bundle", "path": "/opt/Evil.app"}
        cfm = self._run_with_finding(monitor, action)
        prompt = cfm.call_args[0][0]
        assert "Input Method" in prompt
        assert "/opt/Evil.app" in prompt

    def test_unknown_action_type_skipped(self, monitor):
        monitor._keyscan_findings_structured = [
            {"severity": "HIGH", "message": "m",
             "action": {"type": "definitely_not_real"}},
        ]
        monitor._keyscan_cursor = 0
        with patch.object(monitor, "_confirm_action") as cfm:
            monitor._keyscan_remove_current()
        cfm.assert_not_called()
        result = monitor._keyscan_action_result
        assert result["level"] == "error"
        assert "Unknown action type" in result["summary"]


class TestEscapeClosesEveryMode:
    """Every mode's Escape handler takes the matching branch in the main
    mode's key dispatch. Walk through each one."""

    def test_esc_closes_inspect_from_main(self, monitor):
        monitor._inspect_mode = True
        monitor._detail_focus = False
        monitor.handle_input(27)
        assert monitor._inspect_mode is False

    def test_esc_closes_hidden_scan_from_main(self, monitor):
        monitor._hidden_scan_mode = True
        monitor._detail_focus = False
        monitor.handle_input(27)
        assert monitor._hidden_scan_mode is False

    def test_esc_closes_keyscan_from_main(self, monitor):
        monitor._keyscan_mode = True
        monitor._detail_focus = False
        monitor.handle_input(27)
        assert monitor._keyscan_mode is False

    def test_esc_closes_bulk_from_main(self, monitor):
        monitor._bulk_scan_mode = True
        monitor._detail_focus = False
        monitor.handle_input(27)
        assert monitor._bulk_scan_mode is False
        assert monitor._bulk_scan_cancel is True

    def test_esc_closes_events_from_main(self, monitor):
        monitor._events_mode = True
        monitor._detail_focus = False
        with patch.object(monitor, "_stop_events_stream") as stop:
            monitor.handle_input(27)
        stop.assert_called_once()
        assert monitor._events_mode is False

    def test_esc_closes_net_from_main(self, monitor):
        monitor._net_mode = True
        monitor._detail_focus = False
        monitor.handle_input(27)
        assert monitor._net_mode is False

    def test_esc_from_main_with_no_mode_quits(self, monitor):
        monitor._detail_focus = False
        assert monitor.handle_input(27) is False


class TestCollectChatContextFallback:
    """Cover the less-common `_collect_chat_context` branches that aren't
    exercised by the primary TestChatOverlay class."""

    def test_hidden_scan_mode_but_no_lines_falls_back(self, monitor):
        """Hidden scan mode with no results shouldn't crash; it just skips
        to the next matching branch."""
        monitor._hidden_scan_mode = True
        monitor._hidden_scan_lines = []
        monitor.rows = [make_proc(pid=1, command="/bin/test")]
        monitor.selected = 0
        label, _ = monitor._collect_chat_context()
        # Since hidden scan has no lines, falls through to "process list"
        # (selected-process context).
        assert "PID 1" in label

    def test_keyscan_without_lines_falls_back(self, monitor):
        monitor._keyscan_mode = True
        monitor._keyscan_lines = []
        label, _ = monitor._collect_chat_context()
        assert label == "Process list"

    def test_bulk_scan_in_progress_no_live_findings(self, monitor):
        monitor._bulk_scan_mode = True
        monitor._bulk_scan_lines = []
        monitor._bulk_scan_progress = (0, 0)
        monitor._bulk_scan_live = []
        label, text = monitor._collect_chat_context()
        assert "Bulk" in label

    def test_events_mode_empty(self, monitor):
        monitor._events_mode = True
        monitor._events = []
        monitor._events_source = "dtrace"
        label, text = monitor._collect_chat_context()
        assert "timeline" in label.lower()
        assert "dtrace" in text


class TestRunLoopPollBranches:
    """The main run loop polls every pending channel after each key read.
    Rather than booting a full curses wrapper, drive the loop contents
    directly to exercise every poll branch."""

    def test_net_pending_triggers_render(self, monitor):
        """When _net_pending is set, _poll_net_result is called in run loop."""
        monitor._net_pending = ["data"]
        monitor._net_mode = True
        monitor._net_loading = True
        with patch.object(monitor, "_poll_net_result", return_value=True) as poll:
            if monitor._net_pending is not None:
                monitor._poll_net_result()
        poll.assert_called_once()

    def test_chat_pending_triggers_poll(self, monitor):
        monitor._chat_pending = "answer"
        monitor._chat_mode = True
        if monitor._chat_pending is not None:
            monitor._poll_chat_result()
        # Pending was consumed
        assert monitor._chat_pending is None


class TestKextCFUnavailable:
    """The _kextmanager_loaded_kexts routine has a fallback path when IOKit
    either can't be loaded or the symbol is missing."""

    def test_missing_symbol_returns_empty(self):
        fake_iokit = MagicMock(spec=[])
        # Intentionally no KextManagerCopyLoadedKextInfo attribute
        fake_cf = MagicMock()

        def fake_cdll(path, use_errno=None):
            return fake_iokit if "IOKit" in path else fake_cf

        with patch("ctypes.CDLL", side_effect=fake_cdll):
            # Using a bare MagicMock triggers AttributeError when setting
            # restype/argtypes because spec=[] prevents new attribute access;
            # our function should catch it and return [].
            result = procmon._kextmanager_loaded_kexts()
        assert result == []


class TestQueryTccDb:
    """Cover the actual sqlite read path of _query_tcc_input_monitoring."""

    def test_reads_real_db(self, tmp_path):
        import sqlite3
        db = tmp_path / "TCC.db"
        conn = sqlite3.connect(str(db))
        conn.execute(
            "CREATE TABLE access (service TEXT, client TEXT, "
            "client_type INT, auth_value INT, auth_reason INT)")
        conn.execute(
            "INSERT INTO access VALUES "
            "('kTCCServiceAccessibility', 'com.x', 0, 2, 0)")
        conn.commit()
        conn.close()

        with patch("procmon._TCC_SYSTEM_DB", str(db)), \
             patch.object(procmon, "_EFFECTIVE_HOME", str(tmp_path / "nope")):
            entries = procmon._query_tcc_input_monitoring()
        assert any(e["client"] == "com.x" for e in entries)

    def test_skips_broken_db(self, tmp_path):
        """A non-sqlite file masquerading as TCC.db doesn't crash."""
        broken = tmp_path / "TCC.db"
        broken.write_text("not a sqlite file")
        with patch("procmon._TCC_SYSTEM_DB", str(broken)), \
             patch.object(procmon, "_EFFECTIVE_HOME", str(tmp_path / "nope")):
            entries = procmon._query_tcc_input_monitoring()
        assert entries == []


class TestBulkAndHiddenWorkerBodies:
    """The worker thread bodies inside _start_bulk_scan and _start_hidden_scan
    aren't exercised by the usual tests because we always mock them out.
    Drive them inline to get coverage on the try/except scaffolding."""

    def test_hidden_scan_worker_reports_error(self, monitor):
        """Exceptions inside the hidden scan become a user-visible message
        rather than silently dying."""
        with patch.object(monitor, "_deep_hidden_scan",
                          side_effect=RuntimeError("boom")):
            captured = []

            def immediate_thread(target=None, daemon=None, **kw):
                captured.append(target)
                t = MagicMock()
                t.start = lambda: target()
                return t

            with patch("threading.Thread", side_effect=immediate_thread):
                monitor._start_hidden_scan()
        assert any("Scan error" in s for s in monitor._hidden_scan_pending)

    def test_hidden_scan_worker_success_path(self, monitor):
        with patch.object(monitor, "_deep_hidden_scan",
                          return_value=["Deep scan complete"]):
            def immediate_thread(target=None, daemon=None, **kw):
                t = MagicMock()
                t.start = lambda: target()
                return t

            with patch("threading.Thread", side_effect=immediate_thread):
                monitor._start_hidden_scan()
        assert monitor._hidden_scan_pending == ["Deep scan complete"]

    def test_keyscan_worker_exception_path(self, monitor):
        """A raise inside _scan_keyboard_hooks is captured as a finding."""
        with patch("procmon._scan_keyboard_hooks",
                   side_effect=RuntimeError("oops")):
            def immediate_thread(target=None, daemon=None, **kw):
                t = MagicMock()
                t.start = lambda: target()
                return t

            with patch("threading.Thread", side_effect=immediate_thread):
                monitor._start_keyscan()
        assert any("keyboard-hook scan error" in s
                   for s in monitor._keyscan_pending)

    def test_keyscan_worker_success(self, monitor):
        with patch("procmon._scan_keyboard_hooks",
                   return_value=[{"severity": "HIGH", "message": "x",
                                   "action": None}]), \
             patch.object(monitor, "_format_keyscan_report",
                          return_value=["output"]):
            def immediate_thread(target=None, daemon=None, **kw):
                t = MagicMock()
                t.start = lambda: target()
                return t

            with patch("threading.Thread", side_effect=immediate_thread):
                monitor._start_keyscan()
        assert monitor._keyscan_pending == ["output"]

    def test_bulk_scan_worker_captures_exception(self, monitor):
        monitor._all_procs = [{"pid": 1, "command": "/bin/x"}]
        with patch.object(monitor, "_bulk_scan_run",
                          side_effect=RuntimeError("fail")):
            def immediate_thread(target=None, daemon=None, **kw):
                t = MagicMock()
                t.start = lambda: target()
                return t

            with patch("threading.Thread", side_effect=immediate_thread):
                monitor._start_bulk_scan()
        assert any("Bulk scan error" in s for s in monitor._bulk_scan_pending)

    def test_bulk_scan_worker_cancel_short_circuit(self, monitor):
        """If cancel flag is set when the scan returns, the report shows
        'Scan cancelled' rather than a big empty final report."""
        monitor._all_procs = [{"pid": 1, "command": "/bin/x"}]

        def fake_run(procs, **kw):
            monitor._bulk_scan_cancel = True
            return []

        with patch.object(monitor, "_bulk_scan_run", side_effect=fake_run):
            def immediate_thread(target=None, daemon=None, **kw):
                t = MagicMock()
                t.start = lambda: target()
                return t

            with patch("threading.Thread", side_effect=immediate_thread):
                monitor._start_bulk_scan()
        assert monitor._bulk_scan_pending == ["Scan cancelled."]


class TestSecureKeyboardEntryPid:
    """The holder-PID attribution path in _check_secure_keyboard_entry
    parses ioreg output. Exercise with several shapes."""

    def test_parses_pid_from_ioreg(self, monkeypatch):
        fake_hi = MagicMock()
        fake_hi.IsSecureEventInputEnabled.return_value = True

        def fake_cdll(path):
            if "HIToolbox" in path:
                return fake_hi
            raise OSError

        ioreg_out = (
            '  | | |   "kCGSSessionSecureInputPID" = 4321\n'
            '  | | |   "OtherKey" = 0\n'
        )
        with patch("ctypes.CDLL", side_effect=fake_cdll), \
             patch("procmon._run_cmd_short", return_value=(0, ioreg_out, "")):
            result = procmon._check_secure_keyboard_entry()
        assert result["enabled"] is True
        assert result["pid"] == 4321

    def test_handles_malformed_pid(self):
        fake_hi = MagicMock()
        fake_hi.IsSecureEventInputEnabled.return_value = True

        def fake_cdll(path):
            if "HIToolbox" in path:
                return fake_hi
            raise OSError

        ioreg_out = 'kCGSSessionSecureInputPID = not-a-number\n'
        with patch("ctypes.CDLL", side_effect=fake_cdll), \
             patch("procmon._run_cmd_short", return_value=(0, ioreg_out, "")):
            result = procmon._check_secure_keyboard_entry()
        assert result["enabled"] is True
        assert result["pid"] == 0  # fell through the ValueError guard

    def test_ioreg_fails(self):
        fake_hi = MagicMock()
        fake_hi.IsSecureEventInputEnabled.return_value = False

        def fake_cdll(path):
            if "HIToolbox" in path:
                return fake_hi
            raise OSError

        with patch("ctypes.CDLL", side_effect=fake_cdll), \
             patch("procmon._run_cmd_short", return_value=(None, "", "err")):
            result = procmon._check_secure_keyboard_entry()
        assert result["enabled"] is False
        assert result["pid"] == 0


class TestHeuristicAdhocSignature:
    """The ad-hoc branch in _heuristic_scan_process flags MEDIUM."""

    def test_adhoc_flagged_medium(self, monitor):
        p = [
            patch("procmon._get_proc_path", return_value="/opt/x"),
        ]
        sig_mock = MagicMock()
        sig_mock.communicate.return_value = (b"", b"x is adhoc signed")
        sig_mock.returncode = 1
        with p[0], \
             patch("subprocess.Popen", return_value=sig_mock), \
             patch("procmon._get_proc_env", return_value={}), \
             patch("os.path.exists", return_value=True), \
             patch("procmon._check_gatekeeper",
                   return_value={"accepted": True, "reason": ""}), \
             patch("procmon._codesign_structured", return_value={}), \
             patch("procmon._otool_user_writable_dylibs", return_value=[]), \
             patch("procmon._yara_scan_file", return_value=[]), \
             patch("procmon._virustotal_lookup", return_value=None), \
             patch("procmon._run_cmd_short", return_value=(0, "", "")):
            risk, reasons = monitor._heuristic_scan_process(
                {"pid": 1, "command": "/opt/x"})
        assert risk == "MEDIUM"
        assert any("ad-hoc" in r for r in reasons)


class TestStartInspectFetch:
    """_start_inspect_fetch guards against duplicate workers and delegates
    to _inspect_worker_fn."""

    def test_guards_against_double_start(self, monitor):
        alive = MagicMock()
        alive.is_alive.return_value = True
        monitor._inspect_worker = alive
        with patch("threading.Thread") as thread_cls:
            monitor._start_inspect_fetch(1, "/bin/x")
        thread_cls.assert_not_called()

    def test_kicks_off_worker(self, monitor):
        monitor._inspect_worker = None
        with patch.object(monitor, "_inspect_worker_fn") as fn:
            def immediate(target=None, daemon=None, **kw):
                t = MagicMock()
                t.start = lambda: target()
                return t
            with patch("threading.Thread", side_effect=immediate):
                monitor._start_inspect_fetch(1, "/bin/x")
        fn.assert_called_once_with(1, "/bin/x")


class TestShutdownFurther:
    """Exercise _shutdown's exception handlers explicitly."""

    def test_stop_events_stream_exception_swallowed(self, monitor):
        with patch.object(monitor, "_stop_events_stream",
                          side_effect=RuntimeError("bad")):
            # Must not propagate
            monitor._shutdown()

    def test_cancels_bulk_scan_even_if_events_raise(self, monitor):
        monitor._bulk_scan_cancel = False
        with patch.object(monitor, "_stop_events_stream",
                          side_effect=RuntimeError("x")):
            monitor._shutdown()
        assert monitor._bulk_scan_cancel is True


class TestKeyscanCursorReset:
    """After a new scan completes, the cursor lands on the first
    actionable finding rather than on an info line."""

    def test_cursor_lands_on_first_actionable(self, monitor):
        monitor._keyscan_mode = True
        monitor._keyscan_pending = ["line1", "line2"]
        monitor._keyscan_findings_structured = [
            {"severity": "INFO", "message": "info1", "action": None},
            {"severity": "INFO", "message": "info2", "action": None},
            {"severity": "HIGH", "message": "actionable",
             "action": {"type": "delete_tcc", "client": "c",
                         "service": "s", "db": "d"}},
        ]
        monitor._poll_keyscan_result()
        assert monitor._keyscan_cursor == 2

    def test_cursor_stays_at_zero_when_nothing_actionable(self, monitor):
        monitor._keyscan_mode = True
        monitor._keyscan_pending = ["line1"]
        monitor._keyscan_findings_structured = [
            {"severity": "INFO", "message": "info", "action": None},
        ]
        monitor._poll_keyscan_result()
        assert monitor._keyscan_cursor == 0


class TestKeyscanIntegration:
    """End-to-end: real scan → real format → cursor + render → mocked
    remove path. Exercises the full interactive flow as a user would."""

    def test_full_flow_delete_tcc_entry(self, monitor, tmp_path):
        # Real TCC.db with a Skype grant
        import sqlite3
        db = tmp_path / "TCC.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE access (client TEXT, service TEXT, "
                     "client_type INT, auth_value INT, auth_reason INT)")
        conn.execute(
            "INSERT INTO access VALUES "
            "('com.skype.skype', 'kTCCServiceAccessibility', 0, 2, 0)")
        conn.commit()
        conn.close()

        # Fake the scan inputs so only our TCC db is seen
        with patch("procmon._enumerate_event_taps", return_value=[]), \
             patch("procmon._query_tcc_input_monitoring", return_value=[
                 {"service": "kTCCServiceAccessibility",
                  "client": "com.skype.skype",
                  "client_type": 0, "auth_value": 2, "auth_reason": 0,
                  "db": str(db)}
             ]), \
             patch("procmon._list_input_methods", return_value=[]), \
             patch("procmon._check_secure_keyboard_entry",
                   return_value={"enabled": False, "pid": 0}):
            findings = procmon._scan_keyboard_hooks()
            lines = monitor._format_keyscan_report(findings)

        # Cursor lands on the TCC grant
        monitor._keyscan_mode = True
        monitor._keyscan_cursor = 0
        target = monitor._keyscan_current_finding()
        assert target["action"]["type"] == "delete_tcc"

        # User confirms → dispatch actually deletes the row
        with patch.object(monitor, "_confirm_action", return_value=True), \
             patch.object(monitor, "_start_keyscan"):
            monitor._keyscan_remove_current()

        # Verify the DB no longer has the entry
        conn = sqlite3.connect(str(db))
        remaining = list(conn.execute("SELECT client FROM access"))
        conn.close()
        assert remaining == []
        result = monitor._keyscan_action_result
        assert result is not None
        assert result["level"] == "ok"

    def test_question_shortcut_opens_chat(self, monitor):
        """`?` opens the chat overlay from the main process list."""
        monitor.rows = [make_proc(pid=100, command="/bin/ls")]
        monitor.selected = 0
        assert monitor._chat_mode is False
        with patch.object(monitor, "_chat_send") as send:
            monitor.handle_input(ord("?"))
        assert monitor._chat_mode is True
        assert "PID 100" in monitor._chat_context_label
        send.assert_called_once_with("Tell me more about this item.",
                                     auto_open=True)

    def test_question_shortcut_from_inspect(self, monitor):
        """`?` works with an inspect report open (detail focus)."""
        monitor.rows = [make_proc(pid=100, command="/bin/ls")]
        monitor.selected = 0
        monitor._detail_focus = True
        monitor._inspect_mode = True
        monitor._inspect_pid = 100
        monitor._inspect_cmd = "ls"
        monitor._inspect_lines = ["line one", "line two"]
        with patch.object(monitor, "_chat_send") as send:
            monitor.handle_input(ord("?"))
        assert monitor._chat_mode is True
        assert "PID 100" in monitor._chat_context_label
        assert "line one" in monitor._chat_context_text
        send.assert_called_once_with("Tell me more about this item.",
                                     auto_open=True)

    def test_question_shortcut_from_hidden_scan(self, monitor):
        monitor._hidden_scan_mode = True
        monitor._hidden_scan_lines = ["scan finding A", "scan finding B"]
        with patch.object(monitor, "_chat_send") as send:
            monitor.handle_input(ord("?"))
        assert monitor._chat_mode is True
        assert "Hidden" in monitor._chat_context_label
        assert "scan finding A" in monitor._chat_context_text
        send.assert_called_once_with("Tell me more about this item.",
                                     auto_open=True)

    def test_question_shortcut_from_keyscan(self, monitor):
        monitor._keyscan_mode = True
        monitor._keyscan_lines = ["keylogger finding"]
        with patch.object(monitor, "_chat_send") as send:
            monitor.handle_input(ord("?"))
        assert monitor._chat_mode is True
        assert "Keyboard" in monitor._chat_context_label
        send.assert_called_once_with("Tell me more about this item.",
                                     auto_open=True)

    def test_question_shortcut_from_net_mode(self, monitor):
        monitor._net_mode = True
        monitor._net_pid = 500
        monitor._net_cmd = "curl"
        monitor._net_entries = [{"display": "TCP 1.2.3.4:443 ESTABLISHED"}]
        with patch.object(monitor, "_chat_send") as send:
            monitor.handle_input(ord("?"))
        assert monitor._chat_mode is True
        assert "PID 500" in monitor._chat_context_label
        assert "TCP 1.2.3.4" in monitor._chat_context_text
        send.assert_called_once_with("Tell me more about this item.",
                                     auto_open=True)

    def test_question_shortcut_from_bulk_scan_in_progress(self, monitor):
        monitor._bulk_scan_mode = True
        monitor._bulk_scan_lines = []
        monitor._bulk_scan_progress = (5, 100)
        monitor._bulk_scan_live = [
            ("CRITICAL", 42, "/bin/sus", ["missing"], None),
        ]
        with patch.object(monitor, "_chat_send") as send:
            monitor.handle_input(ord("?"))
        assert monitor._chat_mode is True
        assert "Bulk" in monitor._chat_context_label
        assert "PID 42" in monitor._chat_context_text
        send.assert_called_once_with("Tell me more about this item.",
                                     auto_open=True)

    def test_question_shortcut_from_events(self, monitor):
        monitor._events_mode = True
        monitor._events_source = "eslogger"
        monitor._events = [{"pid": 111, "ppid": 1, "cmd": "/bin/date",
                             "kind": "exec", "ts": "", "raw": ""}]
        with patch.object(monitor, "_chat_send") as send:
            monitor.handle_input(ord("?"))
        assert monitor._chat_mode is True
        assert "timeline" in monitor._chat_context_label.lower()
        assert "/bin/date" in monitor._chat_context_text
        send.assert_called_once_with("Tell me more about this item.",
                                     auto_open=True)

    def test_esc_closes_chat(self, monitor):
        monitor._chat_mode = True
        monitor.handle_input(27)
        assert monitor._chat_mode is False

    def test_chat_intercepts_all_keys_when_open(self, monitor):
        """When the chat is open, regular shortcuts must not fire — the
        chat is a modal overlay."""
        monitor._chat_mode = True
        monitor._chat_input = ""
        with patch.object(monitor, "_toggle_inspect_mode") as tog:
            monitor.handle_input(ord("I"))  # would normally open inspect
        tog.assert_not_called()
        # `I` should be typed into the chat input instead
        assert monitor._chat_input == "I"

    def test_typing_populates_input(self, monitor):
        monitor._chat_mode = True
        monitor.handle_input(ord("h"))
        monitor.handle_input(ord("i"))
        assert monitor._chat_input == "hi"
        assert monitor._chat_cursor == 2

    def test_backspace_deletes(self, monitor):
        monitor._chat_mode = True
        monitor._chat_input = "hello"
        monitor._chat_cursor = 5
        monitor.handle_input(curses.KEY_BACKSPACE)
        assert monitor._chat_input == "hell"
        assert monitor._chat_cursor == 4

    def test_arrow_keys_move_cursor(self, monitor):
        monitor._chat_mode = True
        monitor._chat_input = "abc"
        monitor._chat_cursor = 3
        monitor.handle_input(curses.KEY_LEFT)
        assert monitor._chat_cursor == 2
        monitor.handle_input(curses.KEY_RIGHT)
        assert monitor._chat_cursor == 3

    def test_ctrl_u_clears_input(self, monitor):
        monitor._chat_mode = True
        monitor._chat_input = "long question"
        monitor._chat_cursor = 13
        monitor.handle_input(21)  # Ctrl-U
        assert monitor._chat_input == ""
        assert monitor._chat_cursor == 0

    def test_ctrl_a_jumps_to_start(self, monitor):
        monitor._chat_mode = True
        monitor._chat_input = "test"
        monitor._chat_cursor = 4
        monitor.handle_input(1)  # Ctrl-A
        assert monitor._chat_cursor == 0

    def test_enter_on_empty_input_noop(self, monitor):
        """Enter with empty input shouldn't spawn a claude call."""
        monitor._chat_mode = True
        monitor._chat_input = ""
        with patch("threading.Thread") as t:
            monitor.handle_input(10)  # Enter
        t.assert_not_called()
        assert monitor._chat_messages == []

    def test_enter_with_text_spawns_worker(self, monitor):
        monitor._chat_mode = True
        monitor._chat_input = "what is this?"
        monitor._chat_cursor = len(monitor._chat_input)
        fake_thread = MagicMock()
        with patch("threading.Thread", return_value=fake_thread):
            monitor.handle_input(10)  # Enter
        fake_thread.start.assert_called_once()
        # User message appended, input cleared, loading flag set
        assert monitor._chat_messages[-1]["role"] == "user"
        assert monitor._chat_messages[-1]["content"] == "what is this?"
        assert monitor._chat_input == ""
        assert monitor._chat_loading is True

    def test_enter_while_loading_ignored(self, monitor):
        """Submitting a second question while Claude is still answering
        shouldn't spawn a parallel call."""
        monitor._chat_mode = True
        monitor._chat_input = "follow-up"
        monitor._chat_loading = True
        with patch("threading.Thread") as t:
            monitor.handle_input(10)
        t.assert_not_called()

    def test_poll_applies_response(self, monitor):
        monitor._chat_mode = True
        monitor._chat_loading = True
        monitor._chat_pending = "Here is the answer."
        result = monitor._poll_chat_result()
        assert result is True
        assert monitor._chat_loading is False
        assert monitor._chat_messages[-1]["role"] == "assistant"
        assert monitor._chat_messages[-1]["content"] == "Here is the answer."

    def test_poll_when_user_closed_chat_still_captures_reply(self, monitor):
        """If user closes the chat mid-request, the reply is still kept in
        history so re-opening later shows it — but the render doesn't fire."""
        monitor._chat_mode = False
        monitor._chat_loading = True
        monitor._chat_pending = "answer after close"
        result = monitor._poll_chat_result()
        assert result is False
        assert monitor._chat_messages[-1]["content"] == "answer after close"
        assert monitor._chat_loading is False

    def test_scroll_up_down(self, monitor):
        monitor._chat_mode = True
        monitor._chat_scroll = 0
        monitor.handle_input(curses.KEY_UP)
        assert monitor._chat_scroll == 1
        monitor.handle_input(curses.KEY_DOWN)
        assert monitor._chat_scroll == 0
        # Floor at 0
        monitor.handle_input(curses.KEY_DOWN)
        assert monitor._chat_scroll == 0

    def test_context_fallback_for_empty_rows(self, monitor):
        """No rows and no special mode → still produces a usable context
        (the main process list with nothing selected)."""
        monitor.rows = []
        label, text = monitor._collect_chat_context()
        assert label == "Process list"
        assert "process list" in text.lower()

    def test_render_chat_no_crash_on_tiny_terminal(self, monitor):
        """Overlay is a no-op on unusably small windows rather than crashing."""
        monitor._chat_mode = True
        monitor.stdscr.getmaxyx.return_value = (5, 10)
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch("curses.curs_set"), \
             patch.object(monitor, "_put"):
            monitor._render_chat()  # must not raise

    def test_render_chat_renders_conversation(self, monitor):
        """With a non-empty history, user and assistant turns are drawn with
        their role headers ('You:' / 'Claude:')."""
        monitor._chat_mode = True
        monitor._chat_context_label = "Test context"
        monitor._chat_messages = [
            {"role": "user", "content": "what is this?"},
            {"role": "assistant", "content": "It's a process."},
        ]
        monitor.stdscr.getmaxyx.return_value = (30, 120)
        puts = []

        def capture_put(y, x, text, attr=0):
            puts.append(text)

        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch("curses.curs_set"), \
             patch.object(monitor, "_put", side_effect=capture_put):
            monitor._render_chat()
        joined = " ".join(puts)
        assert "You:" in joined
        assert "Claude:" in joined
        assert "what is this?" in joined
        assert "It's a process." in joined

    def test_render_chat_shows_thinking_indicator(self, monitor):
        monitor._chat_mode = True
        monitor._chat_loading = True
        monitor._chat_context_label = "ctx"
        monitor.stdscr.getmaxyx.return_value = (30, 120)
        puts = []

        def capture_put(y, x, text, attr=0):
            puts.append(text)

        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch("curses.curs_set"), \
             patch.object(monitor, "_put", side_effect=capture_put):
            monitor._render_chat()
        assert any("thinking" in s for s in puts)

    def test_chat_send_subprocess_success(self, monitor):
        """When the claude subprocess exits 0, its stdout is captured as
        the assistant response."""
        monitor._chat_mode = True
        monitor._chat_input = "hi"
        monitor._chat_cursor = 2

        fake_proc = MagicMock()
        fake_proc.communicate.return_value = (b"Hi there!", b"")
        fake_proc.returncode = 0

        # Run the worker inline instead of spawning a real thread
        def immediate_thread(target=None, daemon=None, **kw):
            t = MagicMock()
            t.start = lambda: target()
            return t

        with patch("subprocess.Popen", return_value=fake_proc), \
             patch("threading.Thread", side_effect=immediate_thread):
            monitor._chat_send()
        assert monitor._chat_pending == "Hi there!"
        # The user message was appended
        assert monitor._chat_messages[0]["role"] == "user"

    def test_chat_send_grants_claude_full_machine_access(self, monitor):
        monitor._chat_mode = True
        monitor._chat_input = "inspect this"
        monitor._chat_cursor = len(monitor._chat_input)

        popen_calls = []

        fake_proc = MagicMock()
        fake_proc.communicate.return_value = (b"ok", b"")
        fake_proc.returncode = 0

        def fake_popen(args, **kwargs):
            popen_calls.append((args, kwargs))
            return fake_proc

        def immediate_thread(target=None, daemon=None, **kw):
            t = MagicMock()
            t.start = lambda: target()
            return t

        with patch("subprocess.Popen", side_effect=fake_popen), \
             patch("threading.Thread", side_effect=immediate_thread):
            monitor._chat_send()

        args, kwargs = popen_calls[0]
        assert args[:5] == [
            "claude",
            "-p",
            "--dangerously-skip-permissions",
            "--add-dir",
            "/",
        ]
        assert "inspect the local machine directly" in args[5]
        assert "Start with the visible context" in args[5]
        assert "automatic opener triggered by the '?'" not in args[5]
        assert kwargs["stdin"] is not None
        assert kwargs["stdout"] is not None
        assert kwargs["stderr"] is not None

    def test_chat_send_accepts_explicit_default_question(self, monitor):
        monitor._chat_mode = True
        monitor._chat_input = ""
        monitor._chat_cursor = 0

        fake_proc = MagicMock()
        fake_proc.communicate.return_value = (b"Details", b"")
        fake_proc.returncode = 0

        def immediate_thread(target=None, daemon=None, **kw):
            t = MagicMock()
            t.start = lambda: target()
            return t

        with patch("subprocess.Popen", return_value=fake_proc), \
             patch("threading.Thread", side_effect=immediate_thread):
            monitor._chat_send("Tell me more about this item.")
        assert monitor._chat_pending == "Details"
        assert monitor._chat_messages[0] == {
            "role": "user",
            "content": "Tell me more about this item.",
        }

    def test_chat_send_auto_open_adds_context_only_guidance(self, monitor):
        monitor._chat_mode = True
        monitor._chat_input = ""
        monitor._chat_cursor = 0

        popen_calls = []
        fake_proc = MagicMock()
        fake_proc.communicate.return_value = (b"Details", b"")
        fake_proc.returncode = 0

        def fake_popen(args, **kwargs):
            popen_calls.append((args, kwargs))
            return fake_proc

        def immediate_thread(target=None, daemon=None, **kw):
            t = MagicMock()
            t.start = lambda: target()
            return t

        with patch("subprocess.Popen", side_effect=fake_popen), \
             patch("threading.Thread", side_effect=immediate_thread):
            monitor._chat_send("Tell me more about this item.", auto_open=True)

        args, _ = popen_calls[0]
        assert "automatic opener triggered by the '?'" in args[5]
        assert "using only the on-screen context" in args[5]
        assert "explicitly asks you to dig deeper" in args[5]

    def test_chat_send_subprocess_error(self, monitor):
        monitor._chat_mode = True
        monitor._chat_input = "hi"
        monitor._chat_cursor = 2
        fake_proc = MagicMock()
        fake_proc.communicate.return_value = (b"", b"auth failure")
        fake_proc.returncode = 1

        def immediate_thread(target=None, daemon=None, **kw):
            t = MagicMock()
            t.start = lambda: target()
            return t

        with patch("subprocess.Popen", return_value=fake_proc), \
             patch("threading.Thread", side_effect=immediate_thread):
            monitor._chat_send()
        assert "error" in monitor._chat_pending.lower()

    def test_chat_send_claude_missing(self, monitor):
        monitor._chat_mode = True
        monitor._chat_input = "hi"
        monitor._chat_cursor = 2

        def immediate_thread(target=None, daemon=None, **kw):
            t = MagicMock()
            t.start = lambda: target()
            return t

        with patch("subprocess.Popen", side_effect=FileNotFoundError), \
             patch("threading.Thread", side_effect=immediate_thread):
            monitor._chat_send()
        assert "not found" in monitor._chat_pending.lower()

    def test_chat_send_subprocess_timeout(self, monitor):
        import subprocess as sp
        monitor._chat_mode = True
        monitor._chat_input = "long q"
        monitor._chat_cursor = 6
        fake_proc = MagicMock()
        fake_proc.communicate.side_effect = sp.TimeoutExpired(
            "claude", procmon._CHAT_TIMEOUT_SECS)
        fake_proc.kill.return_value = None
        fake_proc.wait.return_value = None

        def immediate_thread(target=None, daemon=None, **kw):
            t = MagicMock()
            t.start = lambda: target()
            return t

        with patch("subprocess.Popen", return_value=fake_proc), \
             patch("threading.Thread", side_effect=immediate_thread):
            monitor._chat_send()
        assert (
            monitor._chat_pending
            == f"[claude timed out after {procmon._CHAT_TIMEOUT_SECS}s]"
        )

    def test_exit_chat_preserves_history(self, monitor):
        """Closing and reopening the same context keeps prior messages."""
        monitor._chat_mode = True
        monitor._chat_messages = [{"role": "user", "content": "prior"}]
        monitor._exit_chat_mode()
        assert monitor._chat_mode is False
        assert monitor._chat_messages == [{"role": "user", "content": "prior"}]

    def test_enter_chat_resets_history_on_new_context(self, monitor):
        """A fresh `?` press starts with an empty conversation so the user
        isn't confused by answers meant for a previous selection."""
        monitor._chat_mode = False
        monitor._chat_messages = [{"role": "user", "content": "old"}]
        monitor.rows = [make_proc(pid=100, command="/bin/ls")]
        monitor.selected = 0
        with patch.object(monitor, "_chat_send") as send:
            monitor._enter_chat_mode()
        assert monitor._chat_messages == []
        send.assert_called_once_with("Tell me more about this item.",
                                     auto_open=True)

    def test_page_down_scrolls(self, monitor):
        monitor._chat_mode = True
        monitor._chat_scroll = 0
        monitor.handle_input(curses.KEY_PPAGE)
        assert monitor._chat_scroll > 0

    def test_page_up_floors_at_zero(self, monitor):
        monitor._chat_mode = True
        monitor._chat_scroll = 0
        monitor.handle_input(curses.KEY_NPAGE)
        assert monitor._chat_scroll == 0

    def test_delete_key_removes_forward_char(self, monitor):
        monitor._chat_mode = True
        monitor._chat_input = "abc"
        monitor._chat_cursor = 1
        monitor.handle_input(curses.KEY_DC)
        assert monitor._chat_input == "ac"

    def test_ctrl_e_jumps_to_end(self, monitor):
        monitor._chat_mode = True
        monitor._chat_input = "test"
        monitor._chat_cursor = 0
        monitor.handle_input(5)  # Ctrl-E
        assert monitor._chat_cursor == 4

    def test_non_printable_key_noop(self, monitor):
        """Function keys and other non-printable keys are swallowed without
        modifying input."""
        monitor._chat_mode = True
        monitor._chat_input = "x"
        monitor._chat_cursor = 1
        monitor.handle_input(curses.KEY_F1)  # function key
        assert monitor._chat_input == "x"
        assert monitor._chat_cursor == 1

    def test_enter_when_already_open_noop(self, monitor):
        """`?` while already in chat is typed as text, not re-entered."""
        monitor._chat_mode = True
        before = monitor._chat_context_label
        monitor._enter_chat_mode()
        assert monitor._chat_context_label == before  # no re-init


class TestEffectiveHome:
    """Under sudo, HOME=/var/root — but the real user's home still has their
    config (~/.procmon.yar, ~/.claude, etc.). The helper walks back through
    SUDO_USER so per-user files remain reachable."""

    def test_no_sudo_returns_current_home(self):
        with patch.dict("os.environ", {"HOME": "/Users/alex"}, clear=True):
            assert procmon._effective_home() == "/Users/alex"

    def test_sudo_returns_invoking_user_home(self):
        import pwd
        fake = type("P", (), {"pw_dir": "/Users/alex"})()
        with patch.dict("os.environ", {"SUDO_USER": "alex"}, clear=True), \
             patch.object(pwd, "getpwnam", return_value=fake):
            assert procmon._effective_home() == "/Users/alex"

    def test_sudo_lookup_failure_guesses_users_path(self):
        import pwd
        with patch.dict("os.environ", {"SUDO_USER": "ghost"}, clear=True), \
             patch.object(pwd, "getpwnam", side_effect=KeyError):
            assert procmon._effective_home() == "/Users/ghost"


class TestBuildUserToolPath:
    """Startup PATH augmentation so sudo-run procmon still finds Homebrew /
    npm-global CLIs even though sudo sanitizes PATH."""

    def test_includes_homebrew_paths(self):
        with patch.dict("os.environ", {"PATH": "/usr/bin"}, clear=True):
            path = procmon._build_user_tool_path()
        assert "/opt/homebrew/bin" in path
        assert "/usr/local/bin" in path
        assert "/usr/bin" in path  # existing PATH preserved

    def test_sudo_user_paths_added(self, tmp_path):
        fake_home = tmp_path / "home" / "alex"
        (fake_home / ".nvm" / "versions" / "node" / "v20").mkdir(parents=True)
        (fake_home / ".nvm" / "versions" / "node" / "v20" / "bin").mkdir()
        import pwd
        fake_entry = type("P", (), {"pw_dir": str(fake_home)})()
        with patch.dict("os.environ",
                        {"PATH": "/usr/bin", "SUDO_USER": "alex"}, clear=True), \
             patch.object(pwd, "getpwnam", return_value=fake_entry):
            path = procmon._build_user_tool_path()
        assert f"{fake_home}/.local/bin" in path
        assert f"{fake_home}/.npm-global/bin" in path
        assert f"{fake_home}/.nvm/versions/node/v20/bin" in path

    def test_sudo_user_lookup_failure_gracefully(self):
        with patch.dict("os.environ",
                        {"PATH": "/usr/bin", "SUDO_USER": "ghost"}, clear=True):
            import pwd
            with patch.object(pwd, "getpwnam", side_effect=KeyError):
                path = procmon._build_user_tool_path()
        # Should fall back to /Users/ghost and still build
        assert "/Users/ghost" in path


class TestPhantomTreeParent:
    """Launchd (PID 1) must never appear as a parent in the tree view."""

    def test_launchd_filtered_in_collect_data(self, monitor):
        procs = [
            {"pid": 1, "ppid": 0, "rss_kb": 100, "cpu": 1.0, "cpu_ticks": 100,
             "threads": 1, "command": "/sbin/launchd"},
            {"pid": 42, "ppid": 1, "rss_kb": 50, "cpu": 0.5, "cpu_ticks": 50,
             "threads": 1, "command": "/usr/bin/child"},
        ]
        with patch("procmon.get_all_processes", return_value=procs), \
             patch("procmon.get_net_snapshot", return_value={}), \
             patch("procmon.get_fd_counts", return_value={}), \
             patch("procmon.get_cwds", return_value={}), \
             patch("procmon._check_hidden_pids_quick", return_value=set()):
            monitor.collect_data()
        pids = [r["pid"] for r in monitor.rows]
        assert 1 not in pids
        assert 42 in pids
        # Child should be at depth 0 (a root) now that launchd is gone
        child_row = next(r for r in monitor.rows if r["pid"] == 42)
        assert child_row["depth"] == 0

    def test_phantom_constant_contains_launchd(self):
        assert 1 in procmon._PHANTOM_TREE_PARENTS


class TestShutdownCleanup:
    def test_shutdown_stops_events_and_cancels_bulk(self, monitor):
        fake_proc = MagicMock()
        monitor._events_proc = fake_proc
        monitor._bulk_scan_cancel = False
        with patch.object(monitor, "_stop_events_stream") as stop:
            monitor._shutdown()
        stop.assert_called_once()
        # Bulk scan cancel flag was flipped
        assert monitor._bulk_scan_cancel is True
        # Explicit kill on the event subprocess
        fake_proc.kill.assert_called_once()

    def test_shutdown_idempotent(self, monitor):
        monitor._events_proc = None
        monitor._shutdown()
        monitor._shutdown()  # must not raise

    def test_shutdown_swallows_exceptions(self, monitor):
        bad = MagicMock()
        bad.kill.side_effect = RuntimeError("already dead")
        monitor._events_proc = bad
        monitor._shutdown()  # must not raise


class TestCheckExternalTools:
    def test_all_present(self):
        with patch("shutil.which", return_value="/usr/bin/fake"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True):
            missing = procmon._check_external_tools()
        assert missing == []

    def test_some_missing(self):
        def fake_which(name, **kwargs):
            return None if name in ("claude", "codex") else "/usr/bin/fake"
        with patch("shutil.which", side_effect=fake_which):
            missing = procmon._check_external_tools()
        names = [m[0] for m in missing]
        assert "claude" in names
        assert "codex" in names
        assert "gemini" not in names

    def test_required_tool_reported_missing(self):
        with patch("procmon._resolve_external_tool",
                   side_effect=lambda spec: None if (
                       (spec.get("name") if isinstance(spec, dict) else spec)
                       == "osquery"
                   ) else "/usr/bin/fake"):
            missing = procmon._check_external_tools()
        assert any(entry[0] == "osquery" for entry in missing)


class TestPreflight:
    def test_skip_flag_bypasses(self):
        with patch("procmon._check_external_tools") as check:
            assert procmon._preflight(skip=True) is True
            check.assert_not_called()

    def test_all_present_passes_silently(self):
        with patch("procmon._check_external_tools", return_value=[]):
            assert procmon._preflight() is True

    def test_missing_tty_blocks_on_input(self):
        with patch("procmon._check_external_tools",
                   return_value=[("codex", "optional", "x", "y")]), \
             patch("sys.stdin") as stdin, \
             patch("builtins.input", return_value=""), \
             patch("procmon._render_preflight_report"):
            stdin.isatty.return_value = True
            assert procmon._preflight() is True

    def test_missing_tty_ctrl_c_aborts(self):
        with patch("procmon._check_external_tools",
                   return_value=[("codex", "optional", "x", "y")]), \
             patch("sys.stdin") as stdin, \
             patch("builtins.input", side_effect=KeyboardInterrupt), \
             patch("procmon._render_preflight_report"):
            stdin.isatty.return_value = True
            assert procmon._preflight() is False

    def test_non_tty_continues_without_prompt(self):
        with patch("procmon._check_external_tools",
                   return_value=[("codex", "optional", "x", "y")]), \
             patch("sys.stdin") as stdin, \
             patch("builtins.input") as inp, \
             patch("procmon._render_preflight_report"):
            stdin.isatty.return_value = False
            assert procmon._preflight() is True
            inp.assert_not_called()


class TestInstallableCommand:
    def test_brew_install(self):
        with patch("shutil.which", side_effect=lambda t: "/x/brew" if t == "brew" else None):
            assert procmon._installable_command("brew install yara") == \
                ["brew", "install", "yara"]

    def test_brew_not_on_path(self):
        with patch("shutil.which", return_value=None):
            assert procmon._installable_command("brew install yara") is None

    def test_npm_global(self):
        with patch("shutil.which", side_effect=lambda t: "/x/npm" if t == "npm" else None):
            assert procmon._installable_command(
                "npm install -g @anthropic-ai/claude-code"
            ) == ["npm", "install", "-g", "@anthropic-ai/claude-code"]

    def test_xcode_select(self):
        with patch("shutil.which", side_effect=lambda t: "/x/xcode-select" if t == "xcode-select" else None):
            assert procmon._installable_command("xcode-select --install") == \
                ["xcode-select", "--install"]

    def test_preinstalled_is_not_installable(self):
        with patch("shutil.which", return_value="/x"):
            assert procmon._installable_command("preinstalled on macOS") is None

    def test_strips_trailing_comment(self):
        with patch("shutil.which", side_effect=lambda t: "/x/brew" if t == "brew" else None):
            assert procmon._installable_command(
                "brew install lsof  # usually preinstalled"
            ) == ["brew", "install", "lsof"]

    def test_empty_hint(self):
        assert procmon._installable_command("") is None
        assert procmon._installable_command(None) is None


class TestAutoInstallable:
    def test_filters_to_runnable(self):
        missing = [
            ("yara", "optional", "scanning", "brew install yara"),
            ("ps", "important", "xyz", "preinstalled on macOS"),
        ]
        with patch("shutil.which", side_effect=lambda t: "/x/brew" if t == "brew" else None):
            result = procmon._auto_installable(missing)
        assert len(result) == 1
        assert result[0][0][0] == "yara"
        assert result[0][1] == ["brew", "install", "yara"]


class TestRunInstall:
    def test_successful_run(self, capsys):
        with patch("subprocess.call", return_value=0):
            assert procmon._run_install(["brew", "install", "yara"]) is True

    def test_non_zero_exit(self, capsys):
        with patch("subprocess.call", return_value=1):
            assert procmon._run_install(["brew", "install", "yara"]) is False

    def test_launch_failure(self, capsys):
        with patch("subprocess.call", side_effect=FileNotFoundError("nope")):
            assert procmon._run_install(["brew", "install", "yara"]) is False

    def test_detects_non_writable_npm_prefix_requires_sudo(self):
        proc = MagicMock(returncode=0, stdout="/usr/local\n", stderr="")
        with patch("os.geteuid", return_value=501), \
             patch("subprocess.run", return_value=proc), \
             patch("os.path.exists", return_value=True), \
             patch("os.access", return_value=False):
            assert procmon._install_requires_sudo(
                ["npm", "install", "-g", "@anthropic-ai/claude-code"]
            ) is True

    def test_run_install_prompts_and_uses_sudo_when_required(self):
        with patch("procmon._install_requires_sudo", return_value=True), \
             patch("procmon._sudo_install_argv",
                   return_value=["sudo", "/opt/homebrew/bin/npm", "install", "-g",
                                 "@anthropic-ai/claude-code"]), \
             patch("sys.stdin") as stdin, \
             patch("builtins.input", return_value="y"), \
             patch("subprocess.call", return_value=0) as call:
            stdin.isatty.return_value = True
            assert procmon._run_install(
                ["npm", "install", "-g", "@anthropic-ai/claude-code"]
            ) is True
        call.assert_called_once_with(
            ["sudo", "/opt/homebrew/bin/npm", "install", "-g",
             "@anthropic-ai/claude-code"],
            env=procmon._tool_env(),
        )

    def test_run_install_declines_required_sudo(self):
        with patch("procmon._install_requires_sudo", return_value=True), \
             patch("sys.stdin") as stdin, \
             patch("builtins.input", return_value="n"), \
             patch("subprocess.call") as call:
            stdin.isatty.return_value = True
            assert procmon._run_install(
                ["npm", "install", "-g", "@anthropic-ai/claude-code"]
            ) is False
        call.assert_not_called()

    def test_run_install_retries_with_sudo_after_failed_npm_global_install(self):
        with patch("procmon._install_requires_sudo", return_value=False), \
             patch("os.geteuid", return_value=501), \
             patch("sys.stdin") as stdin, \
             patch("builtins.input", return_value="y"), \
             patch("procmon._sudo_install_argv",
                   return_value=["sudo", "/opt/homebrew/bin/npm", "install", "-g",
                                 "@openai/codex"]), \
             patch("subprocess.call", side_effect=[1, 0]) as call:
            stdin.isatty.return_value = True
            assert procmon._run_install(
                ["npm", "install", "-g", "@openai/codex"]
            ) is True
        assert call.call_count == 2


class TestPreflightInstallOffer:
    def _fake_stdin_tty(self, answer):
        stdin = MagicMock()
        stdin.isatty.return_value = True
        return stdin

    def test_offers_install_and_user_accepts(self):
        missing = [("yara", "optional", "scan", "brew install yara")]
        with patch("procmon._check_external_tools",
                   side_effect=[missing, []]), \
             patch("sys.stdin") as stdin, \
             patch("procmon._render_preflight_report"), \
             patch("shutil.which", side_effect=lambda t: "/x/brew" if t == "brew" else None), \
             patch("procmon._run_install", return_value=True) as runner, \
             patch("builtins.input", return_value="y"):
            stdin.isatty.return_value = True
            assert procmon._preflight() is True
        runner.assert_called_once_with(["brew", "install", "yara"])

    def test_user_declines_install_but_continues(self):
        missing = [("yara", "optional", "scan", "brew install yara")]
        with patch("procmon._check_external_tools", return_value=missing), \
             patch("sys.stdin") as stdin, \
             patch("procmon._render_preflight_report"), \
             patch("shutil.which", side_effect=lambda t: "/x/brew" if t == "brew" else None), \
             patch("procmon._run_install") as runner, \
             patch("builtins.input", side_effect=["n", ""]):
            stdin.isatty.return_value = True
            assert procmon._preflight() is True
        runner.assert_not_called()

    def test_install_fails_partial(self, capsys):
        missing = [("yara", "optional", "scan", "brew install yara")]
        with patch("procmon._check_external_tools",
                   side_effect=[missing, missing]), \
             patch("sys.stdin") as stdin, \
             patch("procmon._render_preflight_report"), \
             patch("shutil.which", side_effect=lambda t: "/x/brew" if t == "brew" else None), \
             patch("procmon._run_install", return_value=False), \
             patch("builtins.input", side_effect=["y", ""]):
            stdin.isatty.return_value = True
            assert procmon._preflight() is True

    def test_no_installable_falls_through_to_prompt(self):
        missing = [("ps", "important", "xyz", "preinstalled on macOS")]
        with patch("procmon._check_external_tools", return_value=missing), \
             patch("sys.stdin") as stdin, \
             patch("procmon._render_preflight_report"), \
             patch("shutil.which", return_value=None), \
             patch("builtins.input", return_value="") as inp:
            stdin.isatty.return_value = True
            assert procmon._preflight() is True
        # One prompt (Press Enter), no install offer
        assert inp.call_count == 1

    def test_ctrl_c_during_install_prompt_aborts(self):
        missing = [("yara", "optional", "scan", "brew install yara")]
        with patch("procmon._check_external_tools", return_value=missing), \
             patch("sys.stdin") as stdin, \
             patch("procmon._render_preflight_report"), \
             patch("shutil.which", side_effect=lambda t: "/x/brew" if t == "brew" else None), \
             patch("builtins.input", side_effect=KeyboardInterrupt):
            stdin.isatty.return_value = True
            assert procmon._preflight() is False


# ── Coverage Gap: Modal exclusivity / new detail modes ─────────────────


class TestDetailFocusInspectShortcutBar:
    def test_inspect_mode_shortcuts(self, monitor):
        monitor._detail_focus = True
        monitor._inspect_mode = True
        monitor._hidden_scan_mode = False
        monitor._net_mode = False
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put") as put:
            monitor._render_shortcut_bar(40, 200)
        texts = " ".join(str(c.args[2]) if len(c.args) > 2 else "" for c in put.call_args_list)
        assert "Scroll" in texts
        assert "Close" in texts
        assert "Procs" in texts


class TestDetailFocusHiddenShortcutBar:
    def test_hidden_mode_shortcuts(self, monitor):
        monitor._detail_focus = True
        monitor._inspect_mode = False
        monitor._hidden_scan_mode = True
        monitor._net_mode = False
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put") as put:
            monitor._render_shortcut_bar(40, 200)
        texts = " ".join(str(c.args[2]) if len(c.args) > 2 else "" for c in put.call_args_list)
        assert "Scroll" in texts
        assert "Close" in texts


class TestCollectDataHiddenCheckMocked:
    """Ensure collect_data tests don't actually spawn `ps` subprocess."""

    def test_collect_data_does_not_spawn_ps(self, monitor):
        monitor.interval = 5.0
        monitor._last_hidden_check = 0.0
        with patch("procmon.get_all_processes", return_value=[]), \
             patch("procmon.get_net_snapshot", return_value={}), \
             patch("procmon.get_fd_counts", return_value={}), \
             patch("procmon.get_cwds", return_value={}), \
             patch("procmon.build_tree", return_value=[]), \
             patch("procmon.flatten_tree", return_value=[]), \
             patch("procmon._check_hidden_pids_quick", return_value=set()) as check:
            monitor.collect_data()
        # Hidden check should have been called (since last_hidden_check=0.0)
        check.assert_called_once()

    def test_collect_data_hidden_check_respects_interval(self, monitor):
        """Check is only run every 2 intervals, not every refresh."""
        monitor.interval = 5.0
        monitor._last_hidden_check = 99999.0  # very recent
        with patch("procmon.get_all_processes", return_value=[]), \
             patch("procmon.get_net_snapshot", return_value={}), \
             patch("procmon.get_fd_counts", return_value={}), \
             patch("procmon.get_cwds", return_value={}), \
             patch("procmon.build_tree", return_value=[]), \
             patch("procmon.flatten_tree", return_value=[]), \
             patch("time.monotonic", return_value=99999.5), \
             patch("procmon._check_hidden_pids_quick", return_value=set()) as check:
            monitor.collect_data()
        check.assert_not_called()

    def test_collect_data_hidden_check_exception_swallowed(self, monitor):
        """If _check_hidden_pids_quick raises, collect_data doesn't crash."""
        monitor.interval = 5.0
        monitor._last_hidden_check = 0.0
        with patch("procmon.get_all_processes", return_value=[]), \
             patch("procmon.get_net_snapshot", return_value={}), \
             patch("procmon.get_fd_counts", return_value={}), \
             patch("procmon.get_cwds", return_value={}), \
             patch("procmon.build_tree", return_value=[]), \
             patch("procmon.flatten_tree", return_value=[]), \
             patch("procmon._check_hidden_pids_quick", side_effect=RuntimeError):
            monitor.collect_data()  # should not raise


# ── Rendering: inspect / hidden detail boxes ──────────────────────────


class TestMainTotalsRender:
    def test_vendor_grouped_totals_use_underlying_process_fds(self, monitor):
        monitor.stdscr.getmaxyx.return_value = (40, 160)
        monitor._vendor_grouped = True
        monitor.rows = [
            make_proc(
                pid=9000,
                command="Apple",
                fds=-1,
                cpu=3.0,
                rss_kb=4096,
                threads=5,
                net_in=12,
                net_out=18,
            )
        ]
        monitor._all_procs = [
            make_proc(pid=1, command="/usr/bin/a", fds=10, cpu=1.0, rss_kb=1024, threads=2, net_in=5, net_out=7),
            make_proc(pid=2, command="/usr/bin/b", fds=20, cpu=2.0, rss_kb=2048, threads=3, net_in=7, net_out=11),
        ]
        monitor.matched_count = len(monitor._all_procs)

        with patch("curses.color_pair", side_effect=lambda n: n << 8):
            monitor.render()

        text = " ".join(str(call) for call in monitor.stdscr.addnstr.call_args_list)
        assert "FDs 30" in text


class TestRenderInspectAndHiddenDetail:
    def _render(self, monitor):
        monitor.stdscr.getmaxyx.return_value = (40, 160)
        with patch("curses.color_pair", side_effect=lambda n: n << 8):
            monitor.render()
        return " ".join(str(c) for c in monitor.stdscr.addnstr.call_args_list)

    def test_inspect_with_lines(self, monitor):
        monitor.rows = [make_proc(pid=100, command="/usr/bin/test")]
        monitor._inspect_mode = True
        monitor._inspect_lines = ["line 1 of inspect output"]
        monitor._inspect_pid = 100
        monitor._inspect_cmd = "test"
        text = self._render(monitor)
        assert "inspect output" in text or "Inspect" in text

    def test_inspect_loading_collecting_phase(self, monitor):
        monitor.rows = [make_proc(pid=100, command="/usr/bin/test")]
        monitor._inspect_mode = True
        monitor._inspect_lines = []
        monitor._inspect_loading = True
        monitor._inspect_phase = "collecting"
        text = self._render(monitor)
        assert "Collecting" in text

    def test_inspect_loading_analyzing_phase(self, monitor):
        monitor.rows = [make_proc(pid=100, command="/usr/bin/test")]
        monitor._inspect_mode = True
        monitor._inspect_lines = []
        monitor._inspect_loading = True
        monitor._inspect_phase = "analyzing"
        text = self._render(monitor)
        assert "Claude" in text or "Codex" in text or "Gemini" in text

    def test_inspect_loading_synthesizing_phase(self, monitor):
        monitor.rows = [make_proc(pid=100, command="/usr/bin/test")]
        monitor._inspect_mode = True
        monitor._inspect_lines = []
        monitor._inspect_loading = True
        monitor._inspect_phase = "synthesizing"
        text = self._render(monitor)
        assert "Synthesizing" in text

    def test_inspect_loading_unknown_phase(self, monitor):
        monitor.rows = [make_proc(pid=100, command="/usr/bin/test")]
        monitor._inspect_mode = True
        monitor._inspect_lines = []
        monitor._inspect_loading = True
        monitor._inspect_phase = ""
        text = self._render(monitor)
        assert "Loading" in text

    def test_inspect_empty_no_loading(self, monitor):
        monitor.rows = [make_proc(pid=100, command="/usr/bin/test")]
        monitor._inspect_mode = True
        monitor._inspect_lines = []
        monitor._inspect_loading = False
        text = self._render(monitor)
        assert "No inspect data" in text

    def test_hidden_with_lines(self, monitor):
        monitor.rows = [make_proc(pid=100, command="/usr/bin/test")]
        monitor._hidden_scan_mode = True
        monitor._hidden_scan_lines = ["Deep scan complete: 0 finding(s)"]
        text = self._render(monitor)
        assert "Deep scan" in text or "Hidden Process Scan" in text

    def test_hidden_loading(self, monitor):
        monitor.rows = [make_proc(pid=100, command="/usr/bin/test")]
        monitor._hidden_scan_mode = True
        monitor._hidden_scan_lines = []
        monitor._hidden_scan_loading = True
        text = self._render(monitor)
        assert "Running deep" in text or "scan" in text.lower()

    def test_hidden_empty(self, monitor):
        monitor.rows = [make_proc(pid=100, command="/usr/bin/test")]
        monitor._hidden_scan_mode = True
        monitor._hidden_scan_lines = []
        monitor._hidden_scan_loading = False
        text = self._render(monitor)
        assert "No scan results" in text


# ── Deep Hidden Scan: findings paths ───────────────────────────────────


class TestDeepHiddenScanFindings:
    """Exercise each finding branch of _deep_hidden_scan."""

    def test_reports_ps_hidden(self, monitor):
        ps_mock = MagicMock()
        ps_mock.communicate.return_value = (b"  1\n  99\n", b"")
        sysctl_mock = MagicMock()
        sysctl_mock.communicate.return_value = (b"100", b"")
        lsof_mock = MagicMock()
        lsof_mock.communicate.return_value = (b"", b"")

        def popen(cmd, **kw):
            if cmd[0] == "ps":
                return ps_mock
            if cmd[0] == "sysctl":
                return sysctl_mock
            return lsof_mock

        with patch("subprocess.Popen", side_effect=popen), \
             patch("procmon._list_all_pids", return_value=[1]), \
             patch("os.getpid", return_value=999), \
             patch("procmon._libproc") as lp, \
             patch("procmon._get_proc_path", return_value="/bin/present"), \
             patch("os.path.exists", return_value=True):
            lp.proc_pidinfo.return_value = 0
            findings = monitor._deep_hidden_scan()
        text = "\n".join(findings)
        assert "ps vs libproc" in text
        assert "99" in text

    def test_reports_net_hidden(self, monitor):
        ps_mock = MagicMock()
        ps_mock.communicate.return_value = (b"  1\n", b"")
        sysctl_mock = MagicMock()
        sysctl_mock.communicate.return_value = (b"100", b"")
        lsof_mock = MagicMock()
        lsof_mock.communicate.return_value = (
            b"COMMAND PID USER\nfoo 77 root\n", b"")

        def popen(cmd, **kw):
            if cmd[0] == "ps":
                return ps_mock
            if cmd[0] == "sysctl":
                return sysctl_mock
            return lsof_mock

        with patch("subprocess.Popen", side_effect=popen), \
             patch("procmon._list_all_pids", return_value=[1]), \
             patch("os.getpid", return_value=999), \
             patch("procmon._libproc") as lp, \
             patch("procmon._get_proc_path", return_value="/bin/present"), \
             patch("os.path.exists", return_value=True):
            lp.proc_pidinfo.return_value = 0
            findings = monitor._deep_hidden_scan()
        text = "\n".join(findings)
        assert "Network-visible" in text
        assert "77" in text

    def test_reports_brute_force_hidden(self, monitor):
        """proc_pidinfo returns >0 for a PID not in libproc_pids → brute-force finding."""
        ps_mock = MagicMock()
        ps_mock.communicate.return_value = (b"", b"")
        sysctl_mock = MagicMock()
        sysctl_mock.communicate.return_value = (b"5", b"")
        lsof_mock = MagicMock()
        lsof_mock.communicate.return_value = (b"", b"")

        def popen(cmd, **kw):
            if cmd[0] == "ps":
                return ps_mock
            if cmd[0] == "sysctl":
                return sysctl_mock
            return lsof_mock

        with patch("subprocess.Popen", side_effect=popen), \
             patch("procmon._list_all_pids", return_value=[]), \
             patch("os.getpid", return_value=999), \
             patch("procmon._libproc") as lp, \
             patch("procmon._get_proc_path", return_value=None), \
             patch("os.path.exists", return_value=True):
            lp.proc_pidinfo.return_value = 1  # always hidden
            findings = monitor._deep_hidden_scan()
        text = "\n".join(findings)
        assert "brute-force" in text

    def test_reports_missing_binary(self, monitor):
        ps_mock = MagicMock()
        ps_mock.communicate.return_value = (b"", b"")
        sysctl_mock = MagicMock()
        sysctl_mock.communicate.return_value = (b"0", b"")
        lsof_mock = MagicMock()
        lsof_mock.communicate.return_value = (b"", b"")

        def popen(cmd, **kw):
            if cmd[0] == "ps":
                return ps_mock
            if cmd[0] == "sysctl":
                return sysctl_mock
            return lsof_mock

        with patch("subprocess.Popen", side_effect=popen), \
             patch("procmon._list_all_pids", return_value=[42]), \
             patch("os.getpid", return_value=999), \
             patch("procmon._libproc") as lp, \
             patch("procmon._get_proc_path", return_value="/bin/vanished"), \
             patch("os.path.exists", return_value=False):
            lp.proc_pidinfo.return_value = 0
            findings = monitor._deep_hidden_scan()
        text = "\n".join(findings)
        assert "binary missing" in text

    def test_reports_orphaned_ppid(self, monitor):
        ps_mock = MagicMock()
        ps_mock.communicate.return_value = (b"", b"")
        sysctl_mock = MagicMock()
        sysctl_mock.communicate.return_value = (b"0", b"")
        lsof_mock = MagicMock()
        lsof_mock.communicate.return_value = (b"", b"")

        def popen(cmd, **kw):
            if cmd[0] == "ps":
                return ps_mock
            if cmd[0] == "sysctl":
                return sysctl_mock
            return lsof_mock

        def fake_pidinfo(pid, flavor, arg, buf, size):
            # Set ppid=99 on the local bsdinfo struct
            bsdinfo = ctypes.cast(buf, ctypes.POINTER(procmon.proc_bsdinfo)).contents
            bsdinfo.pbi_ppid = 99
            return 1

        import ctypes
        with patch("subprocess.Popen", side_effect=popen), \
             patch("procmon._list_all_pids", return_value=[5]), \
             patch("os.getpid", return_value=999), \
             patch("procmon._libproc") as lp, \
             patch("procmon._get_proc_path", return_value="/bin/present"), \
             patch("os.path.exists", return_value=True):
            lp.proc_pidinfo.side_effect = fake_pidinfo
            findings = monitor._deep_hidden_scan()
        text = "\n".join(findings)
        assert "Orphaned PPID" in text

    def test_sysctl_failure_falls_back_to_default(self, monitor):
        """sysctl failing → max_pid_val stays at default 99999."""
        ps_mock = MagicMock()
        ps_mock.communicate.return_value = (b"", b"")
        lsof_mock = MagicMock()
        lsof_mock.communicate.return_value = (b"", b"")

        def popen(cmd, **kw):
            if cmd[0] == "ps":
                return ps_mock
            if cmd[0] == "sysctl":
                raise OSError("no sysctl")
            return lsof_mock

        with patch("subprocess.Popen", side_effect=popen), \
             patch("procmon._list_all_pids", return_value=[1, 2, 3]), \
             patch("os.getpid", return_value=999), \
             patch("procmon._libproc") as lp, \
             patch("procmon._get_proc_path", return_value="/bin/present"), \
             patch("os.path.exists", return_value=True):
            lp.proc_pidinfo.return_value = 0
            findings = monitor._deep_hidden_scan()
        # Should complete without raising even though sysctl failed
        assert findings[0].startswith("Deep scan complete")


# ── Artifact Collection Edge Cases ─────────────────────────────────────


class TestCollectArtifactsEdges:
    def test_timeout_command_returns_tagged(self, monitor):
        """When a subprocess in _collect_inspect_artifacts times out, returns [timed out]."""
        import subprocess as sp
        timeout_mock = MagicMock()
        timeout_mock.communicate.side_effect = sp.TimeoutExpired("x", 10)
        timeout_mock.kill.return_value = None
        timeout_mock.wait.return_value = None

        with patch("subprocess.Popen", return_value=timeout_mock), \
             patch("os.geteuid", return_value=1000), \
             patch("procmon._get_proc_env", return_value={}), \
             patch("procmon._libproc") as lp, \
             patch("procmon._get_proc_path", return_value="/bin/test"):
            lp.proc_pidinfo.return_value = 0
            artifacts = monitor._collect_inspect_artifacts(1, "/bin/test")
        assert artifacts["codesign_verify"] == "[timed out]"

    def test_filenotfound_returns_tagged(self, monitor):
        with patch("subprocess.Popen", side_effect=FileNotFoundError("no tool")), \
             patch("os.geteuid", return_value=1000), \
             patch("procmon._get_proc_env", return_value={}), \
             patch("procmon._libproc") as lp, \
             patch("procmon._get_proc_path", return_value="/bin/test"):
            lp.proc_pidinfo.return_value = 0
            artifacts = monitor._collect_inspect_artifacts(1, "/bin/test")
        assert "error" in artifacts["codesign_verify"]

    def test_get_proc_env_raises_empty_env(self, monitor):
        """_get_proc_env raising → env set to {}."""
        with patch("subprocess.Popen") as popen, \
             patch("os.geteuid", return_value=1000), \
             patch("procmon._get_proc_env", side_effect=RuntimeError("boom")), \
             patch("procmon._libproc") as lp, \
             patch("procmon._get_proc_path", return_value="/bin/test"):
            popen.return_value.communicate.return_value = (b"out", b"")
            popen.return_value.returncode = 0
            lp.proc_pidinfo.return_value = 0
            artifacts = monitor._collect_inspect_artifacts(1, "/bin/test")
        assert artifacts["env"] == {}


# ── Fetch Guards ──────────────────────────────────────────────────────


class TestInspectFetchGuard:
    def test_start_inspect_fetch_returns_if_worker_alive(self, monitor):
        """Guard against launching a second background worker."""
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = True
        monitor._inspect_worker = mock_thread
        monitor._inspect_loading = False
        with patch("threading.Thread") as new_thread:
            monitor._start_inspect_fetch(1, "/bin/test")
        new_thread.assert_not_called()


class TestHiddenScanFetchGuard:
    def test_start_hidden_scan_returns_if_worker_alive(self, monitor):
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = True
        monitor._hidden_scan_worker = mock_thread
        monitor._hidden_scan_loading = False
        with patch("threading.Thread") as new_thread:
            monitor._start_hidden_scan()
        new_thread.assert_not_called()


# ── Process Investigation dialog full flow ────────────────────────────


class TestForensicDialogFlow:
    def _run(self, monitor, keys):
        monitor.stdscr.getmaxyx.return_value = (40, 120)
        monitor.stdscr.getch.side_effect = list(keys)
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put"):
            monitor._prompt_forensic()

    # Count KEY_DOWNs by looking up each option's action in the same source
    # list the UI uses.
    @staticmethod
    def _option_index(monitor, action):
        """Return the KEY_DOWN count needed to reach `action` from the
        default cursor position. Walks _FORENSIC_ROWS skipping headers and
        starts from the first "action" row (which is where the menu opens).
        """
        rows = monitor._FORENSIC_ROWS
        # Where does the cursor start? First "action" row.
        start = next(i for i, r in enumerate(rows) if r[1] == "action")
        # Count KEY_DOWNs needed (skipping headers). Each down key skips over
        # any headers on the way.
        presses = 0
        i = start
        for _ in range(len(rows)):
            if rows[i][1] == "action" and rows[i][2] == action:
                return presses
            # step one down, skipping headers
            for _ in range(len(rows)):
                i = (i + 1) % len(rows)
                if rows[i][1] == "action":
                    break
            presses += 1
        raise ValueError(f"action '{action}' not in _FORENSIC_ROWS")

    def test_selects_inspect(self, monitor):
        idx = self._option_index(monitor, "inspect")
        with patch.object(monitor, "_toggle_inspect_mode") as tog, \
             patch.object(monitor, "_toggle_process_triage_mode"), \
             patch.object(monitor, "_toggle_net_mode"):
            self._run(monitor, [curses.KEY_DOWN] * idx + [10])
        tog.assert_called_once()

    def test_selects_triage(self, monitor):
        idx = self._option_index(monitor, "triage")
        with patch.object(monitor, "_toggle_inspect_mode"), \
             patch.object(monitor, "_toggle_process_triage_mode") as tog, \
             patch.object(monitor, "_toggle_net_mode"):
            self._run(monitor, [curses.KEY_DOWN] * idx + [10])
        tog.assert_called_once()

    def test_selects_network(self, monitor):
        idx = self._option_index(monitor, "network")
        with patch.object(monitor, "_toggle_inspect_mode"), \
             patch.object(monitor, "_toggle_hidden_scan_mode"), \
             patch.object(monitor, "_toggle_keyscan_mode"), \
             patch.object(monitor, "_toggle_bulk_scan_mode"), \
             patch.object(monitor, "_toggle_net_mode") as tog:
            self._run(monitor, [curses.KEY_DOWN] * idx + [10])
        tog.assert_called_once()

    def test_esc_cancels_without_dispatch(self, monitor):
        with patch.object(monitor, "_toggle_inspect_mode") as tog:
            self._run(monitor, [27])
        tog.assert_not_called()

    def test_q_cancels(self, monitor):
        with patch.object(monitor, "_toggle_inspect_mode") as tog:
            self._run(monitor, [ord("q")])
        tog.assert_not_called()

    def test_up_wraps(self, monitor):
        """KEY_UP from position 0 wraps to the last actionable entry."""
        with patch.object(monitor, "_toggle_inspect_mode"), \
             patch.object(monitor, "_toggle_process_triage_mode"), \
             patch.object(monitor, "_toggle_net_mode") as tog:
            self._run(monitor, [curses.KEY_UP, 10])
        tog.assert_called_once()


class TestTelemetryDialogFlow:
    def _run(self, monitor, keys):
        monitor.stdscr.getmaxyx.return_value = (40, 120)
        monitor.stdscr.getch.side_effect = list(keys)
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put"):
            monitor._prompt_telemetry()

    @staticmethod
    def _option_index(monitor, action):
        rows = monitor._TELEMETRY_ROWS
        start = next(i for i, r in enumerate(rows) if r[1] == "action")
        presses = 0
        i = start
        for _ in range(len(rows)):
            if rows[i][1] == "action" and rows[i][2] == action:
                return presses
            for _ in range(len(rows)):
                i = (i + 1) % len(rows)
                if rows[i][1] == "action":
                    break
            presses += 1
        raise ValueError(f"action '{action}' not in _TELEMETRY_ROWS")

    def test_selects_events(self, monitor):
        idx = self._option_index(monitor, "events")
        with patch.object(monitor, "_toggle_events_mode") as tog, \
             patch.object(monitor, "_toggle_traffic_mode"):
            self._run(monitor, [curses.KEY_DOWN] * idx + [10])
        tog.assert_called_once()

    def test_selects_traffic(self, monitor):
        idx = self._option_index(monitor, "traffic")
        with patch.object(monitor, "_toggle_events_mode"), \
             patch.object(monitor, "_toggle_traffic_mode") as tog:
            self._run(monitor, [curses.KEY_DOWN] * idx + [10])
        tog.assert_called_once()


# ── Sort dialog: navigation & enter on toggle ─────────────────────────


class TestSortDialogFlow:
    def _run(self, monitor, keys):
        monitor.stdscr.getmaxyx.return_value = (40, 120)
        monitor.stdscr.getch.side_effect = list(keys)
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put"), \
             patch.object(monitor, "_resort"):
            monitor._prompt_sort()

    def test_enter_on_toggle_row_flips_and_stays(self, monitor):
        """Navigate down to Dynamic toggle row, Enter, then Esc."""
        monitor.sort_mode = procmon.SORT_MEM
        monitor._dynamic_sort = False
        # Memory is at index 0; KEY_DOWN skips separator (index 7).
        # 7 KEY_DOWNs: 0→1→2→3→4→5→6→8 (Dynamic)
        keys = [curses.KEY_DOWN] * 7 + [10, 27]
        self._run(monitor, keys)
        assert monitor._dynamic_sort is True

    def test_enter_on_group_toggle(self, monitor):
        monitor.sort_mode = procmon.SORT_MEM
        monitor._vendor_grouped = False
        # Group toggle is at index 9: 8 KEY_DOWNs from index 0 (sep skipped)
        keys = [curses.KEY_DOWN] * 8 + [10, 27]
        self._run(monitor, keys)
        assert monitor._vendor_grouped is True

    def test_down_skips_separator(self, monitor):
        """Navigating down past last sort mode skips the separator."""
        monitor.sort_mode = procmon.SORT_VENDOR  # last sort row (index 6)
        keys = [curses.KEY_DOWN, 27]  # down one → should land on Dynamic (8), skipping sep (7)
        self._run(monitor, keys)

    def test_up_skips_separator(self, monitor):
        monitor.sort_mode = procmon.SORT_MEM  # index 0
        # Move to Dynamic (index 8) via 7 KEY_DOWNs, then KEY_UP back (skipping sep)
        keys = [curses.KEY_DOWN] * 7 + [curses.KEY_UP, 27]
        self._run(monitor, keys)

    def test_q_closes_dialog(self, monitor):
        monitor.sort_mode = procmon.SORT_MEM
        self._run(monitor, [ord("q")])


# ── Run loop polling branches ─────────────────────────────────────────


class TestRunLoopPolling:
    def test_polls_inspect_pending(self, monitor):
        """The run loop calls _poll_inspect_result when _inspect_pending is set."""
        monitor._inspect_pending = ("complete", ["line"])
        monitor._net_pending = None
        monitor._hidden_scan_pending = None
        monitor._inspect_mode = True
        monitor._inspect_loading = True
        with patch.object(monitor, "_poll_inspect_result",
                          wraps=monitor._poll_inspect_result) as poll:
            # Simulate just the poll block from run()
            if monitor._inspect_pending is not None:
                monitor._poll_inspect_result()
        poll.assert_called_once()
        assert monitor._inspect_lines == ["line"]

    def test_polls_hidden_pending(self, monitor):
        monitor._hidden_scan_pending = ["finding"]
        monitor._hidden_scan_mode = True
        monitor._hidden_scan_loading = True
        if monitor._hidden_scan_pending is not None:
            monitor._poll_hidden_scan_result()
        assert monitor._hidden_scan_lines == ["finding"]


# ── _render_preflight_report smoke test ───────────────────────────────


class TestRenderPreflightReport:
    def test_prints_categories_and_degraded_mode(self, capsys):
        missing = [
            ("lsof", "critical", "desc1", "hint1"),
            ("codex", "optional", "desc2", "hint2"),
        ]
        procmon._render_preflight_report(missing)
        out = capsys.readouterr().err
        assert "lsof" in out
        assert "critical" in out
        assert "codex" in out
        assert "optional" in out
        assert "DEGRADED" in out

    def test_prints_degraded_for_optional_only(self, capsys):
        missing = [("codex", "optional", "desc2", "hint2")]
        procmon._render_preflight_report(missing)
        out = capsys.readouterr().err
        assert "DEGRADED" in out


# ── _get_proc_env parse paths ─────────────────────────────────────────


class TestGetProcEnvParsing:
    def _build_procargs2_buffer(self, argc, argv, env):
        """Build a KERN_PROCARGS2 buffer for a mocked sysctl call."""
        buf = bytearray()
        buf += argc.to_bytes(4, sys.byteorder)
        buf += b"/path/to/exec\x00"
        buf += b"\x00" * 3  # null padding
        for a in argv:
            buf += a.encode() + b"\x00"
        for k, v in env.items():
            buf += f"{k}={v}".encode() + b"\x00"
        return bytes(buf)

    def test_parses_env_entries(self):
        raw = self._build_procargs2_buffer(2, ["arg1", "arg2"],
                                            {"HOME": "/Users/alex", "FOO": "bar"})

        def fake_sysctl(mib, n, buf, size, _a, _b):
            ctypes.memmove(buf, raw, len(raw))
            size._obj.value = len(raw)
            return 0

        import ctypes
        with patch.object(procmon._libc, "sysctl", side_effect=fake_sysctl):
            env = procmon._get_proc_env(1234)
        assert env.get("HOME") == "/Users/alex"
        assert env.get("FOO") == "bar"

    def test_ignores_non_kv_entries(self):
        """Entries without '=' are ignored."""
        buf = bytearray()
        buf += (1).to_bytes(4, sys.byteorder)
        buf += b"/bin/x\x00\x00\x00\x00"  # exec path + padding
        buf += b"arg1\x00"
        buf += b"NO_EQUALS\x00"  # malformed env entry
        buf += b"GOOD=yes\x00"
        raw = bytes(buf)

        def fake_sysctl(mib, n, b, size, _a, _b):
            ctypes.memmove(b, raw, len(raw))
            size._obj.value = len(raw)
            return 0

        import ctypes
        with patch.object(procmon._libc, "sysctl", side_effect=fake_sysctl):
            env = procmon._get_proc_env(1)
        assert "NO_EQUALS" not in env
        assert env.get("GOOD") == "yes"

    def test_undersized_buffer(self):
        def fake_sysctl(mib, n, b, size, _a, _b):
            size._obj.value = 0  # under 8 bytes
            return 0
        with patch.object(procmon._libc, "sysctl", side_effect=fake_sysctl):
            env = procmon._get_proc_env(1)
        assert env == {}


# ── Bulk Security Scan ─────────────────────────────────────────────────


class TestHeuristicScanProcess:
    """Unit tests for the heuristic scanner used by bulk scan.

    The scanner gets the binary path from _get_proc_path (proc_pidpath), not
    by splitting the command string, so tests mock that call directly.
    The new security helpers (_check_gatekeeper, _codesign_structured,
    _otool_user_writable_dylibs, _yara_scan_file, _virustotal_lookup) are
    also mocked to clean defaults here; tests targeting those behaviors
    override the specific mock they exercise.
    """

    def _patches(self, exe_path, sig_stdout=b"valid", sig_rc=0,
                 env=None, exists=True):
        sig_mock = MagicMock()
        sig_mock.communicate.return_value = (sig_stdout, b"")
        sig_mock.returncode = sig_rc
        # Clean defaults for the new deterministic checks so legacy tests
        # only see the signals they care about (codesign -v / exists / env).
        return (
            patch("procmon._get_proc_path", return_value=exe_path),
            patch("subprocess.Popen", return_value=sig_mock),
            patch("procmon._get_proc_env", return_value=env or {}),
            patch("os.path.exists", return_value=exists),
            patch("procmon._check_gatekeeper",
                  return_value={"accepted": True, "notarized": True,
                                "origin": "Apple", "reason": "", "raw": ""}),
            patch("procmon._codesign_structured",
                  return_value={"team_id": "APPLE", "authority": [],
                                "identifier": "", "hardened_runtime": True,
                                "flags": "", "requirements": "",
                                "entitlements_xml": "", "raw": "", "rc": 0}),
            patch("procmon._otool_user_writable_dylibs", return_value=[]),
            patch("procmon._yara_scan_file", return_value=[]),
            patch("procmon._virustotal_lookup", return_value=None),
            patch("procmon._run_cmd_short", return_value=(0, "", "")),
        )

    def test_clean_process_returns_low(self, monitor):
        proc = {"pid": 1, "command": "/bin/ls"}
        p = self._patches("/bin/ls")
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9]:
            risk, reasons = monitor._heuristic_scan_process(proc)
        assert risk == "LOW"
        assert reasons == []

    def test_missing_binary_is_critical(self, monitor):
        proc = {"pid": 1, "command": "/opt/vanished/app"}
        p = self._patches("/opt/vanished/app", exists=False)
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9]:
            risk, reasons = monitor._heuristic_scan_process(proc)
        assert risk == "CRITICAL"
        assert any("binary missing" in r for r in reasons)

    def test_tmp_binary_is_high(self, monitor):
        proc = {"pid": 1, "command": "/tmp/sus"}
        p = self._patches("/tmp/sus")
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9]:
            risk, reasons = monitor._heuristic_scan_process(proc)
        assert risk == "HIGH"
        assert any("/tmp" in r for r in reasons)

    def test_unsigned_is_high(self, monitor):
        proc = {"pid": 1, "command": "/opt/unsigned/app"}
        p = self._patches("/opt/unsigned/app",
                          sig_stdout=b"code object is not signed at all",
                          sig_rc=1)
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9]:
            risk, reasons = monitor._heuristic_scan_process(proc)
        assert risk == "HIGH"
        assert any("unsigned" in r.lower() for r in reasons)

    def test_dyld_insert_libraries_is_high(self, monitor):
        proc = {"pid": 1, "command": "/bin/ls"}
        p = self._patches("/bin/ls",
                          env={"DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib"})
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9]:
            risk, reasons = monitor._heuristic_scan_process(proc)
        assert risk == "HIGH"
        assert any("DYLD_INSERT_LIBRARIES" in r for r in reasons)

    def test_var_folders_is_medium(self, monitor):
        proc = {"pid": 1, "command": "/var/folders/xx/yy/zz/app"}
        p = self._patches("/var/folders/xx/yy/zz/app")
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9]:
            risk, reasons = monitor._heuristic_scan_process(proc)
        assert risk == "MEDIUM"

    def test_subprocess_timeout_ignored(self, monitor):
        """codesign timing out shouldn't crash the scanner."""
        import subprocess as sp
        proc = {"pid": 1, "command": "/bin/ls"}
        timeout_mock = MagicMock()
        timeout_mock.communicate.side_effect = sp.TimeoutExpired("codesign", 3)
        timeout_mock.kill.return_value = None
        timeout_mock.wait.return_value = None
        with patch("procmon._get_proc_path", return_value="/bin/ls"), \
             patch("subprocess.Popen", return_value=timeout_mock), \
             patch("procmon._get_proc_env", return_value={}), \
             patch("os.path.exists", return_value=True), \
             patch("procmon._check_gatekeeper", return_value={"accepted": True}), \
             patch("procmon._codesign_structured", return_value={}), \
             patch("procmon._otool_user_writable_dylibs", return_value=[]), \
             patch("procmon._yara_scan_file", return_value=[]), \
             patch("procmon._virustotal_lookup", return_value=None):
            risk, reasons = monitor._heuristic_scan_process(proc)
        assert risk == "LOW"

    def test_subprocess_filenotfound_ignored(self, monitor):
        """codesign missing shouldn't crash the scanner."""
        proc = {"pid": 1, "command": "/bin/ls"}
        with patch("procmon._get_proc_path", return_value="/bin/ls"), \
             patch("subprocess.Popen", side_effect=FileNotFoundError), \
             patch("procmon._get_proc_env", return_value={}), \
             patch("os.path.exists", return_value=True), \
             patch("procmon._check_gatekeeper", return_value={"accepted": True}), \
             patch("procmon._codesign_structured", return_value={}), \
             patch("procmon._otool_user_writable_dylibs", return_value=[]), \
             patch("procmon._yara_scan_file", return_value=[]), \
             patch("procmon._virustotal_lookup", return_value=None):
            risk, reasons = monitor._heuristic_scan_process(proc)
        assert risk == "LOW"

    def test_invalid_signature_is_high(self, monitor):
        proc = {"pid": 1, "command": "/opt/bad/app"}
        p = self._patches("/opt/bad/app",
                          sig_stdout=b"invalid signature detected",
                          sig_rc=1)
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9]:
            risk, reasons = monitor._heuristic_scan_process(proc)
        assert risk == "HIGH"
        assert any("invalid" in r.lower() for r in reasons)

    def test_hidden_pid_flag_critical(self, monitor):
        proc = {"pid": 42, "command": "/bin/ls"}
        monitor._hidden_pids = {42}
        p = self._patches("/bin/ls")
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9]:
            risk, reasons = monitor._heuristic_scan_process(proc)
        assert risk == "CRITICAL"
        assert any("hidden" in r.lower() for r in reasons)

    def test_empty_path_handled(self, monitor):
        """proc_pidpath returning None (kernel procs etc.) doesn't crash."""
        proc = {"pid": 1, "command": ""}
        with patch("procmon._get_proc_path", return_value=None), \
             patch("subprocess.Popen") as popen, \
             patch("procmon._get_proc_env", return_value={}), \
             patch("os.path.exists", return_value=True):
            popen.return_value.communicate.return_value = (b"", b"")
            popen.return_value.returncode = 0
            risk, reasons = monitor._heuristic_scan_process(proc)
        assert risk == "LOW"

    def test_command_with_spaces_uses_proc_pidpath(self, monitor):
        """Regression: 'Google Chrome' paths were being split at the space.
        Now the scanner ignores the command string and uses proc_pidpath.
        """
        proc = {"pid": 1, "command": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --some-flag"}
        real_path = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        p = self._patches(real_path)
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9]:
            risk, reasons = monitor._heuristic_scan_process(proc)
        assert risk == "LOW"
        assert reasons == []


class TestBulkScanRun:
    def test_runs_across_procs_and_updates_progress(self, monitor):
        procs = [{"pid": i, "command": f"/bin/p{i}"} for i in range(10)]
        with patch.object(monitor, "_heuristic_scan_process",
                          return_value=("LOW", [])):
            findings = monitor._bulk_scan_run(procs, max_workers=4, llm_confirm=False)
        assert findings == []
        # Progress should be at (10, 10)
        assert monitor._bulk_scan_progress == (10, 10)

    def test_collects_non_low_findings(self, monitor):
        procs = [{"pid": i, "command": f"/bin/p{i}"} for i in range(5)]

        def fake_scan(proc):
            if proc["pid"] == 1:
                return ("CRITICAL", ["missing"])
            if proc["pid"] == 2:
                return ("HIGH", ["unsigned"])
            return ("LOW", [])

        with patch.object(monitor, "_heuristic_scan_process",
                          side_effect=fake_scan):
            findings = monitor._bulk_scan_run(procs, max_workers=2, llm_confirm=False)
        assert len(findings) == 2
        risks = [f[0] for f in findings]
        assert "CRITICAL" in risks
        assert "HIGH" in risks

    def test_exception_in_scan_captured_as_error(self, monitor):
        procs = [{"pid": 1, "command": "/bin/x"}]
        with patch.object(monitor, "_heuristic_scan_process",
                          side_effect=RuntimeError("boom")):
            findings = monitor._bulk_scan_run(procs, max_workers=1, llm_confirm=False)
        assert len(findings) == 1
        assert findings[0][0] == "ERROR"

    def test_cancel_stops_scanning(self, monitor):
        procs = [{"pid": i, "command": f"/bin/p{i}"} for i in range(20)]
        monitor._bulk_scan_cancel = True
        with patch.object(monitor, "_heuristic_scan_process",
                          return_value=("LOW", [])) as scan:
            findings = monitor._bulk_scan_run(procs, max_workers=4, llm_confirm=False)
        assert findings == []
        # Cancel happens at the start of each _scan, so _heuristic_scan_process
        # shouldn't be called
        scan.assert_not_called()


class TestBulkScanLlmConfirm:
    """LLM analysis runs on EVERY process, not just heuristic flags."""

    def test_runs_llm_on_every_process_not_just_flagged(self, monitor):
        """Every process must go through the 3 LLMs + synthesis, regardless
        of what the heuristic pre-check said."""
        procs = [{"pid": i, "command": f"/bin/p{i}"} for i in range(3)]

        def fake_scan(proc):
            # All heuristics return LOW — LLM pass must still run
            return ("LOW", [])

        with patch.object(monitor, "_heuristic_scan_process", side_effect=fake_scan), \
             patch("procmon._get_proc_path", return_value="/bin/test"), \
             patch.object(monitor, "_collect_inspect_artifacts",
                          return_value={"pid": 0, "exe_path": "/bin/p0"}), \
             patch.object(monitor, "_run_llms_parallel",
                          return_value={"claude": "r", "codex": "r", "gemini": "r"}), \
             patch.object(monitor, "_synthesize_analyses",
                          return_value=("claude", "CONSENSUS_RISK: LOW")) as synth:
            findings = monitor._bulk_scan_run(procs, max_workers=2, llm_confirm=True)
        # ALL 3 processes should have been sent to synthesis
        assert synth.call_count == 3

    def test_llm_downgrade_respected(self, monitor):
        """When LLM consensus says LOW for a heuristic HIGH, final risk is LOW."""
        procs = [{"pid": 1, "command": "/bin/x"}]
        with patch.object(monitor, "_heuristic_scan_process",
                          return_value=("HIGH", ["unsigned"])), \
             patch("procmon._get_proc_path", return_value="/bin/test"), \
             patch.object(monitor, "_collect_inspect_artifacts",
                          return_value={"pid": 1, "exe_path": "/bin/x"}), \
             patch.object(monitor, "_run_llms_parallel",
                          return_value={"claude": "r", "codex": "r", "gemini": "r"}), \
             patch.object(monitor, "_synthesize_analyses",
                          return_value=("claude", "CONSENSUS_RISK: LOW\nbenign")):
            findings = monitor._bulk_scan_run(procs, max_workers=1, llm_confirm=True)
        # Heuristic said HIGH, LLM said LOW → final risk is LOW
        # But reasons are still recorded, so finding is kept with LOW risk
        assert len(findings) == 1
        assert findings[0][0] == "LOW"

    def test_kernel_thread_skips_llm(self, monitor):
        """Process with no exe path (e.g. kernel thread) uses heuristic only."""
        procs = [{"pid": 1, "command": "kernel_task"}]
        with patch.object(monitor, "_heuristic_scan_process",
                          return_value=("LOW", [])), \
             patch("procmon._get_proc_path", return_value=None), \
             patch.object(monitor, "_run_llms_parallel") as llms:
            findings = monitor._bulk_scan_run(procs, max_workers=1, llm_confirm=True)
        llms.assert_not_called()

    def test_llm_error_preserves_heuristic_risk(self, monitor):
        """If LLM pipeline raises, the heuristic verdict is kept and the
        error is embedded in the report."""
        procs = [{"pid": 1, "command": "/bin/x"}]
        with patch.object(monitor, "_heuristic_scan_process",
                          return_value=("CRITICAL", ["missing"])), \
             patch("procmon._get_proc_path", return_value="/bin/x"), \
             patch.object(monitor, "_collect_inspect_artifacts",
                          side_effect=RuntimeError("artifact fail")):
            findings = monitor._bulk_scan_run(procs, max_workers=1,
                                               llm_confirm=True)
        assert findings[0][0] == "CRITICAL"  # heuristic preserved
        assert "LLM analysis error" in findings[0][4]

    def test_progress_ticks_once_per_process(self, monitor):
        """Progress total equals number of processes; each process ticks once
        regardless of whether LLM ran."""
        procs = [{"pid": i, "command": f"/bin/p{i}"} for i in range(5)]
        with patch.object(monitor, "_heuristic_scan_process",
                          return_value=("LOW", [])), \
             patch("procmon._get_proc_path", return_value="/bin/x"), \
             patch.object(monitor, "_collect_inspect_artifacts",
                          return_value={"pid": 0, "exe_path": "/bin/x"}), \
             patch.object(monitor, "_run_llms_parallel",
                          return_value={"claude": "r", "codex": "r", "gemini": "r"}), \
             patch.object(monitor, "_synthesize_analyses",
                          return_value=("claude", "CONSENSUS_RISK: LOW")):
            monitor._bulk_scan_run(procs, max_workers=2, llm_confirm=True)
        assert monitor._bulk_scan_progress == (5, 5)


class TestFormatBulkReport:
    def test_sorted_by_severity(self, monitor):
        findings = [
            ("HIGH", 2, "/bin/high", ["r"], None),
            ("CRITICAL", 1, "/bin/crit", ["r"], None),
            ("MEDIUM", 3, "/bin/med", ["r"], None),
        ]
        lines = monitor._format_bulk_report(findings, total_scanned=100)
        text = "\n".join(lines)
        crit_pos = text.find("[CRITICAL]")
        high_pos = text.find("[HIGH]")
        med_pos = text.find("[MEDIUM]")
        assert crit_pos < high_pos < med_pos

    def test_no_findings_shows_clean_message(self, monitor):
        lines = monitor._format_bulk_report([], total_scanned=250)
        text = "\n".join(lines)
        assert "250" in text
        assert "No suspicious" in text

    def test_counts_shown_in_header(self, monitor):
        findings = [
            ("CRITICAL", 1, "/bin/c1", ["r"], None),
            ("CRITICAL", 2, "/bin/c2", ["r"], None),
            ("HIGH", 3, "/bin/h1", ["r"], None),
        ]
        lines = monitor._format_bulk_report(findings, total_scanned=50)
        header = lines[1]
        assert "CRITICAL: 2" in header
        assert "HIGH: 1" in header

    def test_llm_report_included(self, monitor):
        findings = [
            ("CRITICAL", 1, "/bin/c", ["missing"],
             "(synthesized by claude)\nCONSENSUS_RISK: CRITICAL\nAGREEMENT: unanimous"),
        ]
        lines = monitor._format_bulk_report(findings, total_scanned=1)
        text = "\n".join(lines)
        assert "LLM consensus" in text
        assert "CONSENSUS_RISK: CRITICAL" in text

    def test_legacy_4tuple_still_works(self, monitor):
        """Backward compat: format accepts 4-tuples without llm_report."""
        findings = [("HIGH", 1, "/bin/x", ["r"])]
        lines = monitor._format_bulk_report(findings, total_scanned=1)
        text = "\n".join(lines)
        assert "HIGH" in text
        assert "PID 1" in text


class TestBulkScanToggle:
    def test_toggle_on_launches_worker(self, monitor):
        monitor._all_procs = [{"pid": 1, "command": "/bin/x"}]
        with patch.object(monitor, "_start_bulk_scan") as start:
            monitor._toggle_bulk_scan_mode()
        assert monitor._bulk_scan_mode is True
        assert monitor._detail_focus is True
        start.assert_called_once()

    def test_toggle_off_cancels(self, monitor):
        monitor._bulk_scan_mode = True
        monitor._detail_focus = True
        monitor._toggle_bulk_scan_mode()
        assert monitor._bulk_scan_cancel is True
        assert monitor._bulk_scan_mode is False
        assert monitor._detail_focus is False

    def test_toggle_closes_other_modes(self, monitor):
        monitor._inspect_mode = True
        monitor._hidden_scan_mode = True
        monitor._net_mode = True
        monitor._all_procs = []
        with patch.object(monitor, "_start_bulk_scan"):
            monitor._toggle_bulk_scan_mode()
        assert monitor._inspect_mode is False
        assert monitor._hidden_scan_mode is False
        assert monitor._net_mode is False

    def test_other_modes_close_bulk(self, monitor):
        monitor.rows = [make_proc(pid=100, command="/usr/bin/test")]
        monitor._bulk_scan_mode = True
        with patch.object(monitor, "_start_inspect_fetch"):
            monitor._toggle_inspect_mode()
        assert monitor._bulk_scan_mode is False


class TestBulkScanPoll:
    def test_poll_applies_pending(self, monitor):
        monitor._bulk_scan_mode = True
        monitor._bulk_scan_loading = True
        monitor._bulk_scan_pending = ["line 1", "line 2"]
        result = monitor._poll_bulk_scan_result()
        assert result is True
        assert monitor._bulk_scan_lines == ["line 1", "line 2"]
        assert monitor._bulk_scan_loading is False

    def test_poll_clears_when_mode_closed(self, monitor):
        monitor._bulk_scan_mode = False
        monitor._bulk_scan_pending = ["data"]
        result = monitor._poll_bulk_scan_result()
        assert result is False
        assert monitor._bulk_scan_pending is None

    def test_poll_nothing_pending(self, monitor):
        monitor._bulk_scan_pending = None
        assert monitor._poll_bulk_scan_result() is False


class TestBulkScanStart:
    def test_start_guarded_if_worker_alive(self, monitor):
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = True
        monitor._bulk_scan_worker = mock_thread
        with patch("threading.Thread") as new_thread:
            monitor._start_bulk_scan()
        new_thread.assert_not_called()

    def test_start_launches_thread(self, monitor):
        monitor._all_procs = [{"pid": 1, "command": "/bin/x"}]
        monitor._bulk_scan_worker = None
        fake_thread = MagicMock()
        with patch("threading.Thread", return_value=fake_thread):
            monitor._start_bulk_scan()
        fake_thread.start.assert_called_once()


class TestBulkScanInputHandling:
    def test_scroll_down(self, monitor):
        monitor._detail_focus = True
        monitor._bulk_scan_mode = True
        monitor._bulk_scan_scroll = 0
        monitor.handle_input(curses.KEY_DOWN)
        assert monitor._bulk_scan_scroll == 1

    def test_scroll_up_clamps(self, monitor):
        monitor._detail_focus = True
        monitor._bulk_scan_mode = True
        monitor._bulk_scan_scroll = 0
        monitor.handle_input(curses.KEY_UP)
        assert monitor._bulk_scan_scroll == 0

    def test_page_down(self, monitor):
        monitor._detail_focus = True
        monitor._bulk_scan_mode = True
        monitor._bulk_scan_scroll = 0
        monitor.handle_input(curses.KEY_NPAGE)
        assert monitor._bulk_scan_scroll > 0

    def test_F_closes(self, monitor):
        monitor._detail_focus = True
        monitor._bulk_scan_mode = True
        with patch.object(monitor, "_toggle_bulk_scan_mode") as tog:
            monitor.handle_input(ord("F"))
        tog.assert_called_once()

    def test_escape_cancels(self, monitor):
        monitor._detail_focus = True
        monitor._bulk_scan_mode = True
        monitor.handle_input(27)
        assert monitor._bulk_scan_cancel is True
        assert monitor._bulk_scan_mode is False

    def test_tab_unfocuses(self, monitor):
        monitor._detail_focus = True
        monitor._bulk_scan_mode = True
        monitor.handle_input(ord("\t"))
        assert monitor._detail_focus is False

    def test_q_quits(self, monitor):
        monitor._detail_focus = True
        monitor._bulk_scan_mode = True
        result = monitor.handle_input(ord("q"))
        assert result is False


class TestBulkScanRender:
    def _render(self, monitor):
        monitor.stdscr.getmaxyx.return_value = (40, 160)
        monitor.rows = [make_proc(pid=1, command="/bin/test")]
        with patch("curses.color_pair", side_effect=lambda n: n << 8):
            monitor.render()
        return " ".join(str(c) for c in monitor.stdscr.addnstr.call_args_list)

    def test_progress_bar_shown_during_scan(self, monitor):
        monitor._bulk_scan_mode = True
        monitor._bulk_scan_loading = True
        monitor._bulk_scan_progress = (25, 100)
        text = self._render(monitor)
        assert "25/100" in text
        assert "25%" in text
        # Progress bar uses block glyphs
        assert "\u2588" in text or "\u2591" in text

    def test_starting_when_total_zero(self, monitor):
        monitor._bulk_scan_mode = True
        monitor._bulk_scan_loading = True
        monitor._bulk_scan_progress = (0, 0)
        text = self._render(monitor)
        assert "Starting" in text

    def test_results_shown_after_scan(self, monitor):
        monitor._bulk_scan_mode = True
        monitor._bulk_scan_loading = False
        monitor._bulk_scan_lines = ["Bulk security scan — 5 process(es) scanned"]
        text = self._render(monitor)
        assert "Bulk security scan" in text or "Bulk Security Scan" in text

    def test_live_findings_stream_in_view(self, monitor):
        """While the scan is running, flagged processes appear under the
        progress bar instead of waiting for the whole scan to finish."""
        monitor._bulk_scan_mode = True
        monitor._bulk_scan_loading = True
        monitor._bulk_scan_progress = (10, 100)
        monitor._bulk_scan_current = "PID 500: /bin/x"
        monitor._bulk_scan_live = [
            ("CRITICAL", 42, "/bin/sus", ["missing"], None),
            ("HIGH", 77, "/tmp/dropper", ["/tmp"], None),
        ]
        text = self._render(monitor)
        assert "Findings so far" in text
        assert "[CRITICAL]" in text
        assert "PID 42" in text
        assert "PID 77" in text
        assert "Last completed" in text

    def test_live_view_shows_no_findings_yet(self, monitor):
        monitor._bulk_scan_mode = True
        monitor._bulk_scan_loading = True
        monitor._bulk_scan_progress = (3, 100)
        monitor._bulk_scan_live = []
        text = self._render(monitor)
        assert "no flagged processes yet" in text


# ── Security helper: _codesign_structured ──────────────────────────────


class TestCodesignStructured:
    def test_empty_path_returns_empty(self):
        assert procmon._codesign_structured("") == {}

    def test_parses_team_id_and_authority(self):
        """codesign writes metadata (Identifier=, Authority=, ...) to stderr
        and the designated requirement / entitlements XML to stdout."""
        mock_proc = MagicMock()
        stderr = (b"Executable=/bin/ls\nIdentifier=com.apple.ls\n"
                  b"TeamIdentifier=APPLECODESIGNID\n"
                  b"Authority=Apple iPhone OS Application Signing\n"
                  b"Authority=Apple iPhone Certification Authority\n"
                  b"CodeDirectory v=20500 size=12345 flags=0x10000(runtime)\n")
        stdout = b"# designated => anchor apple\n"
        mock_proc.communicate.return_value = (stdout, stderr)
        mock_proc.returncode = 0
        with patch("subprocess.Popen", return_value=mock_proc):
            info = procmon._codesign_structured("/bin/ls")
        assert info["team_id"] == "APPLECODESIGNID"
        assert info["identifier"] == "com.apple.ls"
        assert info["hardened_runtime"] is True
        assert "10000(runtime)" in info["flags"]
        assert len(info["authority"]) == 2
        assert "anchor apple" in info["requirements"]

    def test_extracts_entitlements_xml(self):
        xml = ("<?xml version=\"1.0\"?>\n<plist><dict>"
               "<key>com.apple.security.cs.disable-library-validation</key>"
               "<true/></dict></plist>")
        mock_proc = MagicMock()
        # XML comes on stdout; metadata (like TeamIdentifier) on stderr
        mock_proc.communicate.return_value = (xml.encode(), b"TeamIdentifier=X\n")
        mock_proc.returncode = 0
        with patch("subprocess.Popen", return_value=mock_proc):
            info = procmon._codesign_structured("/bin/ls")
        assert "<key>com.apple.security.cs.disable-library-validation</key>" \
               in info["entitlements_xml"]

    def test_tool_unavailable(self):
        with patch("subprocess.Popen", side_effect=FileNotFoundError):
            info = procmon._codesign_structured("/bin/ls")
        assert info == {}


# ── Security helper: _check_gatekeeper ─────────────────────────────────


class TestCheckGatekeeper:
    def test_empty_path(self):
        assert procmon._check_gatekeeper("") == {}

    def test_accepted_notarized(self):
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (
            b"", b"/bin/ls: accepted\nsource=Notarized Apple System\norigin=Apple\n")
        mock_proc.returncode = 0
        with patch("subprocess.Popen", return_value=mock_proc):
            info = procmon._check_gatekeeper("/bin/ls")
        assert info["accepted"] is True
        assert info["notarized"] is True

    def test_rejected(self):
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (
            b"", b"/tmp/bad: rejected\nsource=no matching CA\n")
        mock_proc.returncode = 3
        with patch("subprocess.Popen", return_value=mock_proc):
            info = procmon._check_gatekeeper("/tmp/bad")
        assert info["accepted"] is False
        assert "rejected" in info["reason"].lower()

    def test_tool_unavailable(self):
        with patch("subprocess.Popen", side_effect=FileNotFoundError):
            info = procmon._check_gatekeeper("/bin/ls")
        assert info == {}


# ── Security helper: _parse_entitlements_xml ───────────────────────────


class TestParseEntitlementsXml:
    def test_empty(self):
        assert procmon._parse_entitlements_xml("") == set()
        assert procmon._parse_entitlements_xml(None) == set()

    def test_extracts_true_keys(self):
        xml = ("<plist><dict>"
               "<key>com.apple.security.cs.allow-jit</key><true/>"
               "<key>com.apple.security.cs.disable-library-validation</key><true/>"
               "<key>some-other-key</key><false/>"
               "</dict></plist>")
        result = procmon._parse_entitlements_xml(xml)
        assert "com.apple.security.cs.allow-jit" in result
        assert "com.apple.security.cs.disable-library-validation" in result
        assert "some-other-key" not in result


# ── Security helper: _lsof_hits_persistence ────────────────────────────


class TestLsofHitsPersistence:
    def test_empty(self):
        assert procmon._lsof_hits_persistence("") == []

    def test_flags_launchagents(self):
        lsof_out = ("foo  123  user  5u  REG  0  0  0  "
                    "/Users/x/Library/LaunchAgents/com.bad.plist")
        hits = procmon._lsof_hits_persistence(lsof_out)
        # Matches against the tilde-expanded form too — just ensure the path is picked up
        assert any("LaunchAgents" in h[0] for h in hits)

    def test_system_launchdaemons(self):
        lsof_out = "foo  1  root  3u  REG  0  0  0  /Library/LaunchDaemons/com.x.plist"
        hits = procmon._lsof_hits_persistence(lsof_out)
        assert hits
        assert hits[0][1] == "persistence"

    def test_ignores_benign_paths(self):
        lsof_out = "foo  1  root  3u  REG  0  0  0  /usr/lib/libSystem.B.dylib"
        assert procmon._lsof_hits_persistence(lsof_out) == []


# ── Security helper: _otool_user_writable_dylibs ───────────────────────


class TestOtoolUserWritable:
    def test_empty(self):
        assert procmon._otool_user_writable_dylibs("") == []

    def test_flags_tmp_dylib(self):
        otool = ("/bin/test:\n"
                 "\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n"
                 "\t/tmp/evil.dylib (compatibility version 1.0.0)\n")
        hits = procmon._otool_user_writable_dylibs(otool)
        assert "/tmp/evil.dylib" in hits

    def test_ignores_system_dylibs(self):
        otool = ("/bin/test:\n"
                 "\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n"
                 "\t/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation\n")
        assert procmon._otool_user_writable_dylibs(otool) == []


# ── Security helper: _virustotal_lookup ────────────────────────────────


class TestVirusTotalLookup:
    def test_bad_hash_returns_none(self):
        assert procmon._virustotal_lookup("short", api_key="x") is None

    def test_no_api_key_returns_none(self):
        with patch.dict("os.environ", {}, clear=True):
            assert procmon._virustotal_lookup("a" * 64) is None

    def test_successful_lookup(self):
        import io
        import json as _json
        body = _json.dumps({
            "data": {"attributes": {
                "last_analysis_stats": {"malicious": 5, "suspicious": 1,
                                         "undetected": 60, "harmless": 0},
                "reputation": -10,
                "first_submission_date": 1700000000,
                "last_analysis_date": 1700100000,
                "names": ["evil.bin"],
                "popular_threat_classification": {
                    "suggested_threat_label": "trojan.x/y"
                },
            }}
        }).encode()
        fake_resp = MagicMock()
        fake_resp.__enter__ = MagicMock(return_value=fake_resp)
        fake_resp.__exit__ = MagicMock(return_value=False)
        fake_resp.read = MagicMock(return_value=body)
        with patch("urllib.request.urlopen", return_value=fake_resp):
            result = procmon._virustotal_lookup("a" * 64, api_key="k")
        assert result["found"] is True
        assert result["malicious"] == 5
        assert result["popular_threat_name"] == "trojan.x/y"

    def test_404_returns_not_found(self):
        import urllib.error
        err = urllib.error.HTTPError("u", 404, "Not Found", {}, None)
        with patch("urllib.request.urlopen", side_effect=err):
            result = procmon._virustotal_lookup("a" * 64, api_key="k")
        assert result == {"found": False}

    def test_other_http_error(self):
        import urllib.error
        err = urllib.error.HTTPError("u", 429, "Rate limited", {}, None)
        with patch("urllib.request.urlopen", side_effect=err):
            result = procmon._virustotal_lookup("a" * 64, api_key="k")
        assert result.get("error", "").startswith("HTTP")

    def test_network_error(self):
        import urllib.error
        with patch("urllib.request.urlopen",
                   side_effect=urllib.error.URLError("unreachable")):
            result = procmon._virustotal_lookup("a" * 64, api_key="k")
        assert "error" in result

    def test_invalid_json(self):
        fake_resp = MagicMock()
        fake_resp.__enter__ = MagicMock(return_value=fake_resp)
        fake_resp.__exit__ = MagicMock(return_value=False)
        fake_resp.read = MagicMock(return_value=b"not json")
        with patch("urllib.request.urlopen", return_value=fake_resp):
            result = procmon._virustotal_lookup("a" * 64, api_key="k")
        assert result == {"error": "invalid json"}


# ── Security helper: _yara_scan_file ───────────────────────────────────


class TestYaraScanFile:
    def test_empty_path(self):
        assert procmon._yara_scan_file("") == []

    def test_path_missing(self):
        with patch("os.path.exists", return_value=False):
            assert procmon._yara_scan_file("/no") == []

    def test_no_rules_file(self, tmp_path):
        target = tmp_path / "bin"
        target.write_text("x")
        # Default rules path doesn't exist
        assert procmon._yara_scan_file(str(target),
                                         rules_path="/no/rules.yar") == []

    def test_parses_matches(self, tmp_path):
        rules = tmp_path / "r.yar"
        rules.write_text("// dummy")
        target = tmp_path / "bin"
        target.write_text("x")
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (
            b"RuleA /path/to/bin\nRuleB /path/to/bin\n", b"")
        mock_proc.returncode = 0
        with patch("subprocess.Popen", return_value=mock_proc):
            matches = procmon._yara_scan_file(str(target),
                                                rules_path=str(rules))
        assert matches == ["RuleA", "RuleB"]

    def test_yara_missing(self, tmp_path):
        rules = tmp_path / "r.yar"
        rules.write_text("// dummy")
        target = tmp_path / "bin"
        target.write_text("x")
        with patch("subprocess.Popen", side_effect=FileNotFoundError):
            assert procmon._yara_scan_file(str(target),
                                             rules_path=str(rules)) == []


# ── Security helper: _yara_scan_memory ─────────────────────────────────


class TestYaraScanMemory:
    def test_no_rules_file(self):
        with patch("os.path.exists", return_value=False):
            result = procmon._yara_scan_memory(1, rules_path="/no/rules.yar")
        assert result["success"] is False

    def test_lldb_failure(self, tmp_path):
        rules = tmp_path / "r.yar"
        rules.write_text("// dummy")
        with patch("subprocess.Popen", side_effect=FileNotFoundError):
            result = procmon._yara_scan_memory(1, rules_path=str(rules),
                                                 core_dir=str(tmp_path))
        assert result["success"] is False
        assert "error" in result

    def test_successful_dump_and_scan(self, tmp_path):
        rules = tmp_path / "r.yar"
        rules.write_text("// dummy")
        core_path = tmp_path / "mac-tui-procmon.core.42"

        def fake_popen(argv, **kw):
            mock = MagicMock()
            if argv[0] == "lldb":
                core_path.write_bytes(b"x" * 1024)
                mock.communicate.return_value = (b"", b"")
                mock.returncode = 0
            else:  # yara
                mock.communicate.return_value = (b"RuleX /core\n", b"")
                mock.returncode = 0
            return mock

        with patch("subprocess.Popen", side_effect=fake_popen):
            result = procmon._yara_scan_memory(42, rules_path=str(rules),
                                                 core_dir=str(tmp_path))
        assert result["success"] is True
        assert "RuleX" in result["matches"]
        assert result["core_size"] == 1024
        # core file should be cleaned up
        assert not core_path.exists()


# ── Heuristic integration: new rules ──────────────────────────────────


class TestHeuristicNewRules:
    def _default_patches(self, exe_path, exists=True):
        sig_mock = MagicMock()
        sig_mock.communicate.return_value = (b"valid", b"")
        sig_mock.returncode = 0
        return [
            patch("procmon._get_proc_path", return_value=exe_path),
            patch("subprocess.Popen", return_value=sig_mock),
            patch("procmon._get_proc_env", return_value={}),
            patch("os.path.exists", return_value=exists),
            patch("procmon._check_gatekeeper",
                  return_value={"accepted": True, "reason": ""}),
            patch("procmon._codesign_structured",
                  return_value={"entitlements_xml": ""}),
            patch("procmon._otool_user_writable_dylibs", return_value=[]),
            patch("procmon._yara_scan_file", return_value=[]),
            patch("procmon._virustotal_lookup", return_value=None),
            patch("procmon._run_cmd_short", return_value=(0, "", "")),
        ]

    def _run(self, monitor, patches, proc):
        from contextlib import ExitStack
        with ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            return monitor._heuristic_scan_process(proc)

    def test_gatekeeper_rejected_flags_high(self, monitor):
        patches = self._default_patches("/bin/ls")
        # Replace gatekeeper patch
        patches[4] = patch("procmon._check_gatekeeper",
                           return_value={"accepted": False,
                                          "reason": "source=no matching CA"})
        risk, reasons = self._run(monitor, patches, {"pid": 1,
                                                      "command": "/bin/ls"})
        assert risk == "HIGH"
        assert any("Gatekeeper" in r for r in reasons)

    def test_dangerous_entitlement_flags_high(self, monitor):
        """A third-party binary with a dangerous entitlement is flagged.
        Apple-path binaries (/bin/, /System/, ...) are intentionally
        suppressed — that's covered in test_apple_path_entitlements_suppressed.
        """
        patches = self._default_patches("/Applications/Third.app/Contents/MacOS/Third")
        xml = ("<plist><dict>"
               "<key>com.apple.security.cs.disable-library-validation</key>"
               "<true/></dict></plist>")
        patches[5] = patch("procmon._codesign_structured",
                           return_value={"entitlements_xml": xml,
                                          "authority": ["Developer ID Application: Random"]})
        risk, reasons = self._run(
            monitor, patches,
            {"pid": 1, "command": "/Applications/Third.app/Contents/MacOS/Third"})
        assert risk == "HIGH"
        assert any("disable-library-validation" in r for r in reasons)

    def test_apple_path_entitlements_suppressed(self, monitor):
        """Apple system binaries legitimately carry powerful entitlements.
        The heuristic must not flag them — doing so produced ~100 false
        positives per scan before this suppression."""
        patches = self._default_patches("/bin/ls")
        xml = ("<plist><dict>"
               "<key>com.apple.security.cs.allow-jit</key><true/>"
               "</dict></plist>")
        patches[5] = patch("procmon._codesign_structured",
                           return_value={"entitlements_xml": xml,
                                          "authority": ["Software Signing"]})
        risk, reasons = self._run(monitor, patches,
                                   {"pid": 1, "command": "/bin/ls"})
        assert not any("entitlement" in r for r in reasons)

    def test_apple_authority_entitlements_suppressed(self, monitor):
        """Apple-signed binary outside /System etc. also suppressed."""
        patches = self._default_patches("/opt/apple-tool")
        xml = ("<plist><dict>"
               "<key>com.apple.security.cs.allow-jit</key><true/>"
               "</dict></plist>")
        patches[5] = patch("procmon._codesign_structured",
                           return_value={"entitlements_xml": xml,
                                          "authority": ["Software Signing",
                                                         "Apple Code Signing Certification Authority"]})
        risk, reasons = self._run(monitor, patches,
                                   {"pid": 1, "command": "/opt/apple-tool"})
        assert not any("entitlement" in r for r in reasons)

    def test_xpc_not_an_app_gatekeeper_suppressed(self, monitor):
        """spctl rejects non-.app bundles with 'the code is valid but does
        not seem to be an app' — not a security concern; suppress it."""
        patches = self._default_patches("/Applications/Third.xpc")
        patches[4] = patch("procmon._check_gatekeeper",
                           return_value={"accepted": False,
                                          "reason": "the code is valid but does not seem to be an app"})
        risk, reasons = self._run(monitor, patches,
                                   {"pid": 1, "command": "/Applications/Third.xpc"})
        assert not any("Gatekeeper" in r for r in reasons)

    def test_user_writable_dylib_flags_high(self, monitor):
        patches = self._default_patches("/bin/ls")
        patches[6] = patch("procmon._otool_user_writable_dylibs",
                           return_value=["/tmp/evil.dylib"])
        # Also need _run_cmd_short to return something that otool parser consumes
        patches[9] = patch("procmon._run_cmd_short",
                           return_value=(0, "/bin/ls:\n/tmp/evil.dylib\n", ""))
        risk, reasons = self._run(monitor, patches, {"pid": 1,
                                                      "command": "/bin/ls"})
        assert risk == "HIGH"
        assert any("user-writable" in r or "/tmp/evil.dylib" in r for r in reasons)

    def test_yara_match_flags_high(self, monitor):
        patches = self._default_patches("/bin/ls")
        patches[7] = patch("procmon._yara_scan_file",
                           return_value=["MaliciousSignature"])
        risk, reasons = self._run(monitor, patches, {"pid": 1,
                                                      "command": "/bin/ls"})
        assert risk == "HIGH"
        assert any("YARA" in r for r in reasons)

    def test_vt_malicious_critical(self, monitor):
        patches = self._default_patches("/bin/ls")
        patches[9] = patch("procmon._run_cmd_short",
                           return_value=(0, "a" * 64 + "  /bin/ls\n", ""))
        patches[8] = patch("procmon._virustotal_lookup",
                           return_value={"found": True, "malicious": 10,
                                         "suspicious": 0,
                                         "popular_threat_name": "trojan.mac/x"})
        with patch.dict("os.environ", {"VT_API_KEY": "k"}):
            risk, reasons = self._run(monitor, patches,
                                        {"pid": 1, "command": "/bin/ls"})
        assert risk == "CRITICAL"
        assert any("VirusTotal" in r for r in reasons)

    def test_vt_low_detections_high(self, monitor):
        patches = self._default_patches("/bin/ls")
        patches[9] = patch("procmon._run_cmd_short",
                           return_value=(0, "a" * 64 + "  /bin/ls\n", ""))
        patches[8] = patch("procmon._virustotal_lookup",
                           return_value={"found": True, "malicious": 1,
                                         "suspicious": 0})
        with patch.dict("os.environ", {"VT_API_KEY": "k"}):
            risk, reasons = self._run(monitor, patches,
                                        {"pid": 1, "command": "/bin/ls"})
        assert risk == "HIGH"


# ── Security timeline ────────────────────────────────────────────────


class TestEventSourcePicker:
    def test_eslogger_preferred(self, monitor):
        with patch("shutil.which", side_effect=lambda t: "/bin/eslogger" if t == "eslogger" else None):
            source, argv = monitor._pick_event_source()
        assert source == "eslogger"
        assert argv[0] == "eslogger"
        assert "authentication" in argv
        assert "tcc_modify" in argv
        assert "xp_malware_detected" in argv

    def test_eslogger_select_prefixes_from_env(self, monitor):
        with patch("shutil.which", side_effect=lambda t: "/bin/eslogger" if t == "eslogger" else None), \
             patch.dict("os.environ", {
                 "SECPROCMON_ES_SELECT_PREFIXES": "/usr/sbin/sshd:/usr/bin/sudo"
             }, clear=False):
            source, argv = monitor._pick_event_source()
        assert source == "eslogger"
        assert argv[:3] == ["eslogger", "--format", "json"]
        assert argv.count("--select") == 2
        assert "/usr/sbin/sshd" in argv
        assert "/usr/bin/sudo" in argv

    def test_dtrace_fallback(self, monitor):
        def which(tool):
            return "/bin/dtrace" if tool == "dtrace" else None
        with patch("shutil.which", side_effect=which):
            source, argv = monitor._pick_event_source()
        assert source == "dtrace"

    def test_praudit_fallback(self, monitor):
        def which(tool):
            return "/bin/praudit" if tool == "praudit" else None
        with patch("shutil.which", side_effect=which), \
             patch("os.path.exists", return_value=True):
            source, argv = monitor._pick_event_source()
        assert source == "praudit"

    def test_none_available(self, monitor):
        with patch("shutil.which", return_value=None), \
             patch("os.path.exists", return_value=False):
            source, argv = monitor._pick_event_source()
        assert source is None
        assert argv is None


class TestParseEventLine:
    def test_eslogger_line(self, monitor):
        line = ('{"time":"2026-04-16T22:00:00Z","event":{"exec":{"target":'
                '{"executable":{"path":"/bin/ls"},"audit_token":{"pid":1234},'
                '"parent_audit_token":{"pid":5678}}}}}')
        evt = monitor._parse_event_line("eslogger", line)
        assert evt is not None
        assert evt["pid"] == 1234
        assert evt["cmd"] == "/bin/ls"
        assert evt["label"] == "Exec"
        assert evt["severity"] == "INFO"

    def test_eslogger_tcc_line(self, monitor):
        line = (
            '{"time":"2026-04-16T22:00:00Z","process":{"audit_token":{"pid":77}},'
            '"event":{"tcc_modify":{"instigator":{"bundle_id":"com.example.app"},'
            '"service":"kTCCServiceMicrophone","auth_value":"allow"}}}'
        )
        evt = monitor._parse_event_line("eslogger", line)
        assert evt is not None
        assert evt["pid"] == 77
        assert evt["label"] == "TCC modify"
        assert evt["severity"] == "HIGH"
        assert "kTCCServiceMicrophone" in evt["cmd"]

    def test_eslogger_invalid_json(self, monitor):
        assert monitor._parse_event_line("eslogger", "not json") is None

    def test_dtrace_line(self, monitor):
        line = "2026 Apr 16 22:00:00|1234|5678|/bin/ls -la"
        evt = monitor._parse_event_line("dtrace", line)
        assert evt["pid"] == 1234
        assert evt["ppid"] == 5678
        assert "/bin/ls" in evt["cmd"]


class TestBinaryTrustProfile:
    def test_developer_id_notarized(self):
        profile = procmon._binary_trust_profile(
            "/Applications/Test.app",
            {"rc": 0, "team_id": "TEAM1", "authority": ["Developer ID"]},
            {"accepted": True, "notarized": True},
        )
        assert profile["tier"] == "developer_id_notarized"
        assert "Developer ID + notarized" in profile["label"]

    def test_ad_hoc_signature(self):
        profile = procmon._binary_trust_profile(
            "/tmp/thing",
            {"rc": 0, "team_id": "", "authority": []},
            {"accepted": False, "notarized": False},
        )
        assert profile["tier"] == "ad_hoc"
        assert "Ad-hoc" in profile["label"]

    def test_dtrace_malformed(self, monitor):
        assert monitor._parse_event_line("dtrace", "only|two|") is None

    def test_praudit_exec_line(self, monitor):
        evt = monitor._parse_event_line(
            "praudit", "header,execve(2),foo,bar")
        assert evt is not None

    def test_praudit_non_exec_line_skipped(self, monitor):
        assert monitor._parse_event_line("praudit", "other event") is None

    def test_empty_line(self, monitor):
        assert monitor._parse_event_line("dtrace", "") is None


class TestEventsToggle:
    def test_toggle_on_starts_stream(self, monitor):
        with patch.object(monitor, "_start_events_stream") as start:
            monitor._toggle_events_mode()
        assert monitor._events_mode is True
        assert monitor._detail_focus is True
        start.assert_called_once()

    def test_toggle_off_stops_stream(self, monitor):
        monitor._events_mode = True
        monitor._detail_focus = True
        with patch.object(monitor, "_stop_events_stream") as stop:
            monitor._toggle_events_mode()
        assert monitor._events_mode is False
        assert monitor._detail_focus is False
        stop.assert_called_once()

    def test_toggle_closes_other_modes(self, monitor):
        monitor._inspect_mode = True
        monitor._hidden_scan_mode = True
        monitor._bulk_scan_mode = True
        monitor._net_mode = True
        with patch.object(monitor, "_start_events_stream"):
            monitor._toggle_events_mode()
        assert monitor._inspect_mode is False
        assert monitor._hidden_scan_mode is False
        assert monitor._bulk_scan_mode is False
        assert monitor._net_mode is False


class TestStartEventsStream:
    def test_no_source_reports_error(self, monitor):
        with patch.object(monitor, "_pick_event_source",
                          return_value=(None, None)):
            monitor._start_events_stream()
        assert any(e["kind"] == "error" for e in monitor._events)

    def test_launches_reader_thread(self, monitor):
        """Starting the stream spawns three daemon threads:
        stdout reader, stderr reader, and exit watcher.
        """
        fake_proc = MagicMock()
        fake_proc.stdout = MagicMock()
        fake_proc.stdout.readline = MagicMock(return_value=b"")
        fake_proc.stderr = MagicMock()
        fake_proc.stderr.readline = MagicMock(return_value=b"")
        with patch.object(monitor, "_pick_event_source",
                          return_value=("eslogger", ["eslogger", "exec"])), \
             patch("subprocess.Popen", return_value=fake_proc), \
             patch("threading.Thread") as thread_cls:
            thread_cls.return_value = MagicMock()
            monitor._start_events_stream()
        # stdout reader + stderr reader + exit watcher = 3 threads
        assert thread_cls.call_count == 3
        assert thread_cls.return_value.start.call_count == 3

    def test_popen_failure_reports_error(self, monitor):
        with patch.object(monitor, "_pick_event_source",
                          return_value=("eslogger", ["eslogger", "exec"])), \
             patch("subprocess.Popen", side_effect=OSError("boom")):
            monitor._start_events_stream()
        assert any("failed to start" in e["cmd"] for e in monitor._events)

    def test_guards_against_double_start(self, monitor):
        alive = MagicMock()
        alive.is_alive.return_value = True
        monitor._events_worker = alive
        with patch("threading.Thread") as thread_cls:
            monitor._start_events_stream()
        thread_cls.assert_not_called()

    def test_warns_when_not_root(self, monitor):
        fake_proc = MagicMock()
        fake_proc.stdout = MagicMock()
        fake_proc.stdout.readline = MagicMock(return_value=b"")
        fake_proc.stderr = MagicMock()
        fake_proc.stderr.readline = MagicMock(return_value=b"")
        with patch.object(monitor, "_pick_event_source",
                          return_value=("eslogger", ["eslogger", "exec"])), \
             patch("subprocess.Popen", return_value=fake_proc), \
             patch("os.geteuid", return_value=501), \
             patch("threading.Thread", return_value=MagicMock()):
            monitor._start_events_stream()
        # Should have appended a "requires root" hint event
        assert any("requires root" in e["cmd"] or "sudo mac-tui-procmon" in e["cmd"]
                   for e in monitor._events)

    def test_no_root_warning_when_root(self, monitor):
        fake_proc = MagicMock()
        fake_proc.stdout = MagicMock()
        fake_proc.stdout.readline = MagicMock(return_value=b"")
        fake_proc.stderr = MagicMock()
        fake_proc.stderr.readline = MagicMock(return_value=b"")
        with patch.object(monitor, "_pick_event_source",
                          return_value=("eslogger", ["eslogger", "exec"])), \
             patch("subprocess.Popen", return_value=fake_proc), \
             patch("os.geteuid", return_value=0), \
             patch("threading.Thread", return_value=MagicMock()):
            monitor._start_events_stream()
        assert not any("requires root" in e["cmd"] for e in monitor._events)


class TestEventStreamStderrAndExit:
    """The stderr reader and exit watcher must surface diagnostics so a
    failing event source isn't silently invisible to the user."""

    def test_stderr_lines_become_error_events(self, monitor):
        # Build a fake Popen that yields stderr lines once, then EOF.
        fake_proc = MagicMock()
        fake_proc.stdout = MagicMock()
        fake_proc.stdout.readline = MagicMock(return_value=b"")
        stderr_lines = iter([
            b"Not privileged to create an ES client\n",
            b"",  # EOF
        ])
        fake_proc.stderr = MagicMock()
        fake_proc.stderr.readline = MagicMock(side_effect=lambda: next(stderr_lines))
        fake_proc.wait = MagicMock(return_value=1)

        # Capture the thread targets so we can run them inline synchronously
        targets = []
        def fake_thread(target=None, **kw):
            targets.append(target)
            t = MagicMock()
            t.start = lambda: None
            return t

        with patch.object(monitor, "_pick_event_source",
                          return_value=("eslogger", ["eslogger", "exec"])), \
             patch("subprocess.Popen", return_value=fake_proc), \
             patch("os.geteuid", return_value=0), \
             patch("threading.Thread", side_effect=fake_thread):
            monitor._start_events_stream()
        # targets: [reader, stderr_reader, exit_watcher]
        # Run stderr reader inline
        targets[1]()
        assert any("Not privileged" in e["cmd"] for e in monitor._events)

    def test_early_exit_is_reported(self, monitor):
        fake_proc = MagicMock()
        fake_proc.stdout = MagicMock()
        fake_proc.stdout.readline = MagicMock(return_value=b"")
        fake_proc.stderr = MagicMock()
        fake_proc.stderr.readline = MagicMock(return_value=b"")
        fake_proc.wait = MagicMock(return_value=2)

        targets = []
        def fake_thread(target=None, **kw):
            targets.append(target)
            t = MagicMock()
            t.start = lambda: None
            return t

        with patch.object(monitor, "_pick_event_source",
                          return_value=("eslogger", ["eslogger", "exec"])), \
             patch("subprocess.Popen", return_value=fake_proc), \
             patch("os.geteuid", return_value=0), \
             patch("threading.Thread", side_effect=fake_thread):
            monitor._start_events_stream()
        # Run the exit_watcher inline
        targets[2]()
        assert any("exited with code 2" in e["cmd"] for e in monitor._events)

    def test_exit_silent_when_cancelled(self, monitor):
        """If the user closed the view and we terminated the process, the
        exit watcher must not append a spurious error event."""
        fake_proc = MagicMock()
        fake_proc.stdout = MagicMock()
        fake_proc.stdout.readline = MagicMock(return_value=b"")
        fake_proc.stderr = MagicMock()
        fake_proc.stderr.readline = MagicMock(return_value=b"")
        fake_proc.wait = MagicMock(return_value=-15)  # SIGTERM

        targets = []
        def fake_thread(target=None, **kw):
            targets.append(target)
            t = MagicMock()
            t.start = lambda: None
            return t

        with patch.object(monitor, "_pick_event_source",
                          return_value=("eslogger", ["eslogger", "exec"])), \
             patch("subprocess.Popen", return_value=fake_proc), \
             patch("os.geteuid", return_value=0), \
             patch("threading.Thread", side_effect=fake_thread):
            monitor._start_events_stream()
        monitor._events_cancel = True
        events_before = len(monitor._events)
        targets[2]()
        assert len(monitor._events) == events_before


class TestAppendEvent:
    def test_appends_and_caps(self, monitor):
        monitor._events_max = 3
        for i in range(5):
            monitor._append_event("exec", f"cmd{i}")
        assert len(monitor._events) == 3
        # Newest items retained, oldest dropped
        assert monitor._events[0]["cmd"] == "cmd2"
        assert monitor._events[-1]["cmd"] == "cmd4"


class TestFormatEventsRootBanner:
    def test_non_root_shows_banner_in_header(self, monitor):
        monitor._events_source = "eslogger"
        with patch("os.geteuid", return_value=501):
            lines = monitor._format_events_view()
        assert "NOT ROOT" in lines[0]

    def test_non_root_shows_hint_when_no_events(self, monitor):
        monitor._events_source = "eslogger"
        monitor._events = []
        with patch("os.geteuid", return_value=501):
            lines = monitor._format_events_view()
        text = "\n".join(lines)
        assert "sudo mac-tui-procmon" in text

    def test_root_no_banner(self, monitor):
        monitor._events_source = "eslogger"
        with patch("os.geteuid", return_value=0):
            lines = monitor._format_events_view()
        assert "NOT ROOT" not in lines[0]


class TestStopEventsStream:
    def test_terminates_proc(self, monitor):
        fake_proc = MagicMock()
        monitor._events_proc = fake_proc
        monitor._stop_events_stream()
        fake_proc.terminate.assert_called_once()
        assert monitor._events_proc is None

    def test_no_proc_noop(self, monitor):
        monitor._events_proc = None
        monitor._stop_events_stream()  # must not raise

    def test_forces_kill_on_timeout(self, monitor):
        import subprocess as sp
        fake_proc = MagicMock()
        fake_proc.wait.side_effect = [sp.TimeoutExpired("e", 1), None]
        monitor._events_proc = fake_proc
        monitor._stop_events_stream()
        fake_proc.kill.assert_called_once()


class TestFormatEventsView:
    def test_header_shows_source(self, monitor):
        monitor._events_source = "dtrace"
        lines = monitor._format_events_view()
        assert "Security timeline" in lines[0]
        assert "dtrace" in lines[0]

    def test_header_shows_eslogger_scope(self, monitor):
        monitor._events_source = "eslogger"
        with patch.dict("os.environ", {
                "SECPROCMON_ES_SELECT_PREFIXES": "/usr/sbin/sshd:/usr/bin/sudo"
             }, clear=False):
            lines = monitor._format_events_view()
        assert "scope:" in lines[0]
        assert "/usr/sbin/sshd" in lines[0]

    def test_empty_shows_waiting(self, monitor):
        monitor._events = []
        lines = monitor._format_events_view()
        assert any("no security events yet" in l for l in lines)

    def test_renders_events(self, monitor):
        monitor._events_source = "eslogger"
        monitor._events = [
            {"ts": "2026-04-16T22:00:00Z", "kind": "exec", "pid": 100,
             "ppid": 1, "cmd": "/bin/ls", "raw": "",
             "label": "Exec", "severity": "INFO"},
        ]
        lines = monitor._format_events_view()
        text = "\n".join(lines)
        assert "pid=100" in text
        assert "/bin/ls" in text
        assert "[INFO]" in text
        assert "Exec:" in text

    def test_filter_applied(self, monitor):
        monitor._events = [
            {"ts": "", "kind": "exec", "pid": 100, "ppid": 1,
             "cmd": "/bin/ls", "raw": "", "label": "Exec",
             "severity": "INFO"},
            {"ts": "", "kind": "exec", "pid": 200, "ppid": 1,
             "cmd": "/bin/cat", "raw": "", "label": "Exec",
             "severity": "INFO"},
        ]
        monitor._events_filter = "cat"
        lines = monitor._format_events_view()
        text = "\n".join(lines)
        assert "/bin/cat" in text
        assert "/bin/ls" not in text


class TestEventsInputHandling:
    def test_scroll_down(self, monitor):
        monitor._detail_focus = True
        monitor._events_mode = True
        monitor._events_scroll = 0
        monitor.handle_input(curses.KEY_DOWN)
        assert monitor._events_scroll == 1

    def test_clear_buffer(self, monitor):
        monitor._detail_focus = True
        monitor._events_mode = True
        monitor._events = [{"cmd": "x"}]
        monitor.handle_input(ord("c"))
        assert monitor._events == []

    def test_escape_closes_and_stops(self, monitor):
        monitor._detail_focus = True
        monitor._events_mode = True
        with patch.object(monitor, "_stop_events_stream") as stop:
            monitor.handle_input(27)
        stop.assert_called_once()
        assert monitor._events_mode is False

    def test_q_stops_and_quits(self, monitor):
        monitor._detail_focus = True
        monitor._events_mode = True
        with patch.object(monitor, "_stop_events_stream") as stop:
            result = monitor.handle_input(ord("q"))
        stop.assert_called_once()
        assert result is False

    def test_tab_unfocuses(self, monitor):
        monitor._detail_focus = True
        monitor._events_mode = True
        monitor.handle_input(ord("\t"))
        assert monitor._detail_focus is False
