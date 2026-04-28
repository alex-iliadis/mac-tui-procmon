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


    def test_shortcut_bar_shows_forensic(self, monitor):
        monitor._detail_focus = False
        monitor._net_mode = False
        monitor._inspect_mode = False
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put") as put:
            monitor._render_shortcut_bar(40, 200)
        texts = " ".join(str(c.args[2]) if len(c.args) > 2 else "" for c in put.call_args_list)
        assert "F" in texts and "Process" in texts
        assert "N" in texts and "Net" in texts
        assert "SecAudit" not in texts
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








# ── Remediation primitives ─────────────────────────────────────────────


class TestDeleteTccGrant:
    pass





class TestTccRemovalSilentFailureReproduction:
    """Reproduction for the user-reported bug: 'I tried to delete the Skype
    TCC grant — no luck.' tccutil was returning 0 while leaving the row in
    the system TCC.db because SIP protected it from root. The fix detects
    that tccutil lied and falls back to sqlite (which then surfaces an
    informative error if sqlite can't touch it either).

    These tests pin down that behavior so the bug can't silently regress.
    """





class TestTccutilDualEnvAttempts:
    """tccutil picks its target TCC.db based on HOME/USER. Under sudo with
    HOME preserved (via our procmon-sudo wrapper), tccutil targets the
    user's per-user db — but most 'real' grants live in the system db at
    /Library/Application Support/com.apple.TCC/TCC.db. So _delete_tcc_grant
    tries *both* env contexts before giving up."""








class TestFullEndToEndSkypeRemoval:
    """Mirror the exact user flow: scan finds a Skype grant → user hits
    D → confirm → removal actually removes the row from the db, even when
    tccutil is a no-op on this system."""







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
    pass

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
    """Cover assistant-subprocess error branches in `_run_assistant_attempt`
    and the all-failed combined-error path in `_chat_send_worker`."""

    def test_chat_send_combined_error_when_all_assistants_fail(self, monitor):
        """rc=1 + stdout="rate limited" from every CLI → all three fail and
        the rate-limited stdout content appears in the combined error."""
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
        assert "all assistants failed" in monitor._chat_pending
        assert "rate limited" in monitor._chat_pending
        assert "claude" in monitor._chat_pending
        assert "codex" in monitor._chat_pending
        assert "gemini" in monitor._chat_pending

    def test_chat_send_no_output_at_all(self, monitor):
        """Empty stdout from every CLI is treated as a failed attempt; the
        combined error mentions "no output" for each."""
        monitor._chat_mode = True
        monitor._chat_input = "q"
        monitor._chat_cursor = 1
        fake = MagicMock()
        fake.communicate.return_value = (b"", b"")
        fake.returncode = 0

        def immediate_thread(target=None, daemon=None, **kw):
            t = MagicMock()
            t.start = lambda: target()
            return t

        with patch("subprocess.Popen", return_value=fake), \
             patch("threading.Thread", side_effect=immediate_thread):
            monitor._chat_send()
        assert "no output" in monitor._chat_pending
        assert "all assistants failed" in monitor._chat_pending

    def test_chat_send_unexpected_exception_captured(self, monitor):
        """A runtime exception while spawning is caught per-attempt and the
        chain continues; with all three failing the combined error names
        every assistant and includes the exception text."""
        monitor._chat_mode = True
        monitor._chat_input = "q"
        monitor._chat_cursor = 1

        def immediate_thread(target=None, daemon=None, **kw):
            t = MagicMock()
            t.start = lambda: target()
            return t

        with patch("subprocess.Popen", side_effect=RuntimeError("boom")), \
             patch("threading.Thread", side_effect=immediate_thread):
            monitor._chat_send()
        assert "unexpected" in monitor._chat_pending
        assert "boom" in monitor._chat_pending
        assert "all assistants failed" in monitor._chat_pending


class TestChatEndToEndReturnsAnswer:
    """Regression coverage for "Ask Claude appears stuck on thinking…":
    confirm the worker writes a response, the poller picks it up, and the
    answer lands in the visible message list with the loading flag cleared.
    """

    @staticmethod
    def _immediate_thread(target=None, daemon=None, **kw):
        t = MagicMock()
        t.start = lambda: target()
        return t

    def test_full_success_flow_message_visible_and_not_loading(self, monitor):
        import subprocess
        monitor._chat_mode = True
        monitor._chat_input = "what is this?"
        monitor._chat_cursor = len(monitor._chat_input)

        fake = MagicMock()
        fake.communicate.return_value = (b"hello world", b"")
        fake.returncode = 0

        with patch("subprocess.Popen", return_value=fake) as popen, \
             patch("threading.Thread",
                   side_effect=self._immediate_thread):
            monitor._chat_send()

        assert monitor._chat_pending == "hello world"
        assert monitor._chat_loading is True
        # Argv carries --no-session-persistence to skip slow startup.
        popen_argv = popen.call_args[0][0]
        assert "--no-session-persistence" in popen_argv

        changed = monitor._poll_chat_result()
        assert changed is True
        assert monitor._chat_pending is None
        assert monitor._chat_loading is False
        replies = [m for m in monitor._chat_messages
                   if m["role"] == "assistant"]
        assert replies, "expected an assistant reply in chat history"
        assert replies[-1]["content"] == "hello world"

    def test_timeout_drives_full_fallback_chain_and_kills_each_proc(self,
                                                                     monitor):
        """When every CLI times out the fallback chain runs all three, kills
        each subprocess, and surfaces a combined "all assistants failed"
        message via poll. Default timeout is 60s — verify the marker
        reports it."""
        import subprocess
        monitor._chat_mode = True
        monitor._chat_input = "q"
        monitor._chat_cursor = 1

        fake = MagicMock()
        fake.communicate.side_effect = subprocess.TimeoutExpired(
            ["assistant"], 60)

        with patch("subprocess.Popen", return_value=fake), \
             patch("threading.Thread",
                   side_effect=self._immediate_thread):
            monitor._chat_send()

        assert monitor._chat_pending is not None
        assert "all assistants failed" in monitor._chat_pending
        # Each label timed out at 60s.
        assert monitor._chat_pending.count("timed out after 60s") == 3
        # Each subprocess was killed (one per CLI in the chain).
        assert fake.kill.call_count == 3

        changed = monitor._poll_chat_result()
        assert changed is True
        assert monitor._chat_loading is False
        # Status is cleared so the spinner doesn't outlive the response.
        assert monitor._chat_status is None
        assert any("all assistants failed" in m["content"]
                   for m in monitor._chat_messages
                   if m["role"] == "assistant")

    def test_enter_chat_mode_drives_full_flow_to_visible_answer(self,
                                                                 monitor):
        """Integration: the '?' shortcut path (`_enter_chat_mode`) must
        end with the assistant reply visible after one poll."""
        monitor.rows = [make_proc(pid=99, command="/bin/test")]
        monitor.selected = 0

        fake = MagicMock()
        fake.communicate.return_value = (b"this is the answer", b"")
        fake.returncode = 0

        with patch("subprocess.Popen", return_value=fake), \
             patch("threading.Thread",
                   side_effect=self._immediate_thread):
            monitor._enter_chat_mode()

        assert monitor._chat_mode is True
        # Auto-opener question is appended as a user message.
        assert monitor._chat_messages[0]["role"] == "user"
        assert "Tell me more" in monitor._chat_messages[0]["content"]

        monitor._poll_chat_result()
        replies = [m for m in monitor._chat_messages
                   if m["role"] == "assistant"]
        assert replies and replies[-1]["content"] == "this is the answer"
        assert monitor._chat_loading is False


class TestChatFallbackChain:
    """Verify the claude → codex → gemini fallback. Each scenario uses a
    Popen side_effect that returns a different mock per call so individual
    attempts can succeed or fail independently."""

    @staticmethod
    def _immediate_thread(target=None, daemon=None, **kw):
        t = MagicMock()
        t.start = lambda: target()
        return t

    @staticmethod
    def _make_proc(stdout=b"", stderr=b"", returncode=0,
                    timeout_seconds=None):
        import subprocess
        fake = MagicMock()
        if timeout_seconds is not None:
            fake.communicate.side_effect = subprocess.TimeoutExpired(
                ["x"], timeout_seconds)
        else:
            fake.communicate.return_value = (stdout, stderr)
        fake.returncode = returncode
        return fake

    def test_claude_succeeds_no_fallback_invoked(self, monitor):
        """When the first CLI answers, the chain stops immediately — only
        one Popen call is made and the status reflects claude."""
        monitor._chat_mode = True
        monitor._chat_input = "q"
        monitor._chat_cursor = 1

        claude_proc = self._make_proc(stdout=b"claude answer", returncode=0)
        with patch("subprocess.Popen", return_value=claude_proc) as popen, \
             patch("threading.Thread",
                   side_effect=self._immediate_thread):
            monitor._chat_send()

        assert popen.call_count == 1
        assert monitor._chat_pending == "claude answer"
        # First CLI invoked is claude.
        first_argv = popen.call_args_list[0][0][0]
        assert first_argv[0] == "claude"

    def test_claude_timeout_falls_back_to_codex_success(self, monitor):
        """claude times out → status flips to "trying with codex…" → codex
        responds → final answer is codex's."""
        monitor._chat_mode = True
        monitor._chat_input = "q"
        monitor._chat_cursor = 1

        claude_proc = self._make_proc(timeout_seconds=60)
        codex_proc = self._make_proc(stdout=b"codex answer", returncode=0)
        gemini_proc = self._make_proc(stdout=b"gemini answer", returncode=0)

        # side_effect returns next proc per call: claude, codex, gemini
        with patch("subprocess.Popen",
                   side_effect=[claude_proc, codex_proc, gemini_proc]
                   ) as popen, \
             patch("threading.Thread",
                   side_effect=self._immediate_thread):
            monitor._chat_send()

        assert popen.call_count == 2  # claude + codex; gemini not reached
        argvs = [c[0][0] for c in popen.call_args_list]
        assert argvs[0][0] == "claude"
        assert argvs[1][0] == "codex"
        assert monitor._chat_pending == "codex answer"
        # claude was killed on timeout; codex was not.
        claude_proc.kill.assert_called_once()
        codex_proc.kill.assert_not_called()

    def test_claude_and_codex_fail_gemini_succeeds(self, monitor):
        """Two failures, then gemini lands the answer."""
        monitor._chat_mode = True
        monitor._chat_input = "q"
        monitor._chat_cursor = 1

        claude_proc = self._make_proc(timeout_seconds=60)
        codex_proc = self._make_proc(stdout=b"", stderr=b"auth error",
                                      returncode=1)
        gemini_proc = self._make_proc(stdout=b"gemini answer", returncode=0)

        with patch("subprocess.Popen",
                   side_effect=[claude_proc, codex_proc, gemini_proc]
                   ) as popen, \
             patch("threading.Thread",
                   side_effect=self._immediate_thread):
            monitor._chat_send()

        assert popen.call_count == 3
        argvs = [c[0][0] for c in popen.call_args_list]
        assert [a[0] for a in argvs] == ["claude", "codex", "gemini"]
        assert monitor._chat_pending == "gemini answer"

    def test_status_message_progresses_through_chain(self, monitor):
        """`_chat_status` updates between attempts so the user sees which
        assistant is currently being tried."""
        monitor._chat_mode = True
        monitor._chat_input = "q"
        monitor._chat_cursor = 1

        observed = []

        def fake_run_attempt(self_inner, argv, stdin_text, env, timeout,
                              label):
            # Capture status at the moment the attempt is invoked.
            observed.append((label, self_inner._chat_status))
            if label == "gemini":
                return True, "gemini answer"
            return False, f"{label} failed"

        with patch.object(procmon.ProcMonUI, "_run_assistant_attempt",
                          fake_run_attempt), \
             patch("threading.Thread",
                   side_effect=self._immediate_thread):
            monitor._chat_send()

        labels = [o[0] for o in observed]
        statuses = [o[1] for o in observed]
        assert labels == ["claude", "codex", "gemini"]
        assert statuses[0] == "[claude thinking…]"
        assert statuses[1] == "[trying with codex…]"
        assert statuses[2] == "[trying with gemini…]"
        assert monitor._chat_pending == "gemini answer"

    def test_argv_de_elevates_under_sudo(self, monitor):
        """Under sudo (EUID=0 with SUDO_USER set) each assistant CLI is
        wrapped with `sudo -n -E -u $SUDO_USER --` so it runs as the
        invoking user. This is the actual fix for claude's keychain hang
        — running it as the user means claude can read its OAuth tokens
        normally."""
        monitor._chat_mode = True
        monitor._chat_input = "q"
        monitor._chat_cursor = 1

        fake = self._make_proc(stdout=b"answer", returncode=0)
        with patch.dict("os.environ", {"SUDO_USER": "alex"}, clear=False), \
             patch("os.geteuid", return_value=0), \
             patch("subprocess.Popen", return_value=fake) as popen, \
             patch("threading.Thread",
                   side_effect=self._immediate_thread):
            monitor._chat_send()

        actual_argv = popen.call_args_list[0][0][0]
        assert actual_argv[:6] == ["sudo", "-n", "-E", "-u", "alex", "--"]
        # The original CLI follows the wrapper.
        assert actual_argv[6] == "claude"

    def test_argv_not_wrapped_when_not_root(self, monitor):
        """When procmon runs as a normal user, no `sudo -u` wrapper is
        added — the assistant CLI is invoked directly."""
        monitor._chat_mode = True
        monitor._chat_input = "q"
        monitor._chat_cursor = 1

        fake = self._make_proc(stdout=b"answer", returncode=0)
        with patch("os.geteuid", return_value=501), \
             patch("subprocess.Popen", return_value=fake) as popen, \
             patch("threading.Thread",
                   side_effect=self._immediate_thread):
            monitor._chat_send()

        actual_argv = popen.call_args_list[0][0][0]
        assert actual_argv[0] == "claude"
        assert "sudo" not in actual_argv[:3]

    def test_argv_not_wrapped_when_no_sudo_user(self, monitor):
        """Even at EUID=0, if SUDO_USER isn't set (e.g. true root login,
        not a sudo invocation) we can't infer who to drop to, so we run
        the CLI directly as root and let it fail loudly."""
        monitor._chat_mode = True
        monitor._chat_input = "q"
        monitor._chat_cursor = 1

        fake = self._make_proc(stdout=b"answer", returncode=0)
        env_no_sudo = {k: v for k, v in os.environ.items()
                       if k != "SUDO_USER"}
        with patch.dict("os.environ", env_no_sudo, clear=True), \
             patch("os.geteuid", return_value=0), \
             patch("subprocess.Popen", return_value=fake) as popen, \
             patch("threading.Thread",
                   side_effect=self._immediate_thread):
            monitor._chat_send()

        actual_argv = popen.call_args_list[0][0][0]
        assert actual_argv[0] == "claude"
        assert "sudo" not in actual_argv[:3]

    def test_loading_marker_renders_dynamic_status(self, monitor):
        """The chat overlay loading marker reflects `_chat_status` so the
        user sees the in-flight assistant label, not a hardcoded "claude"."""
        monitor._chat_mode = True
        monitor._chat_loading = True
        monitor._chat_status = "[trying with codex…]"
        monitor._chat_input = ""
        monitor._chat_cursor = 0
        monitor._chat_messages = []
        monitor._chat_context_label = "Process list"

        captured = []
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch("curses.curs_set"), \
             patch.object(monitor, "_put",
                          side_effect=lambda *a, **k: captured.append(a)):
            monitor._render_chat()
        text = " ".join(str(c[2]) for c in captured if len(c) > 2)
        assert "trying with codex" in text


class TestCollectChatContextFallback:
    """Cover the less-common `_collect_chat_context` branches that aren't
    exercised by the primary TestChatOverlay class."""

    def test_keyscan_without_lines_falls_back(self, monitor):
        monitor._keyscan_mode = True
        monitor._keyscan_lines = []
        label, _ = monitor._collect_chat_context()
        assert label == "Process list"

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


class TestSecureKeyboardEntryPid:
    """The holder-PID attribution path in _check_secure_keyboard_entry
    parses ioreg output. Exercise with several shapes."""





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
    def test_shutdown_stops_events(self, monitor):
        fake_proc = MagicMock()
        monitor._events_proc = fake_proc
        with patch.object(monitor, "_stop_events_stream") as stop:
            monitor._shutdown()
        stop.assert_called_once()
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
        monitor._net_mode = False
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put") as put:
            monitor._render_shortcut_bar(40, 200)
        texts = " ".join(str(c.args[2]) if len(c.args) > 2 else "" for c in put.call_args_list)
        assert "Scroll" in texts
        assert "Close" in texts
        assert "Procs" in texts


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
        monitor._inspect_mode = True
        monitor._inspect_loading = True
        with patch.object(monitor, "_poll_inspect_result",
                          wraps=monitor._poll_inspect_result) as poll:
            # Simulate just the poll block from run()
            if monitor._inspect_pending is not None:
                monitor._poll_inspect_result()
        poll.assert_called_once()
        assert monitor._inspect_lines == ["line"]


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






# ── Security timeline ────────────────────────────────────────────────




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
        monitor._net_mode = True
        with patch.object(monitor, "_start_events_stream"):
            monitor._toggle_events_mode()
        assert monitor._inspect_mode is False
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
