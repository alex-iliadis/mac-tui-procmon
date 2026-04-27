"""Second batch of coverage-boost tests. Targets:

- _audit_global_score end-to-end
- _audit_remediate_current prompt branches for every action type
- _render_detail / _render_colored_line / _tag_color leftover branches
- Remaining audit internals (hardening fallbacks, kernel fallbacks, patch posture)
- Keyscan input handling
- _scroll_audit/keyscan_to_cursor edge cases
- CLI main normal flow (curses.wrapper path)
"""
import os
import sys
import time
import json
import threading
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import procmon
from tests.conftest import make_proc


# ── _audit_global_score ───────────────────────────────────────────────────


class TestGlobalScoreAudit:
    def _mock_all_audits(self, monkeypatch, results_by_name):
        """Replace each _audit_* function with one that returns the canned
        findings in results_by_name; any audit not in the dict returns [].
        Keys map to the short audit_type names used by _audit_global_score
        (e.g. "network" → _audit_network_exposure).
        """
        mapping = [
            ("network", "_audit_network_exposure"),
            ("dns", "_audit_dns_proxy_mdm"),
            ("persistence", "_audit_persistence"),
            ("system_hardening", "_audit_system_hardening"),
            ("kernel_boot", "_audit_kernel_boot"),
            ("patch_posture", "_audit_patch_posture"),
            ("tcc", "_audit_tcc_grants"),
            ("browser_exts", "_audit_browser_extensions"),
            ("usb_hid", "_audit_usb_hid"),
            ("shell_dotfiles", "_audit_shell_dotfiles"),
            ("installed_software", "_audit_installed_software"),
            ("process_entitlements", "_audit_process_entitlements"),
            ("injection_antidebug", "_audit_injection_antidebug"),
            ("filesystem_integrity", "_audit_filesystem_integrity"),
            ("sensitive_paths_delta", "_audit_sensitive_paths_delta"),
            ("keychain", "_audit_keychain_credentials"),
            ("auth_stack", "_audit_authentication_stack"),
            ("binary_authorization", "_audit_binary_authorization"),
            ("tool_correlation", "_audit_tool_correlation"),
            ("packages", "_audit_package_managers"),
            ("baseline_delta", "_audit_baseline_delta"),
            ("rule_engine", "_audit_rule_engine"),
        ]
        for audit_key, fn_name in mapping:
            findings = results_by_name.get(audit_key, [])
            monkeypatch.setattr(procmon, fn_name, lambda f=findings: list(f))

    def test_clean_host_is_green(self, monkeypatch):
        self._mock_all_audits(monkeypatch, {})
        findings = procmon._audit_global_score()
        # Header is OK/GREEN, no fix-first header
        assert findings[0]["severity"] == "OK"
        assert "GREEN" in findings[0]["message"]

    def test_critical_rendered_in_fix_first(self, monkeypatch):
        # Seed CRITICAL findings across every layer to pull the global score
        # into the RED band.
        mass = [
            {"severity": "CRITICAL", "message": f"bad{i}",
             "action": {"type": "enable_alf"}}
            for i in range(4)]
        self._mock_all_audits(monkeypatch, {
            "network": mass, "dns": mass,
            "system_hardening": mass, "patch_posture": mass,
            "kernel_boot": mass, "tcc": mass,
            "persistence": [
                {"severity": "HIGH", "message": "keep me",
                 "action": {"type": "bootout_launchitem", "plist_path": "/x"}},
            ],
        })
        findings = procmon._audit_global_score()
        joined = "\n".join(f["message"] for f in findings)
        # Fix-first entries are prefixed with [audit_key]
        assert "[network]" in joined
        # Score line exists and reflects the band
        assert "Global security score" in findings[0]["message"]
        # Many layers have CRITICAL findings — band should be RED
        assert "RED" in findings[0]["message"]

    def test_per_audit_totals_appended(self, monkeypatch):
        self._mock_all_audits(monkeypatch, {
            "network": [
                {"severity": "HIGH", "message": "h", "action": None},
                {"severity": "HIGH", "message": "h2", "action": None},
            ],
        })
        findings = procmon._audit_global_score()
        # One of the appended lines should summarise the network audit
        assert any(f["message"].startswith("network:")
                   and "HIGH:2" in f["message"]
                   for f in findings)

    def test_exception_captured_without_crashing(self, monkeypatch):
        # If one audit raises, the global score should still complete.
        self._mock_all_audits(monkeypatch, {})
        def boom():
            raise RuntimeError("boom")
        monkeypatch.setattr(procmon, "_audit_network_exposure", boom)
        # No exception bubbles; the per-audit totals include the network row
        # with an INFO count (because the error is recorded as a single INFO
        # finding inside _audit_global_score's try/except).
        findings = procmon._audit_global_score()
        assert any(f["message"].startswith("network:")
                   and "INFO" in f["message"]
                   for f in findings)


# ── _audit_remediate_current prompt-map branches ───────────────────────────


class TestRemediatePromptMap:
    def _run_with_action(self, monitor, action_dict):
        """Confirm=False so dispatch never runs — we just want the prompt."""
        monitor._audit_findings_structured = [{
            "severity": "HIGH", "message": "m", "action": action_dict,
        }]
        monitor._audit_line_for_finding = [0]
        monitor._audit_cursor = 0
        captured = {}
        def fake_confirm(prompt):
            captured["prompt"] = prompt
            return False
        with patch.object(monitor, "_confirm_action",
                          side_effect=fake_confirm):
            monitor._audit_remediate_current()
        return captured.get("prompt", "")

    def test_enable_alf_prompt(self, monitor):
        p = self._run_with_action(monitor, {"type": "enable_alf"})
        assert "Application Firewall" in p

    def test_enable_alf_stealth_prompt(self, monitor):
        p = self._run_with_action(monitor, {"type": "enable_alf_stealth"})
        assert "stealth" in p

    def test_disable_remote_login_prompt(self, monitor):
        p = self._run_with_action(monitor, {"type": "disable_remote_login"})
        assert "Remote Login" in p

    def test_disable_sharing_service_prompt(self, monitor):
        p = self._run_with_action(monitor,
            {"type": "disable_sharing_service",
             "service": "com.apple.screensharing"})
        assert "com.apple.screensharing" in p

    def test_remove_profile_prompt(self, monitor):
        p = self._run_with_action(monitor,
            {"type": "remove_profile", "identifier": "com.x"})
        assert "com.x" in p

    def test_flush_dns_prompt(self, monitor):
        p = self._run_with_action(monitor, {"type": "flush_dns"})
        assert "Flush" in p

    def test_restore_hosts_prompt(self, monitor):
        p = self._run_with_action(monitor, {"type": "restore_hosts"})
        assert "/etc/hosts" in p

    def test_bootout_prompt(self, monitor):
        p = self._run_with_action(monitor,
            {"type": "bootout_launchitem",
             "plist_path": "/x.plist", "label": "x", "domain": "gui"})
        assert "/x.plist" in p
        assert "bootout" in p.lower() or "bootout" in p

    def test_kill_process_prompt(self, monitor):
        p = self._run_with_action(monitor,
            {"type": "kill_process", "pid": 123, "exe": "/bad"})
        assert "123" in p
        assert "/bad" in p

    def test_capture_baseline_prompt(self, monitor):
        p = self._run_with_action(monitor, {"type": "capture_baseline"})
        assert "baseline" in p.lower()

    def test_run_software_update_prompt(self, monitor):
        p = self._run_with_action(monitor, {"type": "run_software_update"})
        assert "softwareupdate" in p

    def test_enable_gatekeeper_prompt(self, monitor):
        p = self._run_with_action(monitor, {"type": "enable_gatekeeper"})
        assert "Gatekeeper" in p

    def test_unknown_action_falls_back_to_generic_prompt(self, monitor):
        p = self._run_with_action(monitor, {"type": "mystery"})
        assert "mystery" in p


# ── Dispatch edge cases that were still missed ────────────────────────────


class TestDispatchExtra:
    def test_bootout_bootout_fail_but_quarantine_ok(self, monitor, tmp_path,
                                                    monkeypatch):
        """If launchctl bootout fails (not loaded) but quarantine succeeds,
        the action is still considered successful — the plist no longer
        re-loads at next login."""
        import threading as _t
        monitor._log_messages = []
        monitor._log_lock = _t.Lock()
        monitor._log_max = 100

        plist = tmp_path / "com.dead.plist"
        plist.write_text("<plist/>")
        monkeypatch.setattr(procmon, "_QUARANTINE_DIR",
                             str(tmp_path / "q"))
        # bootout returns non-zero (not currently loaded)
        with patch.object(procmon, "_run_cmd_short",
                          return_value=(113, "", "not loaded")):
            ok, msg = monitor._dispatch_audit_action({
                "type": "bootout_launchitem",
                "plist_path": str(plist),
                "domain": "system", "label": "x"})
        assert ok is True  # quarantine succeeded
        assert "rc=113" in msg

    def test_capture_baseline_via_dispatch(self, monitor, tmp_path,
                                           monkeypatch):
        import threading as _t
        monitor._log_messages = []
        monitor._log_lock = _t.Lock()
        monitor._log_max = 100

        monkeypatch.setattr(procmon, "_BASELINE_PATH",
                             str(tmp_path / "b.json"))
        monkeypatch.setattr(procmon, "_enumerate_launch_items", lambda: [])
        monkeypatch.setattr(procmon, "_list_system_extensions", lambda: [])
        monkeypatch.setattr(procmon, "_list_listening_sockets", lambda: [])
        monkeypatch.setattr(procmon, "_list_config_profiles", lambda: [])
        monkeypatch.setattr(procmon, "_sharing_services_state", lambda: {})
        ok, msg = monitor._dispatch_audit_action({"type": "capture_baseline"})
        assert ok is True


# ── Rendering helpers: _render_detail / _render_colored_line / _tag_color ─


class TestRenderColoredLine:
    def _put_mock(self, monitor):
        # Use a real put recorder that records (y, x, text)
        calls = []
        def fake(y, x, text, attr=0):
            calls.append((y, x, text, attr))
        monitor._put = fake
        return calls

    def test_renders_with_tags(self, monitor):
        calls = self._put_mock(monitor)
        with patch("curses.color_pair", side_effect=lambda n: n << 8):
            monitor._render_colored_line(
                1, 0, "  [HIGH]  alert", 80, False)
        assert calls  # at least one put call
        texts = " ".join(c[2] for c in calls)
        assert "HIGH" in texts

    def test_selected_line_renders_raw(self, monitor):
        calls = self._put_mock(monitor)
        with patch("curses.color_pair", side_effect=lambda n: n << 8):
            monitor._render_colored_line(
                1, 0, "  some text", 80, True)  # is_selected=True
        # Selected path just renders raw with color_pair(2)
        assert len(calls) == 1
        assert "some text" in calls[0][2]

    def test_byte_count_tag_colored(self, monitor):
        self._put_mock(monitor)
        with patch("curses.color_pair", side_effect=lambda n: n << 8):
            # Cover the byte-suffix branches in _tag_color
            for t in ["[100 MB]", "[2 GB]", "[500 KB]", "[1 B]"]:
                monitor._tag_color(t)

    def test_port_service_tag_colored(self, monitor):
        with patch("curses.color_pair", side_effect=lambda n: n << 8):
            # At least one known _PORT_SERVICES value
            svc = next(iter(procmon._PORT_SERVICES.values()))
            attr = monitor._tag_color(f"[{svc}]")
        assert attr is not None

    def test_city_country_tag_colored(self, monitor):
        with patch("curses.color_pair", side_effect=lambda n: n << 8):
            attr = monitor._tag_color("[Paris/FR]")
        assert attr is not None

    def test_group_tag_colored(self, monitor):
        with patch("curses.color_pair", side_effect=lambda n: n << 8):
            attr = monitor._tag_color("[group:5]")
        assert attr is not None

    def test_tcp_udp_tag(self, monitor):
        with patch("curses.color_pair", side_effect=lambda n: n << 8):
            assert monitor._tag_color("[TCP]") is not None
            assert monitor._tag_color("[UDP]") is not None

    def test_inspect_tag(self, monitor):
        with patch("curses.color_pair", side_effect=lambda n: n << 8):
            assert monitor._tag_color("[INSPECT]") is not None

    def test_risk_tags(self, monitor):
        with patch("curses.color_pair", side_effect=lambda n: n << 8):
            assert monitor._tag_color("[!RISK:HIGH]") is not None
            assert monitor._tag_color("[RISK:LOW]") is not None


class TestRenderDetailEdges:
    def test_renders_when_selected(self, monitor):
        """Exercise the selected-line branch inside _render_detail."""
        monitor.stdscr.getmaxyx.return_value = (40, 120)
        monitor.rows = [make_proc(pid=1, command="/bin/test")]
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put"):
            monitor._render_detail(
                start_y=5, w=100,
                lines=["one", "two", "three"],
                title="T", scroll=0, focused=True, selected_line=1)
        # Didn't raise

    def test_scroll_beyond_content_clamps(self, monitor):
        monitor.stdscr.getmaxyx.return_value = (40, 120)
        monitor.rows = [make_proc(pid=1, command="/bin/test")]
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put"):
            # Pass huge scroll value — should clamp and not crash
            monitor._render_detail(
                start_y=5, w=100, lines=["one", "two"],
                title="T", scroll=9999, focused=False, selected_line=-1)

    def test_small_box_degrades_gracefully(self, monitor):
        monitor.stdscr.getmaxyx.return_value = (6, 40)  # tiny terminal
        monitor.rows = [make_proc(pid=1, command="/bin/test")]
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put"):
            monitor._render_detail(
                start_y=5, w=40, lines=["x"], title="T",
                scroll=0, focused=False, selected_line=-1)


# ── _scroll_audit_to_cursor / _scroll_keyscan_to_cursor edge cases ────────


class TestScrollHelpers:
    def test_audit_scroll_noop_without_line_map(self, monitor):
        monitor._audit_line_for_finding = []
        monitor._audit_cursor = 5
        monitor._audit_scroll = 0
        monitor.stdscr.getmaxyx.return_value = (40, 120)
        monitor._scroll_audit_to_cursor()
        assert monitor._audit_scroll == 0

    def test_audit_scroll_with_action_panel(self, monitor):
        monitor._audit_line_for_finding = [50, 60]
        monitor._audit_cursor = 1
        monitor._audit_scroll = 0
        monitor._audit_action_result = {"level": "ok", "summary": "x",
                                         "detail_text": ""}
        monitor.stdscr.getmaxyx.return_value = (40, 120)
        monitor._scroll_audit_to_cursor()
        # Scrolled down to keep cursor (line 60 + panel height) visible
        assert monitor._audit_scroll > 0

    def test_audit_scroll_cursor_above_viewport(self, monitor):
        monitor._audit_line_for_finding = [1, 100]
        monitor._audit_cursor = 0
        monitor._audit_scroll = 50  # viewport is below cursor
        monitor.stdscr.getmaxyx.return_value = (40, 120)
        monitor._scroll_audit_to_cursor()
        assert monitor._audit_scroll == 0

    def test_keyscan_scroll_cursor_below_viewport(self, monitor):
        monitor._keyscan_line_for_finding = [2, 3, 80]
        monitor._keyscan_cursor = 2
        monitor._keyscan_scroll = 0
        monitor.stdscr.getmaxyx.return_value = (40, 120)
        monitor._scroll_keyscan_to_cursor()
        assert monitor._keyscan_scroll > 0


# ── Keyscan input handling branches ────────────────────────────────────────


class TestKeyscanInput:
    def test_up_on_structured_moves_cursor(self, monitor):
        monitor._detail_focus = True
        monitor._keyscan_mode = True
        monitor._keyscan_findings_structured = [
            {"severity": "HIGH", "message": "a", "action": None},
            {"severity": "HIGH", "message": "b", "action": None},
        ]
        monitor._keyscan_line_for_finding = [2, 3]
        monitor._keyscan_cursor = 1
        import curses
        monitor.handle_input(curses.KEY_UP)
        assert monitor._keyscan_cursor == 0

    def test_page_up_scrolls_structured(self, monitor):
        monitor._detail_focus = True
        monitor._keyscan_mode = True
        monitor._keyscan_findings_structured = []
        monitor._keyscan_scroll = 10
        import curses
        monitor.handle_input(curses.KEY_PPAGE)
        # Scroll decreases
        assert monitor._keyscan_scroll < 10

    def test_tab_exits_detail_focus(self, monitor):
        monitor._detail_focus = True
        monitor._keyscan_mode = True
        monitor._keyscan_findings_structured = []
        monitor.handle_input(ord("\t"))
        assert monitor._detail_focus is False


class TestAuditInputExtra:
    def test_r_key_triggers_rescan(self, monitor):
        monitor._detail_focus = True
        monitor._audit_mode = True
        with patch.object(monitor, "_start_audit") as start:
            monitor.handle_input(ord("r"))
        start.assert_called_once()

    def test_R_key_triggers_rescan(self, monitor):
        monitor._detail_focus = True
        monitor._audit_mode = True
        with patch.object(monitor, "_start_audit") as start:
            monitor.handle_input(ord("R"))
        start.assert_called_once()

    def test_esc_in_detail_closes_audit(self, monitor):
        monitor._detail_focus = True
        monitor._audit_mode = True
        monitor.handle_input(27)
        assert monitor._audit_mode is False
        assert monitor._detail_focus is False

    def test_q_in_audit_detail_returns_false(self, monitor):
        monitor._detail_focus = True
        monitor._audit_mode = True
        result = monitor.handle_input(ord("q"))
        assert result is False

    def test_page_up_scrolls_without_structured(self, monitor):
        monitor._detail_focus = True
        monitor._audit_mode = True
        monitor._audit_findings_structured = []
        monitor._audit_scroll = 30
        import curses
        monitor.handle_input(curses.KEY_PPAGE)
        assert monitor._audit_scroll < 30

    def test_page_down_scrolls(self, monitor):
        monitor._detail_focus = True
        monitor._audit_mode = True
        monitor._audit_findings_structured = []
        monitor._audit_scroll = 0
        import curses
        monitor.handle_input(curses.KEY_NPAGE)
        assert monitor._audit_scroll > 0


# ── Toggle-mode switches other modes off ───────────────────────────────────


class TestToggleAuditExclusivity:
    def test_opening_audit_closes_other_modes(self, monitor):
        monitor._inspect_mode = True
        monitor._hidden_scan_mode = True
        monitor._bulk_scan_mode = True
        monitor._keyscan_mode = True
        monitor._net_mode = True
        with patch.object(monitor, "_start_audit"):
            monitor._toggle_audit_mode("network")
        assert not monitor._inspect_mode
        assert not monitor._hidden_scan_mode
        assert not monitor._bulk_scan_mode
        assert not monitor._keyscan_mode
        assert not monitor._net_mode


# ── _audit_installed_software additional branches ─────────────────────────


class TestInstalledSoftwareExtra:
    def test_hardened_runtime_disabled(self, tmp_path, monkeypatch):
        app = tmp_path / "Z.app"
        app.mkdir()
        with patch.object(procmon, "_iter_app_bundles",
                          return_value=[str(app)]), \
             patch.object(procmon, "_codesign_structured",
                          return_value={"rc": 0, "team_id": "T",
                                        "authority": ["Developer ID"],
                                        "entitlements_xml": "",
                                        "hardened_runtime": False}), \
             patch.object(procmon, "_is_apple_signed", return_value=False):
            findings = procmon._audit_installed_software()
        assert any("Hardened Runtime" in f["message"] for f in findings)

    def test_ad_hoc_signed_is_high(self, tmp_path, monkeypatch):
        app = tmp_path / "Z.app"
        app.mkdir()
        with patch.object(procmon, "_iter_app_bundles",
                          return_value=[str(app)]), \
             patch.object(procmon, "_codesign_structured",
                          return_value={"rc": 0, "team_id": "",
                                        "authority": [],
                                        "entitlements_xml": "",
                                        "hardened_runtime": True}), \
             patch.object(procmon, "_is_apple_signed", return_value=False):
            findings = procmon._audit_installed_software()
        assert any(f["severity"] == "HIGH" and "ad-hoc" in f["message"]
                   for f in findings)


# ── _audit_sensitive_paths_delta: >50 items → "omitted" row ────────────────


class TestSensitivePathsDeltaMany:
    def test_more_than_fifty_recent_changes_truncates(self, tmp_path,
                                                     monkeypatch):
        root = tmp_path / "fake"
        root.mkdir()
        for i in range(60):
            (root / f"f{i}.plist").write_text("x")
        monkeypatch.setattr(procmon, "_SENSITIVE_PATH_ROOTS", [str(root)])
        findings = procmon._audit_sensitive_paths_delta(window_days=7)
        assert any("more recent changes omitted" in f["message"]
                   for f in findings)


# ── _audit_filesystem_integrity branches ───────────────────────────────────


class TestFilesystemIntegrityExtra:
    def test_recent_mtime_surfaces_medium(self, tmp_path, monkeypatch):
        import pwd, grp
        sensitive = tmp_path / "hosts"
        sensitive.write_text("127.0.0.1 localhost")
        os.chmod(sensitive, 0o644)
        monkeypatch.setattr(
            procmon, "_FS_SENSITIVE_FILES",
            [(str(sensitive), 0o644,
              pwd.getpwuid(os.geteuid()).pw_name,
              grp.getgrgid(os.getegid()).gr_name)])
        def fake(argv, **_):
            return (0, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake):
            findings = procmon._audit_filesystem_integrity()
        assert any(f["severity"] == "MEDIUM"
                   and "modified in the last" in f["message"]
                   for f in findings)

    def test_world_writable_files_found(self, tmp_path, monkeypatch):
        # Point sensitive files list at something harmless
        monkeypatch.setattr(procmon, "_FS_SENSITIVE_FILES", [])

        def fake(argv, **_):
            if argv[0] == "find" and "/etc" in argv:
                return (0, "/etc/bad1\n/etc/bad2\n", "")
            if argv[0] == "find" and "/usr/local" in argv:
                return (0, "", "")
            if argv[0] == "security":
                return (1, "", "")
            return (0, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake):
            findings = procmon._audit_filesystem_integrity()
        assert any("World-writable" in f["message"] for f in findings)

    def test_too_many_world_writable_truncates(self, tmp_path, monkeypatch):
        monkeypatch.setattr(procmon, "_FS_SENSITIVE_FILES", [])
        many_files = "\n".join(f"/etc/bad{i}" for i in range(30))
        def fake(argv, **_):
            if argv[0] == "find" and "/etc" in argv:
                return (0, many_files, "")
            return (0, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake):
            findings = procmon._audit_filesystem_integrity()
        assert any("more world-writable files omitted" in f["message"]
                   for f in findings)

    def test_suid_outside_normal_paths_flagged(self, monkeypatch):
        monkeypatch.setattr(procmon, "_FS_SENSITIVE_FILES", [])
        def fake(argv, **_):
            if argv[0] == "find" and "/opt" in argv:
                return (0, "/opt/custom/suidbin\n", "")
            return (0, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake):
            findings = procmon._audit_filesystem_integrity()
        assert any("SUID/SGID" in f["message"] for f in findings)


# ── _audit_network_exposure: pfctl rules ───────────────────────────────────


class TestNetworkPfctl:
    def test_active_pfctl_rules_surface_info(self, monkeypatch):
        def fake(argv, **_):
            cmd = argv[0] if argv else ""
            if cmd == "pfctl":
                return (0, "block drop in all\npass out all\n", "")
            if "socketfilterfw" in cmd:
                return (0, "Firewall is enabled.", "")
            if cmd == "systemsetup":
                return (0, "Remote Login: Off", "")
            return (0, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake):
            findings = procmon._audit_network_exposure()
        assert any("pfctl" in f["message"] for f in findings)


# ── _audit_persistence extra branches ──────────────────────────────────────


class TestPersistenceExtra:
    def test_sfltool_dumpbtm_skips_when_not_root_to_avoid_prompt(self, monkeypatch):
        monkeypatch.setattr(procmon.os, "geteuid", lambda: 501)
        called = False

        def fake_run(*_args, **_kwargs):
            nonlocal called
            called = True
            return (0, "UUID: x", "")

        monkeypatch.setattr(procmon, "_run_cmd_short", fake_run)

        assert procmon._sfltool_dumpbtm() == ""
        assert called is False

    def test_sfltool_dumpbtm_runs_when_root(self, monkeypatch):
        monkeypatch.setattr(procmon.os, "geteuid", lambda: 0)
        monkeypatch.setattr(
            procmon,
            "_run_cmd_short",
            lambda argv, timeout=15: (0, "UUID: root-btm", ""),
        )

        assert procmon._sfltool_dumpbtm() == "UUID: root-btm"

    def test_privileged_helper_unsigned(self, tmp_path, monkeypatch):
        # Simulate a single helper and check the UNSIGNED path
        monkeypatch.setattr(procmon, "_enumerate_launch_items", lambda: [])
        monkeypatch.setattr(procmon, "_list_privileged_helpers",
                             lambda: ["/Library/PrivilegedHelperTools/com.bad"])
        monkeypatch.setattr(procmon, "_user_crontabs", lambda: [])
        monkeypatch.setattr(procmon, "_sfltool_dumpbtm", lambda: "")
        with patch("os.path.exists", return_value=True), \
             patch.object(procmon, "_codesign_structured",
                          return_value={"rc": 1, "team_id": "",
                                        "authority": []}), \
             patch.object(procmon, "_is_apple_signed", return_value=False), \
             patch.object(procmon, "_run_cmd_short",
                          return_value=(0, "", "")):
            findings = procmon._audit_persistence()
        assert any(f["severity"] == "HIGH" and "UNSIGNED" in f["message"]
                   for f in findings)

    def test_privileged_helper_signed_third_party(self, tmp_path, monkeypatch):
        monkeypatch.setattr(procmon, "_enumerate_launch_items", lambda: [])
        monkeypatch.setattr(procmon, "_list_privileged_helpers",
                             lambda: ["/Library/PrivilegedHelperTools/com.vendor"])
        monkeypatch.setattr(procmon, "_user_crontabs", lambda: [])
        monkeypatch.setattr(procmon, "_sfltool_dumpbtm", lambda: "")
        with patch("os.path.exists", return_value=True), \
             patch.object(procmon, "_codesign_structured",
                          return_value={"rc": 0, "team_id": "VID",
                                        "authority": ["Developer ID"]}), \
             patch.object(procmon, "_is_apple_signed", return_value=False), \
             patch.object(procmon, "_run_cmd_short",
                          return_value=(0, "", "")):
            findings = procmon._audit_persistence()
        assert any(f["severity"] == "MEDIUM" and "team=VID" in f["message"]
                   for f in findings)

    def test_legacy_loginhook_flagged(self, monkeypatch):
        monkeypatch.setattr(procmon, "_enumerate_launch_items", lambda: [])
        monkeypatch.setattr(procmon, "_list_privileged_helpers", lambda: [])
        monkeypatch.setattr(procmon, "_user_crontabs", lambda: [])
        monkeypatch.setattr(procmon, "_sfltool_dumpbtm", lambda: "")
        def fake(argv, **_):
            if argv == ["defaults", "read", "com.apple.loginwindow"]:
                return (0, "{\n  LoginHook = /tmp/evil.sh;\n}", "")
            return (0, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake):
            findings = procmon._audit_persistence()
        assert any(f["severity"] == "HIGH"
                   and "LoginHook" in f["message"]
                   for f in findings)


# ── _audit_patch_posture: unsupported major version ────────────────────────


class TestPatchPostureExtra:
    def test_unsupported_major_version(self, monkeypatch):
        def fake(argv, **_):
            if "-productVersion" in argv:
                return (0, "10.13", "")  # old High Sierra
            if "-buildVersion" in argv:
                return (0, "17G123", "")
            if argv[0] == "softwareupdate":
                return (0, "No new software available.", "")
            return (0, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake), \
             patch.object(procmon, "_read_plist_defaults", return_value={}):
            findings = procmon._audit_patch_posture()
        assert any(f["severity"] == "HIGH"
                   and "supported branches" in f["message"]
                   for f in findings)


# ── Main() entry — curses.wrapper path ────────────────────────────────────


class TestMainCursesPath:
    def test_main_default_path_launches_curses(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["procmon"])
        with patch.object(procmon, "_preflight", return_value=True), \
             patch.object(procmon, "_self_test", return_value=True), \
             patch.object(procmon, "_harden_process"), \
             patch("signal.signal"), \
             patch("curses.wrapper") as wrapper:
            procmon.main()
        wrapper.assert_called_once()

    def test_main_keyboard_interrupt_swallowed(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["procmon"])
        with patch.object(procmon, "_preflight", return_value=True), \
             patch.object(procmon, "_self_test", return_value=True), \
             patch.object(procmon, "_harden_process"), \
             patch("signal.signal"), \
             patch("curses.wrapper", side_effect=KeyboardInterrupt):
            # Should not raise
            procmon.main()

    def test_main_preflight_abort(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["procmon"])
        with patch.object(procmon, "_preflight", return_value=False), \
             patch("curses.wrapper") as wrapper:
            procmon.main()
        wrapper.assert_not_called()
