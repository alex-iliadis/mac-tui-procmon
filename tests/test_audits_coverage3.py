"""Third batch of coverage-boost tests — target the last remaining large
uncovered blocks:

- _enumerate_launch_items, _list_privileged_helpers, _user_crontabs direct
- _audit_package_managers Python dist-info and Cargo branches
- _start_audit / _poll_audit_result worker lifecycle
- Keyscan remove-current dispatcher branches
- Small remaining parsers (_parse_btm_items, _parse_sharing_list,
  _resolve_chromium_message)
"""
import json
import os
import sys
import time
import threading
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import procmon
from tests.conftest import make_proc


# ── Direct tests for enumerator helpers ────────────────────────────────────


class TestEnumerateLaunchItems:
    def test_parses_plist_and_classifies_domain(self, tmp_path, monkeypatch):
        root = tmp_path / "LaunchAgents"
        root.mkdir()
        p = root / "com.sample.agent.plist"
        p.write_text(
            '<?xml version="1.0"?>\n<plist version="1.0"><dict>\n'
            '<key>Label</key><string>com.sample.agent</string>\n'
            '<key>Program</key><string>/usr/local/bin/agent</string>\n'
            '<key>RunAtLoad</key><true/>\n'
            '</dict></plist>\n'
        )
        monkeypatch.setattr(procmon, "_LAUNCH_ROOTS", [str(root)])
        items = procmon._enumerate_launch_items()
        assert len(items) == 1
        it = items[0]
        assert it["label"] == "com.sample.agent"
        assert it["program"] == "/usr/local/bin/agent"
        assert it["run_at_load"] is True

    def test_skips_non_plist_files(self, tmp_path, monkeypatch):
        root = tmp_path / "Agents"
        root.mkdir()
        (root / "README.md").write_text("ignore me")
        monkeypatch.setattr(procmon, "_LAUNCH_ROOTS", [str(root)])
        assert procmon._enumerate_launch_items() == []

    def test_missing_root_skipped(self, tmp_path, monkeypatch):
        monkeypatch.setattr(procmon, "_LAUNCH_ROOTS",
                             [str(tmp_path / "nope")])
        assert procmon._enumerate_launch_items() == []


class TestListPrivilegedHelpers:
    def test_missing_dir_returns_empty(self):
        with patch("os.path.isdir", return_value=False):
            assert procmon._list_privileged_helpers() == []

    def test_skips_dotfiles(self):
        # Patch just isdir + listdir; os.path.join works normally and returns
        # a composed path under /Library/PrivilegedHelperTools/<name>.
        real_isdir = os.path.isdir
        def fake_isdir(p):
            if p == "/Library/PrivilegedHelperTools":
                return True
            return real_isdir(p)
        with patch("os.path.isdir", side_effect=fake_isdir), \
             patch("os.listdir",
                   return_value=[".DS_Store", "com.vendor.helper"]):
            result = procmon._list_privileged_helpers()
        # Dotfile filtered out, helper kept
        assert any("com.vendor.helper" in r for r in result)
        assert not any(".DS_Store" in r for r in result)


class TestUserCrontabs:
    def test_reads_tabs_directory(self, tmp_path):
        """Patch isdir+listdir+open so the function walks a fake /var/at/tabs."""
        real_isdir = os.path.isdir
        real_open = open
        fake_tabs = tmp_path
        (fake_tabs / "alice").write_text("* * * * * /tmp/hello\n")
        (fake_tabs / "empty").write_text("")

        def fake_isdir(p):
            if p == "/var/at/tabs":
                return True
            return real_isdir(p)

        def fake_open(p, *a, **k):
            if isinstance(p, str) and p.startswith("/var/at/tabs/"):
                name = p.rsplit("/", 1)[-1]
                return real_open(str(fake_tabs / name), *a, **k)
            return real_open(p, *a, **k)

        with patch("os.path.isdir", side_effect=fake_isdir), \
             patch("os.listdir", return_value=["alice", "empty"]), \
             patch("builtins.open", side_effect=fake_open):
            result = procmon._user_crontabs()

        users = [u for u, _body in result]
        assert "alice" in users
        assert "empty" not in users  # empty body is skipped

    def test_missing_tabs_dir_returns_empty(self):
        def fake_isdir(p):
            return False  # /var/at/tabs doesn't exist
        with patch("os.path.isdir", side_effect=fake_isdir):
            assert procmon._user_crontabs() == []


# ── _audit_package_managers Python dist-info + Cargo ──────────────────────


class TestPackageManagersPythonCargo:
    def test_recent_pip_installs_surfaced(self, tmp_path, monkeypatch):
        """Python branch: site-packages with recent .dist-info dirs."""
        site_dir = tmp_path / "site-packages"
        site_dir.mkdir()
        recent = site_dir / "freshpkg-1.0.0.dist-info"
        recent.mkdir()
        # mtime is now by default — counts as <30 days

        def fake(argv, **_):
            cmd = argv[0] if argv else ""
            # Python branch: the function calls
            #   python3 -c "import site; print('\\n'.join(site.getsitepackages()+[site.getusersitepackages()]))"
            if cmd.startswith("python"):
                return (0, f"{site_dir}\n", "")
            return (1, "", "")

        monkeypatch.setattr(procmon, "_EFFECTIVE_HOME", str(tmp_path))
        with patch.object(procmon, "_run_cmd_short", side_effect=fake):
            findings = procmon._audit_package_managers()
        assert any("pip" in f["message"] and "freshpkg" in
                   (f.get("evidence") or "")
                   for f in findings)

    def test_cargo_bin_counted(self, tmp_path, monkeypatch):
        cargo_bin = tmp_path / ".cargo" / "bin"
        cargo_bin.mkdir(parents=True)
        (cargo_bin / "rg").write_text("")
        (cargo_bin / "fd").write_text("")
        monkeypatch.setattr(procmon, "_EFFECTIVE_HOME", str(tmp_path))
        def fake(argv, **_):
            return (1, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake):
            findings = procmon._audit_package_managers()
        assert any("Cargo" in f["message"] and "2" in f["message"]
                   for f in findings)


# ── _start_audit / _poll_audit_result worker lifecycle ────────────────────


class TestStartAuditWorker:
    def test_worker_runs_scan_and_populates_pending(self, monitor):
        monitor._audit_type = "network"
        monitor._audit_worker = None
        # Stub the scan to return a canned finding list
        fake_findings = [{"severity": "HIGH", "message": "m",
                          "action": None}]
        with patch.dict(monitor._AUDIT_SCANS,
                        {"network": (lambda: fake_findings, "Test")},
                        clear=False):
            monitor._start_audit()
            # Wait for the daemon thread to complete
            for _ in range(50):
                if monitor._audit_pending is not None:
                    break
                time.sleep(0.01)
        assert monitor._audit_pending is not None
        # _poll_audit_result should now apply the lines
        monitor._audit_mode = True
        assert monitor._poll_audit_result() is True
        assert monitor._audit_lines == monitor._audit_pending or \
               monitor._audit_lines  # already consumed

    def test_start_audit_noop_on_running_worker(self, monitor):
        monitor._audit_type = "network"
        fake_worker = MagicMock()
        fake_worker.is_alive.return_value = True
        monitor._audit_worker = fake_worker
        with patch("threading.Thread") as mk_thread:
            monitor._start_audit()
        mk_thread.assert_not_called()

    def test_start_audit_noop_on_unknown_type(self, monitor):
        monitor._audit_type = "nope"
        monitor._audit_worker = None
        with patch("threading.Thread") as mk_thread:
            monitor._start_audit()
        mk_thread.assert_not_called()

    def test_poll_without_pending_returns_false(self, monitor):
        monitor._audit_pending = None
        monitor._audit_mode = True
        assert monitor._poll_audit_result() is False

    def test_poll_when_mode_closed_clears_pending(self, monitor):
        monitor._audit_pending = ["line"]
        monitor._audit_mode = False
        assert monitor._poll_audit_result() is False
        assert monitor._audit_pending is None

    def test_worker_exception_captured_in_lines(self, monitor):
        monitor._audit_type = "network"
        monitor._audit_worker = None
        def boom():
            raise RuntimeError("nope")
        with patch.dict(monitor._AUDIT_SCANS,
                        {"network": (boom, "Test")},
                        clear=False):
            monitor._start_audit()
            for _ in range(50):
                if monitor._audit_pending is not None:
                    break
                time.sleep(0.01)
        assert monitor._audit_pending
        assert any("audit error" in l for l in monitor._audit_pending)


# ── Keyscan remove-current dispatch branches ──────────────────────────────


class TestKeyscanRemoveCurrent:
    def _seed(self, monitor, action):
        monitor._keyscan_findings_structured = [{
            "severity": "HIGH", "message": "m", "action": action}]
        monitor._keyscan_line_for_finding = [0]
        monitor._keyscan_cursor = 0
        monitor._log_messages = []
        monitor._log_lock = threading.Lock()
        monitor._log_max = 100

    def test_delete_tcc_path(self, monitor):
        self._seed(monitor, {"type": "delete_tcc", "client": "c",
                              "service": "s", "db": "d"})
        with patch.object(monitor, "_confirm_action", return_value=True), \
             patch.object(procmon, "_delete_tcc_grant",
                          return_value=(True, "removed")), \
             patch.object(monitor, "_start_keyscan"):
            monitor._keyscan_remove_current()
        assert monitor._keyscan_action_result["level"] == "ok"

    def test_delete_tcc_failure_gives_sip_explanation(self, monitor):
        self._seed(monitor, {"type": "delete_tcc", "client": "c",
                              "service": "s", "db": "d"})
        with patch.object(monitor, "_confirm_action", return_value=True), \
             patch.object(procmon, "_delete_tcc_grant",
                          return_value=(False, "readonly: SIP")):
            monitor._keyscan_remove_current()
        assert monitor._keyscan_action_result["level"] == "error"
        assert "TCC" in monitor._keyscan_action_result["summary"]

    def test_kill_process_path(self, monitor):
        self._seed(monitor, {"type": "kill_process", "pid": 999,
                              "exe": "/bad"})
        with patch.object(monitor, "_confirm_action", return_value=True), \
             patch("os.kill") as killer, \
             patch.object(monitor, "_start_keyscan"):
            monitor._keyscan_remove_current()
        killer.assert_called_once()

    def test_remove_bundle_path(self, monitor):
        self._seed(monitor, {"type": "remove_bundle", "path": "/x.app"})
        with patch.object(monitor, "_confirm_action", return_value=True), \
             patch.object(procmon, "_remove_bundle",
                          return_value=(True, "gone")), \
             patch.object(monitor, "_start_keyscan"):
            monitor._keyscan_remove_current()
        assert monitor._keyscan_action_result["level"] == "ok"

    def test_unknown_action_type_errors(self, monitor):
        self._seed(monitor, {"type": "alien"})
        monitor._keyscan_remove_current()
        assert monitor._keyscan_action_result["level"] == "error"

    def test_cancel_via_confirm(self, monitor):
        self._seed(monitor, {"type": "delete_tcc", "client": "c",
                              "service": "s", "db": "d"})
        with patch.object(monitor, "_confirm_action", return_value=False):
            monitor._keyscan_remove_current()
        assert monitor._keyscan_action_result["level"] == "info"
        assert "Cancelled" in monitor._keyscan_action_result["summary"]

    def test_informational_finding_blocks_remove(self, monitor):
        self._seed(monitor, None)
        monitor._keyscan_remove_current()
        assert monitor._keyscan_action_result["level"] == "info"

    def test_nothing_selected_returns_info(self, monitor):
        monitor._keyscan_findings_structured = []
        monitor._keyscan_line_for_finding = []
        monitor._keyscan_cursor = 0
        monitor._keyscan_remove_current()
        assert monitor._keyscan_action_result["level"] == "info"


# ── SIP-explanation helper ────────────────────────────────────────────────


class TestSipExplanation:
    def test_root_euid_branch(self, monitor):
        text = monitor._sip_explanation(0, "readonly: SIP is protecting TCC.db")
        assert "sudo alone" in text

    def test_non_root_branch(self, monitor):
        text = monitor._sip_explanation(501, "readonly: SIP protects")
        assert "uid=501" in text

    def test_raw_error_only_when_no_sip(self, monitor):
        text = monitor._sip_explanation(0, "some other error")
        assert "some other error" in text


# ── _parse_btm_items additional edge cases ────────────────────────────────


class TestParseBtmEdges:
    def test_empty_input(self):
        assert procmon._parse_btm_items("") == []

    def test_fields_without_uuid_are_ignored(self):
        items = procmon._parse_btm_items(
            "URL: /somewhere\nDeveloper Name: X\n")
        assert items == []


class TestSharingListEdges:
    def test_trailing_empty_stanza_handled(self):
        text = (
            "name:  A\npath: /a\nshared over: SMB\n\n"
            "name:  B\npath: /b\nshared over: AFP\n")
        rows = procmon._parse_sharing_list(text)
        assert len(rows) == 2


# ── CLI --audit details branch + stale findings ───────────────────────────


class TestCliAuditDetailsEmpty:
    def test_findings_with_only_ok_produces_no_details(self, monkeypatch,
                                                      capsys):
        monkeypatch.setattr(
            procmon, "_audit_network_exposure",
            lambda: [{"severity": "OK", "message": "ok", "action": None},
                     {"severity": "INFO", "message": "info",
                      "action": None}])
        monkeypatch.setattr(sys, "argv",
                             ["procmon", "--audit", "network"])
        with patch.object(procmon, "_preflight", return_value=True), \
             patch.object(procmon, "_self_test", return_value=True), \
             patch.object(procmon, "_harden_process"):
            with pytest.raises(SystemExit):
                procmon.main()
        out = capsys.readouterr().out
        # DETAILS section only renders when there's evidence or an action —
        # neither present here, so no DETAILS header.
        assert "FINDINGS" in out
        assert "DETAILS" not in out


# ── Baseline capture: sharing/subsystem contents ─────────────────────────


class TestBaselineSnapshotContents:
    def test_launch_items_hash_missing_file(self, tmp_path, monkeypatch):
        """A launch item whose plist file no longer exists still gets stored
        (hash is just empty). Regression: would-be crash in _collect_baseline_snapshot."""
        monkeypatch.setattr(
            procmon, "_enumerate_launch_items",
            lambda: [{"path": "/nonexistent.plist",
                      "label": "x", "program": "/x", "hash": ""}])
        monkeypatch.setattr(procmon, "_list_system_extensions",
                             lambda: [])
        monkeypatch.setattr(procmon, "_list_listening_sockets",
                             lambda: [])
        monkeypatch.setattr(procmon, "_list_config_profiles",
                             lambda: [])
        monkeypatch.setattr(procmon, "_sharing_services_state",
                             lambda: {})
        snap = procmon._collect_baseline_snapshot()
        assert snap["launch_items"][0]["hash"] == ""


# ── _resolve_chromium_message additional cases ───────────────────────────


class TestResolveChromiumMessageExtra:
    def test_default_locale_preferred(self, tmp_path):
        # Build an extension with fr+en locales; default_locale=fr
        vdir = tmp_path / "ext" / "1.0.0"
        vdir.mkdir(parents=True)
        locales = vdir / "_locales"
        (locales / "fr").mkdir(parents=True)
        (locales / "fr" / "messages.json").write_text(json.dumps({
            "appName": {"message": "Bonjour"}}))
        (locales / "en").mkdir()
        (locales / "en" / "messages.json").write_text(json.dumps({
            "appName": {"message": "Hello"}}))
        assert procmon._resolve_chromium_message(
            str(vdir), "appName", "fr") == "Bonjour"

    def test_messages_json_without_key_returns_empty(self, tmp_path):
        vdir = tmp_path / "ext" / "1.0.0"
        vdir.mkdir(parents=True)
        locales = vdir / "_locales" / "en"
        locales.mkdir(parents=True)
        (locales / "messages.json").write_text(json.dumps({
            "otherKey": {"message": "X"}}))
        assert procmon._resolve_chromium_message(
            str(vdir), "appName", "en") == ""

    def test_messages_json_malformed_skipped(self, tmp_path):
        vdir = tmp_path / "ext" / "1.0.0"
        vdir.mkdir(parents=True)
        locales = vdir / "_locales" / "en"
        locales.mkdir(parents=True)
        (locales / "messages.json").write_text("not-json{")
        assert procmon._resolve_chromium_message(
            str(vdir), "appName", "en") == ""


# ── _audit_browser_extensions additional ───────────────────────────────────


class TestBrowserFamilies:
    def test_multiple_browser_families_surfaced(self, tmp_path, monkeypatch):
        """Exercise the multi-family loop so we cover Brave/Edge/Arc paths."""
        def make_ext(root, ext_id, name):
            d = root / ext_id / "1.0.0"
            d.mkdir(parents=True)
            (d / "manifest.json").write_text(json.dumps({
                "name": name, "permissions": []}))

        # Chrome + Brave + Edge + Arc layouts
        layouts = {
            "Chrome": "Library/Application Support/Google/Chrome",
            "Brave": "Library/Application Support/BraveSoftware/Brave-Browser",
            "Edge": "Library/Application Support/Microsoft Edge",
            "Arc": "Library/Application Support/Arc/User Data",
        }
        for name, rel in layouts.items():
            profile = tmp_path / rel / "Default" / "Extensions"
            profile.mkdir(parents=True)
            make_ext(profile, f"{name}Ext", f"{name} Test Ext")
        monkeypatch.setattr(procmon, "_EFFECTIVE_HOME", str(tmp_path))
        with patch.object(procmon, "_enum_safari_extensions",
                          return_value=[]), \
             patch.object(procmon, "_enum_firefox_extensions",
                          return_value=[]):
            findings = procmon._audit_browser_extensions()
        msgs = "\n".join(f["message"] for f in findings)
        for family in layouts:
            assert family in msgs


# ── Shell dotfile: nohup and path-home branches ──────────────────────────


class TestShellDotfileMoreBranches:
    def test_nohup_triggers_medium(self, tmp_path, monkeypatch):
        zshrc = tmp_path / ".zshrc"
        zshrc.write_text("nohup /usr/local/bin/something &\n")
        monkeypatch.setattr(procmon, "_DOTFILE_PATHS", [str(zshrc)])
        monkeypatch.setattr(procmon, "_DOTFILE_PATH_DIRS", [])
        findings = procmon._audit_shell_dotfiles()
        assert any("nohup" in f["message"].lower() for f in findings)

    def test_path_home_subdir_not_flagged(self, tmp_path, monkeypatch):
        # PATH prepend pointing inside $HOME should NOT be flagged
        zshrc = tmp_path / ".zshrc"
        zshrc.write_text(f'export PATH="{tmp_path}/bin:$PATH"\n')
        monkeypatch.setattr(procmon, "_EFFECTIVE_HOME", str(tmp_path))
        monkeypatch.setattr(procmon, "_DOTFILE_PATHS", [str(zshrc)])
        monkeypatch.setattr(procmon, "_DOTFILE_PATH_DIRS", [])
        findings = procmon._audit_shell_dotfiles()
        # Not flagged → no HIGH/MEDIUM, only OK
        assert all(f["severity"] in ("OK", "INFO") for f in findings)


# ── Network audit extra branches ──────────────────────────────────────────


class TestNetworkExposureExtraBranches:
    def test_stealth_off_flags_medium(self, monkeypatch):
        def fake(argv, **_):
            cmd = argv[0] if argv else ""
            if "socketfilterfw" in cmd:
                if "--getstealthmode" in argv:
                    return (0, "Stealth mode disabled", "")
                if "--getblockall" in argv:
                    return (0, "Block all DISABLED!", "")
                return (0, "Firewall is enabled.", "")
            if cmd == "systemsetup":
                return (0, "Remote Login: Off", "")
            return (0, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake):
            findings = procmon._audit_network_exposure()
        assert any(f["severity"] == "MEDIUM"
                   and "stealth" in f["message"]
                   for f in findings)

    def test_airdrop_everyone_flagged(self, monkeypatch):
        def fake(argv, **_):
            cmd = argv[0] if argv else ""
            if "socketfilterfw" in cmd:
                return (0, "Firewall is enabled.", "")
            if cmd == "systemsetup":
                return (0, "Remote Login: Off", "")
            if cmd == "defaults":
                return (0, "DiscoverableMode = Everyone;\n", "")
            return (0, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake):
            findings = procmon._audit_network_exposure()
        assert any("AirDrop" in f["message"] for f in findings)

    def test_apple_listener_info(self, monkeypatch):
        lsof = ("COMMAND PID USER FD TYPE DEVICE SIZE NODE NAME\n"
                "cfprefsd 123 root 3u IPv4 0 0 TCP *:80 (LISTEN)\n")
        def fake(argv, **_):
            cmd = argv[0] if argv else ""
            if "socketfilterfw" in cmd:
                return (0, "Firewall is enabled.", "")
            if cmd == "systemsetup":
                return (0, "Remote Login: Off", "")
            if cmd == "lsof":
                return (0, lsof, "")
            return (0, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake), \
             patch.object(procmon, "_get_proc_path",
                          return_value="/System/Library/cfprefsd"), \
             patch.object(procmon, "_codesign_structured",
                          return_value={"team_id": "", "authority": [],
                                        "rc": 0, "entitlements_xml": ""}), \
             patch.object(procmon, "_is_apple_signed", return_value=True):
            findings = procmon._audit_network_exposure()
        assert any(f["severity"] == "INFO"
                   and "Apple signed" in f["message"]
                   for f in findings)
