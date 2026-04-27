"""Unit tests for the three host security audits (Network / DNS / Persistence)."""
import curses
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import procmon


# ── Parsing helpers ───────────────────────────────────────────────────────


class TestParseLsofListen:
    def test_parses_ipv4_wildcard(self):
        text = (
            "COMMAND  PID   USER   FD  TYPE DEVICE SIZE/OFF NODE NAME\n"
            "sshd    1234   root    3u IPv4 0x1234      0t0  TCP *:22 (LISTEN)\n"
        )
        rows = procmon._parse_lsof_listen(text)
        assert len(rows) == 1
        assert rows[0]["pid"] == 1234
        assert rows[0]["command"] == "sshd"
        assert rows[0]["addr"] == "*"
        assert rows[0]["port"] == "22"

    def test_parses_ipv6_loopback(self):
        text = (
            "cupsd   5678   root    7u IPv6 0x5678      0t0  TCP [::1]:631 (LISTEN)\n"
        )
        rows = procmon._parse_lsof_listen(text)
        assert len(rows) == 1
        assert rows[0]["addr"] == "[::1]"
        assert rows[0]["port"] == "631"

    def test_skips_header_and_short_lines(self):
        text = "COMMAND  PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\ngarbage\n"
        rows = procmon._parse_lsof_listen(text)
        assert rows == []


class TestAddrIsPublicBind:
    def test_wildcard_is_public(self):
        assert procmon._addr_is_public_bind("*") is True
        assert procmon._addr_is_public_bind("0.0.0.0") is True
        assert procmon._addr_is_public_bind("[::]") is True

    def test_loopback_is_not_public(self):
        assert procmon._addr_is_public_bind("127.0.0.1") is False
        assert procmon._addr_is_public_bind("[::1]") is False

    def test_private_ip_is_still_reachable(self):
        # 192.168.x is reachable from the LAN — we treat it as public-ish.
        assert procmon._addr_is_public_bind("192.168.1.5") is True


class TestParseSharingList:
    def test_parses_multi_protocol_share(self):
        text = (
            "name:          Public\n"
            "path:          /Users/alex/Public\n"
            "shared over:   AFP, SMB\n"
        )
        rows = procmon._parse_sharing_list(text)
        assert len(rows) == 1
        assert rows[0]["name"] == "Public"
        assert rows[0]["path"] == "/Users/alex/Public"
        assert "AFP" in rows[0]["protocols"]
        assert "SMB" in rows[0]["protocols"]

    def test_empty_input(self):
        assert procmon._parse_sharing_list("") == []


class TestParseScutilDns:
    def test_parses_multiple_resolvers(self):
        text = (
            "resolver #1\n"
            "  nameserver[0] : 8.8.8.8\n"
            "  nameserver[1] : 8.8.4.4\n"
            "  flags    : Request A records\n"
            "\n"
            "resolver #2\n"
            "  domain   : local\n"
            "  nameserver[0] : 224.0.0.251\n"
        )
        r = procmon._parse_scutil_dns(text)
        assert len(r) == 2
        assert r[0]["resolver_id"] == 1
        assert r[0]["nameservers"] == ["8.8.8.8", "8.8.4.4"]
        assert r[1]["resolver_id"] == 2
        assert r[1]["domain"] == "local"


class TestParseScutilProxy:
    def test_extracts_http_proxy(self):
        text = (
            "<dictionary> {\n"
            "  HTTPEnable : 1\n"
            "  HTTPProxy : 10.0.0.5\n"
            "  HTTPPort : 3128\n"
            "}\n"
        )
        p = procmon._parse_scutil_proxy(text)
        assert p["HTTPEnable"] == "1"
        assert p["HTTPProxy"] == "10.0.0.5"
        assert p["HTTPPort"] == "3128"


class TestReadHostsFile:
    def test_filters_default_entries(self, tmp_path):
        hosts = tmp_path / "hosts"
        hosts.write_text(
            "# Default hosts file\n"
            "127.0.0.1       localhost\n"
            "255.255.255.255 broadcasthost\n"
            "::1             localhost\n"
            "10.0.0.1        evil.apple.com\n"
        )
        extras, raw = procmon._read_hosts_file(str(hosts))
        assert len(extras) == 1
        assert extras[0]["ip"] == "10.0.0.1"
        assert extras[0]["host"] == "evil.apple.com"
        assert raw

    def test_missing_file(self):
        extras, raw = procmon._read_hosts_file("/nonexistent/hosts")
        assert extras == []
        assert raw == b""


class TestExtractLaunchProgram:
    def test_prefers_program_key(self):
        plist = {"Program": "/usr/local/bin/foo",
                 "ProgramArguments": ["/bin/other"]}
        assert procmon._extract_launch_program(plist) == "/usr/local/bin/foo"

    def test_falls_back_to_first_arg(self):
        plist = {"ProgramArguments": ["/usr/local/bin/foo", "--daemon"]}
        assert procmon._extract_launch_program(plist) == "/usr/local/bin/foo"

    def test_empty_plist(self):
        assert procmon._extract_launch_program({}) == ""
        assert procmon._extract_launch_program(None) == ""


class TestParseBtmItems:
    def test_parses_two_items(self):
        text = (
            "UUID: 11111111-1111\n"
            "  URL: /Applications/App1.app\n"
            "  Developer Name: Alice Corp\n"
            "  Team ID: ABCDEF\n"
            "UUID: 22222222-2222\n"
            "  URL: /Applications/App2.app\n"
            "  Bundle identifier: com.bob\n"
        )
        items = procmon._parse_btm_items(text)
        assert len(items) == 2
        assert items[0]["dev_name"] == "Alice Corp"
        assert items[0]["team"] == "ABCDEF"
        assert items[1]["bundle_id"] == "com.bob"


# ── Audit functions: end-to-end with mocks ────────────────────────────────


class TestAuditNetworkExposure:
    def test_flags_disabled_alf(self):
        def fake_run(argv, **kwargs):
            cmd = argv[0] if argv else ""
            if "socketfilterfw" in cmd or (len(argv) >= 2 and "socketfilterfw" in argv[0]):
                return (0, "Firewall is disabled. (State = 0)", "")
            if cmd == "systemsetup":
                return (0, "Remote Login: Off", "")
            if cmd == "sharing":
                return (0, "", "")
            if cmd == "launchctl":
                return (0, "", "")
            if cmd == "defaults":
                return (0, "", "")
            if cmd == "lsof":
                return (0, "", "")
            if cmd == "pfctl":
                return (0, "", "")
            return (0, "", "")

        with patch.object(procmon, "_run_cmd_short", side_effect=fake_run):
            findings = procmon._audit_network_exposure()
        msgs = [f["message"] for f in findings]
        assert any("Firewall is OFF" in m for m in msgs), msgs
        assert any(f["severity"] == "HIGH" and f["action"]
                   and f["action"]["type"] == "enable_alf"
                   for f in findings)

    def test_flags_remote_login_when_on(self):
        def fake_run(argv, **kwargs):
            cmd = argv[0] if argv else ""
            if "socketfilterfw" in cmd:
                return (0, "Firewall is enabled.", "")
            if cmd == "systemsetup":
                return (0, "Remote Login: On", "")
            return (0, "", "")

        with patch.object(procmon, "_run_cmd_short", side_effect=fake_run):
            findings = procmon._audit_network_exposure()
        assert any(f["action"] and f["action"]["type"] == "disable_remote_login"
                   for f in findings)

    def test_flags_unsigned_public_listener(self):
        lsof_output = (
            "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
            "evil   9999 root  3u IPv4 0x1   0t0 TCP *:4444 (LISTEN)\n"
        )

        def fake_run(argv, **kwargs):
            cmd = argv[0] if argv else ""
            if "socketfilterfw" in cmd:
                return (0, "Firewall is enabled.", "")
            if cmd == "systemsetup":
                return (0, "Remote Login: Off", "")
            if cmd == "lsof":
                return (0, lsof_output, "")
            return (0, "", "")

        with patch.object(procmon, "_run_cmd_short", side_effect=fake_run), \
             patch.object(procmon, "_get_proc_path", return_value="/tmp/evil"), \
             patch.object(procmon, "_codesign_structured", return_value={}), \
             patch.object(procmon, "_is_apple_signed", return_value=False):
            findings = procmon._audit_network_exposure()
        assert any(
            f["severity"] == "HIGH" and "4444" in f["message"]
            and f["action"] and f["action"]["type"] == "kill_process"
            for f in findings
        )

    def test_clean_host_reports_ok(self):
        def fake_run(argv, **kwargs):
            cmd = argv[0] if argv else ""
            if "socketfilterfw" in cmd:
                if "--getblockall" in argv:
                    return (0, "Block all DISABLED!", "")
                if "--getstealthmode" in argv:
                    return (0, "Stealth mode enabled", "")
                return (0, "Firewall is enabled.", "")
            if cmd == "systemsetup":
                return (0, "Remote Login: Off", "")
            return (0, "", "")

        with patch.object(procmon, "_run_cmd_short", side_effect=fake_run):
            findings = procmon._audit_network_exposure()
        assert any(f["severity"] == "OK" for f in findings)


class TestAuditDnsProxyMdm:
    def test_flags_http_proxy(self):
        proxy_text = (
            "  HTTPEnable : 1\n"
            "  HTTPProxy : 10.0.0.5\n"
            "  HTTPPort : 3128\n"
        )

        def fake_run(argv, **kwargs):
            cmd = argv[0] if argv else ""
            if cmd == "scutil" and "--proxy" in argv:
                return (0, proxy_text, "")
            if cmd == "scutil" and "--dns" in argv:
                return (0, "", "")
            if cmd == "profiles":
                return (0, "", "")
            return (0, "", "")

        with patch.object(procmon, "_run_cmd_short", side_effect=fake_run), \
             patch.object(procmon, "_read_hosts_file", return_value=([], b"")), \
             patch.object(procmon, "_list_resolver_dir", return_value=[]):
            findings = procmon._audit_dns_proxy_mdm()
        assert any(f["severity"] == "CRITICAL" and "HTTP proxy" in f["message"]
                   for f in findings)

    def test_flags_mdm_dns_profile(self):
        profiles_text = (
            "_computerlevel[1] attribute: profileIdentifier: com.bad.dns\n"
            "_computerlevel[1] attribute: profileDisplayName: Bad DNS\n"
            "_computerlevel[1]     PayloadType = \"com.apple.dnsSettings.managed\"\n"
        )

        def fake_run(argv, **kwargs):
            cmd = argv[0] if argv else ""
            if cmd == "scutil":
                return (0, "", "")
            if cmd == "profiles" and "show" in argv:
                return (0, profiles_text, "")
            if cmd == "profiles" and "status" in argv:
                return (0, "MDM enrollment: No", "")
            return (0, "", "")

        with patch.object(procmon, "_run_cmd_short", side_effect=fake_run), \
             patch.object(procmon, "_read_hosts_file", return_value=([], b"")), \
             patch.object(procmon, "_list_resolver_dir", return_value=[]):
            findings = procmon._audit_dns_proxy_mdm()
        crit_remove = [f for f in findings
                       if f["severity"] == "CRITICAL" and f.get("action")
                       and f["action"]["type"] == "remove_profile"]
        assert crit_remove, findings
        assert crit_remove[0]["action"]["identifier"] == "com.bad.dns"

    def test_flags_hosts_file_redirection(self, tmp_path):
        hosts = tmp_path / "hosts"
        hosts.write_text("127.0.0.1 localhost\n1.2.3.4 icloud.com\n")

        def fake_run(argv, **kwargs):
            return (0, "", "")

        with patch.object(procmon, "_run_cmd_short", side_effect=fake_run), \
             patch.object(procmon, "_read_hosts_file",
                          return_value=(
                              [{"ip": "1.2.3.4", "host": "icloud.com"}], b"")), \
             patch.object(procmon, "_list_resolver_dir", return_value=[]):
            findings = procmon._audit_dns_proxy_mdm()
        assert any(f["severity"] == "CRITICAL"
                   and "icloud.com" in f["message"]
                   for f in findings)

    def test_clean_returns_ok(self):
        def fake_run(argv, **kwargs):
            return (0, "", "")

        with patch.object(procmon, "_run_cmd_short", side_effect=fake_run), \
             patch.object(procmon, "_read_hosts_file", return_value=([], b"")), \
             patch.object(procmon, "_list_resolver_dir", return_value=[]):
            findings = procmon._audit_dns_proxy_mdm()
        assert any(f["severity"] == "OK" for f in findings)


class TestAuditPersistence:
    def test_flags_unsigned_launch_item(self):
        fake_items = [{
            "path": "/Library/LaunchAgents/com.evil.plist",
            "label": "com.evil",
            "program": "/tmp/evil_bin",
            "domain": "gui",
            "system_signed": False,
            "run_at_load": True,
            "keep_alive": False,
        }]

        def fake_run(argv, **kwargs):
            return (0, "", "")

        with patch.object(procmon, "_enumerate_launch_items", return_value=fake_items), \
             patch.object(procmon, "_list_privileged_helpers", return_value=[]), \
             patch.object(procmon, "_user_crontabs", return_value=[]), \
             patch.object(procmon, "_sfltool_dumpbtm", return_value=""), \
             patch.object(procmon, "_run_cmd_short", side_effect=fake_run), \
             patch("os.path.exists", return_value=True), \
             patch.object(procmon, "_codesign_structured",
                          return_value={"team_id": "", "rc": 1,
                                        "authority": [], "raw": ""}), \
             patch.object(procmon, "_is_apple_signed", return_value=False):
            findings = procmon._audit_persistence()
        assert any(f["severity"] == "HIGH"
                   and "com.evil" in f["message"]
                   and f["action"] and f["action"]["type"] == "bootout_launchitem"
                   for f in findings)

    def test_flags_missing_program(self):
        fake_items = [{
            "path": "/Library/LaunchAgents/com.missing.plist",
            "label": "com.missing",
            "program": "/tmp/missing_bin",
            "domain": "gui",
            "system_signed": False,
            "run_at_load": False,
            "keep_alive": False,
        }]

        def fake_run(argv, **kwargs):
            return (0, "", "")

        # _codesign_structured on a missing path would have rc!=0, and
        # _audit_persistence also calls os.path.exists(prog) — patch that to False.
        def exists_side_effect(p):
            if p == "/tmp/missing_bin":
                return False
            return True

        with patch.object(procmon, "_enumerate_launch_items", return_value=fake_items), \
             patch.object(procmon, "_list_privileged_helpers", return_value=[]), \
             patch.object(procmon, "_user_crontabs", return_value=[]), \
             patch.object(procmon, "_sfltool_dumpbtm", return_value=""), \
             patch.object(procmon, "_run_cmd_short", side_effect=fake_run), \
             patch("os.path.exists", side_effect=exists_side_effect), \
             patch.object(procmon, "_codesign_structured", return_value={}), \
             patch.object(procmon, "_is_apple_signed", return_value=False):
            findings = procmon._audit_persistence()
        assert any(f["severity"] == "CRITICAL" and "MISSING" in f["message"]
                   for f in findings)

    def test_skips_system_signed_items(self):
        fake_items = [{
            "path": "/System/Library/LaunchDaemons/com.apple.foo.plist",
            "label": "com.apple.foo",
            "program": "/System/Library/foo",
            "domain": "system",
            "system_signed": True,
            "run_at_load": True,
            "keep_alive": True,
        }]

        def fake_run(argv, **kwargs):
            return (0, "", "")

        with patch.object(procmon, "_enumerate_launch_items", return_value=fake_items), \
             patch.object(procmon, "_list_privileged_helpers", return_value=[]), \
             patch.object(procmon, "_user_crontabs", return_value=[]), \
             patch.object(procmon, "_sfltool_dumpbtm", return_value=""), \
             patch.object(procmon, "_run_cmd_short", side_effect=fake_run):
            findings = procmon._audit_persistence()
        # /System/ items filtered out — no HIGH/CRITICAL findings
        assert not any(f["severity"] in ("HIGH", "CRITICAL") for f in findings)

    def test_flags_user_crontab(self):
        def fake_run(argv, **kwargs):
            return (0, "", "")

        with patch.object(procmon, "_enumerate_launch_items", return_value=[]), \
             patch.object(procmon, "_list_privileged_helpers", return_value=[]), \
             patch.object(procmon, "_user_crontabs",
                          return_value=[("alice", "* * * * * /tmp/beacon")]), \
             patch.object(procmon, "_sfltool_dumpbtm", return_value=""), \
             patch.object(procmon, "_run_cmd_short", side_effect=fake_run):
            findings = procmon._audit_persistence()
        assert any(f["severity"] == "MEDIUM" and "alice" in f["message"]
                   for f in findings)


# ── UI wiring ─────────────────────────────────────────────────────────────


class TestAuditMode:
    def test_toggle_opens_and_starts_scan(self, monitor):
        with patch.object(monitor, "_start_audit") as start:
            monitor._toggle_audit_mode("network")
        assert monitor._audit_mode is True
        assert monitor._audit_type == "network"
        assert monitor._detail_focus is True
        start.assert_called_once()

    def test_toggle_same_type_closes(self, monitor):
        monitor._audit_mode = True
        monitor._audit_type = "network"
        monitor._toggle_audit_mode("network")
        assert monitor._audit_mode is False

    def test_toggle_different_type_switches(self, monitor):
        monitor._audit_mode = True
        monitor._audit_type = "network"
        with patch.object(monitor, "_start_audit"):
            monitor._toggle_audit_mode("dns")
        assert monitor._audit_mode is True
        assert monitor._audit_type == "dns"

    def test_toggle_rejects_unknown_type(self, monitor):
        monitor._toggle_audit_mode("bogus")
        assert monitor._audit_mode is False

    def test_structured_report_has_title_bar_and_summary(self, monitor):
        findings = [
            {"severity": "HIGH", "message": "bad thing",
             "action": {"type": "enable_alf"}},
            {"severity": "INFO", "message": "fyi", "action": None},
            {"severity": "OK", "message": "good", "action": None},
        ]
        line_map = []
        lines = monitor._format_structured_report(
            "Test Audit", findings, line_map)
        # Title bar is present and upper-cased
        assert any("TEST AUDIT" in l for l in lines[:3])
        # Severity summary line lists each present severity with a count
        sev_line = next(l for l in lines if "Severity:" in l)
        assert "[HIGH 1]" in sev_line
        assert "[INFO 1]" in sev_line
        assert "[OK 1]" in sev_line
        # "Actionable" shows the count
        act_line = next(l for l in lines if "Actionable:" in l)
        assert "1" in act_line
        # FINDINGS section header
        assert any("FINDINGS" in l for l in lines)

    def test_structured_report_omits_inline_evidence(self, monitor):
        """Evidence is shown in a separate DETAIL pane at render time, not
        inline in the findings list. The formatter itself should never
        embed evidence text."""
        findings = [
            {"severity": "HIGH", "message": "alert",
             "evidence": "very-secret-evidence-text",
             "action": {"type": "enable_alf"}},
        ]
        line_map = []
        lines = monitor._format_structured_report(
            "T", findings, line_map)
        assert not any("very-secret-evidence-text" in l for l in lines)

    def test_finding_detail_block_shape(self, monitor):
        finding = {"severity": "CRITICAL", "message": "msg",
                   "evidence": "line1\nline2",
                   "action": {"type": "enable_alf"}}
        detail = monitor._format_finding_detail(finding, 80)
        joined = "\n".join(detail)
        assert "DETAIL" in joined
        assert "[CRITICAL]" in joined
        assert "msg" in joined
        assert "line1" in joined
        assert "line2" in joined
        assert "enable_alf" in joined
        assert "press [D]" in joined

    def test_finding_detail_empty_when_nothing_selected(self, monitor):
        assert monitor._format_finding_detail(None, 80) == []

    def test_audit_report_four_space_indent_for_cursor_overlay(self, monitor):
        """Finding rows start with exactly four spaces so the render-time
        cursor overlay (`"  \u25b6 "`) aligns. Regression guard: a future
        refactor that changes the indent will break the cursor alignment
        silently unless this test flags it."""
        findings = [{"severity": "HIGH", "message": "uniquetoken",
                     "action": {"type": "enable_alf"}}]
        monitor._audit_type = "network"
        lines = monitor._format_audit_report(findings)
        idx = monitor._audit_line_for_finding[0]
        finding_line = lines[idx]
        assert "uniquetoken" in finding_line
        assert finding_line.startswith("    ")  # 4-space indent

    def test_format_audit_report_sorts_by_severity(self, monitor):
        findings = [
            {"severity": "INFO", "message": "info1", "action": None},
            {"severity": "CRITICAL", "message": "crit1", "action": None},
            {"severity": "HIGH", "message": "high1", "action": None},
            {"severity": "OK", "message": "ok1", "action": None},
        ]
        monitor._audit_type = "network"
        lines = monitor._format_audit_report(findings)
        crit_line = next(i for i, L in enumerate(lines) if "crit1" in L)
        high_line = next(i for i, L in enumerate(lines) if "high1" in L)
        info_line = next(i for i, L in enumerate(lines) if "info1" in L)
        ok_line = next(i for i, L in enumerate(lines) if "ok1" in L)
        assert crit_line < high_line < info_line < ok_line

    def test_format_audit_report_marks_actionable(self, monitor):
        findings = [
            {"severity": "HIGH", "message": "REMEDY_AVAILABLE",
             "action": {"type": "kill_process", "pid": 1}},
            {"severity": "HIGH", "message": "INFO_ONLY", "action": None},
        ]
        monitor._audit_type = "network"
        lines = monitor._format_audit_report(findings)
        act_idx = next(i for i, L in enumerate(lines) if "REMEDY_AVAILABLE" in L)
        noop_idx = next(i for i, L in enumerate(lines) if "INFO_ONLY" in L)
        assert "[x]" in lines[act_idx]
        assert "[x]" not in lines[noop_idx]

    def test_move_cursor_clamps(self, monitor):
        monitor._audit_findings_structured = [
            {"severity": "HIGH", "message": "a", "action": None},
            {"severity": "HIGH", "message": "b", "action": None},
        ]
        monitor._audit_line_for_finding = [2, 3]
        monitor._audit_cursor = 0
        monitor.stdscr.getmaxyx.return_value = (40, 120)
        monitor._audit_move_cursor(5)
        assert monitor._audit_cursor == 1  # clamped at n-1
        monitor._audit_move_cursor(-99)
        assert monitor._audit_cursor == 0

    def test_remediate_current_confirms_and_dispatches(self, monitor):
        monitor._audit_findings_structured = [
            {"severity": "HIGH", "message": "bad",
             "action": {"type": "enable_alf"}},
        ]
        monitor._audit_line_for_finding = [2]
        monitor._audit_cursor = 0
        monitor._audit_type = "network"
        with patch.object(monitor, "_confirm_action", return_value=True), \
             patch.object(monitor, "_dispatch_audit_action",
                          return_value=(True, "ok")) as dispatch, \
             patch.object(monitor, "_start_audit"):
            monitor._audit_remediate_current()
        dispatch.assert_called_once()
        assert monitor._audit_action_result["level"] == "ok"

    def test_remediate_optimistically_removes_finding(self, monitor):
        """After a successful remediation the remediated row should disappear
        from the visible list immediately — without waiting for the async
        rescan. Guards against the bug where a slow global-score rescan
        leaves the remediated finding on screen for 30+ seconds."""
        monitor._audit_findings_structured = [
            {"severity": "CRITICAL", "message": "first",
             "action": {"type": "enable_alf"}},
            {"severity": "HIGH", "message": "second", "action": None},
        ]
        monitor._audit_line_for_finding = [2, 3]
        monitor._audit_cursor = 0
        monitor._audit_type = "network"
        with patch.object(monitor, "_confirm_action", return_value=True), \
             patch.object(monitor, "_dispatch_audit_action",
                          return_value=(True, "ok")), \
             patch.object(monitor, "_start_audit"):
            monitor._audit_remediate_current()
        # The "first" finding is gone — the optimistic UI update ran before
        # the (mocked-out) rescan had a chance to do anything.
        msgs = [f["message"] for f in monitor._audit_findings_structured]
        assert "first" not in msgs
        assert "second" in msgs
        # _audit_lines was rebuilt from the remaining finding — should NOT
        # contain the remediated message anywhere.
        assert not any("first" in l for l in monitor._audit_lines)

    def test_remediate_failure_does_not_remove_finding(self, monitor):
        """If the remediation fails, keep the finding visible so the user
        can see the error and try a different fix."""
        monitor._audit_findings_structured = [
            {"severity": "HIGH", "message": "bad",
             "action": {"type": "enable_alf"}},
        ]
        monitor._audit_line_for_finding = [2]
        monitor._audit_cursor = 0
        monitor._audit_type = "network"
        with patch.object(monitor, "_confirm_action", return_value=True), \
             patch.object(monitor, "_dispatch_audit_action",
                          return_value=(False, "permission denied")):
            monitor._audit_remediate_current()
        # Finding is still there since the fix didn't take
        assert len(monitor._audit_findings_structured) == 1
        assert monitor._audit_action_result["level"] == "error"

    def test_remove_current_finding_adjusts_cursor(self, monitor):
        """Removing the last finding drops the cursor onto the previous one."""
        monitor._audit_findings_structured = [
            {"severity": "HIGH", "message": "a", "action": None},
            {"severity": "HIGH", "message": "b", "action": None},
        ]
        monitor._audit_line_for_finding = [2, 3]
        monitor._audit_cursor = 1  # last
        monitor._audit_type = "network"
        monitor._audit_remove_current_finding()
        assert len(monitor._audit_findings_structured) == 1
        assert monitor._audit_cursor == 0

    def test_remove_current_finding_empty_list_noop(self, monitor):
        monitor._audit_findings_structured = []
        monitor._audit_line_for_finding = []
        monitor._audit_cursor = 0
        monitor._audit_type = "network"
        # Should not raise
        monitor._audit_remove_current_finding()


    def test_remediate_current_cancel(self, monitor):
        monitor._audit_findings_structured = [
            {"severity": "HIGH", "message": "bad",
             "action": {"type": "enable_alf"}},
        ]
        monitor._audit_line_for_finding = [2]
        monitor._audit_cursor = 0
        with patch.object(monitor, "_confirm_action", return_value=False):
            monitor._audit_remediate_current()
        assert monitor._audit_action_result["level"] == "info"
        assert "ancel" in monitor._audit_action_result["summary"]

    def test_remediate_no_action_is_informational(self, monitor):
        monitor._audit_findings_structured = [
            {"severity": "INFO", "message": "just info", "action": None},
        ]
        monitor._audit_line_for_finding = [2]
        monitor._audit_cursor = 0
        monitor._audit_remediate_current()
        assert monitor._audit_action_result["level"] == "info"

    def test_dispatch_enable_alf_runs_socketfilterfw(self, monitor):
        monitor._log_messages = []
        import threading
        monitor._log_lock = threading.Lock()
        monitor._log_max = 100
        with patch.object(procmon, "_run_cmd_short",
                          return_value=(0, "enabled", "")) as run:
            ok, msg = monitor._dispatch_audit_action({"type": "enable_alf"})
        assert ok is True
        assert "socketfilterfw" in run.call_args[0][0][0]

    def test_dispatch_remove_profile_requires_id(self, monitor):
        monitor._log_messages = []
        import threading
        monitor._log_lock = threading.Lock()
        monitor._log_max = 100
        ok, msg = monitor._dispatch_audit_action({"type": "remove_profile"})
        assert ok is False

    def test_dispatch_unknown_action(self, monitor):
        monitor._log_messages = []
        import threading
        monitor._log_lock = threading.Lock()
        monitor._log_max = 100
        ok, msg = monitor._dispatch_audit_action({"type": "nonsense"})
        assert ok is False
        assert "unknown" in msg.lower()


class TestChatContextInAuditMode:
    """When the user presses `?` inside an audit view, the chat must capture
    the audit's context — not fall through to whatever process happens to be
    selected in the main list."""

    def test_audit_context_is_preferred_over_process_row(self, monitor):
        from tests.conftest import make_proc
        monitor.rows = [make_proc(pid=9999, command="/Applications/Chrome")]
        monitor.selected = 0
        monitor._audit_mode = True
        monitor._audit_type = "kernel_boot"
        monitor._audit_lines = [
            "  \u2501\u2501 KERNEL / BOOT INTEGRITY \u2501\u2501",
            "  \u2500\u2500 FINDINGS \u2500\u2500",
            "    [HIGH]  5 non-Apple kext(s) in /Library/Extensions",
        ]
        monitor._audit_findings_structured = [
            {"severity": "HIGH",
             "message": "5 non-Apple kext(s) in /Library/Extensions",
             "evidence": "YamahaSteinbergUSBAudio.kext\nSoftRAID.kext",
             "action": None},
        ]
        monitor._audit_line_for_finding = [2]
        monitor._audit_cursor = 0

        label, text = monitor._collect_chat_context()
        assert "Kernel" in label
        assert "Chrome" not in text
        assert "non-Apple kext" in text
        assert "YamahaSteinbergUSBAudio.kext" in text
        assert "SoftRAID.kext" in text

    def test_audit_context_survives_when_no_cursor(self, monitor):
        from tests.conftest import make_proc
        monitor.rows = [make_proc(pid=1234, command="/bin/bash")]
        monitor.selected = 0
        monitor._audit_mode = True
        monitor._audit_type = "network"
        monitor._audit_lines = [" \u2501\u2501 NETWORK \u2501\u2501 ",
                                "  \u2500\u2500 FINDINGS \u2500\u2500 "]
        monitor._audit_findings_structured = []
        monitor._audit_line_for_finding = []
        monitor._audit_cursor = 0

        label, text = monitor._collect_chat_context()
        assert "bash" not in text
        assert "Network" in label

    def test_keyscan_context_inlines_cursor(self, monitor):
        monitor._keyscan_mode = True
        monitor._keyscan_lines = ["  \u2501\u2501 KEYBOARD HOOK SCAN \u2501\u2501"]
        monitor._keyscan_findings_structured = [
            {"severity": "HIGH", "message": "TCC grant: com.evil",
             "action": {"type": "delete_tcc"}},
        ]
        monitor._keyscan_line_for_finding = [0]
        monitor._keyscan_cursor = 0

        label, text = monitor._collect_chat_context()
        assert "TCC grant: com.evil" in text


class TestAuditInputHandling:
    def test_a_opens_audit_menu(self, monitor):
        monitor._detail_focus = False
        with patch.object(monitor, "_prompt_audit") as prompt:
            monitor.handle_input(ord("a"))
        prompt.assert_called_once()

    def test_escape_closes_audit_mode(self, monitor):
        monitor._audit_mode = True
        monitor._audit_type = "network"
        monitor._detail_focus = False  # main-list path
        result = monitor.handle_input(27)  # Esc
        assert result is True
        assert monitor._audit_mode is False
