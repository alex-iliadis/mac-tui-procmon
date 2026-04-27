import tui_report_assertions as tra


def test_structured_report_summary_matches_rendered_rows():
    capture = {
        "requested_action": "audit_network_exposure",
        "scope": "audit",
        "action": "network",
        "title": "Network Exposure Audit",
        "state": "ready",
        "raw_lines": [
            "[REPORT] scope=audit action=network title=Network Exposure Audit",
            "[SUMMARY] critical=1 high=0 medium=1 info=0 ok=0 actionable=1 findings=2",
            "",
            "  Severity:    [CRITICAL 1]  [MEDIUM 1]",
            "  Actionable:  1 — press [D] on a [x]-marked row to remediate",
            "  ── FINDINGS ------------------------------------------------------------",
            "",
            "    [x] [CRITICAL]  Remote login enabled",
            "",
            "        [MEDIUM]  AirDrop visible to everyone",
        ],
    }

    assert tra.review_capture(capture) == []


def test_detects_summary_count_mismatch():
    capture = {
        "requested_action": "audit_network_exposure",
        "scope": "audit",
        "action": "network",
        "title": "Network Exposure Audit",
        "state": "ready",
        "raw_lines": [
            "[REPORT] scope=audit action=network title=Network Exposure Audit",
            "[SUMMARY] critical=2 high=0 medium=0 info=0 ok=0 actionable=0 findings=1",
            "",
            "  Severity:    [CRITICAL 1]",
            "  Actionable:  (none)",
            "  ── FINDINGS ------------------------------------------------------------",
            "",
            "        [CRITICAL]  Remote login enabled",
        ],
    }

    errors = tra.review_capture(capture)
    assert any("summary critical=2 does not match rendered 1" in error
               for error in errors)


def test_detects_missing_expected_hidden_scan_text():
    capture = {
        "requested_action": "forensic_hidden",
        "scope": "forensic",
        "action": "hidden",
        "title": "Hidden Processes + Kernel Modules Scan",
        "state": "ready",
        "raw_lines": [
            "[REPORT] scope=forensic action=hidden title=Hidden Processes + Kernel Modules Scan",
            "",
            "placeholder",
        ],
    }

    errors = tra.review_capture(capture)
    assert any("Deep scan complete:" in error for error in errors)


def test_detects_missing_expected_domain_signal():
    capture = {
        "requested_action": "audit_dns",
        "scope": "audit",
        "action": "dns",
        "title": "DNS / Proxy / MDM Audit",
        "state": "ready",
        "raw_lines": [
            "[REPORT] scope=audit action=dns title=DNS / Proxy / MDM Audit",
            "[SUMMARY] critical=0 high=0 medium=0 info=1 ok=0 actionable=0 findings=1",
            "",
            "  Severity:    [INFO 1]",
            "  Actionable:  (none)",
            "  ── FINDINGS ------------------------------------------------------------",
            "",
            "        [INFO]  Generic placeholder with no domain evidence",
        ],
    }

    errors = tra.review_capture(capture)
    assert any("missing one of expected texts" in error for error in errors)


def test_process_triage_uses_new_title_expectation():
    capture = {
        "requested_action": "forensic_process_triage",
        "scope": "audit",
        "action": "process_triage",
        "title": "Deep Process Triage — PID 321 (evilbin)",
        "state": "ready",
        "raw_lines": [
            "[REPORT] scope=audit action=process_triage title=Deep Process Triage — PID 321 (evilbin)",
            "[SUMMARY] critical=0 high=1 medium=0 info=0 ok=0 actionable=0 findings=1",
            "",
            "  Severity:    [HIGH 1]",
            "  Actionable:  (none)",
            "  ── FINDINGS ------------------------------------------------------------",
            "",
            "        [HIGH]  Live DYLD injection environment",
        ],
    }

    assert tra.review_capture(capture) == []


def test_security_timeline_uses_new_expectation_text():
    capture = {
        "requested_action": "forensic_events",
        "scope": "forensic",
        "action": "events",
        "title": "Security Timeline",
        "state": "ready",
        "raw_lines": [
            "[REPORT] scope=forensic action=events title=Security Timeline",
            "",
            "  Security timeline — source: eslogger — exec/auth/login/TCC/XProtect/launch items",
            "  [INFO]      2026-04-24T20:00:00 pid=100 ppid=1 Exec: /bin/ls",
        ],
    }

    assert tra.review_capture(capture) == []
