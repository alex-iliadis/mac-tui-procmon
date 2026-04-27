#!/usr/bin/env python3
"""Assertions for secprocmon TUI detail-pane capture files."""

from __future__ import annotations

import json
import re
from pathlib import Path


SUMMARY_RE = re.compile(r"([a-z_]+)=([0-9]+)")
SEVERITY_RE = re.compile(r"\[(CRITICAL|HIGH|MEDIUM|INFO|OK)\]")
ACTIONABLE_RE = re.compile(r"\[x\]\s+\[(CRITICAL|HIGH|MEDIUM|INFO|OK)\]")

GENERIC_FORBIDDEN = (
    "traceback",
    "[audit error:",
    "[scan error:",
    "[bulk scan error:",
    "[inspect error:",
    "summary error:",
)

EXPECTATIONS = {
    "forensic_inspect": {
        "scope": "forensic",
        "action": "inspect",
        "title_contains": "Inspect",
        "must_contain": ["[INSPECT] PID", "Code Signature", "Test Mode Analysis"],
    },
    "forensic_process_triage": {
        "scope": "audit",
        "action": "process_triage",
        "title_contains": "Deep Process Triage",
        "must_contain": ["Severity:", "FINDINGS"],
        "must_contain_any": [[
            "Selected process identity",
            "DYLD injection",
            "selected process shows live DYLD injection",
            "Code signature",
        ]],
        "structured": True,
    },
    "live_process_triage": {
        "scope": "audit",
        "action": "process_triage",
        "title_contains": "Deep Process Triage",
        "must_contain": ["Severity:", "FINDINGS"],
        "must_contain_any": [[
            "Selected process identity",
            "DYLD_INSERT_LIBRARIES",
            "anti-debug",
            "Code signature",
        ]],
        "structured": True,
    },
    "forensic_hidden": {
        "scope": "forensic",
        "action": "hidden",
        "title_contains": "Hidden Processes",
        "must_contain": ["Deep scan complete:", "Live kernel-hook detection"],
    },
    "forensic_bulk_scan": {
        "scope": "forensic",
        "action": "bulk",
        "title_contains": "Bulk Security Scan",
        "must_contain": ["Bulk security scan", "Press Esc or F to cancel."],
        "must_contain_any": [[
            "Last completed:",
            "Findings so far",
            "(no flagged processes yet)",
        ]],
    },
    "forensic_process_entitlements": {
        "scope": "audit",
        "action": "process_entitlements",
        "title_contains": "Per-Process Entitlements",
        "must_contain": ["Severity:", "FINDINGS"],
        "must_contain_any": [["entitlement", "No dangerous runtime entitlements"]],
        "structured": True,
    },
    "forensic_injection_antidebug": {
        "scope": "audit",
        "action": "injection_antidebug",
        "title_contains": "Injection / Anti-Debug Audit",
        "must_contain": ["Severity:", "FINDINGS"],
        "must_contain_any": [["DYLD", "anti-debug", "injection", "No injection"]],
        "structured": True,
    },
    "live_injection_summary": {
        "scope": "audit",
        "action": "injection_antidebug",
        "title_contains": "Injection / Anti-Debug Audit",
        "must_contain": ["Severity:", "FINDINGS"],
        "must_contain_any": [["DYLD", "anti-debug", "injection", "No injection"]],
        "structured": True,
    },
    "forensic_keyscan": {
        "scope": "forensic",
        "action": "keyscan",
        "title_contains": "Keyboard Hook",
        "must_contain": ["Severity:", "FINDINGS", "Signal sources:"],
        "structured": True,
    },
    "forensic_usb_hid": {
        "scope": "audit",
        "action": "usb_hid",
        "title_contains": "USB / HID Audit",
        "must_contain": ["Severity:", "FINDINGS"],
        "must_contain_any": [["USB", "HID"]],
        "structured": True,
    },
    "forensic_events": {
        "scope": "forensic",
        "action": "events",
        "title_contains": "Security Timeline",
        "must_contain": ["Security timeline", "source:"],
    },
    "forensic_traffic": {
        "scope": "forensic",
        "action": "traffic",
        "title_contains": "Traffic Inspector",
        "must_contain": ["mitmdump", "127.0.0.1:8080", "Captured"],
        "must_contain_any": [["waiting for traffic", "flow(s)", "ERROR:"]],
    },
    "forensic_network": {
        "scope": "forensic",
        "action": "network",
        "title_contains": "Network",
        "must_contain": ["Network"],
        "must_contain_any": [["→", "No active network connections", "[TCP]", "[UDP]", "org:"]],
    },
    "audit_global_score": {
        "scope": "audit",
        "action": "global_score",
        "title_contains": "Global Security Score",
        "must_contain": ["Severity:", "Actionable:", "FINDINGS"],
        "must_contain_any": [["Global security score", "Test mode global score"]],
        "structured": True,
    },
    "audit_automated_security_scan": {
        "scope": "audit",
        "action": "automated_security_scan",
        "title_contains": "Automated Security Scan",
        "must_contain": [
            "AUTOMATED SECURITY SCAN",
            "SUMMARY:",
            "READ THIS FIRST",
            "Reviewers used",
            "FIX FIRST - NATIVE EVIDENCE",
            "PRIORITY FINDINGS - REVIEWER CONSENSUS",
            "PER-AUDIT HEATMAP",
            "REVIEWER EXCERPTS (TRIMMED)",
            "Layer scores:",
            "Additive synthesis:",
        ],
    },
    "audit_network_exposure": {
        "scope": "audit",
        "action": "network",
        "title_contains": "Network Exposure Audit",
        "must_contain": ["Severity:", "Actionable:", "FINDINGS"],
        "must_contain_any": [["Firewall", "Remote Login", "listening", "No listening"]],
        "structured": True,
    },
    "audit_dns": {
        "scope": "audit",
        "action": "dns",
        "title_contains": "DNS / Proxy / MDM Audit",
        "must_contain": ["Severity:", "Actionable:", "FINDINGS"],
        "must_contain_any": [["DNS", "proxy", "/etc/hosts", "configuration profiles"]],
        "structured": True,
    },
    "audit_system_hardening": {
        "scope": "audit",
        "action": "system_hardening",
        "title_contains": "System Hardening",
        "must_contain": ["Severity:", "Actionable:", "FINDINGS"],
        "must_contain_any": [[
            "System Integrity Protection",
            "Gatekeeper",
            "FileVault",
            "XProtect",
            "hardening data unavailable",
        ]],
        "structured": True,
    },
    "audit_kernel_boot": {
        "scope": "audit",
        "action": "kernel_boot",
        "title_contains": "Kernel / Boot Integrity",
        "must_contain": ["Severity:", "Actionable:", "FINDINGS"],
        "must_contain_any": [["kext", "system extension", "Secure Boot", "APFS", "No kernel/boot"]],
        "structured": True,
    },
    "audit_patch_posture": {
        "scope": "audit",
        "action": "patch_posture",
        "title_contains": "OS Patch Posture",
        "must_contain": ["Severity:", "Actionable:", "FINDINGS"],
        "must_contain_any": [["macOS", "Software Update"]],
        "structured": True,
    },
    "audit_filesystem_integrity": {
        "scope": "audit",
        "action": "filesystem_integrity",
        "title_contains": "Filesystem Integrity",
        "must_contain": ["Severity:", "Actionable:", "FINDINGS"],
        "must_contain_any": [["/etc", "modified", "world-writable", "filesystem"]],
        "structured": True,
    },
    "audit_persistence": {
        "scope": "audit",
        "action": "persistence",
        "title_contains": "Persistence Audit",
        "must_contain": ["Severity:", "Actionable:", "FINDINGS"],
        "must_contain_any": [["Launch", "Login Item", "PrivilegedHelperTool", "Background", "persistence"]],
        "structured": True,
    },
    "audit_shell_dotfiles": {
        "scope": "audit",
        "action": "shell_dotfiles",
        "title_contains": "Shell Dotfile Scanner",
        "must_contain": ["Severity:", "Actionable:", "FINDINGS"],
        "must_contain_any": [[".zshrc", ".bashrc", "dotfile", "shell"]],
        "structured": True,
    },
    "audit_sensitive_paths_delta": {
        "scope": "audit",
        "action": "sensitive_paths_delta",
        "title_contains": "Sensitive Paths Delta",
        "must_contain": ["Severity:", "Actionable:", "FINDINGS"],
        "must_contain_any": [["modified", "sensitive path", "No sensitive"]],
        "structured": True,
    },
    "audit_tcc": {
        "scope": "audit",
        "action": "tcc",
        "title_contains": "TCC Grants Audit",
        "must_contain": ["Severity:", "Actionable:", "FINDINGS"],
        "must_contain_any": [["TCC", "Full Disk", "Accessibility"]],
        "structured": True,
    },
    "audit_keychain": {
        "scope": "audit",
        "action": "keychain",
        "title_contains": "Keychain & Credential Hygiene",
        "must_contain": ["Severity:", "Actionable:", "FINDINGS"],
        "must_contain_any": [["keychain", "Keychain"]],
        "structured": True,
    },
    "audit_auth_stack": {
        "scope": "audit",
        "action": "auth_stack",
        "title_contains": "Authentication Stack",
        "must_contain": ["Severity:", "Actionable:", "FINDINGS"],
        "must_contain_any": [["auth", "PAM", "LoginHook", "SecurityAgentPlugins"]],
        "structured": True,
    },
    "audit_binary_authorization": {
        "scope": "audit",
        "action": "binary_authorization",
        "title_contains": "Binary Authorization Telemetry",
        "must_contain": ["Severity:", "Actionable:", "FINDINGS"],
        "must_contain_any": [["Santa", "Gatekeeper", "binary authorization"]],
        "structured": True,
    },
    "audit_tool_correlation": {
        "scope": "audit",
        "action": "tool_correlation",
        "title_contains": "Optional Backend Correlation",
        "must_contain": ["Severity:", "Actionable:", "FINDINGS"],
        "must_contain_any": [[
            "Santa",
            "osquery",
            "KnockKnock",
            "BlockBlock",
            "optional-backend",
            "runtime scan",
        ]],
        "structured": True,
    },
    "audit_installed_software": {
        "scope": "audit",
        "action": "installed_software",
        "title_contains": "Installed Software Trust",
        "must_contain": ["Severity:", "Actionable:", "FINDINGS"],
        "must_contain_any": [["App:", "Applications", "signature", "installed software"]],
        "structured": True,
    },
    "audit_browser_exts": {
        "scope": "audit",
        "action": "browser_exts",
        "title_contains": "Browser Extensions Audit",
        "must_contain": ["Severity:", "Actionable:", "FINDINGS"],
        "must_contain_any": [["extension", "Chrome", "Firefox", "browser"]],
        "structured": True,
    },
    "audit_packages": {
        "scope": "audit",
        "action": "packages",
        "title_contains": "Package Manager Supply Chain",
        "must_contain": ["Severity:", "Actionable:", "FINDINGS"],
        "must_contain_any": [["pip", "npm", "Homebrew", "Cargo", "package"]],
        "structured": True,
    },
    "audit_baseline_delta": {
        "scope": "audit",
        "action": "baseline_delta",
        "title_contains": "Baseline Delta",
        "must_contain": ["Severity:", "Actionable:", "FINDINGS"],
        "must_contain_any": [["baseline", "Baseline"]],
        "structured": True,
    },
    "audit_rule_engine": {
        "scope": "audit",
        "action": "rule_engine",
        "title_contains": "Rule Engine",
        "must_contain": ["Severity:", "Actionable:", "FINDINGS"],
        "must_contain_any": [["ODK", "rule", "Rule"]],
        "structured": True,
    },
}


def load_capture(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def parse_summary(lines: list[str]) -> dict[str, int]:
    for line in lines:
        if line.startswith("[SUMMARY] "):
            return {key: int(value) for key, value in SUMMARY_RE.findall(line)}
    return {}


def severity_counts(lines: list[str]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "info": 0, "ok": 0}
    in_summary_panel = False
    for line in lines:
        if line.startswith("[SUMMARY] "):
            continue
        if "AI SUMMARY" in line:
            in_summary_panel = True
            continue
        if in_summary_panel:
            if line.startswith("  ━━") and "AI SUMMARY" not in line:
                in_summary_panel = False
            else:
                continue
        if not line.startswith("    "):
            continue
        match = SEVERITY_RE.search(line)
        if match:
            counts[match.group(1).lower()] += 1
    return counts


def actionable_count(lines: list[str]) -> int:
    return sum(1 for line in lines if ACTIONABLE_RE.search(line))


def review_capture(capture: dict) -> list[str]:
    requested = capture.get("requested_action", "")
    expected = EXPECTATIONS.get(requested)
    if expected is None:
        return [f"no expectation profile for {requested!r}"]

    errors: list[str] = []
    title = capture.get("title", "")
    raw_lines = capture.get("raw_lines") or []
    joined = "\n".join(raw_lines)
    lower = joined.lower()
    body_lines = [
        line for line in raw_lines
        if not line.startswith("[REPORT] ") and not line.startswith("[SUMMARY] ")
    ]
    body_lower = "\n".join(body_lines).lower()

    if (capture.get("state") != "ready"
            and requested != "forensic_bulk_scan"):
        errors.append(f"capture state is {capture.get('state')}, expected ready")
    if capture.get("scope") != expected["scope"]:
        errors.append(
            f"scope mismatch: expected {expected['scope']}, got {capture.get('scope')}")
    if capture.get("action") != expected["action"]:
        errors.append(
            f"action mismatch: expected {expected['action']}, got {capture.get('action')}")
    if expected["title_contains"] not in title:
        errors.append(
            f"title mismatch: expected {expected['title_contains']!r} in {title!r}")
    if not raw_lines:
        errors.append("raw_lines is empty")
    if not any(line.startswith("[REPORT] ") for line in raw_lines):
        errors.append("missing [REPORT] marker")

    for needle in expected.get("must_contain", []):
        if needle not in joined:
            errors.append(f"missing expected text: {needle!r}")

    for choices in expected.get("must_contain_any", []):
        if not any(choice.lower() in body_lower for choice in choices):
            errors.append(
                "missing one of expected texts: "
                + ", ".join(repr(choice) for choice in choices))

    for needle in GENERIC_FORBIDDEN:
        if needle in lower:
            errors.append(f"forbidden error text present: {needle!r}")

    if expected.get("structured"):
        summary = parse_summary(raw_lines)
        rendered = severity_counts(raw_lines)
        if not summary:
            errors.append("missing [SUMMARY] marker for structured report")
        else:
            for sev in ("critical", "high", "medium", "info", "ok"):
                if summary.get(sev, 0) != rendered.get(sev, 0):
                    errors.append(
                        f"summary {sev}={summary.get(sev, 0)} does not match rendered {rendered.get(sev, 0)}")
            if summary.get("actionable", 0) != actionable_count(raw_lines):
                errors.append("summary actionable count does not match rendered actionable rows")

    return errors
