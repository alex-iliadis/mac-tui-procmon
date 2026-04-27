# mac-tui-procmon

Terminal process monitor for macOS. This project stays process-focused: live process tree, per-process network connections, process inspection, alerts, grouping, sorting, and TUI validation.

Host-wide security posture, CVE intelligence, TCC, kernel, persistence, auth stack, browser extensions, and remediation workflows live in `mac-system-security`.

## Quick Start

```bash
python3 mac_tui_procmon.py
python3 mac_tui_procmon.py firefox -i 2
sudo python3 mac_tui_procmon.py --skip-preflight
```

Compatibility entrypoints remain:

```bash
python3 secprocmon.py
python3 procmon.py
```

## Product Boundary

`mac-tui-procmon` owns process-level visibility:

- Process tree rendered from macOS `libproc` and `sysctl`.
- Per-process CPU, memory, threads, file descriptors, forks, and network rates.
- Process grouping by parent tree and vendor.
- Per-process network connection view.
- Process detail inspection, hidden-process signals, keylogger/hook checks, and event stream views where they are scoped to live processes.
- TUI screenshots and semantic screen assertions.

`mac-system-security` owns host-wide security:

- Kernel, boot, SIP, SSV, FileVault, Gatekeeper, and update posture.
- TCC, keychain, auth stack, persistence, browser extension, and CVE intelligence.
- Full browser dashboard, scan history, deltas, remediation, and AI-backed report synthesis.

## Test Layers

```bash
# Unit and integration
/opt/homebrew/bin/python3 -m pytest -q

# Coverage gate
/opt/homebrew/bin/python3 -m pytest -q --cov=mac_tui_procmon --cov-report=term-missing --cov-fail-under=95
```

Current local validation: `1484 passed`; public entrypoint coverage: `100%`.

## Wiki

- [Home](docs/wiki/Home.md)
- [Testing](docs/wiki/Testing.md)
- [Screenshots](docs/wiki/Screenshots.md)

