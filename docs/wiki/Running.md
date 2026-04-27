# Running

## Quick start

```bash
python3 mac_tui_procmon.py
python3 mac_tui_procmon.py firefox -i 2
sudo -n /usr/local/sbin/mac-tui-procmon-sudo --skip-preflight
```

`procmon.py` remains as a compatibility shim.

## Sudo wrapper

Some features need root: memory-region YARA inside Inspect, the
hidden-process kqueue scan, and `eslogger` for the Endpoint
Security stream. The wrapper at `scripts/mac-tui-procmon-sudo` is
the canonical privileged entry point — it preserves the caller's
PATH / HOME so user-installed CLIs (eslogger, osquery, mitmdump,
yara, codesign-checker, …) resolve under sudo the same way they do
without it.

Install once with:

```bash
sudo scripts/install-sudo-wrapper.sh
```

This:
1. Installs `scripts/mac-tui-procmon-sudo` to `/usr/local/sbin/mac-tui-procmon-sudo` (root:wheel, mode 0755).
2. Drops `/etc/sudoers.d/mac-tui-procmon` with the matching NOPASSWD entry, after a `visudo -c` syntax check.

After install:

```bash
sudo -n /usr/local/sbin/mac-tui-procmon-sudo --help
sudo -n /usr/local/sbin/mac-tui-procmon-sudo
```

The sudoers entry is:

```
alex ALL=(root) NOPASSWD: /usr/local/sbin/mac-tui-procmon-sudo *
```

## CLI flags

| Flag                  | Effect                                         |
|-----------------------|------------------------------------------------|
| `name` (positional)   | Process-name substring filter                  |
| `-i / --interval SECS`| Refresh interval (default 5)                   |
| `--no-fd`             | Skip file-descriptor counting (faster)         |
| `--skip-preflight`    | Skip external-tool dependency check            |

That's the whole flag set. Host-wide auditing, baseline capture,
and full security scans are intentionally not here — they live in
[`mac-system-security`](https://github.com/alex-iliadis/mac-system-security):

```bash
python3 -m mac_system_security audit <name>
python3 -m mac_system_security full-scan --html --open-html
python3 -m mac_system_security capture-baseline
```

## Environment variables

| Variable                                  | Effect                                   |
|-------------------------------------------|------------------------------------------|
| `MAC_TUI_PROCMON_CHAT_TIMEOUT`            | Chat-overlay LLM timeout (seconds)       |
| `MAC_TUI_PROCMON_TEST_MODE`               | Skip background workers (test fixtures)  |
| `MAC_TUI_PROCMON_CAPTURE_DIR`             | Directory for `*.screen.json` snapshots  |
| `MAC_TUI_PROCMON_CAPTURE_ACTION`          | Snapshot-file basename                   |
| `MAC_TUI_PROCMON_TEST_ACTION`             | Auto-trigger an action on TUI start      |
| `MAC_TUI_PROCMON_TEST_SELECT_PID`         | Auto-select this PID on start            |
| `MAC_TUI_PROCMON_TEST_ALLOW_LLM`          | Allow real LLM CLIs in test mode         |
| `MAC_TUI_PROCMON_ES_SELECT_PREFIXES`      | Path-prefixes filter for Endpoint stream |
| `MAC_TUI_PROCMON_INJECTION_PIDS`          | PIDs to scan for injection in triage     |
| `MAC_TUI_PROCMON_SUDO_NONINTERACTIVE`     | Skip sudo password prompts under `-n`    |
