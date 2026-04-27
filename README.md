# mac-tui-procmon

Terminal UI process monitor for macOS. Built on direct `libproc` /
`sysctl` calls — no `fork()` per refresh — so it survives fork bombs
and memory exhaustion that knock other monitors offline.

```bash
python3 mac_tui_procmon.py
python3 mac_tui_procmon.py firefox -i 2
sudo -n /usr/local/sbin/mac-tui-procmon-sudo --skip-preflight
```

Compatibility entrypoints `procmon.py` and `secprocmon.py` remain.

## Features

- Live process tree with parent grouping, vendor grouping, and 7
  sort modes (memory / CPU / net rate / alpha / vendor / bytes
  in / bytes out). Press the same sort key twice to invert.
- Dynamic sort (`d`) — alert-threshold violators float above
  everything else.
- Per-process forensics (`I`): codesign + Gatekeeper + Apple-signed,
  YARA on disk, YARA on memory (root), VirusTotal lookup,
  binary-trust profile, badges.
- Deep process triage (`T`): adds osquery, injection / anti-debug
  evidence, and a structured cursor over remediable findings.
- Per-process network (`N`): connection list with `k` to kill an
  individual connection without killing the process.
- Hidden-process scan, keylogger / event-tap scan with one-key
  removal, bulk YARA scan over every visible process.
- Endpoint Security stream (`E` → Security timeline): exec, auth,
  login, TCC, XProtect events. Two-stage Esc — first stops the
  stream and requests an LLM summary, second closes.
- Experimental Traffic Inspector (mitmproxy) attributing flows to
  the selected process.
- Alert engine with thresholds for CPU, memory, threads, FDs,
  forks, net rates, and total bytes.
- AI chat overlay (`?`) auto-grounded in whatever screen you have
  open.
- Debug log overlay (`L`) viewable from anywhere.
- TUI snapshot capture: every screen writes a `*.screen.json`
  artifact for regression tests.

Host-wide security audits (TCC, kernel, persistence, browser
extensions, CVE intelligence, full security score, remediation
workflows) live in [`mac-system-security`](https://github.com/alex-iliadis/mac-system-security).
The TUI bridges to it via `H` / `J` / `G` / `X` and the `a` menu.

## Sudo wrapper

For features that need root (memory-region YARA in Inspect, the
hidden-process kqueue scan, `eslogger`), install the wrapper:

```bash
sudo scripts/install-sudo-wrapper.sh
```

After install, the canonical privileged invocation is:

```bash
sudo -n /usr/local/sbin/mac-tui-procmon-sudo
sudo -n /usr/local/sbin/mac-tui-procmon-sudo --capture-baseline
```

Sudoers entry installed at `/etc/sudoers.d/mac-tui-procmon`:

```
alex ALL=(root) NOPASSWD: /usr/local/sbin/mac-tui-procmon-sudo *
```

## Testing

```bash
# All tests
/opt/homebrew/bin/python3 -m pytest -q

# Honest coverage on the implementation module
/opt/homebrew/bin/python3 -m pytest -q \
    --cov=mac_tui_procmon_impl \
    --cov-report=term-missing
```

Local: `1569 passed`, 76% coverage on `mac_tui_procmon_impl.py`
(9185 statements). The 100% number on the public shim is an
artifact of measuring the re-export module — the wiki's
[Testing](docs/wiki/Testing.md) page has the full breakdown.

## Wiki

- [Home](docs/wiki/Home.md)
- [Features](docs/wiki/Features.md)
- [Keybindings](docs/wiki/Keybindings.md)
- [Screens](docs/wiki/Screens.md)
- [Running](docs/wiki/Running.md)
- [Testing](docs/wiki/Testing.md)
- [Screenshots](docs/wiki/Screenshots.md)
