# mac-tui-procmon Wiki

Terminal UI process monitor for macOS. Built around `libproc` and `sysctl`
direct-call snapshots — no `fork()` per refresh, so it survives fork bombs
and memory exhaustion that knock other monitors offline.

The app stays process-focused. Host-wide security auditing (TCC, kernel,
persistence, browser extensions, CVE intelligence, full security score,
remediation workflows) lives in the sister project `mac-system-security`,
which `mac-tui-procmon` bridges to via `H/J/G/X` and the `a` menu.

## Pages

- [Features](Features.md) — every feature in the app, what it does, and how to reach it.
- [Keybindings](Keybindings.md) — every keypress in every mode, in one table.
- [Screens](Screens.md) — every TUI screen, what it shows, what triggers it.
- [Running](Running.md) — invocation, sudo wrapper, CLI flags.
- [Testing](Testing.md) — test layers and how to run them.
- [Screenshots](Screenshots.md) — index of screenshots in `screenshots/`.

## At a glance

- Live process tree with parent grouping, vendor grouping, and 7 sort
  modes (memory, CPU, network rate, alpha, vendor, bytes received,
  bytes sent), plus a dynamic-sort mode that surfaces alert-threshold
  violators above everything else.
- Per-process: CPU, RSS, threads, file descriptors, fork count, net
  rates, total bytes in/out, command, working directory.
- Per-process forensics: code-sign / Gatekeeper / Apple-signed
  inference, YARA against disk, YARA against memory (root), VirusTotal
  reputation, deep triage with osquery + injection / anti-debug
  evidence.
- Per-process network connection list with one-key kill (`k`).
- Hidden-process scan, keylogger / event-tap scan, bulk YARA scan.
- Endpoint Security live event stream (exec, auth, login, TCC,
  XProtect) with a two-stage Esc that synthesizes an LLM summary
  before closing.
- Experimental mitmproxy-backed Traffic Inspector for the selected
  process.
- Alert engine (cpu / mem / threads / fds / forks / net rate / bytes
  thresholds) with audible alert and a max-count guard rail.
- AI chat overlay (`?`) that auto-captures the current screen as
  grounded context — works from anywhere in the TUI.
- Debug log overlay (`L`) viewable from anywhere.
- TUI snapshot capture: every menu and screen writes a
  `*.screen.json` artifact when the capture dir is set, used for
  regression tests.

## Product boundary

| Owned by `mac-tui-procmon`              | Owned by `mac-system-security`         |
|-----------------------------------------|----------------------------------------|
| Live process tree                       | Kernel / boot / SIP / SSV posture      |
| Per-process metrics & forensics         | TCC, keychain, auth stack              |
| Per-process network connections         | Persistence, browser extensions        |
| Inspect / triage / hidden / keyscan     | CVE intelligence                       |
| Endpoint Security stream (process-scope)| Full security score + remediation      |
| Traffic Inspector (per-process)         | AI report synthesis (host-wide)        |
| Alert engine                            |                                        |
