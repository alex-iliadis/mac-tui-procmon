# mac-tui-procmon Wiki

Terminal UI process monitor for macOS: AI-assisted process forensics
plus a crypto-bubble style PID galaxy inside a real Mac terminal.
Built around `libproc` and `sysctl` direct-call snapshots — no
`fork()` per refresh, so it survives fork bombs and memory
exhaustion that knock other monitors offline.

This tool is **process-monitoring only**. Host-wide security
auditing (TCC sweeps, kernel/boot, persistence, browser extensions,
CVE intelligence, full security score, remediation workflows,
headless audit reports) lives in the sister project
[`mac-system-security`](https://github.com/alex-iliadis/mac-system-security).

## Pages

- [Features](Features.md) — every feature in the app.
- [Keybindings](Keybindings.md) — every keypress in every mode.
- [Screens](Screens.md) — every TUI screen, what shows it.
- [Running](Running.md) — invocation, sudo wrapper, CLI flags.
- [Testing](Testing.md) — test layers and how to run them.
- [Screenshots](Screenshots.md) — index of screenshots.

## At a glance

- Live process tree with parent grouping, vendor grouping, and 7
  sort modes (memory, CPU, network rate, alpha, vendor, bytes
  received, bytes sent). Same key twice inverts; `d` floats
  alert-threshold violators above everything else.
- Per-process: CPU, RSS, threads, file descriptors, fork count, net
  rates, total bytes in/out, command, working directory.
- Per-process forensics scoped to the selected PID:
  - Inspect (`I`): codesign / Gatekeeper / Apple-signed inference,
    YARA on disk, YARA on memory (root), binary trust profile.
  - Deep triage (`T`): adds osquery snapshot, injection /
    anti-debug evidence, structured cursor over findings.
- Per-process network connection list with one-key kill (`k`).
- Fullscreen Process Galaxy (`G`) with crypto-bubble style PID
  cards, load-sized vendor bubbles, fork rings, packet trails,
  comet streaks, and a gravity-lens swirl around the dominant
  process.
- Endpoint Security live event stream (exec, auth, login, TCC,
  XProtect) with a two-stage Esc that synthesizes an LLM summary
  before closing.
- Experimental mitmproxy-backed Traffic Inspector for the selected
  process.
- Alert engine (cpu / mem / threads / fds / forks / net rate /
  bytes thresholds) with audible alert and a max-count guard rail.
- AI chat overlay (`?`) that auto-captures the current screen as
  grounded context, plus Claude / Codex / Gemini consensus during
  Inspect.
- Debug log overlay (`L`) viewable from anywhere.
- TUI snapshot capture: every menu and screen writes a
  `*.screen.json` artifact when the capture dir is set, used for
  regression tests.

## Product boundary

| `mac-tui-procmon`                       | `mac-system-security`                  |
|-----------------------------------------|----------------------------------------|
| Live process tree                       | Kernel / boot / SIP / SSV posture      |
| Per-process metrics & forensics         | TCC, keychain, auth stack              |
| Per-process network connections         | Persistence, browser extensions        |
| Inspect / triage                        | CVE intelligence                       |
| Endpoint Security stream (process)      | Full security score + remediation      |
| Traffic Inspector (per-process)         | Headless audit reports + AI synthesis  |
| Alert engine                            | Quarantine / hooks-removal             |
