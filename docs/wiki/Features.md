# Features

Every user-facing feature in `mac-tui-procmon`, grouped by what it does.

## Process tree and metrics

- **Direct libproc/sysctl snapshots.** No `fork()` per refresh, so
  fork bombs and memory exhaustion don't kill the monitor.
- **Per-process columns:** PID, command, CPU%, RSS, threads, FDs,
  fork count, net-in rate, net-out rate, bytes in, bytes out,
  working directory.
- **Parent-tree grouping.** Children indent under their parent. `←`
  collapses, `→` expands.
- **Vendor grouping (`g`).** Group rows by code-sign team / vendor
  rather than by process tree.
- **Sort modes:**
  - `m` — memory (RSS)
  - `c` — CPU%
  - `n` — net rate (in + out)
  - `A` — alphabetical by command
  - `V` — vendor (code-sign team)
  - `R` — bytes received
  - `O` — bytes sent
  - Press the same key twice to invert.
- **Dynamic sort (`d`).** When on, processes that exceed any alert
  threshold float to the top of whatever sort mode is active.
- **Sort dialog (`s`).** Full sort menu when you can't remember the
  hotkey.
- **Filter (`f`).** Substring filter on command name; supports
  multiple include and exclude patterns.

## Per-process forensics (selected process only)

- **Inspect (`I`)** — full forensic report for the selected
  process:
  - Codesign team-id, authority, identifier, signed/ad-hoc/unsigned.
  - Gatekeeper assessment.
  - Apple-signed inference.
  - YARA against the on-disk binary.
  - YARA against memory regions (requires root — see
    [Running](Running.md#sudo-wrapper)).
  - Memory-dump status badge: `[MEMORY-DUMPED]`,
    `[MEMORY-SKIPPED]`, `[DISK-YARA]`.
- **Deep process triage (`T`)** — adds osquery telemetry,
  injection / anti-debug evidence, binary trust profile, and a
  structured finding list with cursor navigation.

## Per-process network

- **Network mode (`N`)** — opens a panel showing every TCP/UDP
  connection owned by the selected process (local + remote
  endpoints, state, foreign DNS).
- **`k` kills the highlighted connection** (without killing the
  process itself).

## Live telemetry

- **Endpoint Security stream (`E` → Security timeline)** — live
  feed of exec, auth, login-window, TCC, and XProtect events from
  `eslogger`, scoped to processes you care about. Tail the buffer;
  press `c` to clear; press Esc once to halt the stream and request
  an LLM summary; press Esc again to close.
- **Traffic Inspector (`E` → Traffic Inspector, experimental)** —
  spins up a `mitmproxy` shim on a local port and surfaces flows
  attributed to the selected process.

## Alerts

- **Threshold engine** with separate thresholds for CPU, memory MB,
  threads, FDs, forks, net-in rate, net-out rate, total bytes in,
  total bytes out.
- **Audible alert** with a configurable cooldown and max-count cap.
- **Alert config dialog (`Shift+C`)** to set every threshold from
  the TUI.
- **Dynamic sort (`d`)** uses these thresholds — anything exceeding
  surfaces above everything else.

## AI chat overlay

- **`?`** opens an AI chat overlay from anywhere in the TUI.
- **Auto-grounded:** the current screen is captured as the
  conversation's system prompt, so follow-ups stay tied to what's
  visible — process triage, inspect, network view, events stream,
  whatever you were looking at.
- **Fallback chain:** the overlay tries `claude` first; on
  timeout / failure it auto-falls-back to `codex`, then `gemini`.
  The status line in the prompt updates as the chain advances
  (`[claude thinking…]` → `[trying with codex…]` → `[trying with
  gemini…]`) so you always know which assistant is working. Per-CLI
  timeout defaults to 60s; override with
  `MAC_TUI_PROCMON_CHAT_TIMEOUT`.
- **De-elevates under sudo.** When procmon runs as root with
  `SUDO_USER` set, each assistant subprocess is wrapped with `sudo
  -n -E -u $SUDO_USER --` so the CLI runs as the invoking user. This
  matters for `claude`, whose OAuth/keychain reads gate on process
  UID — running it as root makes it hang on auth.

## Debug log

- **`L`** opens an in-TUI log overlay from anywhere. Scrollable,
  capped at 500 lines, written by every internal subsystem
  (preflight, traffic shim, inspect worker, etc.).

## Process control

- **`k`** kills the selected process (`SIGTERM`).
- In Network mode, `k` kills the highlighted connection only.

## Test instrumentation

- **TUI snapshot capture.** Every menu and screen writes a
  `<surface>.screen.json` artifact when the
  `MAC_TUI_PROCMON_CAPTURE_DIR` env var is set — the regression
  tests use this to assert rendered text without depending on a
  real terminal.
- **Semantic screen assertions** in `tui_screen_assertions.py` so
  tests describe screen content (not pixels).
- **Coverage:** 5770 statements in the core impl module, 75%
  covered by 945 tests.
