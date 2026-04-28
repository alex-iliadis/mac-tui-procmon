# Screens

Every distinct screen the TUI can render, what triggers it, and the
key bindings active while it's open.

## Main process list (default)

The default view. Process tree with metric columns, sort indicator,
filter indicator, alert state, and the active mode badges. Open by
launching the app.

## Sort dialog (`s`)

Modal menu for picking a sort mode without remembering the hotkey.
Up / Down to navigate, Enter to select, Esc to cancel.

## Alert config dialog (`Shift+C`)

Set thresholds for CPU, memory, threads, FDs, forks, net rates, and
total bytes. Includes the audible-alert cooldown and the max-count
cap.

## Filter dialog (`f`)

Set include / exclude name patterns. Substring matching,
case-insensitive.

## Process Investigation menu (`F`)

Sectioned menu:
- Selected Process → Inspect, Deep Process Triage, Network connections.

## Live Telemetry menu (`E`)

Sectioned menu:
- Endpoint Security → Security timeline.
- Experimental → Traffic Inspector.

## Inspect screen (`I` or via Process Investigation)

Forensic report for the selected process. Sections include codesign,
Gatekeeper, YARA disk, YARA memory (root-only), binary-trust
profile.

## Deep Process Triage (`T` or via Process Investigation)

Augments inspect with osquery, injection / anti-debug findings, and
a structured cursor over remediable findings.

## Network connections (`N` or via Process Investigation)

List of TCP/UDP endpoints owned by the selected process: state,
local, remote, foreign DNS. `k` kills the highlighted connection.

## Endpoint Security stream (`E` → Security timeline)

Live `eslogger` events: exec, auth, login-window, TCC, XProtect.
Tail the buffer; `c` clears; first Esc halts and requests an LLM
summary; second Esc closes.

## Traffic Inspector (`E` → Traffic Inspector)

Experimental. mitmproxy shim attributing flows to the selected
process. `c` clears flows.

## AI chat overlay (`?`)

Floating chat overlay. Auto-captures the underlying screen as the
system prompt so questions stay grounded in what's visible.

## Debug log overlay (`L`)

In-TUI log viewer. Scrollable; `c` clears; closes with `L`, `Esc`,
or `q`.

## Snapshot artifacts

When the `MAC_TUI_PROCMON_CAPTURE_DIR` env var is set, every screen
render writes a `<surface>.screen.json` artifact: dimensions,
visible lines, focused box. Used by regression tests in
`tests/test_tui_screen_capture.py` and
`tests/test_tui_screen_assertions.py`.

## AI chat overlay — fallback chain

When you press `?`, the overlay tries the locally-installed
assistants in order: `claude` → `codex` → `gemini`. The status line
in the prompt updates as the chain advances so you always know which
assistant is working. Under `sudo`, each subprocess is wrapped with
`sudo -n -E -u $SUDO_USER --` to drop back to the invoking user — a
necessary trick for `claude`, whose keychain reads gate on process
UID rather than `$HOME`.
