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

## SecAuditor menu (`a`)

Sectioned menu bridging to the `mac-system-security` browser/API
product:
- Open SecAuditor browser app.
- Show SecAuditor commands.

## Inspect screen (`I` or via Process Investigation)

Forensic report for the selected process. Sections include codesign,
Gatekeeper, YARA disk, YARA memory (root-only), VirusTotal,
binary-trust profile.

## Deep Process Triage (`T` or via Process Investigation)

Augments inspect with osquery, injection / anti-debug findings, and
a structured cursor over remediable findings. Press `D` on a finding
to apply the suggested action.

## Network connections (`N` or via Process Investigation)

List of TCP/UDP endpoints owned by the selected process: state,
local, remote, foreign DNS. `k` kills the highlighted connection.

## Hidden-process scan

Diff of `libproc` against `sysctl` / `ps`. Surfaces processes
visible to one but not the other.

## Keylogger / event-tap scan

TCC Accessibility grants, Input Method bundles, CGEventTap owners.
Cursor over a finding and press `D` to remove the hook.

## Bulk scan

Runs the inspect pipeline across every visible process. Findings
aggregate; live progress at the top; Esc cancels.

## Endpoint Security stream (`E` → Security timeline)

Live `eslogger` events: exec, auth, login-window, TCC, XProtect.
Tail the buffer; `c` clears; first Esc halts and requests an LLM
summary; second Esc closes.

## Traffic Inspector (`E` → Traffic Inspector)

Experimental. mitmproxy shim attributing flows to the selected
process. `c` clears flows.

## SecAuditor bridge panel (`H` / `J` / `G` / `X`)

Static panel with the SecAuditor commands and a launch confirmation
when the browser/API product was started.

## AI chat overlay (`?`)

Floating chat overlay. Auto-captures the underlying screen as the
system prompt so questions stay grounded in what's visible.

## Debug log overlay (`L`)

In-TUI log viewer. Scrollable; `c` clears; closes with `L`, `Esc`,
or `q`.

## Snapshot artifacts

When `_tui_capture_dir` is set, every screen render writes a
`<surface>.screen.json` artifact: dimensions, visible lines,
focused box. Used by regression tests in
`tests/test_tui_screen_capture.py` and
`tests/test_tui_screen_assertions.py`.
