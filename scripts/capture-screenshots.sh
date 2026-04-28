#!/usr/bin/env bash
# capture-screenshots.sh — drive the TUI through every screen in a real
# Terminal.app window and write one PNG per surface into screenshots/.
#
# Pattern lifted from the legacy procmon repo: osascript launches and
# drives Terminal, screencapture -R writes a region PNG. The Terminal
# window is positioned at known bounds so screencapture and osascript
# agree on coordinates.
#
# Pass `--root` to launch via the sudo wrapper (full capabilities).
# Default is unprivileged. Re-run as needed; each invocation overwrites
# the captured PNGs.
#
# This script will pop up Terminal.app and steal focus for the duration.
# Don't touch the keyboard while it runs.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SHOTS="$ROOT_DIR/screenshots"
mkdir -p "$SHOTS"

USE_SUDO=0
if [ "${1:-}" = "--root" ]; then
  USE_SUDO=1
fi

# Window geometry in screen points (top-left origin). Wide enough to
# show every TUI column without wrap, tall enough for menus and detail
# panels.
X1=80
Y1=80
X2=1480
Y2=1000
W=$(( X2 - X1 ))
H=$(( Y2 - Y1 ))

# Capture region. We deliberately start CAP_Y1 below Y1 to crop out the
# Terminal title bar — macOS renders user@host, dirname, and dimensions
# there (e.g. `mac-tui-procmon — alex@laptop — ~/code/... — 194×62`),
# which leaks both the username and the hostname into public docs.
# Setting `custom title` only rewrites one segment; the others remain.
# Cropping ~30pt below the window top removes the entire title bar.
CAP_Y1=$(( Y1 + 30 ))
CAP_H=$(( Y2 - CAP_Y1 ))

if [ "$USE_SUDO" -eq 1 ]; then
  TUI_CMD="sudo -n /usr/local/sbin/mac-tui-procmon-sudo --skip-preflight"
else
  TUI_CMD="/opt/homebrew/bin/python3 $ROOT_DIR/mac_tui_procmon.py --skip-preflight"
fi

osa_run() {
  /usr/bin/osascript -e "$1"
}

press() {
  # press <key-spec> [settle-secs]
  # key-spec is the literal text or a special name we map below.
  local key="$1"
  local settle="${2:-0.6}"
  case "$key" in
    Escape)  osa_run 'tell application "System Events" to key code 53' ;;
    Return)  osa_run 'tell application "System Events" to key code 36' ;;
    Tab)     osa_run 'tell application "System Events" to key code 48' ;;
    Up)      osa_run 'tell application "System Events" to key code 126' ;;
    Down)    osa_run 'tell application "System Events" to key code 125' ;;
    Left)    osa_run 'tell application "System Events" to key code 123' ;;
    Right)   osa_run 'tell application "System Events" to key code 124' ;;
    *)
      # Single-character keystroke. Quote-escape for AppleScript.
      local esc="${key//\\/\\\\}"
      esc="${esc//\"/\\\"}"
      osa_run "tell application \"System Events\" to keystroke \"$esc\""
      ;;
  esac
  /bin/sleep "$settle"
}

shot() {
  local name="$1"
  /usr/sbin/screencapture -R "$X1,$CAP_Y1,$W,$CAP_H" -t png -x "$SHOTS/$name.png"
  /bin/echo "  captured $SHOTS/$name.png"
}

# Open Terminal with the TUI, position the window deterministically.
# `set custom title` overrides the default "<dir> — <cmd>" rendering so
# the Terminal title bar in the captured PNGs doesn't leak the absolute
# path (e.g. `/Users/<name>/code/...`) into public docs.
echo "Launching Terminal.app and the TUI…"
/usr/bin/osascript <<OSA
tell application "Terminal"
  activate
  do script "cd \"$ROOT_DIR\" && clear && TERM=xterm-256color $TUI_CMD"
  delay 1
  set bounds of front window to {$X1, $Y1, $X2, $Y2}
  set custom title of selected tab of front window to "mac-tui-procmon"
end tell
OSA
/bin/sleep 4   # let preflight + first refresh settle

# Bring Terminal forward before sending keystrokes.
osa_run 'tell application "Terminal" to activate'
/bin/sleep 0.5

# ── Main list ──────────────────────────────────────────────────────────
shot "general-view"

# ── Sort dialog ────────────────────────────────────────────────────────
press "s" 1.0
shot "sort-dialog"
press "Escape" 0.6

# ── Vendor grouping toggle ─────────────────────────────────────────────
press "g" 1.0
shot "vendor-grouping"
press "g" 0.6   # toggle off

# ── Dynamic sort indicator ─────────────────────────────────────────────
press "d" 0.8
shot "dynamic-sort"
press "d" 0.4   # toggle off

# ── Alpha sort variant ─────────────────────────────────────────────────
press "A" 0.8
shot "alpha-sort"

# ── Filter dialog ──────────────────────────────────────────────────────
press "f" 1.0
shot "process-filter"
press "Escape" 0.6

# ── Alert config dialog ────────────────────────────────────────────────
press "C" 1.0
shot "alert-config"
press "Escape" 0.6

# ── Forensic menu ──────────────────────────────────────────────────────
press "F" 1.0
shot "forensic-menu"
press "Escape" 0.6

# ── Telemetry menu ─────────────────────────────────────────────────────
press "E" 1.0
shot "telemetry-menu"
press "Escape" 0.6

# ── Log overlay ────────────────────────────────────────────────────────
press "L" 1.0
shot "log-overlay"
press "L" 0.4

# ── Inspect mode (codesign + on-disk YARA + Apple-signed inference;
# on a real Chrome binary this can take 15–25s end-to-end). Wait long
# enough to capture the populated panel, not the "Collecting forensic
# artifacts…" loading state.
press "I" 28.0
shot "inspect-view"
press "Escape" 0.8

# ── Process triage (osquery snapshot + injection/anti-debug scan;
# similar 20–30s window). ─────────────────────────────────────────────
press "T" 32.0
shot "triage-view"
press "Escape" 0.8

# Network connections panel deliberately NOT captured: the panel shows
# remote endpoints with vendor/geolocation labels (e.g. [Athens/GR],
# [San Francisco/CA]). The CDN edge is correlated with the user's
# country, so the screenshot is a country leak. Users see the live
# panel themselves; it doesn't need to ship as a public PNG.

# ── Ask Claude overlay ─────────────────────────────────────────────────
# Open the chat overlay and snap immediately, before the assistant has
# finished thinking — the loading marker is the most representative
# state ("[claude thinking…]" / "[trying with codex…]") and avoids
# capturing whatever assistant output happens to come back, which can
# itself echo identifying details.
press "?" 1.5
shot "ask-claude"
press "Escape" 0.8

# ── Quit ───────────────────────────────────────────────────────────────
press "q" 0.5

echo "Done. Screenshots written to $SHOTS"
echo "Captured surfaces:"
ls -1 "$SHOTS" | sort
