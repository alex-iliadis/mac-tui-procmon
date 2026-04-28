# Screenshots

Index of screenshots in `screenshots/`. Filenames follow the
`<surface>.png` convention; a few include a `-ai` suffix for the
chat-overlay variant of the same surface.

| File                          | What it shows                                      |
|-------------------------------|----------------------------------------------------|
| `general-view.png`            | Main process list (default view)                   |
| `process-filter.png`          | Filter dialog populated                            |
| `vendor-grouping.png`         | Process list grouped by code-sign vendor           |
| `dynamic-sort.png`            | Dynamic-sort indicator (alert exceeders on top)    |
| `alpha-sort.png`              | Alphabetical sort                                  |
| `sort-dialog.png`             | Sort dialog (`s` key)                              |
| `forensic-menu.png`           | Process Investigation menu                         |
| `telemetry-menu.png`          | Live Telemetry menu (`E`)                          |
| `inspect-view.png`            | Inspect mode (codesign + YARA + trust profile)     |
| `triage-view.png`             | Deep process triage (`T`)                          |
| `alert-config.png`            | Alert thresholds dialog (`Shift+C`)                |
| `log-overlay.png`             | Debug log overlay (`L`)                            |
| `ask-claude.png`              | AI chat overlay grounded in current screen         |

The network connections panel is intentionally not shipped as a PNG:
the live view shows remote-endpoint geolocation tags (e.g.
`[Athens/GR]`, `[San Francisco/CA]`) that correlate with the user's
country via CDN edge proximity. The feature still exists; users see
it in their own terminal.

## Capturing new screenshots

The TUI is curses-based; pixel screenshots are taken from a real
Terminal.app window. The repo's snapshot tests already produce
semantic JSON renderings (see
[Testing](Testing.md) → "TUI snapshot tests"); those stay machine
readable.

For PNGs, run:

```bash
scripts/capture-screenshots.sh         # unprivileged
scripts/capture-screenshots.sh --root  # via the sudo wrapper
```

The script launches Terminal.app at a known geometry, drives the
TUI through every screen via `osascript` keystrokes, and writes one
PNG per surface into `screenshots/` using `screencapture -R`.

The capture region is offset to **crop out the Terminal title bar**.
macOS renders user@host, working dir, and dimensions there
(e.g. `mac-tui-procmon — alex@laptop — ~/code/... — 194×62`), which
would leak both the username and the hostname into public docs.
`set custom title` only rewrites one segment; cropping below the
title bar removes all of them.
