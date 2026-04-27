# Screenshots

Index of screenshots in `screenshots/`. Filenames follow the
`<surface>.png` convention; a few include a `-ai` suffix for the
chat-overlay variant of the same surface.

| File                          | What it shows                                      |
|-------------------------------|----------------------------------------------------|
| `general-view.png`            | Main process list (default view)                   |
| `process-filter.png`          | Filter dialog populated                            |
| `process-group-view.png`      | Tree grouped by parent process                     |
| `vendor-grouping.png`         | Same list grouped by code-sign vendor              |
| `dynamic-sort.png`            | Dynamic-sort indicator (alert exceeders on top)    |
| `alpha-sort.png`              | Alphabetical sort                                  |
| `sort-dialog.png`             | Sort dialog (`s` key)                              |
| `network-view.png`            | Network connections panel for the selected process |
| `forensic-menu.png`           | Process Investigation menu                         |
| `telemetry-menu.png`          | Live Telemetry menu (`E`)                          |
| `inspect-view.png`            | Inspect mode (codesign + YARA + trust profile)     |
| `triage-view.png`             | Deep process triage (`T`)                          |
| `process-entitlements.png`    | Process entitlements / triage detail               |
| `alert-config.png`            | Alert thresholds dialog (`Shift+C`)                |
| `config-view.png`             | Alert config — alternate view                      |
| `log-overlay.png`             | Debug log overlay (`L`)                            |
| `ask-claude.png`              | AI chat overlay grounded in current screen         |

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
