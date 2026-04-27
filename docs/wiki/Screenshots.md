# Screenshots

Index of screenshots in `screenshots/`. Filenames follow the
`<surface>.png` convention; a few include a `-ai` suffix for the
chat-overlay variant of the same surface.

| File                              | What it shows                                            |
|-----------------------------------|----------------------------------------------------------|
| `general-view.png`                | Main process list (default view)                         |
| `process-filter.png`              | Filter dialog populated                                  |
| `process-group-view.png`          | Tree grouped by parent process                           |
| `vendor-grouping.png`             | Same list grouped by code-sign vendor                    |
| `sort-dialog.png`                 | Sort dialog (`s` key)                                    |
| `network-view.png`                | Network connections panel for the selected process       |
| `forensic-menu.png`               | Process Investigation menu                               |
| `process-entitlements.png`        | Process entitlements / triage detail                     |
| `audits-menu.png`                 | SecAuditor menu (`a`)                                    |
| `config-view.png`                 | Alert config dialog (`Shift+C`)                          |
| `alert-config.png`                | Alert thresholds detail                                  |
| `quarantine-dialog.png`           | Quarantine confirmation flow                             |
| `keylogger-scan.png`              | Keylogger / event-tap scan                               |
| `keylogger-scan-ai.png`           | Same, with AI chat overlay open                          |
| `live-event-stream.png`           | Endpoint Security stream                                 |
| `live-event-stream-ai.png`        | Same, with AI chat overlay open                          |
| `fix-first-list.png`              | Triage findings sorted by remediability                  |
| `global-security-score.png`       | SecAuditor global score (rendered via the bridge)        |
| `ask-claude.png`                  | AI chat overlay grounded in current screen               |

## Capturing new screenshots

The TUI is curses-based; pixel screenshots are taken from a real
Terminal.app window. The repo's snapshot tests already produce
semantic JSON renderings (see
[Testing](Testing.md) → "TUI snapshot tests"); those stay machine
readable. For PNGs, run the TUI in Terminal.app and use
`screencapture -l <window-id>` or the macOS screenshot tool against
the Terminal window.
