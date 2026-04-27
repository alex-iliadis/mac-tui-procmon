# mac-tui-procmon Wiki

`mac-tui-procmon` is the terminal UI process monitor. It deliberately avoids owning host-wide security posture so it can stay fast, readable, and process-centered.

## Main Workflows

- Open the live process tree and filter by process name.
- Sort by memory, CPU, network, bytes received, bytes sent, vendor, or command.
- Inspect one process without switching to the security dashboard.
- Open per-process network connections and active runtime detail panes.
- Capture TUI snapshots for regression tests.

## Renaming

The canonical app name is `mac-tui-procmon`. `procmon.py` and `secprocmon.py` are compatibility shims for old commands.

