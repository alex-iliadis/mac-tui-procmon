# procmon

A resilient, real-time process monitor for macOS with tree view, network tracking, and color-coded resource alerts. Single-file, zero dependencies.

## Screenshots

### General View
Process list sorted by memory with detail panel showing PID, CPU, memory, threads, FDs, network rates, and the full command path.

![General View](screenshots/general-view.png)

### Network View
Per-process network connections with protocol, service, organization, GeoIP location, and per-flow byte counters. Full org name shown for the selected connection.

![Network View](screenshots/network-view.png)

### Process Group View
Expanded process tree showing parent and child processes with aggregated stats across the group.

![Process Group View](screenshots/process-group-view.png)

### Alert Configuration
System-wide alert thresholds with configurable repeat interval and max alert count. Settings persist to `~/.procmon.json`.

![Alert Configuration](screenshots/config-view.png)

## Features

- **Process Tree View** - Hierarchical parent-child display with collapsible nodes, aggregated stats across subtrees (CPU, memory, threads, FDs, forks, network)
- **Sibling Grouping** - Child processes with the same name are automatically grouped into a collapsible parent node with combined stats
- **7 Sort Modes** - Memory, CPU, Network rate, Bytes In, Bytes Out, Vendor, Alphabetical. Press the same key twice to reverse direction
- **Network Connections** - Per-process connection list via `lsof` with per-flow byte tracking via `nettop`
- **GeoIP & Org Lookup** - Remote IPs show city/country and abbreviated organization (e.g. `[AWS]`, `[Anthropic]`). Full org name shown on selected connection
- **Color-Coded Alerts** - Rows turn red when a process group exceeds: 2 GB memory, 80% CPU, 15 forks, 1025 file descriptors, or 250 threads. Orange at lower thresholds
- **Sound Alerts** - Configurable system-wide threshold alerts with sound notifications. Set CPU, memory, threads, FDs, forks, and network thresholds. Configurable repeat interval and max alert count. Resets when values drop below threshold
- **Process Filtering** - Include and exclude filters (comma-separated). Combine both to narrow results
- **File Descriptor Tracking** - Per-process and aggregated FD counts (can be disabled with `--no-fd` for speed)
- **Kill Support** - Kill a process subtree or a specific network connection's owning process
- **Persistent Config** - Alert thresholds and settings saved to `~/.procmon.json`, loaded automatically on startup
- **Resilient Design** - Locks its own memory and boosts priority so it keeps running during fork bombs or memory exhaustion. Avoids `fork()`/`exec()` by using ctypes directly

## Platform

macOS only. Uses native `libproc.dylib` and `libc.dylib` via ctypes for process enumeration without spawning subprocesses.

**System tools used:** `lsof` (network connections), `nettop` (per-flow byte counters)

## Requirements

- Python 3
- No external dependencies (stdlib only)

## Usage

```
procmon [name] [-i SECONDS] [--no-fd]
```

| Argument | Description |
|----------|-------------|
| `name` | Optional process name filter (case-insensitive substring match) |
| `-i`, `--interval` | Refresh interval in seconds (default: 5) |
| `--no-fd` | Skip file descriptor counting for faster updates |

**Examples:**

```bash
procmon                    # Monitor all processes
procmon firefox -i 2       # Monitor Firefox, refresh every 2 seconds
procmon --no-fd            # All processes, no FD tracking
```

## Configuration

Press `C` to open the alert thresholds dialog. Settings are saved to `~/.procmon.json` and persist across sessions.

| Setting | Description |
|---------|-------------|
| CPU % | System-wide CPU usage threshold |
| MEM (MB) | System-wide memory threshold in MB |
| Threads | Total thread count threshold |
| FDs | Total file descriptor threshold |
| Forks | Total fork count threshold |
| In/Out (KB/s) | Network rate thresholds |
| Recv/Sent (MB) | Cumulative network byte thresholds |
| Interval (s) | Seconds between repeated alerts (default: 60) |
| Max alerts | Maximum alert sounds before stopping (0 = unlimited, default: 5) |

Alerts reset immediately when values drop below threshold.

## Keybindings

### Process List

| Key | Action |
|-----|--------|
| `m` | Sort by memory |
| `c` | Sort by CPU |
| `n` | Sort by network rate |
| `A` | Sort alphabetically |
| `V` | Sort by vendor |
| `R` | Sort by bytes received |
| `O` | Sort by bytes sent |
| `N` | Open network connections for selected process |
| `f` | Filter processes |
| `C` | Open alert threshold configuration |
| `Left/Right` | Collapse / expand tree node |
| `PgUp/PgDn` | Page navigation |
| `k` | Kill selected process subtree |
| `q` | Quit |

### Network View

| Key | Action |
|-----|--------|
| `Up/Down` | Select connection |
| `k` | Kill process owning selected connection |
| `N` | Close network view |
| `Tab` | Toggle focus between process list and connections |
| `Esc` | Back |

### Filter Prompt

| Key | Action |
|-----|--------|
| `Enter` | Apply filter |
| `Esc` | Cancel |
| `Ctrl-A` / `Home` | Jump to start |
| `Ctrl-E` / `End` | Jump to end |
| `Ctrl-U` | Clear line |
