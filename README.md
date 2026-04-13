# procmon

A resilient, real-time process monitor for macOS with tree view, network tracking, and color-coded resource alerts. Single-file, zero dependencies.

## Features

- **Process Tree View** - Hierarchical parent-child display with collapsible nodes, aggregated stats across subtrees (CPU, memory, threads, FDs, forks, network)
- **7 Sort Modes** - Memory, CPU, Network rate, Bytes In, Bytes Out, Vendor, Alphabetical. Press the same key twice to reverse direction
- **Network Connections** - Per-process connection list via `lsof` with per-flow byte tracking via `nettop`
- **GeoIP & Org Lookup** - Remote IPs show city/country and organization (e.g. `[AWS]`, `[Anthropic]`). Full org name shown on selected connection
- **Color-Coded Alerts** - Rows turn red when a process group exceeds: 2 GB memory, 80% CPU, 15 forks, 1025 file descriptors, or 250 threads. Orange at lower thresholds
- **Process Filtering** - Case-insensitive substring filter, live-updated
- **File Descriptor Tracking** - Per-process and aggregated FD counts (can be disabled with `--no-fd` for speed)
- **Kill Support** - Kill a process subtree or a specific network connection's owning process
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
