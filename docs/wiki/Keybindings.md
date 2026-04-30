# Keybindings

Every key the TUI binds, by mode.

## Main process list

| Key            | Action                                                |
|----------------|-------------------------------------------------------|
| `↑` / `↓`      | Move selection                                        |
| `←` / `→`      | Collapse / expand the selected node's children       |
| `PgUp`/`PgDn`  | Page through the list                                 |
| `m`            | Sort by memory                                        |
| `c`            | Sort by CPU                                           |
| `n`            | Sort by network rate                                  |
| `A`            | Sort alphabetically by command                        |
| `V`            | Sort by vendor (code-sign team)                       |
| `R`            | Sort by bytes received                                |
| `O`            | Sort by bytes sent                                    |
| same sort key  | Invert direction                                      |
| `d`            | Toggle dynamic sort (alert-exceeders to top)          |
| `g`            | Toggle vendor grouping                                |
| `s`            | Open the sort dialog                                  |
| `f`            | Open the filter dialog                                |
| `F`            | Open Process Investigation menu                       |
| `E`            | Open Live Telemetry menu                              |
| `N`            | Toggle Network mode for the selected process          |
| `I`            | Toggle Inspect mode for the selected process          |
| `T`            | Toggle Deep Process Triage for the selected process   |
| `U`            | Toggle Unified Log stream for selected process        |
| `G`            | Toggle Process Galaxy fullscreen visualizer           |
| `r`            | Toggle Attack Chain Replay                            |
| `Shift+C`      | Open alert-config dialog                              |
| `k`            | Kill the selected process (`SIGTERM`)                 |
| `L`            | Toggle debug log overlay                              |
| `?`            | Toggle AI chat overlay                                |
| `Tab`          | Enter detail focus (when a special mode is open)      |
| `Esc`          | Close the current special mode (or quit if none open) |
| `q`            | Quit                                                  |

## Detail focus — common keys

These work in every detail mode (Inspect, Audit, Events, Traffic,
Network, Unified Log, Galaxy):

| Key            | Action                            |
|----------------|-----------------------------------|
| `↑` / `↓`      | Scroll one line / move cursor    |
| `PgUp`/`PgDn`  | Page                              |
| `Tab`          | Release detail focus              |
| `Esc`          | Close this mode                   |
| `q`            | Quit the app                      |

## Inspect mode

| Key | Action                  |
|-----|-------------------------|
| `I` | Toggle inspect mode off |

## Audit mode (used by Deep Process Triage)

| Key       | Action                                                  |
|-----------|---------------------------------------------------------|
| `↑` / `↓` | Move structured cursor (or scroll if no findings)       |
| `R` / `r` | Re-run the triage                                       |

## Events mode (Endpoint Security stream)

| Key   | Action                                                     |
|-------|------------------------------------------------------------|
| `c`   | Clear the event buffer                                     |
| `Esc` | Stage 1: stop stream, request LLM summary. Stage 2: close. |
| `q`   | Stop stream and quit                                       |

## Traffic Inspector

| Key       | Action                                  |
|-----------|-----------------------------------------|
| `c`       | Clear captured flows                    |
| `Esc`/`q` | Stop the mitmproxy shim and close       |

## Network mode

| Key | Action                                  |
|-----|-----------------------------------------|
| `g` | Toggle orbit constellation              |
| `k` | Kill the highlighted connection owner   |
| `N` | Toggle network mode off                 |

## Unified Log mode

| Key       | Action                         |
|-----------|--------------------------------|
| `c`       | Clear the log ring buffer      |
| `Esc`/`q` | Stop `log stream` and close    |

## Process Galaxy

| Key       | Action                                      |
|-----------|---------------------------------------------|
| `↑`/`↓`/`←`/`→` | Move selected bubble                 |
| `Enter`   | Inspect the selected PID                    |
| `G`/`Esc` | Close galaxy mode                           |

## Attack Chain Replay

| Key     | Action                    |
|---------|---------------------------|
| `←`/`→` | Step through events       |
| `Space` | Play / pause replay       |
| `r`/`Esc` | Close replay mode       |

## Chat overlay (`?`)

Standard text input — characters type into the prompt, `Enter`
sends, `Esc` closes, arrow keys / PgUp / PgDn scroll the chat
history.

## Log overlay (`L`)

| Key       | Action               |
|-----------|----------------------|
| `↑` / `↓` | Scroll one line     |
| `PgUp`/`PgDn` | Page             |
| `c`       | Clear the log buffer |
| `L` / `Esc` / `q` | Close        |
