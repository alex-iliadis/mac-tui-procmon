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
| `Shift+C`      | Open alert-config dialog                              |
| `k`            | Kill the selected process (`SIGTERM`)                 |
| `L`            | Toggle debug log overlay                              |
| `?`            | Toggle AI chat overlay                                |
| `Tab`          | Enter detail focus (when a special mode is open)      |
| `Esc`          | Close the current special mode (or quit if none open) |
| `q`            | Quit                                                  |

## Detail focus — common keys

These work in every detail mode (Inspect, Hidden scan, Audit, Bulk
scan, Events, Traffic, Network):

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

## Hidden-scan mode

| Key | Action                      |
|-----|-----------------------------|
| `H` | Toggle hidden-scan mode off |

## Audit mode (used by Deep Process Triage)

| Key       | Action                                                  |
|-----------|---------------------------------------------------------|
| `↑` / `↓` | Move structured cursor (or scroll if no findings)       |
| `R` / `r` | Re-run the triage                                       |

## Bulk-scan mode

| Key | Action                          |
|-----|---------------------------------|
| `F` | Toggle bulk-scan off            |
| `Esc` | Cancel running scan and close |

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

| Key | Action                                 |
|-----|----------------------------------------|
| `k` | Kill the highlighted connection        |
| `N` | Toggle network mode off                |

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
