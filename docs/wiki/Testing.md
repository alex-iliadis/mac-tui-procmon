# Testing

## Layers

The suite has four layers, mostly mocked at the libproc/sysctl
boundary so it runs in <10s without any real macOS APIs:

1. **Unit tests** — `test_unit.py`, `test_vendor_group.py`, format /
   parse helpers, sort comparators, alert-threshold logic.
2. **Integration tests** — `test_integration.py`,
   `test_inspect_hidden.py`, `test_new_features.py`,
   `test_shortcuts_integration.py`, `test_tui_flow_paths.py`.
   Drive `handle_input(key)` through every keypress in every mode
   and assert observable state changes.
3. **TUI snapshot tests** — `test_tui_screen_capture.py`,
   `test_tui_screen_assertions.py`, `test_tui_report_assertions.py`.
   Render every menu / panel / dialog into a `*.screen.json`
   artifact and assert visible lines + focused box.
4. **Coverage tests** — `test_coverage.py`, `test_coverage2.py`,
   `test_coverage3.py`, `test_coverage_final.py`. Targeted at
   specific code paths to keep coverage above the gate.

## Running

```bash
# All tests
/opt/homebrew/bin/python3 -m pytest -q

# With coverage on the implementation module (not the shim)
/opt/homebrew/bin/python3 -m pytest -q \
    --cov=mac_tui_procmon_impl \
    --cov-report=term-missing
```

## Coverage

| Target                       | Statements | Cover |
|------------------------------|-----------:|------:|
| `mac_tui_procmon_impl.py`    |       5770 |  75%  |
| `mac_tui_procmon` (shim)     |          - | 100%  |

The shim re-exports from the implementation module — measuring
coverage there is not meaningful. The honest number is the impl
coverage: 75% across 5770 statements. The remaining 25% is mostly
worker-thread bodies and error-recovery branches reachable only
with a real osquery / codesign / Gatekeeper / mitmdump backend.

## GUI / TUI flow paths

`tests/test_tui_flow_paths.py` covers every keypress path through
`handle_input`. It parametrises over every mode (Inspect, Hidden
scan, Audit, Bulk scan, Events, Traffic, Network) and asserts:

- Scroll keys (Up / Down / PgUp / PgDn) on every panel.
- Mode-toggle keys (`I`, `H`, `F`, `N`, `T`).
- Action keys (`R`/`r` rescan triage, `c` clear events / traffic,
  `k` kill connection).
- The Esc closes / two-stage-close (Events) / cancel-and-close
  (Bulk scan) chains.
- Tab toggles between detail focus and main mode.
- Main-mode hotkeys: `T` triage, `F` forensic menu, `E` telemetry
  menu, `s` sort dialog, `?` chat overlay, `L` log overlay.
- Esc-from-main closes whichever special mode is currently open.

## Test counts

`1036 passed` locally. Run the full suite before pushing.
