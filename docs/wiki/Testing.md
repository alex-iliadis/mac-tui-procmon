# Testing

## Layers

The suite has four layers, mostly mocked at the libproc/sysctl
boundary so it runs in <10s without any real macOS APIs:

1. **Unit tests** — `test_unit.py`, `test_vendor_group.py`, format /
   parse helpers, sort comparators, alert-threshold logic.
2. **Audit tests** — `test_audits*.py`, every SecAuditor audit
   function with synthetic inputs / outputs.
3. **Integration tests** — `test_integration.py`,
   `test_inspect_hidden.py`, `test_new_features.py`,
   `test_shortcuts_integration.py`, `test_tui_flow_paths.py`.
   Drive `handle_input(key)` through every keypress in every mode
   and assert observable state changes.
4. **TUI snapshot tests** — `test_tui_screen_capture.py`,
   `test_tui_screen_assertions.py`, `test_tui_report_assertions.py`.
   Render every menu / panel / dialog into a `*.screen.json`
   artifact and assert visible lines + focused box.

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
| `mac_tui_procmon_impl.py`    |       9185 |  76%  |
| `mac_tui_procmon` (shim)     |          - | 100%  |

The shim re-exports from the implementation module — measuring
coverage there is not meaningful. The honest number is the impl
coverage: 76% across 9185 statements. The remaining 24% is mostly
audit body builders and HTML-report rendering reachable only with a
real osquery / codesign / Gatekeeper / VT backend.

## GUI / TUI flow paths

`tests/test_tui_flow_paths.py` covers every keypress path through
`handle_input` that earlier integration tests left out. It
parametrises over every mode (Inspect, Hidden scan, Keyscan, Audit,
Bulk scan, Events, Traffic, Network) and asserts:

- Scroll keys (Up / Down / PgUp / PgDn) on every panel.
- Mode-toggle keys (`I`, `H`, `F`, `N`).
- Action keys (`D`/`d` remediate or remove hook, `R`/`r` rescan,
  `c` clear, `k` kill connection).
- The Esc closes / two-stage-close (Events) / cancel-and-close
  (Bulk scan) chains.
- Tab toggles between detail focus and main mode.
- Main-mode hotkeys: `T` triage, `H/J/G/X` SecAuditor bridge, `a`
  audit menu, `F` forensic menu, `E` telemetry menu, `s` sort
  dialog, `?` chat overlay, `L` log overlay.
- Esc-from-main closes whichever special mode is currently open.

## Test counts

`1569 passed` locally. Run the full suite before pushing.
