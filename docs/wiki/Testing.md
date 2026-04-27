# Testing

## Unit And Integration

```bash
/opt/homebrew/bin/python3 -m pytest -q
```

Validated locally with `1484 passed`.

## Coverage

```bash
/opt/homebrew/bin/python3 -m pytest -q --cov=mac_tui_procmon --cov-report=term-missing --cov-fail-under=95
```

Validated locally at `100%` for the public renamed app entrypoint.

## TUI Quality

The suite includes semantic TUI report and screen assertions through `tui_report_assertions.py`, `tui_screen_assertions.py`, and TUI capture tests. The assertions check rendered text and state, not just whether a command exits.

