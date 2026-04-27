# Running

## Quick start

```bash
python3 mac_tui_procmon.py
python3 mac_tui_procmon.py firefox -i 2
sudo -n /usr/local/sbin/mac-tui-procmon-sudo --skip-preflight
```

`procmon.py` and `secprocmon.py` remain as compatibility shims.

## Sudo wrapper

Some features need root: memory-region YARA inside Inspect, the
hidden-process kqueue scan, and `eslogger` for the Endpoint Security
stream. The wrapper at `scripts/mac-tui-procmon-sudo` is the
canonical privileged entry point — it preserves the caller's PATH /
HOME so user-installed CLIs (eslogger, osquery, mitmdump, yara,
codesign-checker, …) resolve under sudo the same way they do
without it.

Install once with:

```bash
sudo scripts/install-sudo-wrapper.sh
```

This:
1. Installs `scripts/mac-tui-procmon-sudo` to `/usr/local/sbin/mac-tui-procmon-sudo` (root:wheel, mode 0755).
2. Drops `/etc/sudoers.d/mac-tui-procmon` with the matching NOPASSWD entry, after a `visudo -c` syntax check.

After install:

```bash
sudo -n /usr/local/sbin/mac-tui-procmon-sudo --help
sudo -n /usr/local/sbin/mac-tui-procmon-sudo
sudo -n /usr/local/sbin/mac-tui-procmon-sudo --capture-baseline
```

The sudoers entry is:

```
alex ALL=(root) NOPASSWD: /usr/local/sbin/mac-tui-procmon-sudo *
```

(Replaces the legacy `secprocmon-sudo` entry. The
`secauditor-serve` entry belongs to `mac-system-security`, not this
repo, and is unaffected.)

## CLI flags

| Flag                         | Effect                                                       |
|------------------------------|--------------------------------------------------------------|
| `name` (positional)          | Process-name substring filter                                |
| `-i / --interval SECS`       | Refresh interval (default 5)                                 |
| `--no-fd`                    | Skip file-descriptor counting (faster)                       |
| `--skip-preflight`           | Skip external-tool dependency check                          |
| `--capture-baseline`         | Write `~/.secprocmon-baseline.json` and exit                 |
| `--audit <name>`             | Run a single SecAuditor audit headless and print the report  |
| `--automated-security-scan`  | Run the full SecAuditor suite + AI synthesis, write HTML     |
| `--full-audit-report`        | Alias for `--automated-security-scan`                        |
| `--no-html-report`           | With `--automated-security-scan`: skip the HTML artifact     |
| `--no-open-report`           | With `--automated-security-scan`: write HTML but don't open  |

### Available `--audit` names

`network`, `dns`, `persistence`, `system_hardening`, `kernel_boot`,
`patch_posture`, `tcc`, `browser_exts`, `usb_hid`, `shell_dotfiles`,
`installed_software`, `process_entitlements`,
`injection_antidebug`, `filesystem_integrity`,
`sensitive_paths_delta`, `keychain`, `auth_stack`,
`binary_authorization`, `tool_correlation`, `packages`,
`baseline_delta`, `rule_engine`, `global_score`.

These are kept for backwards compatibility with old scripts. New
scripts should use the `secauditor` CLI or its browser/API product
directly.
