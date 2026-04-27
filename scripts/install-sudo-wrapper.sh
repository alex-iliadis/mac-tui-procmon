#!/bin/bash
# install-sudo-wrapper.sh
#
# Installs the mac-tui-procmon-sudo wrapper into /usr/local/sbin and
# drops the matching sudoers entry into /etc/sudoers.d. Run with sudo:
#
#   sudo scripts/install-sudo-wrapper.sh
#
# Idempotent: safe to re-run.

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "install-sudo-wrapper.sh: must run as root" >&2
  echo "Try: sudo scripts/install-sudo-wrapper.sh" >&2
  exit 1
fi

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$SRC_DIR/mac-tui-procmon-sudo"
DST="/usr/local/sbin/mac-tui-procmon-sudo"

if [ ! -f "$SRC" ]; then
  echo "install-sudo-wrapper.sh: source $SRC missing" >&2
  exit 2
fi

mkdir -p /usr/local/sbin
install -o root -g wheel -m 0755 "$SRC" "$DST"
echo "Installed $DST"

CALLER="${SUDO_USER:-$USER}"
SUDOERS_FILE="/etc/sudoers.d/mac-tui-procmon"
SUDOERS_LINE="$CALLER ALL=(root) NOPASSWD: $DST *"

# Validate sudoers fragment in a temp file before installing; visudo -c
# is the only safe way to add to /etc/sudoers.d.
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
echo "$SUDOERS_LINE" > "$TMP"
if ! visudo -c -f "$TMP" >/dev/null; then
  echo "install-sudo-wrapper.sh: refusing to install — sudoers syntax check failed" >&2
  exit 3
fi
install -o root -g wheel -m 0440 "$TMP" "$SUDOERS_FILE"
echo "Wrote $SUDOERS_FILE: $SUDOERS_LINE"

echo
echo "Verify with:"
echo "  sudo -n $DST --help"
