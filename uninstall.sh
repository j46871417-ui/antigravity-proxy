#!/usr/bin/env bash
# Remove an Antigravity Proxy installation created by install.sh.
# The script is deliberately conservative: it does not remove shared apt packages.
set -Eeuo pipefail

INSTALL_DIR="/opt/antigravity-proxy"
CONF_DIR="/etc/antigravity-proxy"
SERVICE="antigravity-proxy.service"
BACKUP_ROOT="/var/backups/antigravity-proxy"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash uninstall.sh [--yes]" >&2
  exit 1
fi

YES=0
for arg in "$@"; do
  case "$arg" in
    --yes) YES=1 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

if [[ "$YES" -ne 1 ]]; then
  read -r -p "Remove Antigravity Proxy from this server? [y/N] " answer
  [[ "$answer" =~ ^[Yy]$ ]] || { echo "Cancelled."; exit 0; }
fi

stamp="$(date -u +%Y%m%d-%H%M%S)"
backup="$BACKUP_ROOT/uninstall-$stamp"
install -d -m 700 "$backup"

backup_file() {
  local source="$1"
  [[ -e "$source" ]] || return 0
  cp -a -- "$source" "$backup/"
}

backup_file "$CONF_DIR"
backup_file /etc/haproxy/haproxy.cfg
backup_file /etc/systemd/system/$SERVICE

systemctl disable --now "$SERVICE" 2>/dev/null || true
systemctl daemon-reload

# A compose deployment is scoped to this exact project/container name.
if command -v docker >/dev/null 2>&1 && docker ps -a --format '{{.Names}}' | grep -qx 'antigravity-proxy'; then
  docker rm -f antigravity-proxy >/dev/null 2>&1 || true
fi

rm -f -- "/etc/systemd/system/$SERVICE"
rm -rf -- "$INSTALL_DIR" "$CONF_DIR"

if id -u antigravity >/dev/null 2>&1; then
  if ! pgrep -u antigravity >/dev/null 2>&1 && [[ ! -d "/home/antigravity" ]]; then
    userdel antigravity 2>/dev/null || true
  fi
fi

# Restore the config saved by install.sh, when available. If this installation
# had no predecessor, leave the current file removed but keep it in the backup.
if [[ -f /var/backups/antigravity-proxy/install/haproxy.cfg ]]; then
  cp -a /var/backups/antigravity-proxy/install/haproxy.cfg /etc/haproxy/haproxy.cfg
fi

echo "Antigravity Proxy removed. A rollback backup was saved at: $backup"
echo "Shared packages (HAProxy, Python, OpenSSL) were left installed."
