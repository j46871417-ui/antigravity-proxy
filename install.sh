#!/usr/bin/env bash
# Antigravity Proxy v2 installer (Go engine)
set -Eeuo pipefail

if [ "${EUID}" -ne 0 ]; then
    echo "Run as root: sudo bash install.sh" >&2
    exit 1
fi
if [ "$(uname -s)" != "Linux" ]; then
    echo "This installer supports Linux only." >&2
    exit 1
fi

REPO="https://github.com/j46871417-ui/antigravity-proxy"
GO_VERSION="1.27.2"
INSTALL_DIR="/opt/antigravity-proxy"
CONF_DIR="/etc/antigravity-proxy"
CONFIG_FILE="$CONF_DIR/config.env"
WORK_DIR="$(mktemp -d)"
BACKUP_DIR="/var/backups/antigravity-proxy/$(date -u +%Y%m%dT%H%M%SZ)"
HAD_HAPROXY=0
mkdir -p "$INSTALL_DIR" "$CONF_DIR" "$BACKUP_DIR"
trap 'rm -rf "$WORK_DIR"' EXIT

if systemctl is-active --quiet haproxy; then HAD_HAPROXY=1; fi
for file in "$CONFIG_FILE" /etc/systemd/system/antigravity-proxy.service /opt/antigravity-proxy/antigravity-proxy; do
    if [ -e "$file" ]; then
        cp -a "$file" "$BACKUP_DIR/"
    fi
done
echo "Backup: $BACKUP_DIR"

apt-get update -qq
apt-get install -y -qq ca-certificates curl tar gzip

GO_BIN="$(command -v go || true)"
GO_OK=0
if [ -n "$GO_BIN" ]; then
    GO_VER="$("$GO_BIN" version | sed -nE 's/.* go([0-9]+\.[0-9]+).*/\1/p')"
    if [ -n "$GO_VER" ] && [ "$(printf '%s\n' 1.22 "$GO_VER" | sort -V | head -n1)" = "1.22" ]; then
        GO_OK=1
    fi
fi

if [ "$GO_OK" -ne 1 ]; then
    case "$(uname -m)" in
        x86_64|amd64)
            GO_ARCH="amd64"
            GO_SHA256="ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5"
            ;;
        aarch64|arm64)
            GO_ARCH="arm64"
            GO_SHA256="94f3e30b8e374bc285e7dadc11e0865726b9bc6e85b841ccceaabc0214c6b7c8"
            ;;
        *)
            echo "Unsupported architecture: $(uname -m). Install Go 1.22+ and rerun." >&2
            exit 1
            ;;
    esac
    GO_ARCHIVE="$WORK_DIR/go.tar.gz"
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -o "$GO_ARCHIVE"
    echo "$GO_SHA256  $GO_ARCHIVE" | sha256sum -c -
    tar -xzf "$GO_ARCHIVE" -C "$WORK_DIR"
    GO_BIN="$WORK_DIR/go/bin/go"
fi

SOURCE_DIR="$WORK_DIR/source"
mkdir -p "$SOURCE_DIR"
curl -fsSL "$REPO/archive/refs/heads/main.tar.gz" | tar -xz --strip-components=1 -C "$SOURCE_DIR"
(
    cd "$SOURCE_DIR"
    GOTOOLCHAIN=local "$GO_BIN" build -trimpath -ldflags="-s -w" -o "$WORK_DIR/antigravity-proxy" .
)

read_config_value() {
    local key="$1"
    if [ -f "$CONFIG_FILE" ]; then
        sed -n "s/^$key=//p" "$CONFIG_FILE" | head -n1
    fi
}
PROXY_USER="${PROXY_USER:-$(read_config_value PROXY_USER)}"
PROXY_PASS="${PROXY_PASS:-$(read_config_value PROXY_PASS)}"
PROXY_USER="${PROXY_USER:-ag_user}"
PROXY_PASS="${PROXY_PASS:-$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
if [[ ! "$PROXY_USER" =~ ^[A-Za-z0-9._-]+$ ]] || [[ ! "$PROXY_PASS" =~ ^[A-Za-z0-9._~-]+$ ]]; then
    echo "PROXY_USER/PROXY_PASS must use URL-safe characters (letters, digits, . _ ~ -)." >&2
    exit 1
fi

USERS_FILE="${USERS_FILE:-$(read_config_value USERS_FILE)}"
USERS_FILE="${USERS_FILE:-$INSTALL_DIR/users.json}"
USER_TRAFFIC_FILE="${USER_TRAFFIC_FILE:-$(read_config_value USER_TRAFFIC_FILE)}"
USER_TRAFFIC_FILE="${USER_TRAFFIC_FILE:-$INSTALL_DIR/user_traffic.json}"
STATS_DB="${STATS_DB:-$(read_config_value STATS_DB)}"
STATS_DB="${STATS_DB:-$INSTALL_DIR/stats.db}"
STATS_LOCATION="${STATS_LOCATION:-$(read_config_value STATS_LOCATION)}"
STATS_LOCATION="${STATS_LOCATION:-it}"
SERVER_IP="$(curl -fsS4 --max-time 5 https://api.ipify.org || echo YOUR_SERVER_IP)"

if ! id -u antigravity >/dev/null 2>&1; then
    useradd --system --home-dir "$INSTALL_DIR" --shell /usr/sbin/nologin antigravity
fi

CONFIG_TMP="$WORK_DIR/config.env"
if [ -f "$CONFIG_FILE" ]; then
    grep -Ev '^(PROXY_USER|PROXY_PASS|PROXY_HOST|PROXY_PORT|USERS_FILE|USER_TRAFFIC_FILE|STATS_DB|STATS_LOCATION)=' "$CONFIG_FILE" > "$CONFIG_TMP" || true
else
    : > "$CONFIG_TMP"
fi
cat >> "$CONFIG_TMP" <<EOF
PROXY_USER=$PROXY_USER
PROXY_PASS=$PROXY_PASS
PROXY_HOST=0.0.0.0
PROXY_PORT=50128
USERS_FILE=$USERS_FILE
USER_TRAFFIC_FILE=$USER_TRAFFIC_FILE
STATS_DB=$STATS_DB
STATS_LOCATION=$STATS_LOCATION
EOF
install -o root -g antigravity -m 0640 "$CONFIG_TMP" "$CONFIG_FILE"
install -o antigravity -g antigravity -m 0750 "$WORK_DIR/antigravity-proxy" "$INSTALL_DIR/antigravity-proxy"
touch "$USERS_FILE"
chown antigravity:antigravity "$USERS_FILE" "$INSTALL_DIR"
chmod 0600 "$USERS_FILE"
chown antigravity:antigravity "$INSTALL_DIR" "$CONF_DIR"
chmod 0750 "$INSTALL_DIR"

cat > /etc/systemd/system/antigravity-proxy.service <<EOF
[Unit]
Description=Antigravity Proxy v2 Go Core
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=antigravity
Group=antigravity
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$CONFIG_FILE
ExecStart=$INSTALL_DIR/antigravity-proxy
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR

[Install]
WantedBy=multi-user.target
EOF

if [ "$HAD_HAPROXY" -eq 1 ]; then
    systemctl stop haproxy
    systemctl disable haproxy >/dev/null 2>&1 || true
fi
systemctl daemon-reload
systemctl enable antigravity-proxy.service
systemctl restart antigravity-proxy.service
systemctl --no-pager --full status antigravity-proxy.service

echo
echo "Antigravity Proxy v2 Go engine is active."
echo "Server: $SERVER_IP  Port: 50128"
echo "Login: $PROXY_USER"
echo "Password: $PROXY_PASS"
echo "HTTPS proxy: https://$PROXY_USER:$PROXY_PASS@$SERVER_IP:50128"
echo "Generate additional accounts with:"
echo "  sudo -u antigravity $INSTALL_DIR/antigravity-proxy users generate --host $SERVER_IP --count 1"
echo "Backup: $BACKUP_DIR"
