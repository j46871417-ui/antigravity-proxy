#!/usr/bin/env bash
# ==============================================================================
# Antigravity Proxy Server - One-Line Installer
# Author: confeden/Antigravity Community
# Supported OS: Ubuntu 20.04+, Debian 11+
# ==============================================================================

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}   🚀 Antigravity Proxy Server Automated Installer  ${NC}"
echo -e "${BLUE}====================================================${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}❌ Please run as root (e.g. sudo bash install.sh)${NC}"
    exit 1
fi

# Detect external IP
SERVER_IP=$(curl -s4 --max-time 5 ifconfig.me || curl -s4 --max-time 5 api.ipify.org || echo "YOUR_SERVER_IP")

echo -e "\n${YELLOW}📦 Step 1: Installing dependencies...${NC}"
apt-get update -qq
apt-get install -y -qq haproxy python3 openssl curl

INSTALL_DIR="/opt/antigravity-proxy"
CONF_DIR="/etc/antigravity-proxy"
mkdir -p "$INSTALL_DIR" "$CONF_DIR"

# Generate random credentials if not provided
if [ -z "$PROXY_USER" ]; then
    PROXY_USER="ag_user"
fi
if [ -z "$PROXY_PASS" ]; then
    PROXY_PASS=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 12)
fi

echo -e "\n${YELLOW}⚙️ Step 2: Setting up configuration and credentials...${NC}"
cat <<EOF > "$CONF_DIR/config.env"
PROXY_USER=$PROXY_USER
PROXY_PASS=$PROXY_PASS
PROXY_LISTEN_HOST=127.0.0.1
PROXY_LISTEN_PORT=50127
EOF

# Copy proxy.py & stats.py
if [ -f "proxy.py" ]; then
    cp proxy.py "$INSTALL_DIR/proxy.py"
else
    # Fetch from github if running via curl pipe
    curl -sSL -o "$INSTALL_DIR/proxy.py" "https://raw.githubusercontent.com/j46871417-ui/antigravity-proxy/main/proxy.py"
fi
chmod +x "$INSTALL_DIR/proxy.py"

if [ -f "stats.py" ]; then
    cp stats.py "$INSTALL_DIR/stats.py"
else
    curl -sSL -o "$INSTALL_DIR/stats.py" "https://raw.githubusercontent.com/j46871417-ui/antigravity-proxy/main/stats.py" || true
fi

echo -e "\n${YELLOW}🔒 Step 3: Generating SSL certificate for HTTPS Proxy mode...${NC}"
if [ ! -f "$CONF_DIR/proxy_bundle.pem" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$CONF_DIR/proxy.key" \
        -out "$CONF_DIR/proxy.crt" \
        -days 3650 \
        -subj "/CN=$SERVER_IP/O=Antigravity/C=EU" >/dev/null 2>&1
    cat "$CONF_DIR/proxy.key" "$CONF_DIR/proxy.crt" > "$CONF_DIR/proxy_bundle.pem"
    chmod 600 "$CONF_DIR/proxy_bundle.pem"
fi

echo -e "\n${YELLOW}🌐 Step 4: Configuring HAProxy dual-mode frontend...${NC}"
cat <<EOF > /etc/haproxy/haproxy.cfg
global
    log stdout format raw local0 info
    chroot /var/lib/haproxy
    user haproxy
    group haproxy
    daemon
    maxconn 4096

defaults
    log global
    mode tcp
    option dontlognull
    timeout connect 5s
    timeout client 10m
    timeout server 10m

# === DUAL-MODE (HYBRID) ANTIGRAVITY PROXY FRONTEND ===
frontend ag_proxy_in
    bind 0.0.0.0:50128
    mode tcp
    option tcplog
    stick-table type ip size 100k expire 10m store conn_cur
    tcp-request connection reject if { src_conn_cur ge 30 }
    tcp-request connection track-sc0 src
    tcp-request inspect-delay 2s
    tcp-request content accept if { req_ssl_hello_type 1 }

    use_backend ag_ssl_backend if { req_ssl_hello_type 1 }
    default_backend ag_plain_backend

backend ag_ssl_backend
    mode tcp
    server local_ssl 127.0.0.1:50130 send-proxy

frontend ag_ssl_terminator
    bind 127.0.0.1:50130 ssl crt $CONF_DIR/proxy_bundle.pem accept-proxy
    mode tcp
    default_backend ag_plain_backend

backend ag_plain_backend
    mode tcp
    server python_proxy 127.0.0.1:50127 send-proxy
EOF

echo -e "\n${YELLOW}👤 Step 5: Creating isolated unprivileged system user...${NC}"
if ! id -u antigravity >/dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin -d "$INSTALL_DIR" antigravity
fi
chown -R antigravity:antigravity "$INSTALL_DIR" "$CONF_DIR"
chmod 644 "$CONF_DIR/proxy_bundle.pem" 2>/dev/null || true

echo -e "\n${YELLOW}🚀 Step 6: Creating and enabling systemd service...${NC}"
cat <<EOF > /etc/systemd/system/antigravity-proxy.service
[Unit]
Description=Antigravity Zero-Trust Proxy Core
After=network.target

[Service]
Type=simple
User=antigravity
Group=antigravity
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$CONF_DIR/config.env
ExecStart=/usr/bin/python3 $INSTALL_DIR/proxy.py
Restart=always
RestartSec=3
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl restart haproxy
systemctl enable --now antigravity-proxy.service

echo -e "\n${GREEN}====================================================${NC}"
echo -e "${GREEN}   🎉 Antigravity Proxy Successfully Installed!     ${NC}"
echo -e "${GREEN}====================================================${NC}"
echo -e "\n📋 ${YELLOW}Connection Details:${NC}"
echo -e "• Type:     ${BLUE}HTTPS / HTTP CONNECT (Dual-Mode)${NC}"
echo -e "• Server:   ${BLUE}$SERVER_IP${NC}"
echo -e "• Port:     ${BLUE}50128${NC}"
echo -e "• Login:    ${BLUE}$PROXY_USER${NC}"
echo -e "• Password: ${BLUE}$PROXY_PASS${NC}"

PROXY_URL="https://$PROXY_USER:$PROXY_PASS@$SERVER_IP:50128"
echo -e "\n📌 ${GREEN}Antigravity Connection String:${NC}"
echo -e "${YELLOW}$PROXY_URL${NC}"

echo -e "\n💡 ${BLUE}How to use:${NC}"
echo -e "1. Launch Antigravity.exe"
echo -e "2. Press '1. Own proxy'"
echo -e "3. Paste the URL above and press Enter!"
echo -e "4. Enjoy high-speed Google Cloud Code / Gemini AI without restrictions."
echo -e "\n💬 ${BLUE}Telegram Community & Support:${NC} ${YELLOW}https://t.me/+8qU7020rMF84OWNi${NC}\n"
