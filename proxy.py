#!/usr/bin/env python3
"""
Dedicated Antigravity HTTP/HTTPS CONNECT Proxy Core
Author: confeden/Antigravity Community
Purpose: High-performance, zero-trust whitelisted proxy for Google Antigravity and Gemini Code Assist.
"""

import asyncio
import base64
import logging
import os
import sys
import json
import ipaddress
import urllib.parse
from datetime import datetime

# --- CONFIGURATION ---
LISTEN_HOST = os.getenv("PROXY_LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.getenv("PROXY_LISTEN_PORT", "50127"))
BUFFER_SIZE = int(os.getenv("BUFFER_SIZE", "65536"))

# Standalone single credentials (set via env or generated on install)
STATIC_USER = os.getenv("PROXY_USER", "antigravity")
STATIC_PASS = os.getenv("PROXY_PASS", "secret_pass")

# Optional multi-user JSON file (e.g. {"username": "password"})
USERS_FILE = os.getenv("USERS_FILE", "users.json")

# Configure logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("AntigravityProxy")

# Antigravity, Google Cloud Code & AI APIs strict whitelist
ALLOWED_EXACT_HOSTS = {
    "cloudcode-pa.googleapis.com",
    "daily-cloudcode-pa.googleapis.com",
    "accounts.google.com",
    "oauth2.googleapis.com",
    "generativelanguage.googleapis.com",
    "jetski-webchannel.googleapis.com",
    "storage.googleapis.com",
    "antigravity.google",
    "antigravity-unleash.goog",
    "ai.google.dev",
    "www.cloudflare.com",
    "chatgpt.com",
    "claude.ai",
    "www.google.com",
    "myaccount.google.com",
    "gemini-api-docs-mcp.dev",
    "api.openai.com",
    "antigravity-cli-auto-updater-974169037036.us-central1.run.app",
}

ALLOWED_DOMAIN_SUFFIXES = (
    ".googleapis.com",
    ".googleusercontent.com",
    ".gstatic.com",
    ".google.com",
    ".run.app",
    ".openai.com",
)

ALLOWED_PORTS = {80, 443, 5228}

# Known Google IP subnets (AS15169) for clients resolving DNS locally
GOOGLE_IP_NETWORKS = [
    ipaddress.ip_network("172.217.0.0/16"),
    ipaddress.ip_network("142.250.0.0/15"),
    ipaddress.ip_network("142.251.0.0/16"),
    ipaddress.ip_network("108.177.0.0/17"),
    ipaddress.ip_network("209.85.128.0/17"),
    ipaddress.ip_network("173.194.0.0/16"),
    ipaddress.ip_network("64.233.160.0/19"),
    ipaddress.ip_network("74.125.0.0/16"),
    ipaddress.ip_network("172.253.0.0/16"),
    ipaddress.ip_network("192.179.0.0/16"),
    ipaddress.ip_network("216.58.192.0/19"),
    ipaddress.ip_network("216.239.32.0/19"),
]

def is_google_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in GOOGLE_IP_NETWORKS)
    except ValueError:
        return False

def load_multi_users() -> dict:
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Could not parse users file {USERS_FILE}: {e}")
    return {}

def authenticate_user(user: str, password: str) -> bool:
    # 1. Check static env user
    if STATIC_USER and STATIC_PASS:
        if user == STATIC_USER and password == STATIC_PASS:
            return True

    # 2. Check multi-user file
    users_db = load_multi_users()
    if user in users_db and users_db[user] == password:
        return True

    return False

def is_host_allowed(host: str, port: int) -> bool:
    if port not in ALLOWED_PORTS:
        return False
    h = host.strip().lower().rstrip('.')
    if h in ALLOWED_EXACT_HOSTS:
        return True
    for suffix in ALLOWED_DOMAIN_SUFFIXES:
        if h.endswith(suffix):
            return True
    if h and (h[0].isdigit() or ':' in h):
        if is_google_ip(h):
            return True
    return False

USER_TRAFFIC_FILE = os.getenv("USER_TRAFFIC_FILE", "/opt/antigravity-proxy/user_traffic.json")
USER_MONTHLY_SOFT_LIMIT_BYTES = int(os.getenv("USER_MONTHLY_SOFT_LIMIT_BYTES", str(30 * 1024 * 1024 * 1024)))  # 30 GB

_traffic_month = datetime.now().strftime("%Y-%m")
_user_traffic_mem = {}

def load_user_traffic():
    global _user_traffic_mem, _traffic_month
    cur_m = datetime.now().strftime("%Y-%m")
    _traffic_month = cur_m
    if os.path.exists(USER_TRAFFIC_FILE):
        try:
            with open(USER_TRAFFIC_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if data.get("month") == cur_m:
                    _user_traffic_mem = data.get("traffic", {})
        except Exception as e:
            logger.debug(f"Could not load user traffic file: {e}")

def save_user_traffic():
    try:
        tmp_path = USER_TRAFFIC_FILE + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump({"month": _traffic_month, "traffic": _user_traffic_mem}, f)
        os.replace(tmp_path, USER_TRAFFIC_FILE)
    except Exception as e:
        logger.debug(f"Could not save user traffic file: {e}")

def record_user_traffic(user: str, num_bytes: int):
    global _traffic_month
    cur_m = datetime.now().strftime("%Y-%m")
    if cur_m != _traffic_month:
        _user_traffic_mem.clear()
        _traffic_month = cur_m
    _user_traffic_mem[user] = _user_traffic_mem.get(user, 0) + num_bytes

def is_user_soft_throttled(user: str) -> bool:
    return _user_traffic_mem.get(user, 0) > USER_MONTHLY_SOFT_LIMIT_BYTES

async def traffic_persist_loop():
    while True:
        await asyncio.sleep(60)
        save_user_traffic()

async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, proxy_user: str = None, is_throttled: bool = False):
    try:
        while True:
            data = await reader.read(BUFFER_SIZE)
            if not data:
                break
            data_len = len(data)
            if proxy_user:
                record_user_traffic(proxy_user, data_len)

            writer.write(data)
            await writer.drain()

            if is_throttled:
                # Soft throttle to ~400 KB/s (~3.2 Mbps)
                await asyncio.sleep(data_len / 400_000.0)
            else:
                # Smoothing burst limiter for heavy chunks (>32KB) to cap sustained line speed at ~28 Mbps
                if data_len > 32768:
                    await asyncio.sleep(data_len / 3_500_000.0)
    except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        logger.debug(f"Pipe stream error: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def handle_client(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
    client_ip = "unknown"
    peer = client_writer.get_extra_info("peername")
    if peer:
        client_ip = peer[0]

    try:
        header_data = bytearray()
        while b"\r\n\r\n" not in header_data and len(header_data) < 65536:
            chunk = await asyncio.wait_for(client_reader.read(4096), timeout=15.0)
            if not chunk:
                break
            header_data.extend(chunk)

        if not header_data:
            client_writer.close()
            return

        header_bytes, sep, remaining_body = header_data.partition(b"\r\n\r\n")
        lines = header_bytes.split(b"\r\n")
        if not lines or not lines[0]:
            client_writer.close()
            return

        request_line = lines[0].decode("latin-1", errors="replace")
        parts = request_line.split()
        if len(parts) < 2:
            client_writer.close()
            return

        method, target = parts[0].upper(), parts[1]

        headers = {}
        for line in lines[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                headers[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()

        # Check Proxy Authentication
        auth_header = headers.get("proxy-authorization")
        if not auth_header or not auth_header.lower().startswith("basic "):
            client_writer.write(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                b"Proxy-Authenticate: Basic realm=\"Antigravity Secure Gateway\"\r\n"
                b"Connection: close\r\n"
                b"Content-Length: 32\r\n\r\n"
                b"Proxy Authentication Required.\r\n"
            )
            await client_writer.drain()
            client_writer.close()
            return

        try:
            b64_creds = auth_header.split(" ", 1)[1].strip()
            decoded = base64.b64decode(b64_creds).decode("utf-8", errors="replace")
            proxy_user, proxy_pass = decoded.split(":", 1)
        except Exception:
            client_writer.write(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                b"Proxy-Authenticate: Basic realm=\"Antigravity Secure Gateway\"\r\n"
                b"Connection: close\r\n"
                b"Content-Length: 21\r\n\r\n"
                b"Invalid credentials.\r\n"
            )
            await client_writer.drain()
            client_writer.close()
            return

        if not authenticate_user(proxy_user, proxy_pass):
            logger.warning(f"Unauthorized auth attempt for user '{proxy_user}' from {client_ip}")
            client_writer.write(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                b"Proxy-Authenticate: Basic realm=\"Antigravity Secure Gateway\"\r\n"
                b"Connection: close\r\n"
                b"Content-Length: 21\r\n\r\n"
                b"Invalid credentials.\r\n"
            )
            await client_writer.drain()
            client_writer.close()
            return

        # Parse target host and port
        if method == "CONNECT":
            if ":" in target:
                host_str, port_str = target.split(":", 1)
                try:
                    port = int(port_str)
                except ValueError:
                    port = 443
            else:
                host_str = target
                port = 443
        else:
            parsed = urllib.parse.urlparse(target)
            host_str = parsed.hostname or headers.get("host", "").split(":")[0]
            port = parsed.port or 80

        host_str = host_str.strip().lower().rstrip('.')

        # Strict Zero-Trust Whitelist Check
        if not is_host_allowed(host_str, port):
            logger.warning(f"BLOCKED: {proxy_user}@{client_ip} tried to access unauthorized host {host_str}:{port}")
            resp_body = b"Access Denied: unauthorized host. This proxy is strictly for Google Antigravity.\r\n"
            client_writer.write(
                b"HTTP/1.1 403 Forbidden\r\n"
                b"Connection: close\r\n"
                b"Content-Type: text/plain; charset=utf-8\r\n"
                + f"Content-Length: {len(resp_body)}\r\n\r\n".encode("latin-1")
                + resp_body
            )
            await client_writer.drain()
            client_writer.close()
            return

        logger.info(f"Allowed {method} {host_str}:{port} ({proxy_user})")

        # Open upstream connection
        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(host_str, port),
                timeout=12.0
            )
        except Exception as e:
            logger.warning(f"Failed to connect to remote host {host_str}:{port}: {e}")
            client_writer.write(
                b"HTTP/1.1 502 Bad Gateway\r\n"
                b"Connection: close\r\n"
                b"Content-Length: 17\r\n\r\n"
                b"Connection failed\r\n"
            )
            await client_writer.drain()
            client_writer.close()
            return

        if method == "CONNECT":
            client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await client_writer.drain()
            if remaining_body:
                remote_writer.write(remaining_body)
                await remote_writer.drain()
        else:
            path = parsed.path or "/"
            if parsed.query:
                path += f"?{parsed.query}"
            new_req_lines = [f"{method} {path} HTTP/1.1"]
            for k, v in headers.items():
                if k not in ("proxy-authorization", "proxy-connection"):
                    new_req_lines.append(f"{k.title()}: {v}")
            new_req_lines.append("Connection: close")
            req_data = "\r\n".join(new_req_lines).encode("latin-1") + b"\r\n\r\n"
            remote_writer.write(req_data)
            if remaining_body:
                remote_writer.write(remaining_body)
            await remote_writer.drain()

        is_throttled = is_user_soft_throttled(proxy_user)
        # Bidirectional relay with traffic accounting and soft shaping
        await asyncio.gather(
            pipe(client_reader, remote_writer, proxy_user=proxy_user, is_throttled=is_throttled),
            pipe(remote_reader, client_writer, proxy_user=proxy_user, is_throttled=is_throttled),
            return_exceptions=True
        )

    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        logger.debug(f"Handle client exception: {e}")
    finally:
        try:
            client_writer.close()
            await client_writer.wait_closed()
        except Exception:
            pass

async def main():
    load_user_traffic()
    asyncio.create_task(traffic_persist_loop())
    logger.info(f"Starting Antigravity Proxy Core on {LISTEN_HOST}:{LISTEN_PORT}...")
    server = await asyncio.start_server(handle_client, LISTEN_HOST, LISTEN_PORT)
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    logger.info(f"Ready and serving on {addrs}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Proxy stopped.")
