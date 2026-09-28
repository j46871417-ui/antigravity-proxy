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

# Antigravity & Google Cloud Code strict whitelist
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
}

ALLOWED_DOMAIN_SUFFIXES = (
    ".googleapis.com",
    ".googleusercontent.com",
    ".gstatic.com",
    ".google.com",
)

ALLOWED_PORTS = {80, 443}

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
    return False

async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            data = await reader.read(BUFFER_SIZE)
            if not data:
                break
            writer.write(data)
            await writer.drain()
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

        # Bidirectional relay
        await asyncio.gather(
            pipe(client_reader, remote_writer),
            pipe(remote_reader, client_writer),
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
