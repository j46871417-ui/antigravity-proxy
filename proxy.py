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
import socket
import urllib.parse
from datetime import datetime
import time as _time
import threading as _threading

# --- Статистика запросов (модуль stats.py рядом с proxy.py) ---
try:
    from stats import RequestStats
    _STATS_AVAILABLE = True
except Exception as _e:
    RequestStats = None
    _STATS_AVAILABLE = False
    print(f"[stats] модуль недоступен: {_e}", flush=True)

# --- CONFIGURATION ---
LISTEN_HOST = os.getenv("PROXY_LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.getenv("PROXY_LISTEN_PORT", "50127"))
BUFFER_SIZE = int(os.getenv("BUFFER_SIZE", "65536"))

# Standalone single credentials (set via env or generated on install)
STATIC_USER = os.getenv("PROXY_USER", "antigravity")
STATIC_PASS = os.getenv("PROXY_PASS", "secret_pass")

# Optional multi-user JSON file (e.g. {"username": "password"} or {"username": ["pass1", "pass2"]})
USERS_FILE = os.getenv("USERS_FILE", "users.json")

# Configure logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("AntigravityProxy")

# --- Сборщик статистики ---
STATS = None
STATS_DB = os.getenv("STATS_DB", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "stats.db"))
STATS_LOCATION = os.getenv("STATS_LOCATION", "it")
if _STATS_AVAILABLE:
    try:
        STATS = RequestStats(STATS_DB, location=STATS_LOCATION)
        STATS.init_db()
    except Exception as _e:
        print(f"[stats] инициализация не удалась: {_e}", flush=True)
        STATS = None


def _log_stat(user, host, port, status, bytes_in=0, bytes_out=0, duration_ms=0):
    """Статистика не должна ломать прокси: любые ошибки глотаем."""
    if STATS is None:
        return
    try:
        STATS.log(user, host, port, status, bytes_in, bytes_out, duration_ms)
    except Exception:
        pass


# Учёт трафика и длительности по соединению
_conn_stats = {}  # id(writer) -> учёт байт, времени и метаданных соединения
_conn_lock = _threading.Lock()


def _conn_start(key, user, host, port):
    with _conn_lock:
        _conn_stats[key] = {"bytes_in": 0, "bytes_out": 0,
                            "t0": _time.time(), "user": user,
                            "host": host, "port": port}


def _conn_add(key, direction, n):
    with _conn_lock:
        e = _conn_stats.get(key)
        if e:
            e[direction] += n


def _conn_finish(key, status="allowed"):
    with _conn_lock:
        e = _conn_stats.pop(key, None)
    if not e:
        return
    dur = int((_time.time() - e["t0"]) * 1000)
    if status == "allowed" and e["bytes_out"] == 0 and e["bytes_in"] > 0:
        status = "timeout_no_data"
    _log_stat(e["user"], e["host"], e["port"], status,
              bytes_in=e["bytes_in"], bytes_out=e["bytes_out"],
              duration_ms=dur)


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
    "api.anthropic.com",
    "antigravity-cli-auto-updater-974169037036.us-central1.run.app",
}

ALLOWED_DOMAIN_SUFFIXES = (
    ".googleapis.com",
    ".googleusercontent.com",
    ".gstatic.com",
    ".google.com",
    ".google",
    ".goog",
    ".google.dev",
    ".run.app",
    ".openai.com",
    ".anthropic.com",
    ".claude.ai",
)

ALLOWED_PORTS = {80, 443, 5228}

# Known Google IP subnets (AS15169 & Google Cloud / Cloud Run) for clients resolving DNS locally
GOOGLE_IP_NETWORKS = [
    # Legacy AS15169 subnets
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
    # Google Cloud & Cloud Run IP ranges
    ipaddress.ip_network("34.0.0.0/8"),
    ipaddress.ip_network("35.0.0.0/8"),
    ipaddress.ip_network("199.36.153.0/24"),
    ipaddress.ip_network("199.36.158.0/24"),
    # Google IPv6 subnets
    ipaddress.ip_network("2600:1900::/28"),
    ipaddress.ip_network("2607:f8b0::/32"),
    ipaddress.ip_network("2a00:1450::/32"),
    ipaddress.ip_network("2a04:4e42::/32"),
    ipaddress.ip_network("2001:4860::/32"),
    ipaddress.ip_network("2404:6800::/32"),
    ipaddress.ip_network("2800:3f0::/32"),
    ipaddress.ip_network("2a02:d340::/32"),
]


def is_google_ip(ip_str: str) -> bool:
    try:
        clean_ip = ip_str.strip("[]")
        addr = ipaddress.ip_address(clean_ip)
        return any(addr in net for net in GOOGLE_IP_NETWORKS)
    except ValueError:
        return False


_USERS_CACHE = {}
_USERS_CACHE_MTIME = 0.0

def load_multi_users() -> dict:
    global _USERS_CACHE, _USERS_CACHE_MTIME
    if os.path.exists(USERS_FILE):
        try:
            mtime = os.path.getmtime(USERS_FILE)
            if mtime != _USERS_CACHE_MTIME:
                with open(USERS_FILE, "r", encoding="utf-8") as f:
                    _USERS_CACHE = json.load(f)
                _USERS_CACHE_MTIME = mtime
            return _USERS_CACHE
        except Exception as e:
            logger.warning(f"Could not parse users file {USERS_FILE}: {e}")
            return _USERS_CACHE
    return {}


def authenticate_user(user: str, password: str) -> bool:
    # 1. Check static env user
    if STATIC_USER and STATIC_PASS:
        if user == STATIC_USER and password == STATIC_PASS:
            return True

    # 2. Check multi-user file (supports string password or list of valid passwords)
    users_db = load_multi_users()
    if user in users_db:
        expected = users_db[user]
        if isinstance(expected, list):
            return password in expected
        return expected == password

    return False


def is_host_allowed(host: str, port: int) -> bool:
    if port not in ALLOWED_PORTS:
        return False
    h = host.strip().lower().rstrip('.').strip("[]")
    if h in ALLOWED_EXACT_HOSTS:
        return True
    for suffix in ALLOWED_DOMAIN_SUFFIXES:
        if h.endswith(suffix):
            return True
    # If host is an IP address
    if h and (h[0].isdigit() or ':' in h):
        if is_google_ip(h):
            return True
    return False


USER_TRAFFIC_FILE = os.getenv("USER_TRAFFIC_FILE", "/opt/antigravity_proxy/user_traffic.json")
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


def _set_tcp_keepalive(writer: asyncio.StreamWriter):
    """Enable and configure aggressive TCP keepalive on underlying socket."""
    sock = writer.get_extra_info("socket")
    if sock:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            # Linux keepalive options
            if hasattr(socket, "TCP_KEEPIDLE"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
            if hasattr(socket, "TCP_KEEPINTVL"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
            if hasattr(socket, "TCP_KEEPCNT"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        except Exception:
            pass


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, proxy_user: str = None, is_throttled: bool = False, stat_key=None, direction="bytes_in"):
    try:
        while True:
            data = await reader.read(BUFFER_SIZE)
            if not data:
                break
            data_len = len(data)
            if proxy_user:
                record_user_traffic(proxy_user, data_len)
            if stat_key is not None:
                _conn_add(stat_key, direction, data_len)

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

    _set_tcp_keepalive(client_writer)

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
            logger.warning(f"Unauthorized auth attempt for user '{proxy_user}' (sent pass: '{proxy_pass}') from {client_ip}")
            _log_stat(proxy_user, target, 0, "blocked_auth")
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

        # Parse target host and port safely (including IPv6 addresses)
        if method == "CONNECT":
            if target.startswith("["):
                # Bracketed IPv6 address: e.g. [2600:1900::1]:443 or [2600:1900::1]
                if "]:" in target:
                    host_str, port_str = target.split("]:", 1)
                    host_str = host_str.lstrip("[")
                    try:
                        port = int(port_str)
                    except ValueError:
                        port = 443
                else:
                    host_str = target.strip("[]")
                    port = 443
            elif ":" in target:
                host_str, port_str = target.rsplit(":", 1)
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
            _log_stat(proxy_user, host_str, port, "blocked_whitelist")
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
        _conn_key = id(client_writer)
        _conn_start(_conn_key, proxy_user, host_str, port)

        # Open upstream connection
        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(host_str, port),
                timeout=12.0
            )
        except Exception as e:
            logger.warning(f"Failed to connect to remote host {host_str}:{port}: {e}")
            _log_stat(proxy_user, host_str, port, "error")
            client_writer.write(
                b"HTTP/1.1 502 Bad Gateway\r\n"
                b"Connection: close\r\n"
                b"Content-Length: 17\r\n\r\n"
                b"Connection failed\r\n"
            )
            await client_writer.drain()
            client_writer.close()
            return

        _set_tcp_keepalive(remote_writer)

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
        # Bidirectional relay with clean cancellation on first completion
        t1 = asyncio.create_task(pipe(client_reader, remote_writer, proxy_user=proxy_user, is_throttled=is_throttled,
                 stat_key=_conn_key, direction="bytes_in"))
        t2 = asyncio.create_task(pipe(remote_reader, client_writer, proxy_user=proxy_user, is_throttled=is_throttled,
                 stat_key=_conn_key, direction="bytes_out"))

        done, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        for p in pending:
            p.cancel()
        await asyncio.gather(t1, t2, return_exceptions=True)

        # Соединение закрыто — фиксируем итог
        _conn_finish(_conn_key, "allowed")

    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        logger.error(f"Handler error for {client_ip}: {e}")
    finally:
        with _conn_lock:
            if _conn_key in _conn_stats:
                _conn_finish(_conn_key, "closed_error")
        try:
            client_writer.close()
            await client_writer.wait_closed()
        except Exception:
            pass


async def main():
    load_user_traffic()
    asyncio.create_task(traffic_persist_loop())

    if STATS is not None:
        try:
            STATS.start()
        except Exception as _e:
            logger.warning(f"Failed to start stats collector: {_e}")

    server = await asyncio.start_server(
        handle_client,
        LISTEN_HOST,
        LISTEN_PORT,
        backlog=512,
        reuse_address=True
    )
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    logger.info(f"Antigravity Proxy Core running on {addrs}")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Proxy Core stopped by user.")
    finally:
        save_user_traffic()
        if STATS is not None:
            try:
                STATS.stop()
            except Exception:
                pass
