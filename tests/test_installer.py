"""Regression checks for credential issuance; no root, apt or systemd required."""
import base64
import http.server
import os
import pathlib
import shlex
import subprocess
import tempfile
import threading
import unittest
import urllib.parse


SOURCE = (pathlib.Path(__file__).resolve().parents[1] / "install.sh").read_text()
CREDENTIALS = "# Reuse installed credentials" + SOURCE.split(
    "# Reuse installed credentials", 1
)[1].split("# Copy proxy.py", 1)[0]
ACTIVATION = SOURCE.split("systemctl daemon-reload\n", 1)[1].split(
    'echo -e "\\n${GREEN}====================================================', 1
)[0]
DISPLAY = SOURCE.split('echo -e "\\n${GREEN}====================================================', 1)[1]
DISPLAY = 'echo -e "\\n${GREEN}====================================================' + DISPLAY


def values(path):
    result = {}
    if path.exists():
        for line in path.read_text().splitlines():
            key, _, value = line.partition("=")
            result[key] = shlex.split(value)[0]
    return result


class InstallerCredentials(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        self.config = self.root / "config.env"
        self.active = self.root / "active.env"
        self.calls = self.root / "systemctl.calls"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        systemctl = self.bin / "systemctl"
        systemctl.write_text(
            '#!/usr/bin/env bash\n'
            'printf "%s\\n" "$*" >> "$TEST_CALLS"\n'
            'if [ "$*" = "restart antigravity-proxy.service" ]; then\n'
            '  if [ "${TEST_SKIP_RESTART:-0}" != 1 ]; then\n'
            '    cp "$CONF_DIR/config.env" "$TEST_ACTIVE"\n'
            '  fi\n'
            'fi\n'
        )
        systemctl.chmod(0o755)
        active = self.active

        class Gateway(http.server.BaseHTTPRequestHandler):
            def do_CONNECT(self):
                credentials = values(active)
                expected = base64.b64encode(
                    (credentials.get("PROXY_USER", "") + ":" + credentials.get("PROXY_PASS", "")).encode()
                ).decode()
                authorized = self.headers.get("Proxy-Authorization") == "Basic " + expected
                body = b"Access Denied: unauthorized host" if authorized else b"Invalid credentials."
                self.send_response(403 if authorized else 407)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.gateway = http.server.HTTPServer(("127.0.0.1", 0), Gateway)
        thread = threading.Thread(target=self.gateway.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.gateway.server_close)
        self.addCleanup(self.gateway.shutdown)

    def run_install(self, user=None, password=None, skip_restart=False):
        environment = os.environ.copy()
        for key in ("PROXY_USER", "PROXY_PASS"):
            environment.pop(key, None)
        environment.update(
            CONF_DIR=str(self.root),
            TEST_ACTIVE=str(self.active),
            TEST_CALLS=str(self.calls),
            TEST_SKIP_RESTART="1" if skip_restart else "0",
            PATH=str(self.bin) + os.pathsep + environment["PATH"],
            SERVER_IP="177.3.218.239",
            GREEN="", BLUE="", YELLOW="", RED="", NC="",
        )
        if user is not None:
            environment["PROXY_USER"] = user
        if password is not None:
            environment["PROXY_PASS"] = password
        activation = ACTIVATION.replace('"127.0.0.1", 50127', '"127.0.0.1", ' + str(self.gateway.server_port))
        return subprocess.run(
            ["bash", "-c", "set -e\n" + CREDENTIALS + activation + DISPLAY],
            env=environment, capture_output=True, text=True, timeout=15,
        )

    def assert_issued(self, result, user, password):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Login:    " + user, result.stdout)
        self.assertIn("Password: " + password, result.stdout)
        url = next(line for line in result.stdout.splitlines() if line.startswith("https://"))
        parsed = urllib.parse.urlsplit(url)
        self.assertEqual(urllib.parse.unquote(parsed.username), user)
        self.assertEqual(urllib.parse.unquote(parsed.password), password)
        self.assertEqual(parsed.hostname, "177.3.218.239")
        self.assertEqual(parsed.port, 50128)
        self.assertEqual(values(self.active)["PROXY_PASS"], password)

    def test_fresh_install_issues_saved_password(self):
        result = self.run_install()
        saved = values(self.config)
        self.assert_issued(result, "ag_user", saved["PROXY_PASS"])
        self.assertEqual(len(saved["PROXY_PASS"]), 24)
        self.assertRegex(saved["PROXY_PASS"], "^[0-9a-f]{24}$")

    def test_reinstall_preserves_existing_credentials(self):
        self.config.write_text("PROXY_USER=existing_user\nPROXY_PASS=ExistingPassword12345678\n")
        self.active.write_text(self.config.read_text())
        result = self.run_install()
        self.assert_issued(result, "existing_user", "ExistingPassword12345678")

    def test_explicit_rotation_restarts_running_proxy(self):
        self.config.write_text("PROXY_USER=ag_user\nPROXY_PASS=old_password\n")
        self.active.write_text(self.config.read_text())
        result = self.run_install(password="new_password")
        self.assert_issued(result, "ag_user", "new_password")
        self.assertEqual(self.calls.read_text().splitlines(), [
            "enable antigravity-proxy.service",
            "restart antigravity-proxy.service",
            "restart haproxy",
        ])

    def test_special_characters_survive_config_display_and_url(self):
        user, password = "ag user@/名", 'P@ss:#%/ ?\\"$`'
        self.assert_issued(self.run_install(user, password), user, password)
        self.assert_issued(self.run_install(), user, password)

    def test_stale_running_password_prevents_success_output(self):
        self.active.write_text("PROXY_USER=ag_user\nPROXY_PASS=old_password\n")
        result = self.run_install(password="new_password", skip_restart=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("credentials were rejected", result.stderr)
        self.assertNotIn("Successfully Installed", result.stdout)
        self.assertNotIn("Connection String", result.stdout)

    def test_invalid_basic_login_is_rejected_before_config_write(self):
        result = self.run_install(user="invalid:user", password="some_password")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.config.exists())
        self.assertFalse(self.calls.exists())


if __name__ == "__main__":
    unittest.main()
