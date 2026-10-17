from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from remote222.auth_client import AuthClient, AuthConnectionError, SessionStore
from remote222.broker import BrokerServer
from remote222.client import Client, ClientError, main, normalize_url
from remote222.relay import RelayClient


class AccountClientTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.server = BrokerServer(0, self.root / "broker", "c" * 43, "w" * 43)
        self.username, self.password = "test-owner", "private-account-password"
        self.server.accounts.set_account(self.username, self.password)
        self.thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.01), daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.store = SessionStore(self.root / "private" / "controller.json")

    def close_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)

    def login(self, role="controller"):
        return AuthClient(self.url).login(self.username, self.password, role)

    def cli(self, args, **environment):
        out, err = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, environment), redirect_stdout(out), redirect_stderr(err):
            status = main(args)
        return status, out.getvalue(), err.getvalue()

    def test_login_private_storage_and_logout(self):
        response = self.login()
        profile = self.store.save(self.url + "/", {**response, "password": self.password})
        self.assertEqual(self.store.load(expected_url=self.url), profile)
        self.assertNotIn(self.password, self.store.path.read_text())
        self.assertNotIn("password", profile)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(self.store.path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(self.store.path.parent.stat().st_mode), 0o700)
        self.assertTrue(RelayClient(profile["url"], profile["session_token"]).status()["ok"])
        auth = AuthClient(profile["url"], profile["session_token"])
        self.assertEqual(auth.session()["role"], "controller")
        auth.logout()
        with self.assertRaisesRegex(ClientError, "unauthorized"):
            AuthClient(self.url, profile["session_token"]).session()

    def test_expired_or_wrong_role_profile_never_reaches_network(self):
        self.store.save(self.url, self.login("worker"))
        with patch("urllib.request.OpenerDirector.open") as opened:
            code, _, err = self.cli(["--session-file", str(self.store.path), "info"])
            self.assertEqual(code, 1)
            self.assertIn("role", err)
            opened.assert_not_called()
        response = self.login()
        self.store.save(self.url, response)
        data = json.loads(self.store.path.read_text())
        data["expires_at"] = time.time() - 1
        self.store.path.write_text(json.dumps(data))
        with patch("urllib.request.OpenerDirector.open") as opened:
            code, _, err = self.cli(["--session-file", str(self.store.path), "info"], REMOTE222_TOKEN="stale")
            self.assertEqual(code, 1)
            self.assertIn("expired", err)
            opened.assert_not_called()

    def test_canonical_url_mismatch_does_not_forward_session(self):
        self.store.save(self.url, self.login())
        with patch("urllib.request.OpenerDirector.open") as opened:
            code, _, err = self.cli(["--url", "https://other.example", "--session-file", str(self.store.path), "info"])
            self.assertEqual(code, 1)
            self.assertIn("different server", err)
            opened.assert_not_called()
        self.assertEqual(normalize_url("https://EXAMPLE.com:443/"), "https://example.com")
        self.assertNotEqual(normalize_url("https://example.com:8443"), normalize_url("https://example.com"))

    def test_explicit_and_default_profiles_ignore_all_stale_environment_settings(self):
        self.store.save(self.url, self.login())
        for flags in (["--session-file", str(self.store.path)], []):
            with self.subTest(flags=flags), patch("remote222.auth_client.default_session_path", return_value=self.store.path), \
                    patch.object(RelayClient, "info", RelayClient.status):
                code, out, err = self.cli([*flags, "info"], REMOTE222_URL="https://wrong.example",
                                          REMOTE222_TOKEN="wrong-old-token", REMOTE222_TRANSPORT="direct")
                self.assertEqual(code, 0, err)
                self.assertTrue(json.loads(out)["ok"])
                self.assertFalse(json.loads(out)["online"])

    def test_cli_relay_info_uses_explicit_request_id(self):
        self.store.save(self.url, self.login())
        request_id = "repeat-info-request-123"
        code, out, err = self.cli(["--session-file", str(self.store.path),
                                   "--request-id", request_id, "info"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out), {"ok": False, "id": request_id, "error": "worker_offline"})
        self.assertIn(f"Request ID: {request_id}", err)

    def test_cli_direct_info_keeps_get_endpoint_with_request_id(self):
        client = Client(self.url, "unused-fixture-credential")
        with patch("remote222.client._operation_client", return_value=client), \
                patch.object(client, "request", return_value={"ok": True, "result": {}}) as request:
            code, _, err = self.cli(["--request-id", "direct-info-request-123", "info"])
        self.assertEqual(code, 0, err)
        request.assert_called_once_with("/v1/info")

    def test_device_connect_recovers_lost_success_and_does_not_print_credentials(self):
        original_start, original_poll = AuthClient.device_start, AuthClient.device_poll
        captured, polls = {}, []

        def start(auth, label):
            result = original_start(auth, label)
            captured.update(result)
            self.server.accounts.approve_device(result["user_code"], self.username, self.password,
                                                self.server.accounts.browser_challenge())
            return {**result, "interval": 0.1}

        def poll(auth, code, **kwargs):
            result = original_poll(auth, code, **kwargs)
            polls.append(code)
            if len(polls) == 1:
                raise AuthConnectionError("Account connection failed")
            return result

        with patch.object(AuthClient, "device_start", start), patch.object(AuthClient, "device_poll", poll):
            status, out, err = self.cli(["--url", self.url, "--session-file", str(self.store.path), "connect"])
        self.assertEqual(status, 0, err)
        self.assertEqual(polls, [captured["device_code"], captured["device_code"]])
        profile = self.store.load()
        self.assertIn(self.url + "/connect", out)
        self.assertIn(captured["user_code"], out)
        for secret in (profile["session_token"], captured["device_code"], self.password):
            self.assertNotIn(secret, out + err)
        self.assertTrue(RelayClient(self.url, profile["session_token"]).status()["ok"])

    def test_device_expiry_does_not_save_or_restart_pairing(self):
        original = AuthClient.device_start

        def start(auth, label):
            return {**original(auth, label), "interval": 0.1, "expires_in": 0.05}

        with patch.object(AuthClient, "device_start", start), patch.object(AuthClient, "device_poll") as poll:
            code, _, err = self.cli(["--url", self.url, "--session-file", str(self.store.path), "connect"])
            poll.assert_not_called()
        self.assertEqual(code, 1)
        self.assertIn("expired", err)
        self.assertFalse(self.store.path.exists())

    def test_session_command_only_prints_public_metadata_and_logout_revokes(self):
        profile = self.store.save(self.url, self.login())
        code, out, err = self.cli(["--session-file", str(self.store.path), "session"])
        self.assertEqual(code, 0, err)
        self.assertNotIn(profile["session_token"], out + err)
        self.assertEqual(set(json.loads(out)), {"ok", "url", "role", "expires_at"})
        code, _, err = self.cli(["--session-file", str(self.store.path), "logout"])
        self.assertEqual(code, 0, err)
        self.assertFalse(self.store.path.exists())
        with self.assertRaisesRegex(ClientError, "unauthorized"):
            AuthClient(self.url, profile["session_token"]).session()

    @unittest.skipIf(os.name == "nt", "POSIX permissions and unprivileged symlink tests")
    def test_permissions_and_symbolic_links_are_rejected(self):
        response = self.login()
        self.store.save(self.url, response)
        self.store.path.chmod(0o644)
        with self.assertRaisesRegex(ClientError, "0600"):
            self.store.load()
        self.store.path.chmod(0o600)
        self.store.path.parent.chmod(0o755)
        with self.assertRaisesRegex(ClientError, "0700"):
            self.store.load()
        self.store.path.parent.chmod(0o700)
        link = self.root / "linked"
        link.symlink_to(self.store.path.parent, target_is_directory=True)
        for operation in (lambda: SessionStore(link / "controller.json").load(),
                          lambda: SessionStore(link / "new.json").save(self.url, response),
                          lambda: SessionStore(link / "controller.json").delete()):
            with self.assertRaisesRegex(ClientError, "symbolic"):
                operation()
        self.assertTrue(self.store.path.exists())

    def test_module_cli_reports_session_failure_without_traceback(self):
        result = subprocess.run([sys.executable, "-m", "remote222.client", "--session-file",
                                 str(self.store.path), "info"], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertIn("connect first", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


class AccountTransportTests(unittest.TestCase):
    def test_redirect_and_reflected_error_do_not_expose_password(self):
        received = []
        reflected = "test-password-reflected-by-server"

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(self.path)
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                if self.server.redirect:
                    self.send_response(307)
                    self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/stolen")
                    self.end_headers()
                else:
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": reflected}).encode())

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for redirect in (True, False):
                server.redirect = redirect
                with self.assertRaises(ClientError) as result:
                    AuthClient(f"http://127.0.0.1:{server.server_port}").login("owner", reflected)
                self.assertNotIn(reflected, str(result.exception))
                self.assertNotIn("/stolen", received)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(3)

    def test_malformed_session_roles_and_tokens_have_safe_errors(self):
        auth = AuthClient("https://example.com")
        for overrides in ({"role": []}, {"session_token": []}, {"expires_at": float("nan")}):
            payload = {"ok": True, "role": "worker", "session_token": "a" * 43,
                       "expires_at": time.time() + 3600, **overrides}
            with self.subTest(fields=list(overrides)), patch.object(auth, "_request", return_value=payload), self.assertRaises(ClientError):
                auth.login("owner", "example-password")


if __name__ == "__main__":
    unittest.main()
