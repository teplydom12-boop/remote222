import base64
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from remote222.actions import MAX_FILE
from remote222.agent import AgentServer, MAX_BODY, prepare_state
from remote222.client import Client, ClientError, normalize_url


@contextmanager
def running_agent(state, token):
    server = AgentServer(0, state, token)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / "state"
        self.token = prepare_state(self.state)
        self.context = running_agent(self.state, self.token)
        self.server, self.url = self.context.__enter__()
        self.addCleanup(self.context.__exit__, None, None, None)
        self.client = Client(self.url, self.token)

    def action(self, name, args, request_id=None):
        return self.client.action(name, args, request_id)

    def test_authenticated_info_and_bad_key(self):
        result = self.client.info()
        self.assertTrue(result["ok"])
        self.assertIn("shell", result["result"]["capabilities"])
        with self.assertRaisesRegex(ClientError, "HTTP 401"):
            Client(self.url, "wrong-key").info()

    def test_unauthorized_action_has_no_side_effect(self):
        path = Path(self.temp.name) / "unauthorized.txt"
        with self.assertRaisesRegex(ClientError, "HTTP 401"):
            Client(self.url, "wrong-key").action("write", {
                "path": str(path), "data_base64": "aGk="})
        self.assertFalse(path.exists())
        self.assertEqual(self.server.store.lookup("unauthorized"), None)

    def test_browser_origin_rejected(self):
        req = urllib.request.Request(self.url + "/v1/info", headers={
            "Authorization": "Bearer " + self.token, "Origin": "https://example.com"})
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(req)
        self.assertEqual(caught.exception.code, 403)

    def test_file_roundtrip_overwrite_and_list(self):
        path = Path(self.temp.name) / "данные.txt"
        content = "Проверка UTF-8 🌍".encode()
        params = {"path": str(path), "data_base64": base64.b64encode(content).decode()}
        self.assertTrue(self.action("write", params)["ok"])
        self.assertFalse(self.action("write", params)["ok"])
        self.assertTrue(self.action("write", {**params, "overwrite": True})["ok"])
        result = self.action("read", {"path": str(path)})
        self.assertEqual(base64.b64decode(result["result"]["data_base64"]), content)
        result = self.action("list", {"path": self.temp.name})
        self.assertIn(path.name, [item["name"] for item in result["result"]["entries"]])

    def test_duplicate_id_does_not_repeat_write(self):
        path = Path(self.temp.name) / "once.txt"
        params = {"path": str(path), "data_base64": "Zmlyc3Q=", "overwrite": True}
        first = self.action("write", params, "unique-request-123")
        path.write_text("changed-locally")
        second = self.action("write", params, "unique-request-123")
        self.assertEqual(first, second)
        self.assertEqual(path.read_text(), "changed-locally")
        with self.assertRaisesRegex(ClientError, "id_conflict"):
            self.action("info", {}, "unique-request-123")

    def test_restart_preserves_duplicate_protection(self):
        path = Path(self.temp.name) / "persisted.txt"
        params = {"path": str(path), "data_base64": "aGk="}
        first = self.action("write", params, "persist-request-123")
        with running_agent(self.state, self.token) as (_, url):
            replay = Client(url, self.token).action("write", params, "persist-request-123")
        self.assertEqual(first, replay)

    def test_interrupted_request_is_not_reexecuted(self):
        fingerprint = hashlib.sha256(json.dumps(["info", {}], sort_keys=True).encode()).hexdigest()
        self.server.store.reserve("interrupted-123", fingerprint)
        with self.assertRaisesRegex(ClientError, "outcome_unknown"):
            self.action("info", {}, "interrupted-123")

    def test_expired_results_preserve_request_ids(self):
        for index in range(101):
            self.server.store.reserve(f"request-{index}", "fingerprint")
            self.server.store.complete(f"request-{index}", '{"ok":true}')
        old = self.server.store.lookup("request-0")
        self.assertEqual(json.loads(old[1])["error"], "result_expired")
        self.assertTrue(json.loads(self.server.store.lookup("request-100")[1])["ok"])

    def test_shell_execution_exit_status_and_timeout(self):
        command = "Write-Output 'remote222'; exit 7" if os.name == "nt" else "printf remote222; exit 7"
        result = self.action("shell", {"command": command})["result"]
        self.assertEqual(result["exit_code"], 7)
        self.assertIn("remote222", result["stdout"])
        command = "Start-Sleep -Seconds 10" if os.name == "nt" else "sleep 10"
        result = self.action("shell", {"command": command, "timeout": 1})["result"]
        self.assertTrue(result["timed_out"])
        self.assertNotEqual(result["exit_code"], 0)

    def test_open_launches_a_real_process(self):
        path = Path(self.temp.name) / "launched.txt"
        script = "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('started')"
        result = self.action("open", {"target": sys.executable, "arguments": ["-c", script, str(path)]})
        self.assertTrue(result["ok"])
        for _ in range(50):
            if path.exists():
                break
            threading.Event().wait(0.05)
        self.assertEqual(path.read_text(), "started")

    def test_busy_response_and_info_stays_available(self):
        with self.server.action_lock:
            with self.assertRaisesRegex(ClientError, "agent_busy"):
                self.action("info", {})
            self.assertTrue(self.client.info()["ok"])

    def test_bad_action_and_arguments(self):
        self.assertFalse(self.action("missing", {})["ok"])
        self.assertFalse(self.action("shell", {"command": "echo hi", "timeout": -1})["ok"])
        self.assertFalse(self.action("write", {"path": "x", "data_base64": "?"})["ok"])

    def test_request_size_limit_and_malformed_json(self):
        headers = {"Authorization": "Bearer " + self.token, "Content-Type": "application/json"}
        req = urllib.request.Request(self.url + "/v1/actions", data=b"{}", headers={
            **headers, "Content-Length": str(MAX_BODY + 1)})
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(req)
        self.assertEqual(caught.exception.code, 413)
        req = urllib.request.Request(self.url + "/v1/actions", data=b"broken", headers=headers)
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(req)
        self.assertEqual(caught.exception.code, 400)

    def test_large_file_rejected(self):
        path = Path(self.temp.name) / "large.bin"
        path.write_bytes(b"x" * (MAX_FILE + 1))
        result = self.action("read", {"path": str(path)})
        self.assertFalse(result["ok"])
        self.assertIn("1 MiB", result["message"])

    def test_cli_nonzero_status_and_file_download(self):
        env = {**os.environ, "REMOTE222_URL": self.url, "REMOTE222_TOKEN": self.token}
        result = subprocess.run([sys.executable, "-m", "remote222.client", "shell", "exit 9"],
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["result"]["exit_code"], 9)
        source = Path(self.temp.name) / "source.txt"
        target = Path(self.temp.name) / "target.txt"
        source.write_bytes(b"download test")
        result = subprocess.run([sys.executable, "-m", "remote222.client", "read", str(source),
                                 "--output", str(target)], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(target.read_bytes(), b"download test")

    def test_audit_contains_no_token_or_command_body(self):
        command = "Write-Output 'private-test-content'" if os.name == "nt" else "printf private-test-content"
        self.action("shell", {"command": command}, "audit-request-123")
        log = (self.state / "audit.log").read_text()
        self.assertIn("audit-request-123", log)
        self.assertNotIn(self.token, log)
        self.assertNotIn("private-test-content", log)

    @unittest.skipIf(os.name == "nt", "Linux-specific desktop capability check")
    def test_windows_action_reports_platform_requirement(self):
        result = self.action("screenshot", {})
        self.assertFalse(result["ok"])
        self.assertIn("Windows", result["message"])


class TransportTests(unittest.TestCase):
    def test_https_required_and_url_ambiguity_rejected(self):
        for url in ["http://example.com", "https://user:pass@example.com", "https://example.com/path", "https://example.com?token=foo", "file:///tmp/agent", "https://example.com:bad"]:
            with self.subTest(url=url), self.assertRaises(ClientError):
                normalize_url(url)
        self.assertEqual(normalize_url("https://example.com/"), "https://example.com")
        self.assertEqual(normalize_url("http://127.0.0.1:8765"), "http://127.0.0.1:8765")

    def test_redirect_does_not_forward_bearer(self):
        received = []

        class Receiver(BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        receiver = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)

        class Redirect(Receiver):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{receiver.server_port}/stolen")
                self.end_headers()

        redirect = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
        for server in (receiver, redirect):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with self.assertRaisesRegex(ClientError, "Redirect refused"):
                Client(f"http://127.0.0.1:{redirect.server_port}", "test-secret").info()
            self.assertEqual(received, [])
        finally:
            for server in (receiver, redirect):
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
