import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from remote222.browser import (BrowserController, BrowserState, MAX_ARTIFACT,
                               _helper_command, _shell_json)
from remote222.client import ClientError


def shell_response(result):
    return {"ok": True, "result": {"exit_code": 0, "timed_out": False, "truncated": False,
                                    "stdout": json.dumps({"ok": True, "result": result}), "stderr": ""}}


def helper_request(command):
    match = re.search(r"-RequestBase64 '([A-Za-z0-9+/=]+)'$", command)
    if not match:
        raise AssertionError("Missing helper request")
    return json.loads(base64.b64decode(match[1]))


class FakeRelay:
    url = "https://broker.example"

    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def action(self, action, args, request_id):
        self.calls.append((action, args, request_id))
        return self.handler(action, args, request_id)


class BrowserTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.store = BrowserState(self.root / "private" / "browser.json")
        self.state = {"version": 1, "broker_url": "https://broker.example", "expected_hostname": "TEST-PC",
                      "helper_path": r"C:\Users\Owner\AppData\Local\Remote222\tools\Browser-Control.test.ps1",
                      "helper_sha256": "a" * 64, "chrome_path": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                      "profile_directory": r"C:\Users\Owner\AppData\Local\Remote222\ChromeAutomation",
                      "target_id": "FIRST-TARGET", "installed": True, "requests": {}}
        self.store.save(self.state)

    def test_uncertain_retry_keeps_original_target_command_and_request_id(self):
        expression = "document.title + 'private-expression'"

        def run(action, args, request_id):
            self.assertEqual(self.store.load()["last_request_id"], request_id)
            self.assertIn(request_id, self.store.load()["requests"])
            if len(relay.calls) == 1:
                raise ClientError("Connection failed; execution may already have occurred")
            request = helper_request(args["command"])
            return shell_response({"target_id": request["target_id"], "value": "first page"})

        relay = FakeRelay(run)
        controller = BrowserController(relay, self.store)
        with self.assertRaisesRegex(ClientError, "execution may"):
            controller.execute("evaluate", "browser-retry-123", {"expression": expression})
        changed = self.store.load()
        changed["target_id"] = "SECOND-TARGET"
        self.store.save(changed)
        result = controller.execute("evaluate", "browser-retry-123", {"expression": expression})
        self.assertEqual(result["target_id"], "FIRST-TARGET")
        self.assertEqual(relay.calls[0], relay.calls[1])
        self.assertNotIn(expression, self.store.path.read_text())
        with self.assertRaisesRegex(ClientError, "different operation"):
            controller.execute("evaluate", "browser-retry-123", {"expression": "document.URL"})
        self.assertEqual(len(relay.calls), 2)

    def test_open_reuses_saved_target_and_tracks_returned_target(self):
        def run(action, args, request_id):
            request = helper_request(args["command"])
            self.assertEqual(request["target_id"], "FIRST-TARGET")
            self.assertEqual(request["url"], "https://www.1688.com/")
            self.assertEqual(request["operation"], "open")
            return shell_response({"target_id": "NEW-TARGET", "url": request["url"], "title": "Page"})

        relay = FakeRelay(run)
        controller = BrowserController(relay, self.store)
        result = controller.execute("open", "browser-open-123", {"url": "https://www.1688.com/"})
        self.assertEqual(result["target_id"], "NEW-TARGET")
        self.assertEqual(self.store.load()["target_id"], "NEW-TARGET")
        controller.execute("open", "browser-open-123", {"url": "https://www.1688.com/"})
        self.assertEqual(relay.calls[0], relay.calls[1])

    def test_server_binding_and_changed_configuration_fail_before_network(self):
        relay = FakeRelay(lambda *_: shell_response({"running": True}))
        relay.url = "https://different.example"
        controller = BrowserController(relay, self.store)
        with self.assertRaisesRegex(ClientError, "different account server"):
            controller.execute("status", "browser-status-123", {})
        self.assertEqual(relay.calls, [])
        relay.url = self.state["broker_url"]
        controller.execute("status", "browser-status-123", {})
        changed = self.store.load()
        changed["profile_directory"] += "-different"
        self.store.save(changed)
        with self.assertRaisesRegex(ClientError, "different operation"):
            controller.execute("status", "browser-status-123", {})
        self.assertEqual(len(relay.calls), 1)

    def test_verified_html_download_and_same_id_recovery(self):
        content = "<!doctype html><html><body>真实页面</body></html>".encode("utf-8")
        compressed = gzip.compress(content)
        artifact = {"gzip_path": r"C:\Users\Owner\Downloads\Remote222\page.html.gz",
                    "gzip_bytes": len(compressed), "html_bytes": len(content),
                    "gzip_sha256": hashlib.sha256(compressed).hexdigest(),
                    "html_sha256": hashlib.sha256(content).hexdigest()}
        relay = FakeRelay(lambda *_: {"ok": True, "result": {"data_base64": base64.b64encode(compressed).decode()}})
        controller = BrowserController(relay, self.store)
        output = self.root / "page.html"
        first = controller.download(artifact, "browser-save-123", output)
        self.assertEqual(output.read_bytes(), content)
        self.assertEqual(first["sha256"], artifact["html_sha256"])
        controller.download(artifact, "browser-save-123", output)
        self.assertEqual(relay.calls[0], relay.calls[1])
        output.write_text("unrelated file")
        with self.assertRaisesRegex(ClientError, "different content"):
            controller.download(artifact, "browser-save-123", output)
        self.assertEqual(output.read_text(), "unrelated file")

    def test_corrupt_oversized_and_decompression_bomb_artifacts_are_rejected(self):
        content = b"x" * 100
        compressed = gzip.compress(content)
        artifact = {"gzip_path": r"C:\page.html.gz", "gzip_bytes": len(compressed), "html_bytes": len(content),
                    "gzip_sha256": hashlib.sha256(compressed).hexdigest(), "html_sha256": hashlib.sha256(content).hexdigest()}
        relay = FakeRelay(lambda *_: {"ok": True, "result": {"data_base64": base64.b64encode(compressed).decode()}})
        controller = BrowserController(relay, self.store)
        output = self.root / "never.html"
        with self.assertRaisesRegex(ClientError, "transfer size"):
            controller.download({**artifact, "gzip_bytes": MAX_ARTIFACT + 1}, "browser-save-123", output)
        self.assertEqual(relay.calls, [])
        with self.assertRaisesRegex(ClientError, "SHA256"):
            controller.download({**artifact, "gzip_sha256": "0" * 64}, "browser-save-123", output)
        with patch("remote222.browser.MAX_HTML", 64), self.assertRaisesRegex(ClientError, "oversized"):
            controller.download({**artifact, "html_bytes": 60}, "browser-save-123", output)
        self.assertFalse(output.exists())

    def test_save_url_is_one_helper_operation_plus_one_download(self):
        content = b"<html>captured browser DOM</html>"
        compressed = gzip.compress(content)
        artifact = {"target_id": "CAPTURED-TARGET", "gzip_path": r"C:\page.html.gz", "gzip_bytes": len(compressed),
                    "html_bytes": len(content), "gzip_sha256": hashlib.sha256(compressed).hexdigest(),
                    "html_sha256": hashlib.sha256(content).hexdigest()}

        def run(action, args, request_id):
            if action == "shell":
                request = helper_request(args["command"])
                self.assertEqual(request["target_id"], "FIRST-TARGET")
                self.assertEqual(request["operation"], "save_html")
                self.assertEqual(request["url"], "https://www.1688.com/")
                return shell_response(artifact)
            return {"ok": True, "result": {"data_base64": base64.b64encode(compressed).decode()}}

        relay = FakeRelay(run)
        controller = BrowserController(relay, self.store)
        result = controller.execute("save_html", "browser-save-123",
            {"url": "https://www.1688.com/", "wait_ms": 1500}, output=self.root / "saved.html")
        self.assertEqual([call[0] for call in relay.calls], ["shell", "read"])
        self.assertEqual(Path(result["saved_to"]).read_bytes(), content)
        changed = self.store.load()
        changed["target_id"] = "OTHER-TARGET"
        self.store.save(changed)
        controller.execute("save_html", "browser-save-123", {"url": "https://www.1688.com/", "wait_ms": 1500},
                           output=self.root / "saved.html")
        self.assertEqual(relay.calls[:2], relay.calls[2:])

    def test_install_uploads_hash_named_helper_and_reuses_subrequest_ids(self):
        self.store.path.unlink()
        helper = self.root / "helper.ps1"
        helper.write_text("param($RequestBase64)\n# local test helper\n")
        digest = hashlib.sha256(helper.read_bytes()).hexdigest()
        remote = r"C:\Users\Owner\AppData\Local\Remote222\tools\Browser-Control." + digest + ".ps1"

        def run(action, args, request_id):
            self.assertTrue(self.store.load()["last_request_id"].startswith("browser-install"))
            if action == "write":
                self.assertEqual(args["path"], remote)
                self.assertNotIn("overwrite", args)
                self.assertEqual(hashlib.sha256(base64.b64decode(args["data_base64"])).hexdigest(), digest)
                return {"ok": True, "result": {"bytes_written": len(helper.read_bytes())}}
            if "-RequestBase64" in args["command"]:
                self.assertEqual(helper_request(args["command"])["operation"], "system")
                return shell_response({"chrome_path": self.state["chrome_path"],
                                       "default_profile_directory": self.state["profile_directory"]})
            return shell_response({"helper_path": remote, "installed": False})

        relay = FakeRelay(run)
        controller = BrowserController(relay, self.store)
        result = controller.install("browser-install-123", "TEST-PC", helper_path=helper)
        self.assertTrue(result["installed"])
        self.assertEqual(self.store.load()["helper_sha256"], digest)
        controller.install("browser-install-123", "TEST-PC", helper_path=helper)
        self.assertEqual(relay.calls[:3], relay.calls[3:])
        changed = self.store.load()
        changed["target_id"] = "OLD-PROFILE-TARGET"
        self.store.save(changed)
        controller.install("browser-install-456", "TEST-PC", helper_path=helper,
                           profile_directory=self.state["profile_directory"] + "-different")
        self.assertNotIn("target_id", self.store.load())
        if os.name != "nt":
            self.assertEqual(self.store.path.stat().st_mode & 0o777, 0o600)

    def test_invalid_shell_output_is_not_echoed_and_wrapper_hashes_executed_bytes(self):
        secret = "do-not-echo-invocation-content"
        response = {"ok": True, "result": {"exit_code": 1, "stdout": secret, "stderr": secret,
                                             "timed_out": False, "truncated": False}}
        with self.assertRaises(ClientError) as error:
            _shell_json(response)
        self.assertNotIn(secret, str(error.exception))
        command = _helper_command(self.state, {"operation": "status"})
        self.assertIn("MachineName", command)
        self.assertIn("ComputeHash($bytes)", command)
        self.assertIn("UTF8.GetString($bytes)", command)
        self.assertNotIn("ExecutionPolicy", command)

    @unittest.skipIf(os.name == "nt", "POSIX path permissions")
    def test_private_state_rejects_symlinks_and_broad_permissions(self):
        self.store.path.chmod(0o644)
        with self.assertRaisesRegex(ClientError, "0600"):
            self.store.load()
        self.store.path.chmod(0o600)
        link = self.root / "linked"
        link.symlink_to(self.store.path.parent, target_is_directory=True)
        with self.assertRaisesRegex(ClientError, "symbolic"):
            BrowserState(link / "browser.json").load()


if __name__ == "__main__":
    unittest.main()
