import os
from pathlib import Path
import queue
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from remote222.client import Client
from remote222.session import Session, StateLock, bundled_tunnel


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.state = self.directory / "state"
        self.events = queue.Queue()
        self.fake = self.directory / "fake_tunnel.py"
        self.fake.write_text("import time\nprint('https://session-test.trycloudflare.com', flush=True)\ntime.sleep(60)\n")
        self.session = None
        self.addCleanup(self.stop_session)

    def stop_session(self):
        if self.session:
            self.session.stop()
            self.session.join(10)

    def start(self, probe=None, timeout=5):
        def local_probe(url, token):
            self.assertEqual(url, "https://session-test.trycloudflare.com")
            address = f"http://127.0.0.1:{self.session.server.server_port}"
            return Client(address, token).info()
        self.session = Session(self.state, lambda event, data: self.events.put((event, data)),
                               tunnel_command=[sys.executable, str(self.fake)],
                               probe=probe or local_probe, startup_timeout=timeout)
        self.session.start()

    def wait_for(self, kind):
        for _ in range(20):
            event, data = self.events.get(timeout=10)
            if event == kind:
                return data
            if event == "error" and kind != "error":
                self.fail(data)
        self.fail(f"No {kind} event")

    def test_ready_requires_live_agent_and_stop_closes_tunnel(self):
        self.start()
        self.assertEqual(self.wait_for("ready"), "https://session-test.trycloudflare.com")
        server = self.session.server
        client = Client(f"http://127.0.0.1:{server.server_port}", self.session.token)
        self.assertEqual(client.info()["result"]["pid"], os.getpid())
        self.session.stop()
        self.wait_for("stopped")
        self.session.join(10)
        self.assertFalse(self.session.thread.is_alive())
        self.assertIsNotNone(self.session.process.poll())
        self.assertEqual(server.fileno(), -1)
        self.assertIsNone(self.session.url)
        self.assertNotIn(self.session.token, (self.state / "tunnel.log").read_text())

    def test_wrong_remote_instance_is_never_ready(self):
        self.start(probe=lambda url, token: {"ok": True, "result": {"pid": -1}}, timeout=0.5)
        self.assertIn("Подключение не установлено", self.wait_for("error"))
        self.wait_for("stopped")
        self.assertIsNone(self.session.url)

    def test_tunnel_exit_is_reported_and_agent_stopped(self):
        self.fake.write_text("raise SystemExit(7)\n")
        self.start()
        self.assertIn("Туннель остановился", self.wait_for("error"))
        self.wait_for("stopped")
        self.assertEqual(self.session.server.fileno(), -1)

    def test_cancel_during_startup_releases_resources(self):
        self.fake.write_text("import time\ntime.sleep(60)\n")
        self.start()
        self.session.stop()
        self.wait_for("stopped")
        self.session.join(10)
        self.assertFalse(self.session.thread.is_alive())
        if self.session.process:
            self.assertIsNotNone(self.session.process.poll())

    def test_single_instance_lock_is_released(self):
        self.state.mkdir()
        first = StateLock(self.state / "agent.lock")
        second = StateLock(self.state / "agent.lock")
        first.acquire()
        try:
            with self.assertRaisesRegex(RuntimeError, "уже запущен"):
                second.acquire()
        finally:
            first.close()
        second.acquire()
        second.close()

    def test_rejects_modified_embedded_tunnel(self):
        (self.directory / "cloudflared.exe").write_bytes(b"untrusted executable")
        with patch("remote222.session.bundle_root", return_value=self.directory):
            with self.assertRaisesRegex(RuntimeError, "Проверка компонента"):
                bundled_tunnel()


if __name__ == "__main__":
    unittest.main()
