import os
from pathlib import Path
import queue
import secrets
import tempfile
import threading
import unittest
from unittest.mock import patch

from remote222.broker import BrokerServer
from remote222.client import ClientError
from remote222.relay import RelayClient
from remote222.session import RelaySession


class RelaySessionTests(unittest.TestCase):
    def test_visible_session_runs_without_cloudflared_and_disconnects(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            controller, worker = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            broker = BrokerServer(0, base / "broker", controller, worker)
            thread = threading.Thread(target=broker.serve_forever, daemon=True)
            thread.start()
            events = queue.Queue()
            url = f"http://127.0.0.1:{broker.server_port}"
            session = RelaySession(base / "agent", lambda kind, data: events.put((kind, data)), url, worker)
            try:
                with patch("remote222.session.bundled_tunnel", side_effect=AssertionError("Queue mode must not start a tunnel")):
                    session.start()
                    for _ in range(20):
                        kind, data = events.get(timeout=10)
                        self.assertNotEqual(kind, "error", data)
                        if kind == "ready":
                            self.assertEqual(data, url)
                            break
                    else:
                        self.fail("No ready event")
                    client = RelayClient(url, controller, poll_interval=0.02)
                    self.assertEqual(client.info()["result"]["pid"], os.getpid())
                    self.assertIsNone(session.process)
                    self.assertFalse((base / "agent" / "tunnel.log").exists())
                    session.stop()
                    session.join(12)
                    self.assertFalse(session.thread.is_alive())
                    self.assertIsNone(session.url)
                    self.assertIsNone(session.worker_token)
                    self.assertFalse(client.status()["online"])
                    self.assertEqual(session.server.fileno(), -1)
            finally:
                session.stop()
                session.join(12)
                broker.shutdown()
                broker.server_close()
                thread.join(5)

    def test_rejects_unencrypted_public_broker_before_starting(self):
        with self.assertRaises(ClientError):
            RelaySession(Path("unused"), lambda *args: None,
                         "http://broker.example.com", "local-input")


if __name__ == "__main__":
    unittest.main()
