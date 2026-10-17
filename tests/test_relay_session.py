import os
from pathlib import Path
import queue
import secrets
import tempfile
import threading
import unittest
from contextlib import contextmanager
from unittest.mock import patch

from remote222.broker import BrokerServer
from remote222.auth_client import AuthClient, SessionStore
from remote222.client import ClientError
from remote222.relay import RelayClient
from remote222.session import (AccountLogout, RelaySession, protect_state,
                               read_relay_settings, relay_session_store)


@contextmanager
def account_broker():
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        broker = BrokerServer(0, base / "broker", secrets.token_urlsafe(32), secrets.token_urlsafe(32))
        username, password = "windows-owner", secrets.token_urlsafe(24)
        broker.accounts.set_account(username, password)
        thread = threading.Thread(target=broker.serve_forever, daemon=True)
        thread.start()
        try:
            yield base, broker, f"http://127.0.0.1:{broker.server_port}", username, password
        finally:
            broker.shutdown()
            broker.server_close()
            thread.join(5)


class RelaySessionTests(unittest.TestCase):
    def wait_ready(self, events):
        for _ in range(20):
            kind, data = events.get(timeout=10)
            self.assertNotEqual(kind, "error", data)
            if kind == "ready":
                return data
        self.fail("No ready event")

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

    def test_account_login_reuses_private_session_then_logout_revokes_it(self):
        with account_broker() as (base, broker, url, username, password):
            state = base / "agent"
            events = queue.Queue()
            emit = lambda kind, data: events.put((kind, data))
            controller = AuthClient(url).login(username, password, role="controller")
            client = RelayClient(url, controller["session_token"], poll_interval=0.02)
            protect_state(state)
            previous = AuthClient(url).login(username, password, role="worker")
            relay_session_store(state).save(url, previous)
            session = RelaySession(state, emit, url, username=username, password=password)
            try:
                session.start()
                self.assertEqual(self.wait_ready(events), url)
                self.assertEqual(client.info()["result"]["pid"], os.getpid())
                self.assertEqual(session.password, "")
                profile = relay_session_store(state).load(url, role="worker")
                self.assertEqual(AuthClient(url, profile["session_token"]).session()["role"], "worker")
                with self.assertRaisesRegex(ClientError, "HTTP 401"):
                    AuthClient(url, previous["session_token"]).session()
                self.assertEqual(read_relay_settings(state), {"url": url, "username": username})
                session.stop()
                session.join(12)
                self.assertFalse(session.thread.is_alive())
                self.assertEqual(relay_session_store(state).load(url, role="worker"), profile)
                for path in state.rglob("*"):
                    if path.is_file():
                        self.assertNotIn(password.encode(), path.read_bytes())
                events = queue.Queue()
                emit = lambda kind, data: events.put((kind, data))
                session = RelaySession(state, emit, url, username=username)
                with patch.object(AuthClient, "login", side_effect=AssertionError("Saved login must be reused")):
                    session.start()
                    self.wait_ready(events)
                self.assertEqual(client.info()["result"]["pid"], os.getpid())
                session.logout()
                session.join(12)
                self.assertFalse(session.thread.is_alive())
                self.assertFalse(client.status()["online"])
                with self.assertRaises(ClientError):
                    relay_session_store(state).load(url, role="worker")
                with self.assertRaisesRegex(ClientError, "HTTP 401"):
                    AuthClient(url, profile["session_token"]).session()
                self.assertEqual(AuthClient(url, controller["session_token"]).session()["role"], "controller")
                self.assertNotIn(password, repr(list(events.queue)))
                self.assertIn(("logged_out", None), list(events.queue))
            finally:
                session.stop()
                session.join(12)

    def test_stop_or_logout_during_login_never_starts_local_agent(self):
        with account_broker() as (base, broker, url, username, password):
            for logout in (False, True):
                with self.subTest(logout=logout):
                    response = AuthClient(url).login(username, password, role="worker")
                    entered, finish = threading.Event(), threading.Event()
                    events = []

                    def delayed_login(*args, **kwargs):
                        entered.set()
                        if not finish.wait(10):
                            raise AssertionError("Login was not released")
                        return response

                    state = base / ("logout-agent" if logout else "stop-agent")
                    session = RelaySession(state, lambda *args: events.append(args), url,
                                           username=username, password=password)
                    try:
                        with patch.object(AuthClient, "login", side_effect=delayed_login), \
                             patch("remote222.session.AgentServer", side_effect=AssertionError("Stopped login must not launch agent")):
                            session.start()
                            self.assertTrue(entered.wait(5))
                            session.logout() if logout else session.stop()
                            finish.set()
                            session.join(10)
                        self.assertFalse(session.thread.is_alive())
                        self.assertIsNone(session.server)
                        self.assertEqual(session.password, "")
                        self.assertFalse(any(kind in {"error", "ready"} for kind, _ in events), events)
                        if logout:
                            with self.assertRaises(ClientError):
                                relay_session_store(state).load(url, role="worker")
                            with self.assertRaisesRegex(ClientError, "HTTP 401"):
                                AuthClient(url, response["session_token"]).session()
                        else:
                            self.assertEqual(relay_session_store(state).load(url, role="worker")["session_token"], response["session_token"])
                    finally:
                        finish.set()
                        session.stop()
                        session.join(10)

    def test_logout_forgets_session_if_server_is_unreachable(self):
        with account_broker() as (base, broker, url, username, password):
            state = base / "agent"
            protect_state(state)
            response = AuthClient(url).login(username, password, role="worker")
            store = relay_session_store(state)
            store.save(url, response)
            events = []
            logout = AccountLogout(state, lambda *args: events.append(args))
            with patch.object(AuthClient, "logout", side_effect=ClientError("offline")):
                logout.start()
                logout.join(10)
            self.assertFalse(logout.thread.is_alive())
            self.assertFalse(store.path.exists())
            self.assertTrue(any(kind == "error" and "не подтвердил" in message for kind, message in events))
            self.assertIn(("stopped", None), events)
            self.assertNotIn(response["session_token"], repr(events))

    def test_wrong_password_does_not_start_an_agent_or_persist_password(self):
        with account_broker() as (base, broker, url, username, password):
            state = base / "agent"
            events = []
            session = RelaySession(state, lambda *args: events.append(args), url,
                                   username=username, password=password + "-wrong")
            session.start()
            session.join(10)
            self.assertFalse(session.thread.is_alive())
            self.assertIsNone(session.server)
            self.assertEqual(session.password, "")
            self.assertFalse(relay_session_store(state).path.exists())
            self.assertTrue(any(kind == "error" for kind, _ in events))
            self.assertNotIn(password, repr(events))

    def test_failed_session_save_revokes_new_login(self):
        with account_broker() as (base, broker, url, username, password):
            response = AuthClient(url).login(username, password, role="worker")
            events = []
            session = RelaySession(base / "agent", lambda *args: events.append(args), url,
                                   username=username, password=password)
            with patch.object(AuthClient, "login", return_value=response), \
                 patch.object(SessionStore, "save", side_effect=ClientError("Cannot save session")):
                session.start()
                session.join(10)
            self.assertFalse(session.thread.is_alive())
            self.assertIsNone(session.server)
            self.assertTrue(any(kind == "error" for kind, _ in events))
            with self.assertRaisesRegex(ClientError, "HTTP 401"):
                AuthClient(url, response["session_token"]).session()


if __name__ == "__main__":
    unittest.main()
