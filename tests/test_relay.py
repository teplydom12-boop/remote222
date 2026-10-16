import base64
from contextlib import contextmanager
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from remote222.agent import AgentServer, prepare_state
from remote222.broker import BrokerServer
from remote222.client import Client, ClientError
from remote222.relay import PREFIX, RelayClient, RelayWorker


@contextmanager
def running(server):
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.02), daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.agent_state = self.root / "agent"
        self.agent_token = prepare_state(self.agent_state)
        self.agent = AgentServer(0, self.agent_state, self.agent_token)
        context = running(self.agent)
        agent_url = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        self.local = Client(agent_url, self.agent_token)
        broker_state = self.root / "broker"
        broker_state.mkdir()
        self.controller_token = "c" * 43
        self.worker_token = "w" * 43
        self.broker = BrokerServer(0, broker_state, self.controller_token, self.worker_token)
        context = running(self.broker)
        self.url = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        self.client = RelayClient(self.url, self.controller_token, poll_interval=0.02, wait_timeout=5)
        self.events = []
        self.worker_errors = []

    def start_worker(self, local=None, configure=None):
        stop = threading.Event()
        worker = RelayWorker(self.url, self.worker_token, local or self.local, stop,
                             emit=lambda event, value: self.events.append((event, value)),
                             poll_interval=0.02, heartbeat_interval=0.05)
        if configure:
            configure(worker)

        def run():
            try:
                worker.run()
            except Exception as exc:
                self.worker_errors.append(exc)

        thread = threading.Thread(target=run, daemon=True)

        def cleanup():
            stop.set()
            thread.join(timeout=7)
            self.assertFalse(thread.is_alive(), "Worker did not stop")

        self.addCleanup(cleanup)
        thread.start()
        self.assertTrue(worker.connected.wait(3), self.worker_errors)
        return worker, stop, thread

    def test_remote_info_shell_and_file_feedback(self):
        self.start_worker()
        info = self.client.info()
        self.assertTrue(info["ok"])
        self.assertEqual(info["result"]["pid"], os.getpid())
        self.assertIsNotNone(self.agent.store.lookup(info["id"]))
        command = "Write-Output 'relay-output'; exit 7" if os.name == "nt" else "printf relay-output; exit 7"
        shell = self.client.action("shell", {"command": command})
        self.assertTrue(shell["ok"])
        self.assertEqual(shell["result"]["exit_code"], 7)
        self.assertIn("relay-output", shell["result"]["stdout"])
        path = self.root / "feedback.txt"
        content = "Данные через очередь".encode()
        written = self.client.action("write", {"path": str(path), "data_base64": base64.b64encode(content).decode()})
        self.assertTrue(written["ok"])
        downloaded = self.client.action("read", {"path": str(path)})
        self.assertEqual(base64.b64decode(downloaded["result"]["data_base64"]), content)
        self.assertEqual(self.client.result(downloaded["id"])["job"]["response"], downloaded)
        self.assertEqual(self.worker_errors, [])

    def test_offline_does_not_queue_a_future_command(self):
        path = self.root / "never.txt"
        result = self.client.action("write", {"path": str(path), "data_base64": "aGk="}, "offline-request-123")
        self.assertEqual(result["error"], "worker_offline")
        with self.assertRaisesRegex(ClientError, "job_not_found"):
            self.client.result("offline-request-123")
        self.start_worker()
        self.assertTrue(self.client.info()["ok"])
        self.assertFalse(path.exists())

    def test_lost_local_response_recovers_without_repeating_write(self):
        path = self.root / "once-local.txt"
        original = self.local.action
        attempts = []

        def lose_first_response(action, args, request_id):
            attempts.append(request_id)
            response = original(action, args, request_id)
            if len(attempts) == 1:
                path.write_text("modified after first execution")
                raise ClientError("Connection failed (TimeoutError)")
            return response

        self.local.action = lose_first_response
        def short_deadline(worker):
            original_execute = worker._execute

            def execute(job, *, poll_started):
                # Keep the first attempt independent of slow CI polling, while
                # the 0.5 s response retry necessarily exceeds this window.
                return original_execute({**job, "start_in": 0.05}, poll_started=time.monotonic())

            worker._execute = execute

        self.start_worker(configure=short_deadline)
        result = self.client.action("write", {"path": str(path), "data_base64": "aGk=", "overwrite": True}, "lost-local-reply-123")
        self.assertTrue(result["ok"])
        self.assertGreaterEqual(len(attempts), 2)
        self.assertEqual(set(attempts), {"lost-local-reply-123"})
        self.assertEqual(path.read_text(), "modified after first execution")

    def test_lost_result_ack_retries_identical_payload(self):
        path = self.root / "once-result.txt"
        sent = []

        def configure(worker):
            original = worker.client.request

            def lose_ack(endpoint, body=None, timeout=40):
                response = original(endpoint, body, timeout)
                if endpoint == PREFIX + "/result":
                    sent.append(body.copy())
                    if len(sent) == 1:
                        path.write_text("modified after delivery")
                        raise ClientError("Connection failed (TimeoutError)")
                return response

            worker.client.request = lose_ack

        self.start_worker(configure=configure)
        result = self.client.action("write", {"path": str(path), "data_base64": "aGk=", "overwrite": True}, "lost-result-ack-123")
        self.assertTrue(result["ok"])
        deadline = time.monotonic() + 3
        while len(sent) < 2 and time.monotonic() < deadline:
            threading.Event().wait(0.02)
        self.assertGreaterEqual(len(sent), 2)
        self.assertEqual(sent[0], sent[1])
        self.assertEqual(path.read_text(), "modified after delivery")

    def test_same_id_after_new_session_returns_original_result(self):
        worker, stop, thread = self.start_worker()
        path = self.root / "session-once.txt"
        args = {"path": str(path), "data_base64": "aGk=", "overwrite": True}
        first = self.client.action("write", args, "original-session-job-123")
        stop.set()
        thread.join(timeout=3)
        path.write_text("changed locally")
        next_worker, _, _ = self.start_worker()
        self.assertNotEqual(worker.session_id, next_worker.session_id)
        self.assertEqual(self.client.action("write", args, "original-session-job-123"), first)
        self.assertEqual(path.read_text(), "changed locally")
        with self.assertRaisesRegex(ClientError, "different action"):
            self.client.action("write", {**args, "overwrite": False}, "original-session-job-123")

    def test_stop_between_claim_and_execution_prevents_new_action(self):
        path = self.root / "stopped.txt"

        def configure(worker):
            original = worker.client.request

            def stop_after_claim(endpoint, body=None, timeout=40):
                response = original(endpoint, body, timeout)
                if endpoint == PREFIX + "/poll" and response.get("job"):
                    worker.stop_event.set()
                return response

            worker.client.request = stop_after_claim

        worker, _, thread = self.start_worker(configure=configure)
        result = self.client.action("write", {"path": str(path), "data_base64": "aGk="}, "stop-after-claim-123")
        self.assertEqual(result["error"], "outcome_unknown")
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertFalse(path.exists())
        self.assertIsNone(self.agent.store.lookup("stop-after-claim-123"))
        self.assertFalse(self.client.status()["online"])

    def test_stop_after_execution_still_reports_finished_result(self):
        original = self.local.action
        worker_holder = []

        def finish_and_stop(action, args, request_id):
            response = original(action, args, request_id)
            worker_holder[0].stop_event.set()
            return response

        self.local.action = finish_and_stop
        worker, _, thread = self.start_worker(configure=lambda item: worker_holder.append(item))
        result = self.client.info()
        self.assertTrue(result["ok"])
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertFalse(self.client.status()["online"])

    def test_claim_deadline_prevents_execution(self):
        worker = RelayWorker(self.url, self.worker_token, self.local, threading.Event())
        path = self.root / "expired.txt"
        result = worker._execute({"id": "expired-claim-123", "session_id": worker.session_id,
                                  "action": "write", "args": {"path": str(path), "data_base64": "aGk="},
                                  "start_in": 0}, poll_started=time.monotonic())
        self.assertEqual(result["error"], "expired")
        self.assertFalse(path.exists())
        self.assertIsNone(self.agent.store.lookup("expired-claim-123"))

    def test_wall_clock_skew_does_not_expire_a_fresh_command(self):
        self.start_worker()
        real_time = time.time
        for shift in (-3600, 3600):
            # BrokerStore captured the real clock at construction; only the
            # worker's wall clock would now disagree with the server's clock.
            with self.subTest(shift=shift), patch("remote222.relay.time.time", return_value=real_time() + shift):
                result = self.client.info()
                self.assertTrue(result["ok"])
                self.assertIsNotNone(self.agent.store.lookup(result["id"]))

    def test_poll_delay_consumes_the_remaining_start_window(self):
        worker = RelayWorker(self.url, self.worker_token, self.local, threading.Event())
        path = self.root / "delayed.txt"
        result = worker._execute({"id": "delayed-poll-123", "session_id": worker.session_id,
                                  "action": "write", "args": {"path": str(path), "data_base64": "aGk="},
                                  "start_in": 1}, poll_started=time.monotonic() - 2)
        self.assertEqual(result["error"], "expired")
        self.assertFalse(path.exists())
        self.assertIsNone(self.agent.store.lookup("delayed-poll-123"))

    def test_invalid_start_windows_never_reach_the_agent(self):
        worker = RelayWorker(self.url, self.worker_token, self.local, threading.Event())
        for window in (-1, float("nan"), float("inf"), "30", True):
            with self.subTest(window=window), self.assertRaisesRegex(ClientError, "deadline"):
                worker._execute({"id": "invalid-window-123", "session_id": worker.session_id,
                                 "action": "info", "args": {}, "start_in": window},
                                poll_started=time.monotonic())
        self.assertIsNone(self.agent.store.lookup("invalid-window-123"))

    def test_invalid_shell_timeout_does_not_stop_the_worker(self):
        self.start_worker()
        for timeout in ("invalid", None, [], True, 0, 301):
            with self.subTest(timeout=timeout):
                result = self.client.action("shell", {"command": "exit 0", "timeout": timeout})
                self.assertFalse(result["ok"])
                self.assertEqual(result["error"], "action_failed")
                self.assertTrue(self.client.info()["ok"])
        self.assertEqual(self.worker_errors, [])

    def test_timeout_is_recovered_with_original_id(self):
        self.start_worker()
        command = "Start-Sleep -Milliseconds 300; Write-Output 'finished'" if os.name == "nt" else "sleep 0.3; printf finished"
        short_wait = RelayClient(self.url, self.controller_token, poll_interval=0.01, wait_timeout=0.01)
        result = short_wait.action("shell", {"command": command}, "controller-timeout-123")
        self.assertEqual(result["error"], "relay_timeout")
        finished = self.client.action("shell", {"command": command}, "controller-timeout-123")
        self.assertTrue(finished["ok"])
        self.assertIn("finished", finished["result"]["stdout"])
        self.assertEqual(self.client.result("controller-timeout-123")["job"]["state"], "completed")

    def test_heartbeat_continues_during_long_command(self):
        self.start_worker()
        command = "Start-Sleep -Seconds 1" if os.name == "nt" else "sleep 1"
        replies = []
        thread = threading.Thread(target=lambda: replies.append(self.client.action("shell", {"command": command})), daemon=True)
        thread.start()
        deadline = time.monotonic() + 2
        initial = self.client.status()
        while not initial["busy"] and time.monotonic() < deadline:
            threading.Event().wait(0.02)
            initial = self.client.status()
        self.assertTrue(initial["busy"])
        threading.Event().wait(0.2)
        later = self.client.status()
        self.assertTrue(later["online"])
        self.assertTrue(later["busy"])
        self.assertGreater(later["last_seen"], initial["last_seen"])
        thread.join(timeout=5)
        self.assertEqual(len(replies), 1)
        self.assertTrue(replies[0]["ok"])

    def test_explicit_denial_stops_without_reconnecting(self):
        calls = []
        worker = RelayWorker(self.url, self.worker_token, self.local, threading.Event(),
                             emit=lambda event, data: self.events.append((event, data)))

        def denied(path, body=None, timeout=40):
            calls.append((path, body["session_id"]))
            raise ClientError("HTTP 403: http_error")

        worker.client.request = denied
        with self.assertRaisesRegex(ClientError, "HTTP 403"):
            worker.run()
        self.assertEqual([path for path, _ in calls].count(PREFIX + "/connect"), 1)
        self.assertEqual({session for _, session in calls}, {worker.session_id})
        self.assertFalse(worker.connected.is_set())
        self.assertNotIn(self.worker_token, repr(self.events))


if __name__ == "__main__":
    unittest.main()
