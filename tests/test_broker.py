import concurrent.futures
import contextlib
import io
import json
import os
from pathlib import Path
import secrets
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
import uuid

from remote222.broker import (BrokerError, BrokerServer, BrokerStore, MAX_COMMAND,
                              MAX_RESULT, main, prepare_state, request_fingerprint)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "broker.sqlite3"
        self.now = 1000.0
        self.store = BrokerStore(self.path, clock=lambda: self.now)
        self.session = str(uuid.uuid4())
        self.store.connect_session(self.session)

    def job(self, request_id=None, **changes):
        result = {"id": request_id or str(uuid.uuid4()), "session_id": self.session,
                  "action": "info", "args": {}}
        result.update(changes)
        return result

    def assertError(self, code, function, *args):
        with self.assertRaises(BrokerError) as caught:
            function(*args)
        self.assertEqual(caught.exception.code, code)

    def complete(self, job, response=None):
        response = response or {"ok": True, "id": job["id"], "result": {"system": "Windows"}}
        self.store.enqueue(job)
        self.store.poll(job["session_id"])
        body = {"id": job["id"], "session_id": job["session_id"], "response": response}
        self.store.result(body)
        return body

    def test_idempotent_submission_and_conflicts_even_offline(self):
        job = self.job(args={"secret_path": "private"})
        first = self.store.enqueue(job)
        self.now += 21
        self.assertEqual(first, self.store.enqueue(dict(job)))
        self.assertError("id_conflict", self.store.enqueue, job | {"args": {}})
        self.assertError("id_conflict", self.store.enqueue, job | {"session_id": str(uuid.uuid4())})
        self.assertEqual(first["job"]["fingerprint"], request_fingerprint(self.session, job["action"], job["args"]))
        self.assertEqual(first["job"]["session_id"], self.session)

    def test_only_one_job_can_be_enqueued_concurrently(self):
        barrier = threading.Barrier(8)

        def submit(index):
            barrier.wait()
            try:
                return self.store.enqueue(self.job(f"parallel-{index}"))["job"]["id"]
            except BrokerError as exc:
                return exc.code

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(submit, range(8)))
        self.assertEqual(outcomes.count("worker_busy"), 7)

    def test_claim_repeats_same_id_and_does_not_expire_running_action(self):
        job = self.job()
        self.store.enqueue(job)
        first = self.store.poll(self.session)
        self.now += 40
        repeated = self.store.poll(self.session)
        self.assertEqual(first["job"]["id"], repeated["job"]["id"])
        self.assertEqual(first["job"]["args"], repeated["job"]["args"])
        self.assertEqual(repeated["job"]["start_in"], 0)
        self.assertEqual(self.store.get_job(job["id"])["job"]["state"], "claimed")
        self.assertTrue(self.store.status()["busy"])

    def test_poll_deadline_is_relative_to_broker_clock(self):
        # The Windows clock may be hours away from the broker's Unix timestamp.
        # A relative deadline lets the worker use its own monotonic clock.
        self.now = 1_800_000_000.0
        self.store.heartbeat(self.session)
        job = self.job()
        self.store.enqueue(job)
        self.now += 7.25
        first = self.store.poll(self.session)["job"]
        self.assertEqual(first["start_before"], 1_800_000_030.0)
        self.assertEqual(first["start_in"], 22.75)
        self.now += 30
        repeated = self.store.poll(self.session)["job"]
        self.assertEqual(repeated["start_before"], first["start_before"])
        self.assertEqual(repeated["start_in"], 0)
        self.assertEqual(repeated["id"], first["id"])

    def test_lock_wait_cannot_use_time_older_than_concurrent_heartbeat(self):
        original_connect = self.store.connect
        for operation in ("status", "enqueue", "poll", "heartbeat", "connect_session"):
            with self.subTest(operation=operation):
                # Keep only one outstanding command in each subtest.
                self.session = str(uuid.uuid4())
                self.store.connect_session(self.session)
                job = self.job()
                waiting_for_lock = threading.Event()

                @contextlib.contextmanager
                def tracked_connect():
                    waiting_for_lock.set()
                    with original_connect() as db:
                        yield db

                if operation == "status":
                    invoke = self.store.status
                elif operation == "enqueue":
                    invoke = lambda: self.store.enqueue(job)
                else:
                    invoke = lambda: getattr(self.store, operation)(self.session)
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    with patch.object(self.store, "connect", tracked_connect):
                        with original_connect() as blocker:
                            future = pool.submit(invoke)
                            self.assertTrue(waiting_for_lock.wait(5))
                            self.now += 1
                            blocker.execute("UPDATE device SET last_seen=?", (self.now,))
                            if operation == "poll":
                                # Another request enqueues while poll waits for the lock.
                                blocker.execute("INSERT INTO jobs VALUES (?, ?, ?, ?, '{}', 'queued', ?, NULL, NULL)",
                                                (job["id"], request_fingerprint(self.session, "info", {}),
                                                 self.session, "info", self.now + 30))
                        result = future.result(timeout=5)
                if operation == "status":
                    self.assertTrue(result["online"])
                elif operation == "enqueue":
                    self.assertEqual(result["job"]["state"], "queued")
                elif operation == "poll":
                    self.assertEqual(result["job"]["start_in"], 30)
                self.assertEqual(self.store.status()["last_seen"], self.now)

    def test_queued_jobs_expire_before_claim(self):
        job = self.job()
        self.store.enqueue(job)
        self.now += 30
        self.assertIsNone(self.store.poll(self.session)["job"])
        result = self.store.get_job(job["id"])["job"]
        self.assertEqual(result["state"], "expired")
        self.assertEqual(result["response"], {"ok": False, "error": "expired"})
        with self.store.connect() as db:
            row = db.execute("SELECT action,args FROM jobs WHERE id=?", (job["id"],)).fetchone()
            self.assertEqual(tuple(row), (None, None))

    def test_new_session_expires_queued_and_closes_old_session(self):
        job = self.job()
        self.store.enqueue(job)
        new_session = str(uuid.uuid4())
        self.store.connect_session(new_session)
        self.assertEqual(self.store.get_job(job["id"])["job"]["state"], "expired")
        for method in (self.store.poll, self.store.heartbeat, self.store.connect_session):
            self.assertError("session_closed", method, self.session)
        self.assertIsNone(self.store.poll(new_session)["job"])
        self.assertEqual(self.store.enqueue(job)["job"]["state"], "expired")

    def test_claimed_old_job_unknown_and_late_result_can_reconcile_it(self):
        job = self.job()
        self.store.enqueue(job)
        self.store.poll(self.session)
        new_session = str(uuid.uuid4())
        self.store.connect_session(new_session)
        self.assertEqual(self.store.get_job(job["id"])["job"]["state"], "outcome_unknown")
        body = {"id": job["id"], "session_id": self.session,
                "response": {"ok": True, "result": {"started": True}}}
        self.store.result(body)
        self.assertEqual(self.store.get_job(job["id"])["job"]["response"], body["response"])
        self.assertEqual(self.store.status()["session_id"], new_session)

    def test_result_ack_loss_repeats_safely_and_differs_conflict(self):
        job = self.job()
        body = self.complete(job)
        self.assertEqual(self.store.result(body), {"ok": True, "id": job["id"]})
        self.assertError("result_conflict", self.store.result, body | {"response": {"ok": False}})
        self.assertError("session_mismatch", self.store.result, body | {"session_id": str(uuid.uuid4())})
        self.store.disconnect(self.session)
        self.assertTrue(self.store.result(body)["ok"])
        self.assertEqual(self.store.enqueue(job)["job"]["state"], "completed")

    def test_result_requires_claim_and_does_not_revive_expired_job(self):
        job = self.job()
        self.store.enqueue(job)
        body = {"id": job["id"], "session_id": self.session, "response": {"ok": True}}
        self.assertError("job_not_claimed", self.store.result, body)
        self.store.disconnect(self.session)
        self.assertError("job_not_claimed", self.store.result, body)

    def test_disconnect_does_not_close_a_newer_session(self):
        self.store.disconnect(self.session)
        new_session = str(uuid.uuid4())
        self.store.connect_session(new_session)
        self.store.disconnect(self.session)
        self.assertTrue(self.store.status()["online"])
        self.assertEqual(self.store.status()["session_id"], new_session)

    def test_disconnect_before_connect_retires_delayed_session(self):
        delayed_session = str(uuid.uuid4())
        self.assertTrue(self.store.disconnect(delayed_session)["ok"])
        new_session = str(uuid.uuid4())
        self.store.connect_session(new_session)
        self.assertError("session_closed", self.store.connect_session, delayed_session)
        self.assertTrue(self.store.disconnect(delayed_session)["ok"])
        self.assertTrue(self.store.status()["online"])
        self.assertEqual(self.store.status()["session_id"], new_session)

    def test_server_restart_requires_fresh_worker_contact(self):
        self.assertTrue(self.store.status()["online"])
        restarted = BrokerStore(self.path, clock=lambda: self.now)
        status = restarted.status()
        self.assertEqual(status["session_id"], self.session)
        self.assertFalse(status["online"])
        self.assertIsNone(status["last_seen"])
        self.assertError("worker_offline", restarted.enqueue, self.job())
        restarted.heartbeat(self.session)
        self.assertTrue(restarted.status()["online"])
        self.assertEqual(restarted.enqueue(self.job())["job"]["state"], "queued")

    def test_offline_worker_rejects_new_commands(self):
        self.now += 21
        self.assertFalse(self.store.status()["online"])
        self.assertError("worker_offline", self.store.enqueue, self.job())

    def test_retention_redacts_payloads_and_keeps_idempotence_metadata(self):
        original_job = self.job()
        original_result = self.complete(original_job)
        for _ in range(100):
            self.complete(self.job())
        result = self.store.get_job(original_job["id"])["job"]
        self.assertEqual(result["response"]["error"], "result_expired")
        self.assertEqual(result["state"], "completed")
        self.assertEqual(self.store.enqueue(original_job)["job"], result)
        self.assertTrue(self.store.result(original_result)["ok"])
        self.assertError("result_conflict", self.store.result, original_result | {"response": {"different": True}})
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM jobs WHERE action IS NOT NULL OR args IS NOT NULL").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 101)

    def test_payload_limits(self):
        self.assertError("request_too_large", self.store.enqueue, self.job(args={"data": "a" * MAX_COMMAND}))
        job = self.job()
        self.store.enqueue(job)
        self.store.poll(self.session)
        self.assertError("result_too_large", self.store.result,
                         {"id": job["id"], "session_id": self.session, "response": {"data": "a" * MAX_RESULT}})


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.controller, self.worker = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        self.server = BrokerServer(0, Path(self.temp.name), self.controller, self.worker)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.session = str(uuid.uuid4())

    def close_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def request(self, path, token=None, body=None, headers=None, raw=None):
        request_headers = {"Content-Type": "application/json"}
        if token:
            request_headers["Authorization"] = "Bearer " + token
        request_headers.update(headers or {})
        data = raw if raw is not None else json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(self.url + path, data=data, headers=request_headers)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.load(exc)

    def test_roles_are_separate_and_health_reveals_no_device_data(self):
        code, health = self.request("/healthz")
        self.assertEqual(code, 200)
        self.assertEqual(health, {"ok": True, "service": "remote222-broker"})
        self.assertEqual(self.request("/relay/v1/status")[0], 401)
        self.assertEqual(self.request("/relay/v1/status", self.worker)[0], 401)
        body = {"session_id": self.session}
        self.assertEqual(self.request("/relay/v1/connect", self.controller, body)[0], 401)
        self.assertEqual(self.request("/relay/v1/connect", self.worker, body)[0], 200)
        self.assertTrue(self.request("/relay/v1/status", self.controller)[1]["online"])
        job = {"id": str(uuid.uuid4()), "session_id": self.session, "action": "info", "args": {}}
        self.assertEqual(self.request("/relay/v1/jobs", self.worker, job)[0], 401)
        self.assertEqual(self.request("/relay/v1/jobs", self.controller, job)[0], 200)
        self.assertEqual(self.request("/relay/v1/poll", self.controller, body)[0], 401)
        self.assertEqual(self.request("/relay/v1/poll", self.worker, body)[1]["job"]["id"], job["id"])
        self.assertEqual(self.request("/relay/v1/jobs/" + job["id"], self.worker)[0], 401)

    def test_origins_and_unsupported_routes_are_rejected(self):
        self.assertEqual(self.request("/relay/v1/status", self.controller, headers={"Origin": "https://example.com"})[0], 403)
        self.assertEqual(self.request("/relay/v1/status?private=1", self.controller)[0], 404)
        self.assertEqual(self.request("/relay/v1/connect/", self.worker, {"session_id": self.session})[0], 404)
        self.assertEqual(self.request("/relay/v1/jobs/absent-id", self.controller)[1]["error"], "job_not_found")

    def test_bad_json_and_field_types_are_rejected(self):
        for raw in (b'{"session_id":null}', b'{"session_id":"a","session_id":"b"}', b'[]', b'{"session_id":NaN}'):
            with self.subTest(raw=raw):
                self.assertEqual(self.request("/relay/v1/connect", self.worker, raw=raw)[0], 400)
        body = {"session_id": self.session}
        self.assertEqual(self.request("/relay/v1/connect", self.worker, body, headers={"Content-Type": "text/plain"})[0], 415)

    def test_maximum_result_fits_controller_response_allowance(self):
        self.server.store.connect_session(self.session)
        job = {"id": str(uuid.uuid4()), "session_id": self.session, "action": "info", "args": {}}
        self.server.store.enqueue(job)
        self.server.store.poll(self.session)
        response = {"data": "a" * (MAX_RESULT - len('{"data":""}'))}
        body = {"id": job["id"], "session_id": self.session, "response": response}
        self.assertEqual(self.request("/relay/v1/result", self.worker, body)[0], 200)
        request = urllib.request.Request(self.url + "/relay/v1/jobs/" + job["id"],
                                         headers={"Authorization": "Bearer " + self.controller})
        with urllib.request.urlopen(request, timeout=5) as result:
            raw = result.read(MAX_RESULT + 8192 + 1)
            self.assertLessEqual(len(raw), MAX_RESULT + 8192)
            self.assertEqual(len(raw), int(result.headers["Content-Length"]))
        self.assertEqual(json.loads(raw)["job"]["response"], response)


class CredentialTests(unittest.TestCase):
    def test_local_credentials_are_distinct_private_and_persisted(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "state"
            controller, worker = prepare_state(path)
            self.assertNotEqual(controller, worker)
            self.assertEqual(len(controller), 43)
            self.assertEqual(prepare_state(path), (controller, worker))
            if os.name != "nt":
                self.assertEqual((path / "controller.token").stat().st_mode & 0o777, 0o600)
                self.assertEqual((path / "worker.token").stat().st_mode & 0o777, 0o600)

    def test_environment_init_does_not_persist_or_print_credentials(self):
        controller, worker = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "unused"
            output = io.StringIO()
            with patch.dict(os.environ, {"REMOTE222_CONTROLLER_TOKEN": controller, "REMOTE222_WORKER_TOKEN": worker}), \
                    patch("sys.argv", ["broker", "--state-dir", str(target), "--init-only"]), contextlib.redirect_stdout(output):
                main()
            self.assertNotIn(controller, output.getvalue())
            self.assertNotIn(worker, output.getvalue())
            self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
