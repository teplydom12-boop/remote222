"""Outbound command queue transport for an explicitly configured HTTPS broker.

This module uses the same verified TLS and redirect policy as the direct client.
The broker's worker credential is separate from its controller credential.
"""

import hashlib
import json
import math
import re
import threading
import time
import urllib.parse
import uuid

from .client import Client, ClientError


PREFIX = "/relay/v1"
REQUEST_ID = re.compile(r"^[a-zA-Z0-9_-]{8,80}$")
TERMINAL = {"completed", "expired", "outcome_unknown", "result_expired"}


def _request_id(value):
    if not isinstance(value, str) or not REQUEST_ID.fullmatch(value):
        raise ClientError("Invalid request ID; use 8–80 letters, digits, underscores or hyphens")
    return value


def _object(value):
    if not isinstance(value, dict) or value.get("ok") is not True:
        raise ClientError("Invalid broker response")
    return value


def _job(value, request_id):
    job = _object(value).get("job")
    if not isinstance(job, dict) or job.get("id") != request_id:
        raise ClientError("Invalid broker job response")
    return job


def _same_command(job, action, args):
    # Match the broker's canonical fingerprint without retaining old payloads.
    encoded = json.dumps([job.get("session_id"), action, args], ensure_ascii=True,
                         sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest() == job.get("fingerprint")


class RelayClient(Client):
    """Controller API. A request ID identifies an operation across all retries."""

    def __init__(self, url, token, *, poll_interval=0.5, wait_timeout=None):
        super().__init__(url, token)
        self.poll_interval = poll_interval
        self.wait_timeout = wait_timeout

    def status(self):
        return _object(self.request(PREFIX + "/status", timeout=10))

    def result(self, request_id):
        request_id = _request_id(request_id)
        payload = self.request(PREFIX + "/jobs/" + request_id, timeout=10)
        _job(payload, request_id)
        return payload

    def info(self):
        # This round trip proves the worker answered now, rather than returning
        # an old machine description cached by the broker.
        return self.action("info", {})

    def action(self, action, args, request_id=None):
        request_id = _request_id(request_id or str(uuid.uuid4()))
        if not isinstance(action, str) or not isinstance(args, dict):
            raise ClientError("Invalid action or arguments")
        try:
            try:
                job = _job(self.result(request_id), request_id)
            except ClientError as exc:
                if str(exc) != "HTTP 404: job_not_found":
                    raise
                status = self.status()
                if status.get("online") is not True or not status.get("session_id"):
                    return {"ok": False, "id": request_id, "error": "worker_offline"}
                job = _job(self.request(PREFIX + "/jobs", {
                    "id": request_id, "session_id": status["session_id"],
                    "action": action, "args": args,
                }, timeout=10), request_id)
            if not _same_command(job, action, args):
                raise ClientError("Request ID already belongs to a different action or arguments")
            execution = args.get("timeout", 30) if action == "shell" else 0
            execution = execution if type(execution) is int else 30
            wait = self.wait_timeout if self.wait_timeout is not None else min(360, max(60, execution + 60))
            deadline = time.monotonic() + wait
            while True:
                state = job.get("state")
                if state in TERMINAL:
                    response = job.get("response")
                    if not isinstance(response, dict) or type(response.get("ok")) is not bool:
                        raise ClientError("Invalid broker result")
                    return {**response, "id": request_id}
                if state not in {"queued", "claimed"}:
                    raise ClientError("Invalid broker job state")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return {"ok": False, "id": request_id, "error": "relay_timeout",
                            "message": "Execution may have occurred. Retrieve this request ID or retry the same action with the same ID; do not create a new ID."}
                time.sleep(min(self.poll_interval, remaining))
                job = _job(self.result(request_id), request_id)
        except ClientError as exc:
            raise ClientError(f"{exc}. Request ID: {request_id}. Retry only with this ID and the same action and arguments.") from None


class RelayWorker:
    """Visible desktop-session worker; stopping prevents accepting new commands.

    An action already sent to the local agent can finish after Stop is clicked.
    Both local execution retries and broker result retries retain the original ID.
    A session ID is never silently replaced after a broker rejects that session.
    """

    def __init__(self, url, worker_token, local_client, stop_event, emit=None,
                 *, poll_interval=0.5, heartbeat_interval=5):
        self.client = Client(url, worker_token)
        if urllib.parse.urlsplit(local_client.url).hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ClientError("The worker requires a loopback local agent")
        self.local_client = local_client
        self.stop_event = stop_event
        self.emit = emit or (lambda event, data: None)
        self.poll_interval = poll_interval
        self.heartbeat_interval = heartbeat_interval
        self.session_id = str(uuid.uuid4())
        self.last_error = None
        self.connected = threading.Event()
        self._abort = threading.Event()
        self._heartbeat_stop = threading.Event()

    def _stopped(self):
        return self.stop_event.is_set() or self._abort.is_set()

    def _status(self, state, message):
        self.emit("status", {"state": state, "message": message})

    @staticmethod
    def _fatal(exc):
        # Never reconnect around rejected credentials, a retired session, or an
        # explicit endpoint/policy denial. Only temporary failures are retried.
        match = re.match(r"HTTP ([0-9]{3}):", str(exc))
        if match:
            code = int(match[1])
            return 400 <= code < 500 and code not in {408, 429}
        return str(exc).startswith(("Redirect refused", "Invalid broker"))

    def _request(self, path, body, *, deliver_after_stop=False):
        delay = 0.5
        first = True
        retrying = False
        while not self._stopped() or (first and deliver_after_stop):
            first = False
            try:
                response = _object(self.client.request(PREFIX + path, body, timeout=5))
                if retrying and not self._stopped():
                    self.last_error = None
                    self._status("ready", "Связь с сервером очереди восстановлена.")
                return response
            except ClientError as exc:
                if self._fatal(exc):
                    raise
                self.last_error = "Временная ошибка связи с сервером очереди."
                if not retrying and not self._stopped():
                    self._status("reconnecting", self.last_error)
                retrying = True
                if self._stopped():
                    return None
                self.stop_event.wait(delay)
                delay = min(5, delay * 2)
        return None

    def _heartbeat(self):
        # A separate HTTP operation keeps the lease fresh during long commands.
        while not self._heartbeat_stop.wait(self.heartbeat_interval) and not self._stopped():
            try:
                _object(self.client.request(PREFIX + "/heartbeat", {"session_id": self.session_id}, timeout=5))
            except ClientError as exc:
                if self._fatal(exc):
                    self.last_error = "Сервер отклонил текущий сеанс. Подключение остановлено."
                    self._abort.set()
                    return
                self._status("reconnecting", "Ожидается восстановление связи с сервером очереди.")

    def _execute(self, job, *, poll_started):
        request_id = _request_id(job.get("id"))
        if job.get("session_id") != self.session_id or not isinstance(job.get("action"), str) or not isinstance(job.get("args"), dict):
            raise ClientError("Invalid broker job response")
        start_in = job.get("start_in")
        if type(start_in) not in {int, float} or not 0 <= start_in <= 30 or not math.isfinite(start_in):
            raise ClientError("Invalid broker job deadline")
        # Broker wall time and Windows wall time need not agree. Charge the full
        # poll request duration (including retries) against the remaining lease.
        deadline = poll_started + start_in
        # Expiry is checked only before the first execution attempt. An uncertain
        # local HTTP result must still be recovered with the same ID after expiry.
        if self._stopped():
            return None
        if time.monotonic() >= deadline:
            return {"ok": False, "id": request_id, "error": "expired"}
        self._status("busy", "Выполняется команда; отключение остановит приём следующих команд.")
        may_have_started = False
        while not self._stopped():
            if not may_have_started and time.monotonic() >= deadline:
                return {"ok": False, "id": request_id, "error": "expired"}
            try:
                response = self.local_client.action(job["action"], job["args"], request_id)
                if not isinstance(response, dict) or type(response.get("ok")) is not bool:
                    return {"ok": False, "id": request_id, "error": "invalid_local_response"}
                return response
            except ClientError as exc:
                message = str(exc)
                if message in {"HTTP 409: outcome_unknown", "HTTP 409: id_conflict"}:
                    return {"ok": False, "id": request_id, "error": message.rsplit(": ", 1)[1]}
                if self._fatal(exc) and message != "HTTP 409: agent_busy":
                    return {"ok": False, "id": request_id, "error": "local_agent_unavailable"}
                if message != "HTTP 409: agent_busy":
                    may_have_started = True
                # The local agent persists IDs before executing. Retrying this
                # same ID recovers the result without repeating the action.
                self.stop_event.wait(0.5)
        return None

    def run(self):
        heartbeat = None
        connect_attempted = False
        try:
            if self._stopped():
                return
            self._status("connecting", "Проверка локального агента и сервера очереди…")
            local_info = self.local_client.info()
            if not isinstance(local_info, dict) or local_info.get("ok") is not True:
                raise ClientError("Local agent readiness check failed")
            connect_attempted = True
            if self._request("/connect", {"session_id": self.session_id}) is None or self._stopped():
                return
            self.connected.set()
            heartbeat = threading.Thread(target=self._heartbeat, daemon=True, name="remote222-heartbeat")
            heartbeat.start()
            self.emit("ready", {"session_id": self.session_id, "url": self.client.url, "info": local_info["result"]})
            while not self._stopped():
                poll_started = time.monotonic()
                payload = self._request("/poll", {"session_id": self.session_id})
                if payload is None or self._stopped():
                    break
                job = payload.get("job")
                if job is None:
                    self.stop_event.wait(self.poll_interval)
                    continue
                if not isinstance(job, dict):
                    raise ClientError("Invalid broker job response")
                response = self._execute(job, poll_started=poll_started)
                if response is None:
                    break
                # Retain this exact result through lost acknowledgements. Even
                # after Stop, try once to report an already finished operation.
                delivered = self._request("/result", {
                    "session_id": self.session_id, "id": job["id"], "response": response,
                }, deliver_after_stop=True)
                if delivered is not None and not self._stopped():
                    self._status("ready", "Результат команды передан. Ожидание следующей команды.")
            if self._abort.is_set() and not self.stop_event.is_set():
                raise ClientError(self.last_error or "Broker session stopped")
        except ClientError:
            self.last_error = self.last_error or "Подключение отклонено; проверьте адрес сервера и войдите в аккаунт снова."
            raise
        finally:
            self.connected.clear()
            self._heartbeat_stop.set()
            if heartbeat:
                heartbeat.join(timeout=6)
            if connect_attempted:
                try:
                    self.client.request(PREFIX + "/disconnect", {"session_id": self.session_id}, timeout=3)
                except ClientError:
                    pass
            self._status("stopped", "Приём команд остановлен.")
