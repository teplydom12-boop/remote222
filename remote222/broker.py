"""Single-device command queue, served behind the owner's HTTPS reverse proxy."""

import argparse
from contextlib import contextmanager
import getpass
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time
import uuid
from urllib.parse import urlsplit

from .agent import REQUEST_ID
from .auth_server import AccountStore, AuthError, handle_auth

MAX_COMMAND = 2 * 1024 * 1024
MAX_RESULT = 8 * 1024 * 1024
ENVELOPE_ALLOWANCE = 8192
ONLINE_SECONDS = 20
START_SECONDS = 30
RESULTS_TO_KEEP = 100
PREFIX = "/relay/v1/"
TOKEN = re.compile(r"^[A-Za-z0-9_-]{43,128}$")


def encoded(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)


def fingerprint(value):
    return hashlib.sha256(encoded(value).encode("utf-8")).hexdigest()


def request_fingerprint(session_id, action, args):
    return fingerprint([session_id, action, args])


class BrokerError(Exception):
    def __init__(self, status, code):
        super().__init__(code)
        self.status = status
        self.code = code


def valid_session(value):
    if not isinstance(value, str):
        return False
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


def require_fields(body, fields):
    if not isinstance(body, dict) or set(body) != set(fields):
        raise BrokerError(400, "invalid_request")


def require_session(body):
    if not valid_session(body.get("session_id")):
        raise BrokerError(400, "invalid_session")
    return body["session_id"]


def require_id(value):
    if not isinstance(value, str) or not REQUEST_ID.fullmatch(value):
        raise BrokerError(400, "invalid_id")
    return value


def prepare_state(path):
    """Create separate local credentials; callers only display their file paths."""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        path.chmod(0o700)
    values = []
    for name in ("controller.token", "worker.token"):
        target = path / name
        try:
            fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "w", encoding="ascii") as stream:
                stream.write(secrets.token_urlsafe(32) + "\n")
        value = target.read_text(encoding="ascii").strip()
        if not TOKEN.fullmatch(value):
            raise ValueError(f"Invalid credential file: {name}")
        if os.name != "nt":
            target.chmod(0o600)
        values.append(value)
    if secrets.compare_digest(*values):
        raise ValueError("Controller and worker credentials must be different")
    return tuple(values)


class BrokerStore:
    """SQLite transactions serialize all session and queue state transitions."""

    def __init__(self, path, *, clock=None):
        self.path = str(path)
        self.clock = clock or time.time
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, retired INTEGER NOT NULL DEFAULT 0)")
            db.execute("CREATE TABLE IF NOT EXISTS device (singleton INTEGER PRIMARY KEY CHECK(singleton=1), session_id TEXT, last_seen REAL)")
            db.execute("INSERT OR IGNORE INTO device VALUES (1, NULL, NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, session_id TEXT NOT NULL, action TEXT, args TEXT, state TEXT NOT NULL, start_before REAL NOT NULL, response TEXT, result_hash TEXT)")
            # A durable timestamp from before this server boot is not a heartbeat.
            db.execute("UPDATE device SET last_seen=NULL WHERE singleton=1")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _job(row):
        return {"id": row["id"], "state": row["state"],
                "session_id": row["session_id"], "fingerprint": row["fingerprint"],
                "response": json.loads(row["response"]) if row["response"] is not None else None}

    @staticmethod
    def _terminal(db, condition, params, state):
        payload = encoded({"ok": False, "error": state})
        db.execute(f"UPDATE jobs SET state=?, response=?, action=NULL, args=NULL WHERE {condition}",
                   (state, payload, *params))

    def _expire(self, db, now):
        self._terminal(db, "state='queued' AND start_before<=?", (now,), "expired")

    def _end_session(self, db, session_id):
        self._terminal(db, "session_id=? AND state='queued'", (session_id,), "expired")
        self._terminal(db, "session_id=? AND state='claimed'", (session_id,), "outcome_unknown")
        db.execute("UPDATE sessions SET retired=1 WHERE id=?", (session_id,))

    @staticmethod
    def _active(db, session_id):
        row = db.execute("SELECT session_id, last_seen FROM device WHERE singleton=1").fetchone()
        if row["session_id"] != session_id:
            raise BrokerError(409, "session_closed")
        return row

    def connect_session(self, session_id):
        with self.connect() as db:
            now = self.clock()
            previous = db.execute("SELECT session_id FROM device WHERE singleton=1").fetchone()[0]
            known = db.execute("SELECT retired FROM sessions WHERE id=?", (session_id,)).fetchone()
            if known and known[0]:
                raise BrokerError(409, "session_closed")
            if previous != session_id:
                if previous is not None:
                    self._end_session(db, previous)
                db.execute("INSERT OR IGNORE INTO sessions (id) VALUES (?)", (session_id,))
            db.execute("UPDATE device SET session_id=?, last_seen=? WHERE singleton=1", (session_id, now))
            self._expire(db, now)
        return {"ok": True, "session_id": session_id}

    def heartbeat(self, session_id):
        with self.connect() as db:
            now = self.clock()
            self._active(db, session_id)
            db.execute("UPDATE device SET last_seen=? WHERE singleton=1", (now,))
            self._expire(db, now)
        return {"ok": True}

    def disconnect(self, session_id):
        with self.connect() as db:
            active = db.execute("SELECT session_id FROM device WHERE singleton=1").fetchone()[0]
            known = db.execute("SELECT retired FROM sessions WHERE id=?", (session_id,)).fetchone()
            if active == session_id:
                self._end_session(db, session_id)
                db.execute("UPDATE device SET session_id=NULL, last_seen=NULL WHERE singleton=1")
            elif not known:
                # Stop can overtake the initial connect on another connection.
                # Remember it so that delayed connect cannot replace a newer session.
                db.execute("INSERT INTO sessions (id, retired) VALUES (?, 1)", (session_id,))
            elif not known[0]:
                raise BrokerError(409, "session_closed")
        return {"ok": True}

    def status(self):
        with self.connect() as db:
            now = self.clock()
            self._expire(db, now)
            row = db.execute("SELECT session_id, last_seen FROM device WHERE singleton=1").fetchone()
            busy = db.execute("SELECT 1 FROM jobs WHERE state IN ('queued','claimed') LIMIT 1").fetchone() is not None
            online = row["session_id"] is not None and row["last_seen"] is not None and 0 <= now - row["last_seen"] <= ONLINE_SECONDS
            return {"ok": True, "session_id": row["session_id"], "online": online,
                    "busy": busy, "last_seen": row["last_seen"]}

    def enqueue(self, body):
        require_fields(body, ("id", "session_id", "action", "args"))
        request_id = require_id(body["id"])
        session_id = require_session(body)
        if not isinstance(body["action"], str) or not 1 <= len(body["action"]) <= 32 or not isinstance(body["args"], dict):
            raise BrokerError(400, "invalid_request")
        if len(encoded(body).encode("utf-8")) > MAX_COMMAND:
            raise BrokerError(413, "request_too_large")
        digest = request_fingerprint(session_id, body["action"], body["args"])
        with self.connect() as db:
            now = self.clock()
            self._expire(db, now)
            previous = db.execute("SELECT * FROM jobs WHERE id=?", (request_id,)).fetchone()
            if previous:
                if previous["fingerprint"] != digest:
                    raise BrokerError(409, "id_conflict")
                return {"ok": True, "job": self._job(previous)}
            row = self._active(db, session_id)
            if row["last_seen"] is None or not 0 <= now - row["last_seen"] <= ONLINE_SECONDS:
                raise BrokerError(409, "worker_offline")
            if db.execute("SELECT 1 FROM jobs WHERE state IN ('queued','claimed') LIMIT 1").fetchone():
                raise BrokerError(409, "worker_busy")
            db.execute("INSERT INTO jobs VALUES (?, ?, ?, ?, ?, 'queued', ?, NULL, NULL)",
                       (request_id, digest, session_id, body["action"], encoded(body["args"]), now + START_SECONDS))
            row = db.execute("SELECT * FROM jobs WHERE id=?", (request_id,)).fetchone()
            return {"ok": True, "job": self._job(row)}

    def get_job(self, request_id):
        require_id(request_id)
        with self.connect() as db:
            self._expire(db, self.clock())
            row = db.execute("SELECT * FROM jobs WHERE id=?", (request_id,)).fetchone()
            if row is None:
                raise BrokerError(404, "job_not_found")
            return {"ok": True, "job": self._job(row)}

    def poll(self, session_id):
        with self.connect() as db:
            now = self.clock()
            self._active(db, session_id)
            db.execute("UPDATE device SET last_seen=? WHERE singleton=1", (now,))
            self._expire(db, now)
            row = db.execute("SELECT * FROM jobs WHERE session_id=? AND state IN ('queued','claimed') ORDER BY rowid LIMIT 1", (session_id,)).fetchone()
            if row is None:
                return {"ok": True, "job": None}
            db.execute("UPDATE jobs SET state='claimed' WHERE id=?", (row["id"],))
            return {"ok": True, "job": {key: row[key] for key in ("id", "action", "session_id", "start_before")} | {
                "args": json.loads(row["args"]), "start_in": max(0, row["start_before"] - now)}}

    def result(self, body):
        require_fields(body, ("session_id", "id", "response"))
        session_id = require_session(body)
        request_id = require_id(body["id"])
        if not isinstance(body["response"], dict):
            raise BrokerError(400, "invalid_request")
        response = encoded(body["response"])
        if len(response.encode("utf-8")) > MAX_RESULT:
            raise BrokerError(413, "result_too_large")
        digest = hashlib.sha256(response.encode("utf-8")).hexdigest()
        with self.connect() as db:
            row = db.execute("SELECT * FROM jobs WHERE id=?", (request_id,)).fetchone()
            if row is None:
                raise BrokerError(404, "job_not_found")
            if row["session_id"] != session_id:
                raise BrokerError(409, "session_mismatch")
            if row["result_hash"] is not None:
                if row["result_hash"] != digest:
                    raise BrokerError(409, "result_conflict")
                return {"ok": True, "id": request_id}
            if row["state"] not in ("claimed", "outcome_unknown"):
                raise BrokerError(409, "job_not_claimed")
            db.execute("UPDATE jobs SET state='completed', response=?, result_hash=?, action=NULL, args=NULL WHERE id=?",
                       (response, digest, request_id))
            expired = encoded({"ok": False, "error": "result_expired"})
            db.execute("UPDATE jobs SET response=? WHERE result_hash IS NOT NULL AND id NOT IN (SELECT id FROM jobs WHERE result_hash IS NOT NULL ORDER BY rowid DESC LIMIT ?)", (expired, RESULTS_TO_KEEP))
        return {"ok": True, "id": request_id}


class BrokerServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, port, state_dir, controller_token, worker_token, host="127.0.0.1", *, public_url=None, account_only=False):
        if (not isinstance(controller_token, str) or not isinstance(worker_token, str)
                or not TOKEN.fullmatch(controller_token) or not TOKEN.fullmatch(worker_token)
                or secrets.compare_digest(controller_token, worker_token)):
            raise ValueError("Two different 256-bit credentials are required")
        self.controller_token = controller_token
        self.worker_token = worker_token
        self.account_only = account_only
        if public_url is not None:
            parsed = urlsplit(public_url)
            origin_port = parsed.port
            if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                    or parsed.password is not None or parsed.path not in ("", "/") or parsed.query or parsed.fragment
                    or any(c.isspace() or ord(c) < 32 for c in public_url)):
                raise ValueError("Public URL must be an HTTPS origin without a path or credentials")
            hostname = parsed.hostname.encode("idna").decode("ascii").lower()
            hostname = f"[{hostname}]" if ":" in hostname else hostname
            suffix = f":{origin_port}" if origin_port is not None and origin_port != 443 else ""
            self.public_origin = f"https://{hostname}{suffix}"
        else:
            self.public_origin = None
        state_dir = Path(state_dir)
        state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            state_dir.chmod(0o700)
        self.accounts = AccountStore(state_dir / "auth.sqlite3")
        if account_only and not self.accounts.configured():
            raise ValueError("Account mode requires a configured local account")
        self.store = BrokerStore(state_dir / "broker.sqlite3")
        super().__init__((host, port), BrokerHandler)


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Duplicate JSON member")
        result[name] = value
    return result


def reject_constant(value):
    raise ValueError("Non-finite JSON number")


class BrokerHandler(BaseHTTPRequestHandler):
    server_version = "Remote222Relay"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, *args):
        pass

    def reply(self, status, payload):
        body = encoded(payload).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        self.close_connection = True

    def authorize(self, role):
        values = self.headers.get_all("Authorization", [])
        if len(values) != 1 or not values[0].startswith("Bearer "):
            raise BrokerError(401, "unauthorized")
        if self.server.account_only or self.server.accounts.configured():
            self.server.accounts.authorize(values[0][7:], role)
        elif not secrets.compare_digest(values[0].encode("utf-8"), ("Bearer " + getattr(self.server, role + "_token")).encode("utf-8")):
            raise BrokerError(401, "unauthorized")
        if self.headers.get("Origin"):
            raise BrokerError(403, "browser_origin_not_allowed")

    def read_body(self, maximum):
        if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
            raise BrokerError(400, "content_length_required")
        if self.headers.get_content_type() != "application/json":
            raise BrokerError(415, "json_required")
        try:
            length = int(self.headers["Content-Length"])
        except ValueError:
            raise BrokerError(400, "invalid_request") from None
        if not 1 <= length <= maximum:
            raise BrokerError(413, "request_too_large")
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise BrokerError(400, "invalid_request")
        try:
            return json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)
        except (ValueError, UnicodeError, RecursionError):
            raise BrokerError(400, "invalid_request") from None

    def do_GET(self):
        self.handle_request("GET")

    def do_POST(self):
        self.handle_request("POST")

    def handle_request(self, method):
        try:
            path = self.path
            if handle_auth(self, method):
                return
            if method == "GET" and path == "/healthz":
                result = {"ok": True, "service": "remote222-broker"}
            elif method == "GET" and (path == PREFIX + "status" or path.startswith(PREFIX + "jobs/")):
                self.authorize("controller")
                if path == PREFIX + "status":
                    result = self.server.store.status()
                else:
                    result = self.server.store.get_job(path[len(PREFIX + "jobs/"):])
            elif method == "POST" and path == PREFIX + "jobs":
                self.authorize("controller")
                result = self.server.store.enqueue(self.read_body(MAX_COMMAND + ENVELOPE_ALLOWANCE))
            elif method == "POST" and path in {PREFIX + name for name in ("connect", "heartbeat", "poll", "result", "disconnect")}:
                self.authorize("worker")
                operation = path[len(PREFIX):]
                if operation == "result":
                    result = self.server.store.result(self.read_body(MAX_RESULT + ENVELOPE_ALLOWANCE))
                else:
                    body = self.read_body(ENVELOPE_ALLOWANCE)
                    require_fields(body, ("session_id",))
                    session_id = require_session(body)
                    operation = "connect_session" if operation == "connect" else operation
                    result = getattr(self.server.store, operation)(session_id)
            else:
                raise BrokerError(404, "not_found")
            self.reply(200, result)
        except (BrokerError, AuthError) as exc:
            self.reply(exc.status, {"ok": False, "error": exc.code})
        except (ValueError, UnicodeError, RecursionError):
            self.reply(400, {"ok": False, "error": "invalid_request"})
        except TimeoutError:
            self.reply(408, {"ok": False, "error": "request_timeout"})
        except sqlite3.Error:
            self.reply(503, {"ok": False, "error": "storage_unavailable"})
        except Exception:
            self.reply(500, {"ok": False, "error": "internal_error"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8770)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--init-only", action="store_true")
    parser.add_argument("--set-account", action="store_true", help="Set the local login/password and revoke previous sessions")
    parser.add_argument("--public-url", help="Canonical HTTPS origin used by the browser approval page")
    parser.add_argument("--account-only", action="store_true", help="Require account authentication; never enable legacy keys")
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("Invalid port")
    if args.set_account:
        username = input("Логин Remote222: ").strip()
        password = getpass.getpass("Пароль Remote222 (не отображается): ")
        repeated = getpass.getpass("Повторите пароль: ")
        if password != repeated:
            parser.error("Passwords do not match")
        try:
            AccountStore(args.state_dir / "auth.sqlite3").set_account(username, password)
        except ValueError as exc:
            parser.error(str(exc))
        print("Учётная запись сохранена. Прежние сеансы отозваны; старые ключи отключены в новом сервере.")
        return
    account_path = args.state_dir / "auth.sqlite3"
    account_configured = account_path.exists() and AccountStore(account_path).configured()
    if args.account_only and not account_configured:
        parser.error("Account mode requires a configured local account; run --set-account in the private VPS console")
    if account_configured:
        controller_token, worker_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    else:
        controller_token = os.environ.get("REMOTE222_CONTROLLER_TOKEN")
        worker_token = os.environ.get("REMOTE222_WORKER_TOKEN")
    if controller_token is not None or worker_token is not None:
        if (not controller_token or not worker_token or not TOKEN.fullmatch(controller_token)
                or not TOKEN.fullmatch(worker_token) or secrets.compare_digest(controller_token, worker_token)):
            parser.error("Set two different valid REMOTE222_CONTROLLER_TOKEN and REMOTE222_WORKER_TOKEN credentials")
    else:
        controller_token, worker_token = prepare_state(args.state_dir)
        for name in ("controller.token", "worker.token"):
            print(f"Credential file: {args.state_dir / name} (value not displayed)")
    if args.init_only:
        return
    server = BrokerServer(args.port, args.state_dir, controller_token, worker_token, args.host,
                          public_url=args.public_url, account_only=args.account_only)
    print(f"Remote222 broker listening on {args.host}:{server.server_port}. Use a configured HTTPS reverse proxy.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
