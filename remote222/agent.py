"""Loopback-only authenticated agent, intended to sit behind an HTTPS tunnel."""

import argparse
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import secrets
import sqlite3
import threading

from .actions import ActionError, execute

MAX_BODY = 2 * 1024 * 1024
MAX_RESPONSE = 8 * 1024 * 1024
REQUEST_ID = re.compile(r"^[a-zA-Z0-9_-]{8,80}$")


def default_state_dir():
    if os.name == "nt":
        return Path(os.environ["LOCALAPPDATA"]) / "Remote222"
    return Path.home() / ".local" / "state" / "remote222"


def prepare_state(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        path.chmod(0o700)
    token_path = path / "access.token"
    try:
        fd = os.open(token_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(secrets.token_urlsafe(32) + "\n")
    token = token_path.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", token):
        raise ValueError("Invalid access.token; stop the agent and regenerate the key")
    if os.name != "nt":
        token_path.chmod(0o600)
    return token


class Store:
    """Retain request IDs indefinitely so old commands are never replayed."""

    def __init__(self, path):
        self.path = str(path)
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS commands (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, response TEXT, created TEXT NOT NULL)")

    def connect(self):
        return sqlite3.connect(self.path, timeout=10)

    def lookup(self, request_id):
        with self.connect() as db:
            return db.execute("SELECT fingerprint, response FROM commands WHERE id = ?", (request_id,)).fetchone()

    def reserve(self, request_id, fingerprint):
        with self.connect() as db:
            db.execute("INSERT INTO commands VALUES (?, ?, NULL, ?)",
                       (request_id, fingerprint, datetime.now(timezone.utc).isoformat()))

    def complete(self, request_id, response):
        with self.connect() as db:
            db.execute("UPDATE commands SET response = ? WHERE id = ?", (response, request_id))
            # Results can include personal data. Keep only 100 payloads; preserve all IDs.
            db.execute("UPDATE commands SET response = ? WHERE response IS NOT NULL AND id NOT IN (SELECT id FROM commands ORDER BY rowid DESC LIMIT 100)",
                       (json.dumps({"ok": False, "error": "result_expired", "message": "Already processed; result was removed. Command will not run again."}),))


class AgentServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, port, state_dir, token):
        self.token = token
        self.store = Store(state_dir / "commands.sqlite3")
        self.action_lock = threading.Lock()
        self.logger = logging.getLogger(f"remote222.{state_dir}")
        self.logger.setLevel(logging.INFO)
        self.log_handler = RotatingFileHandler(state_dir / "audit.log", maxBytes=1024 * 1024, backupCount=2, encoding="utf-8")
        self.log_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        self.logger.addHandler(self.log_handler)
        super().__init__(("127.0.0.1", port), Handler)

    def server_close(self):
        super().server_close()
        self.logger.removeHandler(self.log_handler)
        self.log_handler.close()


class Handler(BaseHTTPRequestHandler):
    server_version = "Remote222"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, *args):
        # Do not log request headers, shell commands, tokens, or paths.
        pass

    def reply(self, status, payload):
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
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

    def authorized(self):
        supplied = self.headers.get_all("Authorization", [])
        if len(supplied) != 1 or not secrets.compare_digest(
            supplied[0].encode("utf-8"), ("Bearer " + self.server.token).encode("utf-8")
        ):
            self.reply(401, {"ok": False, "error": "unauthorized"})
            return False
        if self.headers.get("Origin"):
            self.reply(403, {"ok": False, "error": "browser_origin_not_allowed"})
            return False
        return True

    def do_GET(self):
        if not self.authorized():
            return
        if self.path != "/v1/info":
            self.reply(404, {"ok": False, "error": "not_found"})
            return
        self.reply(200, {"ok": True, "result": execute("info", {})})

    def do_POST(self):
        if not self.authorized():
            return
        if self.path != "/v1/actions":
            self.reply(404, {"ok": False, "error": "not_found"})
            return
        if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
            self.reply(400, {"ok": False, "error": "content_length_required"})
            return
        if self.headers.get_content_type() != "application/json":
            self.reply(415, {"ok": False, "error": "json_required"})
            return
        try:
            length = int(self.headers["Content-Length"])
            if not 1 <= length <= MAX_BODY:
                self.reply(413, {"ok": False, "error": "request_too_large"})
                return
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("Incomplete body")
            body = json.loads(raw)
            if not isinstance(body, dict) or set(body) != {"id", "action", "args"}:
                raise ValueError("Expected id, action, args")
            request_id, action, args = body["id"], body["action"], body["args"]
            if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
                raise ValueError("Invalid id")
            if not isinstance(action, str) or len(action) > 32 or not isinstance(args, dict):
                raise ValueError("Invalid action or args")
        except (ValueError, UnicodeError, TimeoutError, RecursionError):
            self.reply(400, {"ok": False, "error": "invalid_request"})
            return
        fingerprint = hashlib.sha256(json.dumps([action, args], sort_keys=True).encode()).hexdigest()
        if not self.server.action_lock.acquire(blocking=False):
            self.reply(409, {"ok": False, "error": "agent_busy", "message": "Retry later with the same request ID"})
            return
        try:
            previous = self.server.store.lookup(request_id)
            if previous:
                if previous[0] != fingerprint:
                    self.reply(409, {"ok": False, "error": "id_conflict"})
                elif previous[1] is None:
                    self.reply(409, {"ok": False, "error": "outcome_unknown", "message": "Agent stopped during this request. Inspect the computer before issuing a new command."})
                else:
                    self.reply(200, json.loads(previous[1]))
                return
            self.server.store.reserve(request_id, fingerprint)
            self.server.logger.info("id=%s action=%s started", request_id, action if action.isalpha() else "invalid")
            try:
                result = execute(action, args)
                payload = {"ok": True, "id": request_id, "result": result}
            except (ActionError, OSError, ValueError, TimeoutError) as exc:
                payload = {"ok": False, "id": request_id, "error": "action_failed", "message": str(exc)[:2000]}
            except Exception:
                payload = {"ok": False, "id": request_id, "error": "action_failed", "message": "Internal action error; inspect the local agent"}
            encoded = json.dumps(payload, ensure_ascii=True)
            if len(encoded) > MAX_RESPONSE:
                payload = {"ok": False, "id": request_id, "error": "result_too_large"}
                encoded = json.dumps(payload)
            self.server.store.complete(request_id, encoded)
            self.server.logger.info("id=%s action=%s ok=%s", request_id, action if action.isalpha() else "invalid", payload["ok"])
            self.reply(200, payload)
        finally:
            self.server.action_lock.release()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--state-dir", type=Path, default=default_state_dir())
    parser.add_argument("--init-only", action="store_true")
    parser.add_argument("--allow-full-control", action="store_true",
                        help="Explicitly allow commands with this account's privileges")
    args = parser.parse_args()
    if not args.init_only and not args.allow_full_control:
        parser.error("Starting the agent requires --allow-full-control")
    if not 0 <= args.port <= 65535:
        parser.error("Invalid port")
    token = prepare_state(args.state_dir)
    if args.init_only:
        print(f"Key file prepared: {args.state_dir / 'access.token'} (value not displayed)")
        return
    server = AgentServer(args.port, args.state_dir, token)
    print(f"Remote222: full account control enabled on loopback port {server.server_port}.", flush=True)
    print("Keep this console open. Ctrl+C stops the agent. No automatic startup is installed.", flush=True)
    print(f"Audit log: {args.state_dir / 'audit.log'}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nAgent stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
