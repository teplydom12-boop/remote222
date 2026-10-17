"""Private single-account authentication and browser-approved controller pairing."""

import base64
from contextlib import contextmanager
import hashlib
import hmac
from http.cookies import SimpleCookie
import html
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time
from urllib.parse import parse_qs, urlsplit

SESSION_SECONDS = 30 * 24 * 60 * 60
PAIR_SECONDS = 10 * 60
AUTH_LIMIT = 16 * 1024
PBKDF_ROUNDS = 600_000
ROLES = {"worker", "controller"}
OPAQUE = re.compile(r"^[A-Za-z0-9_-]{43}$")
USER_CODE = re.compile(r"^[A-Z2-9]{4}-[A-Z2-9]{4}$")


class AuthError(Exception):
    def __init__(self, status, code):
        super().__init__(code)
        self.status, self.code = status, code


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class AccountStore:
    """Passwords and issued session bearers are never written to disk."""

    def __init__(self, path, *, clock=None):
        self.path = str(path)
        self.clock = clock or time.time
        parent = Path(path).parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            parent.chmod(0o700)
        fd = os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
        if os.name != "nt":
            Path(self.path).chmod(0o600)
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS account (singleton INTEGER PRIMARY KEY CHECK(singleton=1), username TEXT NOT NULL, salt BLOB NOT NULL, password_hash BLOB NOT NULL, pairing_secret BLOB NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS auth_sessions (token_hash TEXT PRIMARY KEY, role TEXT NOT NULL, expires REAL NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS pairings (device_hash TEXT PRIMARY KEY, user_code TEXT UNIQUE NOT NULL, label TEXT NOT NULL, expires REAL NOT NULL, status TEXT NOT NULL, session_expires REAL, session_hash TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS csrf (token_hash TEXT PRIMARY KEY, expires REAL NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS limits (name TEXT PRIMARY KEY, window REAL NOT NULL, count INTEGER NOT NULL)")

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
    def _password(password, salt):
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF_ROUNDS)

    def configured(self):
        with self.connect() as db:
            return db.execute("SELECT 1 FROM account").fetchone() is not None

    def set_account(self, username, password):
        if (not isinstance(username, str) or not 1 <= len(username) <= 64
                or username != username.strip() or any(ord(c) < 32 for c in username)):
            raise ValueError("Username must contain 1 to 64 characters without surrounding whitespace")
        if not isinstance(password, str) or not 8 <= len(password) <= 1024:
            raise ValueError("Password must contain 8 to 1024 characters")
        salt = secrets.token_bytes(32)
        hashed = self._password(password, salt)
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO account VALUES (1, ?, ?, ?, ?)",
                       (username, salt, hashed, secrets.token_bytes(32)))
            db.execute("DELETE FROM auth_sessions")
            db.execute("DELETE FROM pairings")
            db.execute("DELETE FROM csrf")
            db.execute("DELETE FROM limits")

    def _limit(self, name, maximum, seconds):
        # Commit attempts separately: an authentication failure must still count.
        with self.connect() as db:
            now = self.clock()
            db.execute("DELETE FROM limits WHERE window < ?", (now - 3600,))
            row = db.execute("SELECT window, count FROM limits WHERE name=?", (name,)).fetchone()
            if row and now - row["window"] < seconds:
                if row["count"] >= maximum:
                    raise AuthError(429, "rate_limited")
                db.execute("UPDATE limits SET count=count+1 WHERE name=?", (name,))
            else:
                db.execute("INSERT OR REPLACE INTO limits VALUES (?, ?, 1)", (name, now))

    def _verify_password(self, db, username, password):
        if (not isinstance(username, str) or not isinstance(password, str)
                or len(username) > 64 or len(password) > 1024):
            raise AuthError(401, "unauthorized")
        row = db.execute("SELECT * FROM account").fetchone()
        if row is None:
            raise AuthError(409, "account_not_configured")
        hashed = self._password(password, row["salt"])
        if (not secrets.compare_digest(username.encode("utf-8"), row["username"].encode("utf-8"))
                or not secrets.compare_digest(hashed, row["password_hash"])):
            raise AuthError(401, "unauthorized")
        return row

    def _cleanup(self, db, now):
        db.execute("DELETE FROM auth_sessions WHERE expires<=?", (now,))
        db.execute("DELETE FROM pairings WHERE expires<=?", (now,))
        db.execute("DELETE FROM csrf WHERE expires<=?", (now,))

    def login(self, username, password, role):
        if not isinstance(role, str) or role not in ROLES:
            raise AuthError(400, "invalid_role")
        self._limit("password", 20, 300)
        with self.connect() as db:
            self._verify_password(db, username, password)
            now = self.clock()
            self._cleanup(db, now)
            if db.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0] >= 100:
                raise AuthError(409, "session_limit")
            token = secrets.token_urlsafe(32)
            expires = now + SESSION_SECONDS
            db.execute("INSERT INTO auth_sessions VALUES (?, ?, ?)", (digest(token), role, expires))
        return {"ok": True, "session_token": token, "expires_at": expires, "role": role}

    def authorize(self, token, role=None):
        if not isinstance(token, str) or not OPAQUE.fullmatch(token):
            raise AuthError(401, "unauthorized")
        with self.connect() as db:
            if not db.execute("SELECT 1 FROM account").fetchone():
                raise AuthError(401, "unauthorized")
            row = db.execute("SELECT * FROM auth_sessions WHERE token_hash=?", (digest(token),)).fetchone()
            if row is None or row["expires"] <= self.clock() or (role is not None and role != row["role"]):
                raise AuthError(401, "unauthorized")
            return {"ok": True, "role": row["role"], "expires_at": row["expires"]}

    def logout(self, token):
        self.authorize(token)
        with self.connect() as db:
            token_hash = digest(token)
            db.execute("DELETE FROM auth_sessions WHERE token_hash=?", (token_hash,))
            db.execute("UPDATE pairings SET status='denied' WHERE session_hash=?", (token_hash,))
        return {"ok": True}

    def start_device(self, label):
        if not isinstance(label, str) or not 1 <= len(label) <= 100 or any(ord(c) < 32 for c in label):
            raise AuthError(400, "invalid_label")
        self._limit("device_start", 20, 600)
        device_code = secrets.token_urlsafe(32)
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        with self.connect() as db:
            if not db.execute("SELECT 1 FROM account").fetchone():
                raise AuthError(409, "account_not_configured")
            now = self.clock()
            self._cleanup(db, now)
            for _ in range(10):
                value = "".join(secrets.choice(alphabet) for _ in range(8))
                user_code = value[:4] + "-" + value[4:]
                if not db.execute("SELECT 1 FROM pairings WHERE user_code=?", (user_code,)).fetchone():
                    break
            else:
                raise AuthError(503, "try_again")
            db.execute("INSERT INTO pairings VALUES (?, ?, ?, ?, 'pending', NULL, NULL)",
                       (digest(device_code), user_code, label, now + PAIR_SECONDS))
        return {"ok": True, "device_code": device_code, "user_code": user_code,
                "expires_in": PAIR_SECONDS, "interval": 3, "verification_path": "/connect"}

    def poll_device(self, device_code):
        if not isinstance(device_code, str) or not OPAQUE.fullmatch(device_code):
            raise AuthError(400, "invalid_device_code")
        self._limit("device_poll", 2000, 600)
        with self.connect() as db:
            now = self.clock()
            row = db.execute("SELECT * FROM pairings WHERE device_hash=?", (digest(device_code),)).fetchone()
            if row is None or row["expires"] <= now:
                raise AuthError(410, "expired")
            if row["status"] == "denied":
                raise AuthError(403, "denied")
            if row["status"] == "pending":
                return {"ok": True, "status": "pending"}
            account = db.execute("SELECT pairing_secret FROM account").fetchone()
            token = base64.urlsafe_b64encode(hmac.digest(account[0], device_code.encode("ascii"), "sha256")).decode("ascii").rstrip("=")
            token_hash = digest(token)
            if row["session_hash"] is None:
                self._cleanup(db, now)
                if db.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0] >= 100:
                    raise AuthError(409, "session_limit")
                db.execute("INSERT INTO auth_sessions VALUES (?, 'controller', ?)", (token_hash, row["session_expires"]))
                db.execute("UPDATE pairings SET session_hash=? WHERE device_hash=?", (token_hash, digest(device_code)))
            elif not db.execute("SELECT 1 FROM auth_sessions WHERE token_hash=?", (token_hash,)).fetchone():
                raise AuthError(403, "denied")
            return {"ok": True, "status": "approved", "session_token": token,
                    "expires_at": row["session_expires"], "role": "controller"}

    def browser_challenge(self):
        self._limit("browser_form", 100, 600)
        token = secrets.token_urlsafe(32)
        with self.connect() as db:
            now = self.clock()
            self._cleanup(db, now)
            db.execute("INSERT INTO csrf VALUES (?, ?)", (digest(token), now + PAIR_SECONDS))
        return token

    def approve_device(self, user_code, username, password, csrf, decision="approve"):
        if not isinstance(csrf, str) or not OPAQUE.fullmatch(csrf):
            raise AuthError(403, "invalid_csrf")
        if not isinstance(user_code, str) or not USER_CODE.fullmatch(user_code.upper()):
            raise AuthError(400, "invalid_user_code")
        if decision not in {"approve", "deny"}:
            raise AuthError(400, "invalid_request")
        self._limit("password", 20, 300)
        with self.connect() as db:
            now = self.clock()
            challenge = db.execute("SELECT expires FROM csrf WHERE token_hash=?", (digest(csrf),)).fetchone()
            if challenge is None or challenge[0] <= now:
                raise AuthError(403, "invalid_csrf")
            self._verify_password(db, username, password)
            row = db.execute("SELECT * FROM pairings WHERE user_code=?", (user_code.upper(),)).fetchone()
            if row is None or row["expires"] <= now:
                raise AuthError(410, "expired")
            if row["status"] != "pending":
                raise AuthError(409, "already_decided")
            db.execute("DELETE FROM csrf WHERE token_hash=?", (digest(csrf),))
            status = "approved" if decision == "approve" else "denied"
            db.execute("UPDATE pairings SET status=?, session_expires=? WHERE user_code=?", (status, now + SESSION_SECONDS, row["user_code"]))
        return {"ok": True, "status": status}


def _fields(body, fields):
    if not isinstance(body, dict) or set(body) != set(fields):
        raise AuthError(400, "invalid_request")


def _bearer(handler):
    values = handler.headers.get_all("Authorization", [])
    if len(values) != 1 or not values[0].startswith("Bearer "):
        raise AuthError(401, "unauthorized")
    return values[0][7:]


def _page(handler, title, content, *, cookie=None):
    body = ("<!doctype html><html lang='ru'><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1'>"
            f"<title>{html.escape(title)}</title><body><main><h1>{html.escape(title)}</h1>"
            f"{content}</main></body></html>").encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    # HTML form navigations use Origin:null with no-referrer in Chromium.
    # Keep the same-origin POST identifiable without sending cross-site referrers.
    handler.send_header("Referrer-Policy", "same-origin")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("X-Frame-Options", "DENY")
    handler.send_header("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
    handler.send_header("Connection", "close")
    if cookie:
        handler.send_header("Set-Cookie", f"remote222_csrf={cookie}; Path=/connect; Secure; HttpOnly; SameSite=Strict; Max-Age={PAIR_SECONDS}")
    handler.end_headers()
    handler.wfile.write(body)
    handler.close_connection = True


def handle_auth(handler, method):
    """Return True when an authentication endpoint has handled the request."""
    path = urlsplit(handler.path)
    store = handler.server.accounts
    if path.path == "/connect" and method == "GET":
        query = parse_qs(path.query, keep_blank_values=True, max_num_fields=2)
        if set(query) - {"code"} or len(query.get("code", [])) > 1:
            raise AuthError(400, "invalid_request")
        code = query.get("code", [""])[0]
        if code and not USER_CODE.fullmatch(code.upper()):
            raise AuthError(400, "invalid_user_code")
        csrf = store.browser_challenge()
        form = ("<p>Разрешите управление только тому чату, в котором вы запросили подключение. "
                "Сверьте код с сообщением в этом чате. Разрешение действует 30 дней.</p>"
                "<form method='post' action='/connect'>"
                f"<input type='hidden' name='csrf' value='{csrf}'>"
                f"<p><label>Код из чата <input name='code' value='{html.escape(code, quote=True)}' required maxlength='9' autocomplete='off'></label></p>"
                "<p><label>Логин <input name='username' required maxlength='64' autocomplete='username'></label></p>"
                "<p><label>Пароль <input type='password' name='password' required maxlength='1024' autocomplete='current-password'></label></p>"
                "<button name='decision' value='approve'>Разрешить подключение</button> "
                "<button name='decision' value='deny'>Отклонить</button></form>")
        _page(handler, "Подключение Remote222", form, cookie=csrf)
        return True
    if path.path == "/connect" and method == "POST" and not path.query:
        hosts, origins = handler.headers.get_all("Host", []), handler.headers.get_all("Origin", [])
        expected_origin = handler.server.public_origin or ("https://" + hosts[0] if len(hosts) == 1 else None)
        if len(hosts) != 1 or len(origins) != 1 or origins[0] != expected_origin:
            raise AuthError(403, "invalid_origin")
        if handler.headers.get("Sec-Fetch-Site") not in (None, "same-origin", "none"):
            raise AuthError(403, "invalid_origin")
        if (handler.headers.get("Transfer-Encoding") or len(handler.headers.get_all("Content-Length", [])) != 1
                or handler.headers.get_content_type() != "application/x-www-form-urlencoded"):
            raise AuthError(400, "invalid_request")
        try:
            length = int(handler.headers["Content-Length"])
        except ValueError:
            raise AuthError(400, "invalid_request") from None
        if not 1 <= length <= AUTH_LIMIT:
            raise AuthError(413, "request_too_large")
        raw = handler.rfile.read(length)
        if len(raw) != length:
            raise AuthError(400, "invalid_request")
        fields = parse_qs(raw.decode("utf-8"), keep_blank_values=True, max_num_fields=6, strict_parsing=True)
        if set(fields) != {"code", "username", "password", "csrf", "decision"} or any(len(v) != 1 for v in fields.values()):
            raise AuthError(400, "invalid_request")
        fields = {key: value[0] for key, value in fields.items()}
        cookie = SimpleCookie()
        cookie.load(handler.headers.get("Cookie", ""))
        value = cookie.get("remote222_csrf")
        if value is None or not secrets.compare_digest(value.value.encode("utf-8"), fields["csrf"].encode("utf-8")):
            raise AuthError(403, "invalid_csrf")
        result = store.approve_device(fields["code"], fields["username"], fields["password"], fields["csrf"], fields["decision"])
        text = "Подключение разрешено. Можно вернуться в чат." if result["status"] == "approved" else "Подключение отклонено."
        _page(handler, "Remote222", f"<p>{text}</p>")
        return True
    if not path.path.startswith("/auth/v1/") or path.query:
        return False
    if handler.headers.get("Origin"):
        raise AuthError(403, "browser_origin_not_allowed")
    if method == "GET" and path.path == "/auth/v1/meta":
        result = {"ok": True, "configured": store.configured()}
    elif method == "GET" and path.path == "/auth/v1/session":
        result = store.authorize(_bearer(handler))
    elif method == "POST" and path.path == "/auth/v1/logout":
        result = store.logout(_bearer(handler))
    elif method == "POST" and path.path in {"/auth/v1/login", "/auth/v1/device/start", "/auth/v1/device/poll"}:
        body = handler.read_body(AUTH_LIMIT)
        if path.path == "/auth/v1/login":
            _fields(body, ("username", "password", "role"))
            result = store.login(body["username"], body["password"], body["role"])
        elif path.path.endswith("/start"):
            _fields(body, ("label",))
            result = store.start_device(body["label"])
        else:
            _fields(body, ("device_code",))
            result = store.poll_device(body["device_code"])
    else:
        return False
    handler.reply(200, result)
    return True
