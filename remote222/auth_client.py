"""Account sign-in and private, URL-bound sessions shared by desktop and CLI."""

import http.client
import json
import math
import os
from pathlib import Path
import re
import ssl
import stat
import tempfile
import time
import urllib.error
import urllib.request

from .client import ClientError, NoRedirects, normalize_url


SESSION_TOKEN = re.compile(r"^[A-Za-z0-9_-]{43,256}$")
USER_CODE = re.compile(r"^[A-Z0-9][A-Z0-9-]{3,31}$")
ROLES = {"worker", "controller"}
SAFE_ERRORS = {
    "unauthorized", "invalid_credentials", "invalid_request", "invalid_role",
    "invalid_code", "expired", "expired_code", "device_expired", "device_not_found",
    "access_denied", "rate_limited", "too_many_requests", "account_not_configured",
    "account_disabled", "session_expired", "session_revoked", "invalid_session",
    "authorization_pending", "slow_down", "not_found", "method_not_allowed",
    "session_limit", "invalid_label", "invalid_device_code", "invalid_user_code",
    "invalid_csrf", "invalid_origin", "denied", "already_decided", "try_again",
    "browser_origin_not_allowed",
}


class AuthConnectionError(ClientError):
    """A transport failure that is safe to retry for idempotent device polling."""


class AuthHTTPError(ClientError):
    def __init__(self, status, code):
        self.status = status
        super().__init__(f"HTTP {status}: {code}")


def _object(value):
    if not isinstance(value, dict) or value.get("ok") is not True:
        raise ClientError("Invalid account server response")
    return value


def _session(value, expected_role=None, *, require_token=True):
    value = _object(value)
    role, expires_at = value.get("role"), value.get("expires_at")
    if not isinstance(role, str) or role not in ROLES or (expected_role is not None and role != expected_role):
        raise ClientError("Invalid account session role")
    if type(expires_at) not in {int, float} or not math.isfinite(expires_at) or expires_at <= time.time():
        raise ClientError("Account session expired; sign in again")
    token = value.get("session_token")
    if require_token and (not isinstance(token, str) or not SESSION_TOKEN.fullmatch(token)):
        raise ClientError("Invalid account session response")
    return value


class AuthClient:
    """HTTPS account API. Login passwords are transmitted only to the chosen URL."""

    def __init__(self, url, session_token=None):
        self.url = normalize_url(url)
        if session_token is not None and (not isinstance(session_token, str) or not SESSION_TOKEN.fullmatch(session_token)):
            raise ClientError("Invalid account session")
        self.session_token = session_token
        self.opener = urllib.request.build_opener(NoRedirects())

    def _request(self, path, body=None, *, authenticated=False, timeout=15):
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if authenticated:
            if self.session_token is None:
                raise ClientError("Sign in before using the account session")
            headers["Authorization"] = "Bearer " + self.session_token
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(self.url + path, data=data, headers=headers)
        try:
            with self.opener.open(request, timeout=timeout) as response:
                raw = response.read(16385)
                if len(raw) > 16384:
                    raise ClientError("Account server response is too large")
                try:
                    value = json.loads(raw)
                except (ValueError, UnicodeError):
                    raise ClientError("Invalid account server response") from None
                return _object(value)
        except urllib.error.HTTPError as exc:
            # Even JSON error fields are untrusted and may reflect credentials.
            try:
                payload = json.loads(exc.read(8192))
                code = payload.get("error") if isinstance(payload, dict) else None
            except (ValueError, OSError):
                code = None
            code = code if isinstance(code, str) and code in SAFE_ERRORS else "account_request_failed"
            raise AuthHTTPError(exc.code, code) from None
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, ssl.SSLCertVerificationError):
                raise ClientError("Account HTTPS certificate verification failed; check the server address and certificate") from None
            raise AuthConnectionError("Account connection failed; check the server address and HTTPS certificate") from None
        except ssl.SSLCertVerificationError:
            raise ClientError("Account HTTPS certificate verification failed; check the server address and certificate") from None
        except (TimeoutError, ConnectionError, OSError, http.client.HTTPException):
            raise AuthConnectionError("Account connection failed; check the server address and HTTPS certificate") from None

    def login(self, username, password, role="worker"):
        if not isinstance(role, str) or role not in ROLES or not isinstance(username, str) or not isinstance(password, str) or not username or not password:
            raise ClientError("Enter an account login and password")
        result = _session(self._request("/auth/v1/login", {
            "username": username, "password": password, "role": role,
        }), role)
        self.session_token = result["session_token"]
        return result

    def session(self):
        return _session(self._request("/auth/v1/session", authenticated=True), require_token=False)

    def logout(self):
        result = self._request("/auth/v1/logout", {}, authenticated=True)
        self.session_token = None
        return result

    def device_start(self, label="Codex"):
        result = self._request("/auth/v1/device/start", {"label": label})
        code, user_code = result.get("device_code"), result.get("user_code")
        expires_in, interval = result.get("expires_in"), result.get("interval")
        if (not isinstance(code, str) or not SESSION_TOKEN.fullmatch(code)
                or not isinstance(user_code, str) or not USER_CODE.fullmatch(user_code)
                or result.get("verification_path") != "/connect"
                or type(expires_in) not in {int, float} or not math.isfinite(expires_in) or not 0 < expires_in <= 900
                or type(interval) not in {int, float} or not math.isfinite(interval) or not 0.1 <= interval <= 30):
            raise ClientError("Invalid device sign-in response")
        return result

    def device_poll(self, device_code, *, timeout=15):
        if not isinstance(device_code, str) or not SESSION_TOKEN.fullmatch(device_code):
            raise ClientError("Invalid device sign-in session")
        result = self._request("/auth/v1/device/poll", {"device_code": device_code}, timeout=timeout)
        if result.get("status") == "pending":
            return result
        if result.get("status") != "approved":
            raise ClientError("Device sign-in was declined or expired; start a new connection")
        result = _session(result, "controller")
        self.session_token = result["session_token"]
        return result


def default_session_path(role="controller"):
    if role not in ROLES:
        raise ClientError("Invalid account session role")
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "Remote222"
    else:
        base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "remote222"
    return base / "auth" / (role + ".json")


class SessionStore:
    """An atomic private profile; passwords and unrelated response data are excluded."""

    def __init__(self, path):
        self.path = Path(path).expanduser().absolute()

    def _check_links(self):
        for part in (self.path, *self.path.parents):
            if part.is_symlink() or getattr(part, "is_junction", lambda: False)():
                raise ClientError("Session path must not contain symbolic links")

    def _parent(self, *, create=False):
        self._check_links()
        parent = self.path.parent
        created = create and not parent.exists()
        if create:
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not parent.is_dir():
            raise ClientError("Saved account session not found; connect first")
        if os.name == "nt":
            from .session import protect_private_state, verify_private_state
            if created:
                protect_private_state(parent)
            verify_private_state(parent)
        else:
            details = parent.stat()
            if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o077:
                raise ClientError("Session directory must be owned by you and have permissions 0700; choose a private directory")
        self._check_links()

    @staticmethod
    def _profile(url, session):
        if not isinstance(session, dict):
            raise ClientError("Invalid account session response")
        session = _session({**session, "ok": True})
        return {"version": 1, "url": normalize_url(url), "role": session["role"],
                "expires_at": session["expires_at"], "session_token": session["session_token"]}

    def save(self, url, session_response):
        profile = self._profile(url, session_response)
        temporary = None
        try:
            self._parent(create=True)
            if self.path.exists() and not self.path.is_file():
                raise ClientError("Session path must be a regular file")
            descriptor, temporary = tempfile.mkstemp(prefix=".session-", dir=self.path.parent)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(profile, stream, separators=(",", ":"), allow_nan=False)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            self._check_links()
            os.replace(temporary, self.path)
            temporary = None
            return profile
        except OSError:
            raise ClientError("Could not save the private account session") from None
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    def load(self, expected_url=None, role="controller"):
        try:
            self._parent()
            if os.name == "nt":
                from .session import verify_private_state
                verify_private_state(self.path)
            descriptor = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as stream:
                details = os.fstat(stream.fileno())
                if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
                    raise ClientError("Session path must be a private regular file")
                if os.name != "nt" and (details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o077):
                    raise ClientError("Session file must be owned by you and have permissions 0600")
                raw = stream.read(16385)
            if len(raw) > 16384:
                raise ClientError("Invalid saved account session")
            profile = json.loads(raw)
            if not isinstance(profile, dict) or profile.get("version") != 1:
                raise ClientError("Invalid saved account session")
            canonical = normalize_url(profile.get("url"))
            if profile["url"] != canonical:
                raise ClientError("Invalid saved account server URL")
            if expected_url is not None and normalize_url(expected_url) != canonical:
                raise ClientError("Saved session belongs to a different server; connect a separate profile")
            _session({**profile, "ok": True}, role)
            return self._profile(canonical, profile)
        except FileNotFoundError:
            raise ClientError("Saved account session not found; connect first") from None
        except (OSError, ValueError, TypeError):
            raise ClientError("Could not read the private account session") from None

    def delete(self):
        try:
            self._check_links()
            if not self.path.exists():
                return
            self._parent()
            if not self.path.is_file():
                raise ClientError("Session path must be a regular file")
            self.path.unlink()
        except OSError:
            raise ClientError("Could not remove the private account session") from None
