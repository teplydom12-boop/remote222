import contextlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.error
import urllib.parse
import urllib.request
import uuid

from remote222.auth_server import AccountStore, AuthError, PAIR_SECONDS, SESSION_SECONDS
from remote222.broker import BrokerServer, main


class AccountTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = 1000.0
        self.path = Path(self.temp.name) / "auth.sqlite3"
        self.store = AccountStore(self.path, clock=lambda: self.now)
        self.username, self.password = "owner", "a local password phrase"
        self.store.set_account(self.username, self.password)

    def assertError(self, code, method, *args):
        with self.assertRaises(AuthError) as caught:
            method(*args)
        self.assertEqual(caught.exception.code, code)

    def approve(self, request, decision="approve"):
        return self.store.approve_device(request["user_code"], self.username, self.password,
                                         self.store.browser_challenge(), decision)

    def test_passwords_roles_expiry_and_revocation(self):
        self.assertError("unauthorized", self.store.login, self.username, "wrong", "controller")
        self.assertError("unauthorized", self.store.login, "stranger", self.password, "controller")
        self.assertError("invalid_role", self.store.login, self.username, self.password, "admin")
        worker = self.store.login(self.username, self.password, "worker")
        self.assertEqual(self.store.authorize(worker["session_token"], "worker")["role"], "worker")
        self.assertError("unauthorized", self.store.authorize, worker["session_token"], "controller")
        controller = self.store.login(self.username, self.password, "controller")
        self.store.logout(controller["session_token"])
        self.assertError("unauthorized", self.store.authorize, controller["session_token"])
        self.now += SESSION_SECONDS
        self.assertError("unauthorized", self.store.authorize, worker["session_token"])

    def test_persistent_hashes_do_not_contain_password_or_session_bearer(self):
        login = self.store.login(self.username, self.password, "controller")
        pairing = self.store.start_device("Chat")
        self.approve(pairing)
        session = self.store.poll_device(pairing["device_code"])
        reopened = AccountStore(self.path, clock=lambda: self.now)
        self.assertEqual(reopened.authorize(login["session_token"])["role"], "controller")
        self.assertEqual(reopened.poll_device(pairing["device_code"]), session)
        raw = self.path.read_bytes()
        for value in (self.password, login["session_token"], pairing["device_code"], session["session_token"]):
            self.assertNotIn(value.encode(), raw)
        if os.name != "nt":
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_pairing_approval_retry_and_logout(self):
        request = self.store.start_device("This chat")
        self.assertEqual(self.store.poll_device(request["device_code"]), {"ok": True, "status": "pending"})
        self.approve(request)
        approved = self.store.poll_device(request["device_code"])
        self.assertEqual(approved["role"], "controller")
        self.assertEqual(self.store.poll_device(request["device_code"]), approved)
        self.assertError("unauthorized", self.store.authorize, approved["session_token"], "worker")
        self.store.logout(approved["session_token"])
        self.assertError("denied", self.store.poll_device, request["device_code"])

    def test_pairing_expiry_denial_and_account_reset(self):
        expired = self.store.start_device("Expired")
        self.now += PAIR_SECONDS
        self.assertError("expired", self.store.poll_device, expired["device_code"])
        denied = self.store.start_device("Denied")
        self.approve(denied, "deny")
        self.assertError("denied", self.store.poll_device, denied["device_code"])
        approved = self.store.start_device("Old account")
        self.approve(approved)
        token = self.store.poll_device(approved["device_code"])["session_token"]
        self.store.set_account("new-owner", "a different password")
        self.assertError("unauthorized", self.store.authorize, token)
        self.assertError("expired", self.store.poll_device, approved["device_code"])

    def test_csrf_is_required_and_approval_is_single_use(self):
        pairing = self.store.start_device("Chat")
        challenge = self.store.browser_challenge()
        args = (pairing["user_code"], self.username, self.password)
        self.assertError("invalid_csrf", self.store.approve_device, *args, secrets.token_urlsafe(32))
        self.assertError("unauthorized", self.store.approve_device, pairing["user_code"], self.username, "wrong", challenge)
        self.assertTrue(self.store.approve_device(*args, challenge)["ok"])
        self.assertError("invalid_csrf", self.store.approve_device, *args, challenge)
        self.assertError("already_decided", self.store.approve_device, *args, self.store.browser_challenge())

    def test_rate_limit_counts_failed_logins_and_survives_restart(self):
        for _ in range(20):
            self.assertError("unauthorized", self.store.login, self.username, "wrong", "controller")
        restarted = AccountStore(self.path, clock=lambda: self.now)
        self.assertError("rate_limited", restarted.login, self.username, self.password, "controller")
        self.now += 300
        self.assertTrue(restarted.login(self.username, self.password, "controller")["ok"])

    def test_device_requests_and_browser_forms_are_bounded(self):
        for _ in range(20):
            self.store.start_device("Chat")
        self.assertError("rate_limited", self.store.start_device, "Chat")
        self.assertError("invalid_label", self.store.start_device, "x" * 101)
        for _ in range(100):
            self.store.browser_challenge()
        self.assertError("rate_limited", self.store.browser_challenge)


class AuthHttpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.controller, self.worker = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        self.server = BrokerServer(0, self.temp.name, self.controller, self.worker, public_url="https://broker.example")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.password = "a local password phrase"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def request(self, path, *, body=None, token=None, headers=None, form=None):
        request_headers = dict(headers or {})
        if token is not None:
            request_headers["Authorization"] = "Bearer " + token
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif body is not None:
            data = json.dumps(body).encode()
            request_headers["Content-Type"] = "application/json"
        else:
            data = None
        request = urllib.request.Request(self.url + path, data=data, headers=request_headers)
        try:
            response = urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            raw = response.read().decode()
            payload = json.loads(raw) if response.headers.get_content_type() == "application/json" else raw
            return response.code, payload, response.headers

    def configure(self):
        self.server.accounts.set_account("owner", self.password)

    def login(self, role):
        code, body, _ = self.request("/auth/v1/login", body={"username": "owner", "password": self.password, "role": role})
        self.assertEqual(code, 200)
        return body["session_token"]

    def test_legacy_keys_stop_immediately_after_account_and_roles_remain_separate(self):
        self.assertFalse(self.request("/auth/v1/meta")[1]["configured"])
        self.assertEqual(self.request("/relay/v1/status", token=self.controller)[0], 200)
        self.configure()
        self.assertTrue(self.request("/auth/v1/meta")[1]["configured"])
        self.assertEqual(self.request("/relay/v1/status", token=self.controller)[0], 401)
        session = {"session_id": str(uuid.uuid4())}
        self.assertEqual(self.request("/relay/v1/connect", token=self.worker, body=session)[0], 401)
        worker, controller = self.login("worker"), self.login("controller")
        self.assertEqual(self.request("/relay/v1/connect", token=controller, body=session)[0], 401)
        self.assertEqual(self.request("/relay/v1/connect", token=worker, body=session)[0], 200)
        self.assertEqual(self.request("/relay/v1/status", token=worker)[0], 401)
        self.assertTrue(self.request("/relay/v1/status", token=controller)[1]["online"])
        self.assertEqual(self.request("/auth/v1/session", token=controller)[1]["role"], "controller")
        self.assertEqual(self.request("/auth/v1/logout", body={}, token=controller)[0], 200)
        self.assertEqual(self.request("/relay/v1/status", token=controller)[0], 401)
        self.assertEqual(self.request("/auth/v1/session", token=controller)[0], 401)

    def test_browser_origin_csrf_confirmation_and_pairing_flow(self):
        self.configure()
        _, device, _ = self.request("/auth/v1/device/start", body={"label": "This chat"})
        self.assertEqual(self.request("/auth/v1/device/poll", body={"device_code": device["device_code"]})[1]["status"], "pending")
        code, page, response_headers = self.request("/connect?code=" + device["user_code"])
        self.assertEqual(code, 200)
        self.assertIn("form-action 'self'", response_headers["Content-Security-Policy"])
        # With no-referrer, a real HTML form sends Origin:null even on the same
        # site. Preserve same-origin form navigation while rejecting foreign
        # origins and retaining the CSRF challenge/cookie checks below.
        self.assertEqual(response_headers["Referrer-Policy"], "same-origin")
        cookie = response_headers["Set-Cookie"]
        for attribute in ("Secure", "HttpOnly", "SameSite=Strict"):
            self.assertIn(attribute, cookie)
        csrf = re.search("name='csrf' value='([^']+)'", page).group(1)
        form = {"code": device["user_code"], "csrf": csrf, "username": "owner", "password": self.password, "decision": "approve"}
        headers = {"Origin": "https://broker.example", "Cookie": cookie.split(";")[0]}
        for origin in ("https://evil.example", "null", ""):
            with self.subTest(origin=origin):
                rejected_headers = {"Cookie": headers["Cookie"]}
                if origin:
                    rejected_headers["Origin"] = origin
                self.assertEqual(self.request("/connect", form=form, headers=rejected_headers)[1]["error"], "invalid_origin")
        self.assertEqual(self.request("/connect", form=form, headers={"Origin": headers["Origin"]})[1]["error"], "invalid_csrf")
        self.assertEqual(self.request("/connect", form=form, headers=headers)[0], 200)
        result = self.request("/auth/v1/device/poll", body={"device_code": device["device_code"]})[1]
        self.assertEqual(result["status"], "approved")
        self.assertEqual(self.request("/auth/v1/device/poll", body={"device_code": device["device_code"]})[1], result)
        self.assertEqual(self.request("/relay/v1/status", token=result["session_token"])[0], 200)
        self.assertEqual(self.request("/connect", form=form, headers=headers)[1]["error"], "invalid_csrf")

    def test_login_cannot_be_called_from_browser_and_query_secrets_are_not_supported(self):
        self.configure()
        body = {"username": "owner", "password": self.password, "role": "worker"}
        self.assertEqual(self.request("/auth/v1/login", body=body, headers={"Origin": "https://broker.example"})[0], 403)
        self.assertEqual(self.request("/auth/v1/login?password=hidden", body=body)[0], 404)
        self.assertEqual(self.request("/auth/v1/login", body=body | {"extra": "bad"})[0], 400)
        self.assertEqual(self.request("/connect?code=%3Cscript%3E")[0], 400)

    def test_account_only_never_falls_back_if_account_configuration_disappears(self):
        self.configure()
        self.server.account_only = True
        session = self.login("controller")
        with self.server.accounts.connect() as db:
            db.execute("DELETE FROM account")
        self.assertEqual(self.request("/relay/v1/status", token=self.controller)[0], 401)
        self.assertEqual(self.request("/relay/v1/status", token=session)[0], 401)
        self.assertEqual(self.request("/relay/v1/connect", token=self.worker, body={"session_id": str(uuid.uuid4())})[0], 401)


class AccountCliTests(unittest.TestCase):
    def test_account_only_startup_requires_account_and_does_not_create_legacy_keys(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / "state"
            with patch("sys.argv", ["broker", "--state-dir", str(state), "--account-only", "--init-only"]), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                main()
            self.assertEqual(caught.exception.code, 2)
            self.assertFalse(state.exists())
            AccountStore(state / "auth.sqlite3").set_account("owner", "local test password")
            with patch("sys.argv", ["broker", "--state-dir", str(state), "--account-only", "--init-only"]):
                main()
            self.assertFalse((state / "worker.token").exists())
            self.assertFalse((state / "controller.token").exists())

    def test_account_only_constructor_rejects_empty_account(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "configured local account"):
                BrokerServer(0, temp, secrets.token_urlsafe(32), secrets.token_urlsafe(32), account_only=True)

    def test_canonical_public_origin_and_invalid_ports(self):
        with tempfile.TemporaryDirectory() as temp:
            controller, worker = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            with BrokerServer(0, temp, controller, worker, public_url="https://BROKER.example:443/") as server:
                self.assertEqual(server.public_origin, "https://broker.example")
            with self.assertRaises(ValueError):
                BrokerServer(0, temp, controller, worker, public_url="https://broker.example:invalid")

    def test_set_account_uses_local_prompts_without_touching_queue_or_exposing_password(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp)
            queue = state / "broker.sqlite3"
            queue.write_bytes(b"unchanged marker")
            output = io.StringIO()
            password = "a private local password"
            with patch("sys.argv", ["broker", "--state-dir", temp, "--set-account"]), \
                    patch("builtins.input", return_value="owner"), \
                    patch("remote222.broker.getpass.getpass", side_effect=[password, password]), \
                    contextlib.redirect_stdout(output):
                main()
            self.assertTrue(AccountStore(state / "auth.sqlite3").configured())
            self.assertEqual(queue.read_bytes(), b"unchanged marker")
            self.assertNotIn(password, output.getvalue())
            self.assertFalse((state / "worker.token").exists())


if __name__ == "__main__":
    unittest.main()
