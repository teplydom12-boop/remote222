"""Lifecycle shared by the desktop app and its integration tests."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time

from .agent import AgentServer, prepare_state
from .client import Client, ClientError, normalize_url

CLOUDFLARED_VERSION = "2026.10.1"
CLOUDFLARED_SHA256 = "4d2490e74082c5d48dbfedaf92576fa5bd1702379ab88eb7faa0cfbe8dc891b6"
TUNNEL_URL = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com\b")


def bundle_root():
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1] / "vendor"))


def bundled_tunnel():
    path = bundle_root() / "cloudflared.exe"
    if not path.is_file():
        raise RuntimeError("Компонент туннеля отсутствует. Скачайте полный Remote222.exe из GitHub Releases.")
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != CLOUDFLARED_SHA256:
        raise RuntimeError("Проверка компонента туннеля не пройдена. Скачайте приложение заново.")
    return path


def child_options():
    return {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}


def protect_state(path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        path.chmod(0o700)
        return
    identity = subprocess.run(["whoami.exe", "/user", "/fo", "csv", "/nh"],
                              capture_output=True, check=True, timeout=10, **child_options())
    sid = re.search(rb"S-1-(?:[0-9]+-)*[0-9]+", identity.stdout)
    if not sid:
        raise RuntimeError("Не удалось определить учётную запись Windows.")
    result = subprocess.run(["icacls.exe", str(path), "/inheritance:r", "/grant:r",
                             f"*{sid[0].decode('ascii')}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"],
                            capture_output=True, timeout=15, **child_options())
    if result.returncode:
        raise RuntimeError("Не удалось защитить папку с ключом доступа.")


def _windows_acl_api():
    import ctypes
    from ctypes import wintypes
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.c_void_p
    output = ctypes.POINTER(pointer)
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, output, ctypes.POINTER(wintypes.DWORD)]
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    security.GetSecurityDescriptorDacl.argtypes = [pointer, ctypes.POINTER(wintypes.BOOL), output, ctypes.POINTER(wintypes.BOOL)]
    security.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    security.SetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD, pointer, pointer, pointer, pointer]
    security.SetNamedSecurityInfoW.restype = wintypes.DWORD
    security.GetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD, output, output, output, output, output]
    security.GetNamedSecurityInfoW.restype = wintypes.DWORD
    security.ConvertSidToStringSidW.argtypes = [pointer, output]
    security.ConvertSidToStringSidW.restype = wintypes.BOOL
    security.GetAce.argtypes = [pointer, wintypes.DWORD, output]
    security.GetAce.restype = wintypes.BOOL
    security.GetSecurityDescriptorControl.argtypes = [pointer, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.DWORD)]
    security.GetSecurityDescriptorControl.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [pointer]
    kernel.LocalFree.restype = pointer
    return ctypes, wintypes, security, kernel


def _windows_user_sid():
    identity = subprocess.run(["whoami.exe", "/user", "/fo", "csv", "/nh"],
                              capture_output=True, check=True, timeout=10, **child_options())
    match = re.search(rb"S-1-(?:[0-9]+-)*[0-9]+", identity.stdout)
    if not match:
        raise ClientError("Не удалось определить учётную запись Windows.")
    return match[0].decode("ascii")


def verify_private_state(path):
    """Reject a session path whose ACL grants access to another Windows user."""
    path = Path(path)
    if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
        raise ClientError("Папка входа не должна быть ссылкой.")
    if os.name != "nt":
        details = path.stat()
        if details.st_uid != os.geteuid() or details.st_mode & 0o077:
            raise ClientError("Папка входа должна быть доступна только вашей учётной записи.")
        return
    ctypes, wintypes, security, kernel = _windows_acl_api()
    owner, acl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    allowed = {_windows_user_sid(), "S-1-5-18"}
    # Elevated Windows processes may create Administrators-owned files. That
    # privileged owner can already take ownership; it receives no DACL grant.
    allowed_owners = allowed | {"S-1-5-32-544"}

    def sid_text(address):
        text = ctypes.c_void_p()
        if not security.ConvertSidToStringSidW(address, ctypes.byref(text)):
            raise ClientError("Не удалось проверить права папки входа.")
        try:
            return ctypes.wstring_at(text)
        finally:
            kernel.LocalFree(text)

    try:
        result = security.GetNamedSecurityInfoW(str(path), 1, 0x00000001 | 0x00000004,
                                               ctypes.byref(owner), None, ctypes.byref(acl), None,
                                               ctypes.byref(descriptor))
        if result in {2, 3}:
            raise FileNotFoundError("Private account path does not exist")
        if result or not acl.value or not owner.value or sid_text(owner) not in allowed_owners:
            raise ClientError("Папка входа должна принадлежать вашей учётной записи и иметь закрытые права.")
        control, revision = wintypes.WORD(), wintypes.DWORD()
        if not security.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)):
            raise ClientError("Не удалось проверить права папки входа.")
        if path.is_dir() and not control.value & 0x1000:
            raise ClientError("Папка входа должна иметь собственные закрытые права.")
        # ACL header: BYTE revision, BYTE reserved, WORD size, WORD ACE count.
        ace_count = int.from_bytes(ctypes.string_at(acl, 8)[4:6], "little")
        for index in range(ace_count):
            ace = ctypes.c_void_p()
            if not security.GetAce(acl, index, ctypes.byref(ace)):
                raise ClientError("Не удалось проверить права папки входа.")
            ace_type = ctypes.string_at(ace, 1)[0]
            if ace_type == 1:  # A deny ACE cannot grant another user access.
                continue
            if ace_type != 0 or sid_text(ace.value + 8) not in allowed:
                raise ClientError("Папка входа доступна другой учётной записи. Выберите новую личную папку.")
    finally:
        if descriptor.value:
            kernel.LocalFree(descriptor)


def protect_private_state(path):
    """Set an exact ACL only on a newly created or application-owned auth folder."""
    path = Path(path)
    if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
        raise ClientError("Папка входа не должна быть ссылкой.")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        path.chmod(0o700)
        return
    ctypes, wintypes, security, kernel = _windows_acl_api()
    descriptor, acl = ctypes.c_void_p(), ctypes.c_void_p()
    present, defaulted = wintypes.BOOL(), wintypes.BOOL()
    sddl = f"D:P(A;OICI;FA;;;{_windows_user_sid()})(A;OICI;FA;;;SY)"
    try:
        if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
            raise ClientError("Не удалось защитить папку входа.")
        if not security.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(acl), ctypes.byref(defaulted)) or not present.value:
            raise ClientError("Не удалось защитить папку входа.")
        # DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION.
        if security.SetNamedSecurityInfoW(str(path), 1, 0x80000004, None, None, acl, None):
            raise ClientError("Не удалось защитить папку входа.")
    finally:
        if descriptor.value:
            kernel.LocalFree(descriptor)
    verify_private_state(path)


class StateLock:
    """One active agent per state directory, also across GUI processes."""

    def __init__(self, path):
        self.path = path
        self.stream = None

    def acquire(self):
        stream = self.path.open("a+b")
        try:
            if stream.tell() == 0:
                stream.write(b"0")
                stream.flush()
            stream.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            stream.close()
            raise RuntimeError("Агент уже запущен. Отключите управление в другом окне.") from None
        self.stream = stream

    def close(self):
        if self.stream:
            self.stream.close()
            self.stream = None


class Session:
    def __init__(self, state_dir, emit, *, tunnel_command=None, probe=None, startup_timeout=75):
        self.state_dir = Path(state_dir)
        self.emit = emit
        self.tunnel_command = tunnel_command
        self.probe = probe or (lambda url, token: Client(url, token).request("/v1/info", timeout=3))
        self.startup_timeout = startup_timeout
        self.stop_event = threading.Event()
        self.thread = None
        self.server = None
        self.process = None
        self.token = None
        self.url = None

    def start(self):
        if self.thread is not None:
            raise RuntimeError("Session objects can only be started once")
        self.thread = threading.Thread(target=self._run, daemon=True, name="remote222-session")
        self.thread.start()

    def stop(self):
        self.stop_event.set()

    def join(self, timeout=None):
        if self.thread:
            self.thread.join(timeout)

    def _run(self):
        lock = StateLock(self.state_dir / "agent.lock")
        server_thread = None
        log_writer = None
        try:
            self.emit("status", "Подготовка защищённого подключения…")
            protect_state(self.state_dir)
            lock.acquire()
            self.token = prepare_state(self.state_dir)
            command = self.tunnel_command or [str(bundled_tunnel())]
            if self.stop_event.is_set():
                return
            self.server = AgentServer(0, self.state_dir, self.token)
            server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            server_thread.start()
            local_url = f"http://127.0.0.1:{self.server.server_port}"
            info = Client(local_url, self.token).info()
            if not info.get("ok"):
                raise RuntimeError("Локальный агент не прошёл проверку запуска.")
            log_path = self.state_dir / "tunnel.log"
            log_writer = log_path.open("wb")
            # An empty config keeps a pre-existing user cloudflared configuration intact.
            config = self.state_dir / "quick-tunnel.yml"
            config.write_text("{}\n", encoding="utf-8")
            self.process = subprocess.Popen(
                [*command, "tunnel", "--config", str(config), "--no-autoupdate",
                 "--url", local_url, "--protocol", "http2"],
                stdin=subprocess.DEVNULL, stdout=log_writer, stderr=subprocess.STDOUT,
                **child_options())
            self.emit("status", "Подключение к Cloudflare…")
            deadline = time.monotonic() + self.startup_timeout
            url = None
            ready = False
            partial = ""
            with log_path.open("r", encoding="utf-8", errors="replace") as reader:
                while not self.stop_event.wait(0.2):
                    if self.process.poll() is not None:
                        raise RuntimeError("Туннель остановился. Откройте журнал: tunnel.log.")
                    if not ready and time.monotonic() > deadline:
                        raise RuntimeError("Подключение не установлено. Проверьте интернет и журнал tunnel.log, затем попробуйте снова.")
                    chunk = reader.read(65536)
                    partial = (partial + chunk)[-131072:]
                    if not url:
                        match = TUNNEL_URL.search(partial)
                        if match:
                            url = match[0]
                            self.emit("status", "Проверка HTTPS-соединения…")
                    if url and not ready:
                        try:
                            remote = self.probe(url, self.token)
                            ready = remote.get("ok") is True and remote.get("result", {}).get("pid") == os.getpid()
                        except Exception:
                            ready = False
                        if ready and not self.stop_event.is_set():
                            self.url = url
                            self.emit("ready", url)
                        elif not ready:
                            self.stop_event.wait(0.8)
        except Exception as exc:
            if not self.stop_event.is_set():
                self.emit("error", str(exc))
        finally:
            self.url = None
            if self.process and self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
            if self.server:
                if server_thread:
                    self.server.shutdown()
                self.server.server_close()
            if server_thread:
                server_thread.join(timeout=5)
            if log_writer:
                log_writer.close()
            lock.close()
            self.emit("stopped", None)


def relay_session_store(state_dir):
    from .auth_client import SessionStore
    return SessionStore(Path(state_dir) / "auth" / "worker.json")


def read_relay_settings(state_dir):
    """Read only the last server and account name, never a password or session."""
    try:
        path = Path(state_dir) / "relay-account.json"
        if path.stat().st_size > 8192:
            return {}
        settings = json.loads(path.read_text(encoding="utf-8"))
        url = normalize_url(settings["url"])
        username = settings["username"]
        if not isinstance(username, str) or len(username) > 256:
            return {}
        return {"url": url, "username": username}
    except (OSError, ValueError, TypeError, KeyError, AttributeError, ClientError):
        return {}


def save_relay_settings(state_dir, url, username):
    """Called only after the state-directory lock and Windows ACL are applied."""
    path = Path(state_dir) / "relay-account.json"
    temporary = path.with_suffix(".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump({"url": normalize_url(url), "username": username}, stream)
        stream.write("\n")
    temporary.replace(path)


def forget_relay_account(state_dir, emit):
    """Revoke a saved login, then forget it locally even if the server is offline."""
    from .auth_client import AuthClient
    store = relay_session_store(state_dir)
    try:
        try:
            # The saved URL is authoritative. An edited GUI URL must never
            # receive a session that belongs to a different server.
            profile = store.load(role="worker")
        except ClientError:
            return
        AuthClient(profile["url"], profile["session_token"]).logout()
    except ClientError:
        emit("error", "Вход на этом ПК удалён. Сервер не подтвердил отзыв сеанса: проверьте соединение. Для подключения понадобится войти снова.")
    finally:
        store.delete()


class AccountLogout(Session):
    """Perform server logout outside Tk's thread, with the same state lock."""

    def _run(self):
        lock = StateLock(self.state_dir / "agent.lock")
        try:
            protect_state(self.state_dir)
            lock.acquire()
            protect_private_state(self.state_dir / "auth")
            forget_relay_account(self.state_dir, self.emit)
            self.emit("logged_out", None)
        except Exception:
            self.emit("error", "Не удалось завершить выход. Закройте другие окна Remote222 и попробуйте снова.")
        finally:
            lock.close()
            self.emit("stopped", None)


class RelaySession(Session):
    """Visible interactive agent with outbound polling of an authorized broker."""

    def __init__(self, state_dir, emit, relay_url, worker_token=None, *, username="", password=""):
        super().__init__(state_dir, emit)
        self.relay_url = normalize_url(relay_url)
        if worker_token is not None and (not worker_token or any(char in worker_token for char in "\r\n")):
            raise ValueError("Invalid legacy worker credential")
        if not isinstance(username, str) or len(username) > 256:
            raise ValueError("Проверьте логин.")
        if not isinstance(password, str):
            raise ValueError("Проверьте пароль.")
        if password and not username.strip():
            raise ValueError("Введите логин.")
        self.worker_token = worker_token
        self.username = username.strip()
        self.password = password
        self.account_login = worker_token is None
        self.logout_event = threading.Event()
        self.worker = None

    def logout(self):
        self.logout_event.set()
        self.stop()

    def _authenticate(self):
        from .auth_client import AuthClient
        store = relay_session_store(self.state_dir)
        if self.password:
            self.emit("status", "Вход на сервер…")
            try:
                previous = store.load(expected_url=self.relay_url, role="worker")
            except ClientError:
                previous = None
            try:
                response = AuthClient(self.relay_url).login(self.username, self.password, role="worker")
            except ClientError as exc:
                if str(exc).startswith("HTTP 401:"):
                    raise ClientError("Не удалось войти. Проверьте логин и пароль.") from None
                raise
            finally:
                self.password = ""
            if response.get("role") != "worker":
                raise ClientError("Сервер не подтвердил вход для компьютера.")
            # A successful login can finish just after Stop. Save it for the
            # next explicit Start, but never launch an agent after Stop.
            try:
                profile = store.save(self.relay_url, response)
            except Exception:
                # A new server session that could not be saved should not
                # remain active until its expiry when revocation is available.
                try:
                    AuthClient(self.relay_url, response["session_token"]).logout()
                except ClientError:
                    pass
                raise
            if previous and previous["session_token"] != profile["session_token"]:
                try:
                    AuthClient(previous["url"], previous["session_token"]).logout()
                except ClientError:
                    pass
            save_relay_settings(self.state_dir, self.relay_url, self.username)
        else:
            self.emit("status", "Проверка сохранённого входа…")
            settings = read_relay_settings(self.state_dir)
            if self.username and settings.get("username") != self.username:
                raise ClientError("Для этого логина введите пароль.")
            try:
                profile = store.load(expected_url=self.relay_url, role="worker")
            except ClientError:
                raise ClientError("Введите логин и пароль для входа на сервер.") from None
            try:
                response = AuthClient(self.relay_url, profile["session_token"]).session()
                if response.get("role") != "worker":
                    raise ClientError("Сохранённый вход не подходит для компьютера.")
            except ClientError as exc:
                if str(exc).startswith(("HTTP 401:", "HTTP 403:")):
                    store.delete()
                    raise ClientError("Сеанс завершён. Введите логин и пароль снова.") from None
                raise
        self.worker_token = profile["session_token"]
        self.emit("account_ready", None)

    def _run(self):
        from .relay import RelayWorker
        lock = StateLock(self.state_dir / "agent.lock")
        server_thread = None
        try:
            self.emit("status", "Подготовка подключения к очереди…")
            protect_state(self.state_dir)
            lock.acquire()
            if self.stop_event.is_set():
                return
            if self.account_login:
                protect_private_state(self.state_dir / "auth")
                self._authenticate()
            if self.stop_event.is_set():
                return
            self.token = prepare_state(self.state_dir)
            self.server = AgentServer(0, self.state_dir, self.token)
            server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            server_thread.start()
            local = Client(f"http://127.0.0.1:{self.server.server_port}", self.token)
            info = local.info()
            if not info.get("ok") or info.get("result", {}).get("pid") != os.getpid():
                raise RuntimeError("Локальный агент не прошёл проверку запуска.")

            def worker_event(kind, data):
                if kind == "ready" and not self.stop_event.is_set():
                    self.url = self.relay_url
                    self.emit("ready", self.relay_url)
                elif kind == "status" and not self.stop_event.is_set():
                    self.emit("status", data["message"] if isinstance(data, dict) else data)
                elif kind == "error" and not self.stop_event.is_set():
                    self.emit("error", data)

            self.worker = RelayWorker(self.relay_url, self.worker_token, local,
                                      self.stop_event, emit=worker_event)
            self.worker.run()
        except Exception as exc:
            if not self.stop_event.is_set():
                self.emit("error", str(exc))
        finally:
            self.password = ""
            self.url = None
            self.worker_token = None
            if self.server:
                if server_thread:
                    self.server.shutdown()
                self.server.server_close()
            if server_thread:
                server_thread.join(timeout=5)
            try:
                if self.logout_event.is_set() and lock.stream:
                    forget_relay_account(self.state_dir, self.emit)
                    self.emit("logged_out", None)
            except Exception:
                self.emit("error", "Не удалось удалить сохранённый вход. Проверьте доступ к папке Remote222.")
            finally:
                lock.close()
                self.emit("stopped", None)
