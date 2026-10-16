"""Lifecycle shared by the desktop app and its integration tests."""

import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time

from .agent import AgentServer, prepare_state
from .client import Client

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


class RelaySession(Session):
    """Visible interactive agent with outbound polling of an authorized broker."""

    def __init__(self, state_dir, emit, relay_url, worker_token):
        super().__init__(state_dir, emit)
        from .client import normalize_url
        self.relay_url = normalize_url(relay_url)
        if not worker_token or any(char in worker_token for char in "\r\n"):
            raise ValueError("Укажите ключ компьютера из настроек сервера очереди.")
        self.worker_token = worker_token
        self.worker = None

    def _run(self):
        from .relay import RelayWorker
        lock = StateLock(self.state_dir / "agent.lock")
        server_thread = None
        try:
            self.emit("status", "Подготовка подключения к очереди…")
            protect_state(self.state_dir)
            lock.acquire()
            self.token = prepare_state(self.state_dir)
            if self.stop_event.is_set():
                return
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
            self.url = None
            self.worker_token = None
            if self.server:
                if server_thread:
                    self.server.shutdown()
                self.server.server_close()
            if server_thread:
                server_thread.join(timeout=5)
            lock.close()
            self.emit("stopped", None)
