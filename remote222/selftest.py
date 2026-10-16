"""Exercise the actual frozen Windows executable without a public tunnel."""

import argparse
import ctypes
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import queue
import secrets
import subprocess
import tempfile
import threading

from . import __version__
from .agent import AgentServer, prepare_state
from .client import Client
from .session import RelaySession, bundled_tunnel, child_options, protect_state


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = {"version": __version__, "time": datetime.now(timezone.utc).isoformat(), "checks": [], "ok": False}
    try:
        if os.name != "nt":
            raise RuntimeError("Frozen self-test must run on Windows")
        binary = bundled_tunnel()
        result = subprocess.run([str(binary), "--version"], capture_output=True, check=True, timeout=20, **child_options())
        assert b"2026.10.1" in result.stdout, "Unexpected tunnel version"
        report["checks"].append("bundled cloudflared checksum and executable")
        import tkinter as tk
        from .desktop_app import DesktopApp
        root = tk.Tk()
        try:
            root.withdraw()
            DesktopApp(root)
            root.update()
        finally:
            root.destroy()
        report["checks"].append("frozen Tk GUI initialization")
        from .windows import INPUT, user32
        assert ctypes.sizeof(INPUT) == (40 if ctypes.sizeof(ctypes.c_void_p) == 8 else 28)
        assert user32().GetSystemMetrics(0) > 0
        report["checks"].append("Windows input API loading and ABI")
        with tempfile.TemporaryDirectory(prefix="remote222-selftest-") as temp:
            state = Path(temp) / "state"
            protect_state(state)
            token = prepare_state(state)
            server = AgentServer(0, state, token)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                client = Client(f"http://127.0.0.1:{server.server_port}", token)
                assert client.info()["result"]["system"] == "Windows"
                report["checks"].append("authenticated Windows HTTP agent")
                output = client.action("shell", {"command": "Write-Output 'frozen-agent-ok'"})
                assert output["ok"] and "frozen-agent-ok" in output["result"]["stdout"]
                report["checks"].append("PowerShell execution from frozen agent")
                path = str(Path(temp) / "roundtrip.txt")
                assert client.action("write", {"path": path, "data_base64": "aGVsbG8="})["ok"]
                assert client.action("read", {"path": path})["result"]["data_base64"] == "aGVsbG8="
                report["checks"].append("file transfer through frozen agent")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
        from .broker import BrokerServer
        from .relay import RelayClient
        with tempfile.TemporaryDirectory(prefix="remote222-relay-selftest-") as temp:
            controller, worker = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            broker = BrokerServer(0, Path(temp) / "broker", controller, worker)
            broker_thread = threading.Thread(target=broker.serve_forever, daemon=True)
            broker_thread.start()
            events = queue.Queue()
            url = f"http://127.0.0.1:{broker.server_port}"
            session = RelaySession(Path(temp) / "agent", lambda kind, data: events.put((kind, data)), url, worker)
            try:
                session.start()
                for _ in range(20):
                    kind, data = events.get(timeout=10)
                    if kind == "error":
                        raise RuntimeError(data)
                    if kind == "ready":
                        break
                else:
                    raise RuntimeError("Relay session did not become ready")
                client = RelayClient(url, controller)
                assert client.info()["result"]["system"] == "Windows"
                result = client.action("shell", {"command": "Write-Output 'frozen-queue-ok'"})
                assert result["ok"] and "frozen-queue-ok" in result["result"]["stdout"]
                report["checks"].append("frozen outbound queue, Windows feedback and PowerShell")
                path = str(Path(temp) / "queue-roundtrip.txt")
                assert client.action("write", {"path": path, "data_base64": "cXVldWU="})["ok"]
                assert client.action("read", {"path": path})["result"]["data_base64"] == "cXVldWU="
                report["checks"].append("file round trip through frozen outbound queue")
            finally:
                session.stop()
                session.join(15)
                broker.shutdown()
                broker.server_close()
                broker_thread.join(timeout=5)
            assert not session.thread.is_alive()
            report["checks"].append("queue session shutdown without a tunnel")
        report["ok"] = True
    except Exception as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    if not report["ok"]:
        raise SystemExit(1)
