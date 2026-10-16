"""Actions run with the privileges of the account that started the agent."""

import base64
import os
from pathlib import Path
import platform
import signal
import subprocess
import tempfile
import threading

MAX_FILE = 1024 * 1024
MAX_OUTPUT = 128 * 1024


class ActionError(Exception):
    pass


def text_arg(args, name, *, default=None, limit=32768):
    value = args.get(name, default)
    if not isinstance(value, str) or len(value) > limit or "\0" in value:
        raise ActionError(f"{name} must be a string of at most {limit} characters")
    return value


def int_arg(args, name, default, minimum, maximum):
    value = args.get(name, default)
    if type(value) is not int or not minimum <= value <= maximum:
        raise ActionError(f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


def powershell(script):
    prefix = "$OutputEncoding = [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false); "
    encoded = base64.b64encode((prefix + script).encode("utf-16-le")).decode("ascii")
    return ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]


def _read_output(stream):
    size = stream.tell()
    stream.seek(max(0, size - MAX_OUTPUT))
    return stream.read(MAX_OUTPUT).decode("utf-8", errors="replace"), size > MAX_OUTPUT


def run_shell(args):
    command = text_arg(args, "command")
    timeout = int_arg(args, "timeout", 30, 1, 300)
    cwd = text_arg(args, "cwd", default=str(Path.home()))
    argv = powershell(command) if os.name == "nt" else ["/bin/bash", "-lc", command]
    options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {"start_new_session": True}
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        proc = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                                stdout=stdout, stderr=stderr, **options)
        timed_out = False
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            if os.name == "nt":
                subprocess.run(["taskkill.exe", "/PID", str(proc.pid), "/T", "/F"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
                               creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                os.killpg(proc.pid, signal.SIGKILL)
            proc.kill()
            proc.wait(timeout=10)
        out, out_cut = _read_output(stdout)
        err, err_cut = _read_output(stderr)
    return {"exit_code": proc.returncode, "stdout": out, "stderr": err,
            "timed_out": timed_out, "truncated": out_cut or err_cut}


def open_program(args):
    target = text_arg(args, "target", limit=4096)
    arguments = args.get("arguments", [])
    if not isinstance(arguments, list) or len(arguments) > 100 or any(
        not isinstance(item, str) or "\0" in item or len(item) > 8192 for item in arguments
    ):
        raise ActionError("arguments must be a list of strings")
    if os.name == "nt" and not arguments:
        os.startfile(target)
        return {"started": True, "target": target}
    options = {"creationflags": subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
    proc = subprocess.Popen([target, *arguments], stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **options)
    # Reap launched children without tying their lifetime to the HTTP request.
    threading.Thread(target=proc.wait, daemon=True).start()
    return {"started": True, "pid": proc.pid, "target": target}


def list_files(args):
    path = Path(text_arg(args, "path", default=str(Path.home())))
    limit = int_arg(args, "limit", 200, 1, 1000)
    items = []
    with os.scandir(path) as entries:
        for entry in entries:
            if len(items) == limit:
                return {"path": str(path.resolve()), "entries": items, "truncated": True}
            stat = entry.stat(follow_symlinks=False)
            items.append({"name": entry.name, "is_dir": entry.is_dir(follow_symlinks=False),
                          "is_symlink": entry.is_symlink(), "size": stat.st_size})
    return {"path": str(path.resolve()), "entries": items, "truncated": False}


def read_file(args):
    path = Path(text_arg(args, "path"))
    with path.open("rb") as stream:
        data = stream.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise ActionError("File exceeds 1 MiB; use shell for partial reads")
    return {"path": str(path.resolve()), "data_base64": base64.b64encode(data).decode("ascii")}


def write_file(args):
    path = Path(text_arg(args, "path"))
    encoded = text_arg(args, "data_base64", limit=MAX_FILE * 2)
    try:
        data = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise ActionError("Invalid base64 file content") from exc
    if len(data) > MAX_FILE:
        raise ActionError("File exceeds 1 MiB")
    overwrite = args.get("overwrite", False)
    if type(overwrite) is not bool:
        raise ActionError("overwrite must be boolean")
    # Exclusive creation by default; replacement must be an explicit command.
    with path.open("wb" if overwrite else "xb") as stream:
        stream.write(data)
    return {"path": str(path.resolve()), "bytes_written": len(data)}


def system_info(args):
    return {"system": platform.system(), "release": platform.release(),
            "hostname": platform.node(), "home": str(Path.home()),
            "pid": os.getpid(), "capabilities": sorted(ACTIONS),
            "desktop_available": os.name == "nt"}


def desktop(action, args):
    if os.name != "nt":
        raise ActionError("Desktop actions require Windows in an interactive user session")
    from .windows import perform
    return perform(action, args)


ACTIONS = {
    "info": system_info,
    "open": open_program,
    "shell": run_shell,
    "list": list_files,
    "read": read_file,
    "write": write_file,
    **{name: (lambda args, name=name: desktop(name, args))
       for name in ("screenshot", "text", "keys", "mouse")},
}


def execute(action, args):
    if action not in ACTIONS:
        raise ActionError("Unknown action")
    if not isinstance(args, dict):
        raise ActionError("args must be an object")
    return ACTIONS[action](args)
