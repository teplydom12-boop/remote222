"""Control the user's Windows Chrome through a saved Remote222 account session."""

import argparse
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import stat
import sys
import tempfile
import uuid
import zlib

from .auth_client import SessionStore
from .client import ClientError, normalize_url
from .relay import RelayClient, REQUEST_ID
from .session import StateLock


MAX_STATE = 4 * 1024 * 1024
MAX_ARTIFACT = 1024 * 1024
MAX_HTML = 64 * 1024 * 1024
SHA256 = re.compile(r"^[a-f0-9]{64}$")
HOSTNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
TARGET = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
HELPER = Path(__file__).resolve().parents[1] / "scripts" / "Browser-Control.ps1"


def _json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _id(value):
    if not isinstance(value, str) or not REQUEST_ID.fullmatch(value):
        raise ClientError("Request ID must contain 8–80 letters, digits, underscores or hyphens")
    return value


def _child_id(request_id, step):
    return "browser-" + _sha((request_id + ":" + step).encode())[:48]


def _windows_path(value):
    if (not isinstance(value, str) or len(value) > 4096 or any(ord(c) < 32 for c in value)
            or not PureWindowsPath(value).is_absolute()):
        raise ClientError("Expected an absolute Windows path")
    return value


def _quote(value):
    return "'" + value.replace("'", "''") + "'"


def _host_guard(hostname):
    if not isinstance(hostname, str) or not HOSTNAME.fullmatch(hostname):
        raise ClientError("Invalid expected Windows hostname")
    return "$ErrorActionPreference='Stop'; if([Environment]::MachineName -ine " + _quote(hostname) + "){throw 'Unexpected Windows computer'}; "


def _result(response):
    if not isinstance(response, dict) or response.get("ok") is not True:
        code = response.get("error") if isinstance(response, dict) else None
        code = code if isinstance(code, str) and re.fullmatch(r"[a-z_]{1,64}", code) else "invalid_response"
        raise ClientError(f"Remote operation failed: {code}")
    result = response.get("result")
    if not isinstance(result, dict):
        raise ClientError("Invalid remote operation result")
    return result


def _shell_json(response):
    shell = _result(response)
    if shell.get("timed_out") is True:
        raise ClientError("Browser operation timed out; inspect state before repeating the same request ID")
    if shell.get("truncated") is True:
        raise ClientError("Browser response was truncated; request a smaller result")
    output = shell.get("stdout")
    if not isinstance(output, str) or len(output.encode("utf-8")) > 128 * 1024:
        raise ClientError("Invalid browser helper output")
    try:
        payload = json.loads(output.lstrip("\ufeff").strip())
    except ValueError:
        raise ClientError("Browser helper did not return JSON; check its installation and the Windows shell result") from None
    if shell.get("exit_code") != 0 or not isinstance(payload, dict) or payload.get("ok") is not True:
        code = payload.get("error") if isinstance(payload, dict) else None
        code = code if isinstance(code, str) and re.fullmatch(r"[a-z_]{1,64}", code) else "browser_error"
        message = payload.get("message") if isinstance(payload, dict) else None
        # The helper provides a bounded diagnostic; never echo the entire shell
        # stderr, which could include the invocation and page expressions.
        detail = ""
        if isinstance(message, str) and len(message) <= 512 and not any(ord(c) < 32 for c in message):
            detail = ": " + message
        raise ClientError("Browser helper failed (" + code + ")" + detail)
    return _result(payload)


class BrowserState:
    """Private non-secret configuration and operation checkpoints."""

    def __init__(self, path):
        self.guard = SessionStore(path)
        self.path = self.guard.path

    @contextmanager
    def locked(self):
        self.guard._parent(create=True)
        lock_path = self.path.with_name(self.path.name + ".lock")
        if lock_path.is_symlink():
            raise ClientError("Browser lock must not be a symbolic link")
        lock = StateLock(lock_path)
        try:
            lock.acquire()
        except RuntimeError:
            raise ClientError("Another browser command is using this state file") from None
        try:
            yield
        finally:
            lock.close()

    def load(self):
        self.guard._parent()
        try:
            fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as stream:
                details = os.fstat(stream.fileno())
                if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
                    raise ClientError("Browser state must be a private regular file")
                if os.name != "nt" and (details.st_uid != os.geteuid() or details.st_mode & 0o077):
                    raise ClientError("Browser state must be owned by you with permissions 0600")
                raw = stream.read(MAX_STATE + 1)
            if len(raw) > MAX_STATE:
                raise ClientError("Browser state is too large")
            value = json.loads(raw)
            if not isinstance(value, dict) or value.get("version") != 1 or not isinstance(value.get("requests"), dict):
                raise ClientError("Invalid browser state")
            return value
        except FileNotFoundError:
            return None
        except ValueError:
            raise ClientError("Invalid browser state") from None

    def save(self, value):
        raw = _json(value).encode("utf-8")
        if len(raw) > MAX_STATE:
            raise ClientError("Browser state is too large; preserve it and select a new state file")
        self.guard._parent(create=True)
        fd, temporary = tempfile.mkstemp(prefix=".browser-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            self.guard._check_links()
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def _helper_command(state, request):
    helper_path = _windows_path(state.get("helper_path"))
    digest = state.get("helper_sha256")
    if not isinstance(digest, str) or not SHA256.fullmatch(digest):
        raise ClientError("Invalid installed helper checksum")
    encoded = base64.b64encode(_json(request).encode("utf-8")).decode("ascii")
    command = (_host_guard(state.get("expected_hostname")) + "$helper=" + _quote(helper_path) + "; "
               "$bytes=[IO.File]::ReadAllBytes($helper); $sha=[Security.Cryptography.SHA256]::Create(); "
               "try{$actual=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}; "
               "if($actual -cne " + _quote(digest) + "){throw 'Browser helper checksum mismatch'}; "
               "$source=[Text.Encoding]::UTF8.GetString($bytes); "
               "& ([ScriptBlock]::Create($source)) -RequestBase64 " + _quote(encoded))
    if len(command) > 32768:
        raise ClientError("Browser request is too large for the Windows command channel")
    return command


class BrowserController:
    def __init__(self, relay, state_store):
        self.relay = relay
        self.store = state_store

    def _bound(self, state):
        if state is None:
            raise ClientError("Browser tools are not installed; run install first")
        if normalize_url(state.get("broker_url")) != self.relay.url:
            raise ClientError("Browser state belongs to a different account server")
        _host_guard(state.get("expected_hostname"))
        return state

    def _shell(self, command, request_id):
        return _shell_json(self.relay.action("shell", {"command": command, "timeout": 90}, request_id))

    def install(self, request_id, hostname, *, chrome_path=None, profile_directory=None, helper_path=HELPER):
        request_id = _id(request_id)
        _host_guard(hostname)
        if chrome_path is not None:
            _windows_path(chrome_path)
        if profile_directory is not None:
            _windows_path(profile_directory)
        source = Path(helper_path).read_bytes()
        if not source or len(source) > MAX_ARTIFACT:
            raise ClientError("Browser helper is missing or exceeds the upload limit")
        digest = _sha(source)
        state = self.store.load()
        if state is not None:
            self._bound(state)
            if state["expected_hostname"].casefold() != hostname.casefold():
                raise ClientError("Select a separate browser state file for another Windows computer")
        else:
            state = {"version": 1, "broker_url": self.relay.url, "expected_hostname": hostname,
                     "installed": False, "requests": {}}
        fingerprint = _sha(_json(["install", hostname.casefold(), chrome_path, profile_directory, digest]).encode())
        previous = state["requests"].get(request_id)
        if previous is not None and (not isinstance(previous, dict) or previous.get("fingerprint") != fingerprint):
            raise ClientError("Request ID already belongs to a different browser operation")
        state["requests"][request_id] = {"fingerprint": fingerprint, "operation": "install"}
        state["last_request_id"] = request_id
        self.store.save(state)
        name = "Browser-Control." + digest + ".ps1"
        probe = (_host_guard(hostname) + "$tools=Join-Path $env:LOCALAPPDATA 'Remote222\\tools'; "
                 "$null=[IO.Directory]::CreateDirectory($tools); $helper=Join-Path $tools " + _quote(name) + "; "
                 "$exists=Test-Path -LiteralPath $helper; if($exists -and "
                 "(Get-FileHash -LiteralPath $helper -Algorithm SHA256).Hash -ine " + _quote(digest) +
                 "){throw 'Existing browser helper checksum mismatch'}; "
                 "@{ok=$true;result=@{helper_path=$helper;installed=[bool]$exists}} | ConvertTo-Json -Compress")
        location = self._shell(probe, _child_id(request_id, "probe"))
        remote_path = _windows_path(location.get("helper_path"))
        if location.get("installed") is not True:
            _result(self.relay.action("write", {"path": remote_path,
                    "data_base64": base64.b64encode(source).decode("ascii")}, _child_id(request_id, "upload")))
        configured = {**state, "helper_path": remote_path, "helper_sha256": digest}
        request = {"operation": "system", "request_id": _child_id(request_id, "verify")}
        if chrome_path:
            request["chrome_path"] = chrome_path
        if profile_directory:
            request["profile_directory"] = profile_directory
        result = self._shell(_helper_command(configured, request), _child_id(request_id, "verify"))
        configured.update({"chrome_path": _windows_path(chrome_path or result.get("chrome_path")),
                           "profile_directory": _windows_path(profile_directory or result.get("default_profile_directory")),
                           "installed": True})
        if state.get("profile_directory") != configured["profile_directory"]:
            configured.pop("target_id", None)
        self.store.save(configured)
        return {"installed": True, "expected_hostname": hostname, "helper_path": remote_path,
                "helper_sha256": digest, "chrome_path": configured["chrome_path"],
                "profile_directory": configured["profile_directory"]}

    def execute(self, operation, request_id, parameters, *, output=None):
        request_id = _id(request_id)
        state = self._bound(self.store.load())
        if state.get("installed") is not True:
            raise ClientError("Browser installation is incomplete; repeat install with its request ID")
        fingerprint = _sha(_json([operation, parameters]).encode())
        configuration = _sha(_json([state.get(key) for key in (
            "broker_url", "expected_hostname", "helper_path", "helper_sha256", "chrome_path", "profile_directory")]).encode())
        record = state["requests"].get(request_id)
        if record is not None:
            if not isinstance(record, dict):
                raise ClientError("Invalid browser operation checkpoint")
            if record.get("fingerprint") != fingerprint or record.get("configuration") != configuration:
                raise ClientError("Request ID belongs to a different operation or helper version")
            target = record.get("target_id")
        else:
            target = parameters.get("target_id")
            if target is None and operation in {"open", "inspect", "evaluate", "save_html"}:
                target = state.get("target_id")
        if target is not None and (not isinstance(target, str) or not TARGET.fullmatch(target)):
            raise ClientError("Invalid browser target ID")
        if operation in {"inspect", "evaluate", "save_html"} and not target and not parameters.get("url"):
            raise ClientError("Open a page first or provide --target-id")
        request = {**parameters, "operation": operation, "request_id": request_id,
                   "chrome_path": _windows_path(state.get("chrome_path")),
                   "profile_directory": _windows_path(state.get("profile_directory"))}
        request.pop("target_id", None)
        if target:
            request["target_id"] = target
        command = _helper_command(state, request)
        state["requests"][request_id] = {"fingerprint": fingerprint, "helper_sha256": state["helper_sha256"],
                                         "configuration": configuration, "target_id": target, "operation": operation}
        state["last_request_id"] = request_id
        self.store.save(state)
        result = self._shell(command, request_id)
        updated_target = result.get("target_id")
        if isinstance(updated_target, str) and TARGET.fullmatch(updated_target):
            state["target_id"] = updated_target
            self.store.save(state)
        if operation == "save_html":
            if output is None:
                raise ClientError("Specify a local --output HTML path")
            return {**result, **self.download(result, request_id, output)}
        return result

    def download(self, artifact, request_id, output):
        for field in ("html_sha256", "gzip_sha256"):
            if not isinstance(artifact.get(field), str) or not SHA256.fullmatch(artifact[field]):
                raise ClientError("Invalid browser artifact checksum")
        for field, maximum in (("gzip_bytes", MAX_ARTIFACT), ("html_bytes", MAX_HTML)):
            size = artifact.get(field)
            if type(size) is not int or not 0 < size <= maximum:
                raise ClientError("Browser artifact exceeds the supported transfer size (1 MiB gzip, 64 MiB HTML)")
        path = _windows_path(artifact.get("gzip_path"))
        response = _result(self.relay.action("read", {"path": path}, _child_id(request_id, "download")))
        try:
            raw = base64.b64decode(response.get("data_base64", ""), validate=True)
        except (ValueError, TypeError):
            raise ClientError("Invalid browser artifact transfer") from None
        if len(raw) != artifact["gzip_bytes"] or _sha(raw) != artifact["gzip_sha256"]:
            raise ClientError("Downloaded browser artifact failed its SHA256 check")
        try:
            decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
            content = decompressor.decompress(raw, MAX_HTML + 1)
            if (len(content) > MAX_HTML or not decompressor.eof or decompressor.unused_data
                    or decompressor.unconsumed_tail or len(content) != artifact["html_bytes"]):
                raise ClientError("Invalid or oversized compressed HTML artifact")
        except zlib.error:
            raise ClientError("Invalid compressed HTML artifact") from None
        if _sha(content) != artifact["html_sha256"]:
            raise ClientError("Downloaded HTML failed its SHA256 check")
        output = Path(output)
        if output.is_symlink():
            raise ClientError("HTML output must not be a symbolic link")
        if output.exists():
            if not output.is_file() or output.stat().st_size != len(content) or _sha(output.read_bytes()) != artifact["html_sha256"]:
                raise ClientError("Local output already exists with different content; select another --output path")
        else:
            with output.open("xb") as stream:
                stream.write(content)
        return {"saved_to": str(output.absolute()), "bytes": len(content), "sha256": artifact["html_sha256"]}


def parser_for_cli():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session-file", type=Path, required=True)
    parser.add_argument("--state-file", type=Path, required=True)
    parser.add_argument("--request-id", help="Reuse this ID and the same arguments after an uncertain result")
    commands = parser.add_subparsers(dest="operation", required=True)
    install = commands.add_parser("install", help="Install and verify the Windows helper once")
    install.add_argument("--expected-hostname", required=True)
    install.add_argument("--chrome-path")
    install.add_argument("--profile-directory")
    for name in ("start", "status", "tabs", "system"):
        commands.add_parser(name)
    opened = commands.add_parser("open")
    opened.add_argument("url")
    inspect = commands.add_parser("inspect")
    evaluate = commands.add_parser("eval")
    expression = evaluate.add_mutually_exclusive_group(required=True)
    expression.add_argument("--expression")
    expression.add_argument("--expression-file", type=Path)
    saved = commands.add_parser("save")
    saved.add_argument("--url", help="Open this URL and capture its DOM in the same Windows operation")
    saved.add_argument("--output", type=Path, required=True)
    for command in (opened, inspect, evaluate, saved):
        command.add_argument("--target-id")
    for command in (opened, inspect, saved):
        command.add_argument("--wait-ms", type=int, default=1500)
    return parser


def main(argv=None):
    args = parser_for_cli().parse_args(argv)
    try:
        request_id = _id(args.request_id or str(uuid.uuid4()))
        profile = SessionStore(args.session_file).load(role="controller")
        state = BrowserState(args.state_file)
        controller = BrowserController(RelayClient(profile["url"], profile["session_token"]), state)
        print(f"Request ID: {request_id}", file=sys.stderr, flush=True)
        with state.locked():
            if args.operation == "install":
                result = controller.install(request_id, args.expected_hostname, chrome_path=args.chrome_path,
                                            profile_directory=args.profile_directory)
            else:
                operation = {"eval": "evaluate", "save": "save_html"}.get(args.operation, args.operation)
                parameters = {key: getattr(args, key) for key in ("url", "target_id", "wait_ms")
                              if getattr(args, key, None) is not None}
                if "wait_ms" in parameters and not 0 <= parameters["wait_ms"] <= 15000:
                    raise ClientError("--wait-ms must be between 0 and 15000")
                if args.operation == "eval":
                    expression = args.expression_file.read_text(encoding="utf-8") if args.expression_file else args.expression
                    if len(expression) > 16000:
                        raise ClientError("Browser expression exceeds 16000 characters")
                    parameters["expression"] = expression
                result = controller.execute(operation, request_id, parameters, output=getattr(args, "output", None))
        print(json.dumps({"ok": True, "id": request_id, "result": result}, ensure_ascii=False, indent=2))
        return 0
    except (ClientError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Cancelled. Inspect the previous request ID before repeating the operation.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
