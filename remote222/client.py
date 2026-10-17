"""Linux/Windows controller with browser-approved account sign-in."""

import argparse
import base64
import json
import os
from pathlib import Path
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


class ClientError(Exception):
    pass


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ClientError(f"Redirect refused ({code}); verify the configured agent URL")


def normalize_url(url):
    if not isinstance(url, str) or any(char.isspace() or ord(char) < 32 for char in url):
        raise ClientError("Invalid agent URL")
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ClientError("Invalid agent URL") from exc
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise ClientError("URL must contain only scheme, hostname and optional port")
    local = parsed.hostname in ("127.0.0.1", "localhost", "::1")
    if parsed.scheme != "https" and not (local and parsed.scheme == "http"):
        raise ClientError("HTTPS is required except for loopback tests")
    try:
        hostname = parsed.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ClientError("Invalid agent URL") from None
    hostname = f"[{hostname}]" if ":" in hostname else hostname
    suffix = f":{port}" if port is not None and port != (443 if parsed.scheme == "https" else 80) else ""
    return f"{parsed.scheme}://{hostname}{suffix}"


class Client:
    def __init__(self, url, token):
        self.url = normalize_url(url)
        if not token or any(c in token for c in "\r\n"):
            raise ClientError("Missing or invalid access key")
        self.token = token
        # HTTPS uses Python's default trust store, including platform-injected CA settings.
        self.opener = urllib.request.build_opener(NoRedirects())

    def request(self, path, body=None, timeout=40):
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(self.url + path, data=data, headers={
            "Authorization": "Bearer " + self.token,
            "Content-Type": "application/json", "Accept": "application/json",
        })
        try:
            with self.opener.open(req, timeout=timeout) as response:
                limit = 8 * 1024 * 1024 + 8192  # Allow the relay job envelope.
                raw = response.read(limit + 1)
                if len(raw) > limit:
                    raise ClientError("Agent response is too large")
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            # Do not print proxy responses that could contain request headers.
            try:
                payload = json.loads(exc.read(8192))
                code = payload.get("error", "http_error")
                if not isinstance(code, str) or not code.replace("_", "").isalnum():
                    code = "http_error"
            except (ValueError, AttributeError):
                code = "http_error"
            raise ClientError(f"HTTP {exc.code}: {code}") from None
        except (urllib.error.URLError, TimeoutError, ConnectionError, ValueError) as exc:
            raise ClientError(f"Connection failed ({type(exc).__name__}); check agent and tunnel. For an action, reuse its request ID; execution may already have occurred.") from None

    def info(self):
        return self.request("/v1/info")

    def action(self, action, args, request_id=None):
        request_id = request_id or str(uuid.uuid4())
        requested = args.get("timeout", 30) if isinstance(args, dict) else 30
        execution_timeout = requested if type(requested) is int and 1 <= requested <= 300 else 30
        # The agent validates the original arguments. Invalid timeout input must
        # produce a normal action error, not crash the worker before transmission.
        timeout = execution_timeout + 25 if action == "shell" else 60
        return self.request("/v1/actions", {"id": request_id, "action": action, "args": args}, timeout)


def parser_for_cli():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", help="Server URL (defaults to saved session or REMOTE222_URL)")
    parser.add_argument("--transport", choices=["direct", "relay"])
    parser.add_argument("--token-file", type=Path)
    parser.add_argument("--session-file", type=Path, help="Private saved account session; ignores legacy environment credentials")
    parser.add_argument("--request-id", help="Reuse this ID after an uncertain network result")
    sub = parser.add_subparsers(dest="action", required=True)
    connect = sub.add_parser("connect", help="Link this controller by approving a code in your browser")
    connect.add_argument("--label", default="Codex", help="Name shown on the approval page")
    sub.add_parser("session", help="Check the saved controller sign-in without operating the PC")
    logout = sub.add_parser("logout", help="Revoke and remove the saved controller sign-in")
    logout.add_argument("--local-only", action="store_true", help="Remove local profile without revoking the server session")
    sub.add_parser("info")
    opened = sub.add_parser("open")
    opened.add_argument("target")
    opened.add_argument("arguments", nargs=argparse.REMAINDER)
    shell = sub.add_parser("shell")
    shell.add_argument("command")
    shell.add_argument("--cwd")
    shell.add_argument("--timeout", type=int, default=30)
    listing = sub.add_parser("list")
    listing.add_argument("path", nargs="?")
    listing.add_argument("--limit", type=int, default=200)
    read = sub.add_parser("read")
    read.add_argument("path")
    read.add_argument("--output", type=Path, required=True)
    write = sub.add_parser("write")
    write.add_argument("path")
    write.add_argument("--input", type=Path, required=True)
    write.add_argument("--overwrite", action="store_true")
    shot = sub.add_parser("screenshot")
    shot.add_argument("--output", type=Path, required=True)
    shot.add_argument("--max-width", type=int, default=1600)
    typing = sub.add_parser("text")
    typing.add_argument("text")
    keys = sub.add_parser("keys")
    keys.add_argument("keys")
    mouse = sub.add_parser("mouse")
    mouse.add_argument("x", type=int)
    mouse.add_argument("y", type=int)
    mouse.add_argument("--button", choices=["none", "left", "right", "middle"], default="none")
    mouse.add_argument("--clicks", type=int, choices=[1, 2], default=1)
    mouse.add_argument("--scroll", type=int, default=0)
    return parser


def _account_command(args):
    from .auth_client import AuthClient, AuthConnectionError, AuthHTTPError, SessionStore, default_session_path
    store = SessionStore(args.session_file or default_session_path())
    if args.token_file or args.transport == "direct":
        raise ClientError("Account connections use relay mode; omit direct/token options")
    if args.action == "connect":
        url = args.url or os.environ.get("REMOTE222_URL")
        if not url:
            raise ClientError("Pass --url with your HTTPS server address")
        auth = AuthClient(url)
        started = time.monotonic()
        pairing = auth.device_start(args.label)
        deadline = started + pairing["expires_in"]
        # The server supplies a relative path only. Never display an external
        # verification URL, the polling secret, or the eventual session token.
        print(f"Open: {auth.url}/connect", flush=True)
        print(f"Code: {pairing['user_code']}", flush=True)
        print("Sign in there and approve this controller. Waiting for approval...", flush=True)
        retrying = False
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ClientError("Device sign-in expired; run connect again")
            time.sleep(min(pairing["interval"], remaining))
            if time.monotonic() >= deadline:
                raise ClientError("Device sign-in expired; run connect again")
            try:
                result = auth.device_poll(pairing["device_code"], timeout=min(15, deadline - time.monotonic()))
            except (AuthConnectionError, AuthHTTPError) as exc:
                if isinstance(exc, AuthHTTPError) and exc.status not in {408, 429} and not 500 <= exc.status <= 599:
                    raise
                if not retrying:
                    print("Waiting for the account server to reconnect; the same approval code is still in use.", flush=True)
                    retrying = True
                continue
            if time.monotonic() >= deadline:
                raise ClientError("Device sign-in expired; run connect again")
            if result["status"] == "approved":
                store.save(auth.url, result)
                print("Controller connected. The session was saved privately; no cloud secret setting is needed.")
                return 0
    if args.action == "logout" and args.local_only:
        store.delete()
        print("Local session removed. The server session was not revoked.")
        return 0
    profile = store.load(expected_url=args.url, role="controller")
    auth = AuthClient(profile["url"], profile["session_token"])
    if args.action == "logout":
        auth.logout()
        store.delete()
        print("Controller signed out; the saved session was revoked and removed.")
    else:
        result = auth.session()
        if result["role"] != "controller":
            raise ClientError("Saved account session has the wrong role")
        print(json.dumps({"ok": True, "url": profile["url"], "role": result["role"],
                          "expires_at": result["expires_at"]}, indent=2))
    return 0


def _operation_client(args):
    from .auth_client import SessionStore, default_session_path
    default_path = default_session_path()
    use_profile = args.session_file is not None or (
        args.token_file is None and args.transport != "direct" and default_path.exists())
    if use_profile:
        if args.token_file or args.transport == "direct":
            raise ClientError("Saved account sessions use relay mode; omit direct/token options")
        profile = SessionStore(args.session_file or default_path).load(expected_url=args.url, role="controller")
        from .relay import RelayClient
        return RelayClient(profile["url"], profile["session_token"])
    url = args.url or os.environ.get("REMOTE222_URL")
    if not url:
        raise ClientError("Set REMOTE222_URL, pass --url, or connect an account session")
    token = args.token_file.read_text(encoding="ascii").strip() if args.token_file else os.environ.get("REMOTE222_TOKEN", "")
    transport = args.transport or os.environ.get("REMOTE222_TRANSPORT", "direct")
    if transport not in {"direct", "relay"}:
        raise ClientError("REMOTE222_TRANSPORT must be direct or relay")
    if transport == "relay":
        from .relay import RelayClient
        return RelayClient(url, token)
    return Client(url, token)


def main(argv=None):
    parser = parser_for_cli()
    args = parser.parse_args(argv)
    try:
        if args.action in {"connect", "session", "logout"}:
            return _account_command(args)
        client = _operation_client(args)
        params = {key: value for key, value in vars(args).items()
                  if key not in {"url", "transport", "token_file", "session_file", "request_id", "action", "input", "output"} and value is not None}
        if args.action == "write":
            with args.input.open("rb") as stream:
                content = stream.read(1024 * 1024 + 1)
            if len(content) > 1024 * 1024:
                raise ClientError("File exceeds 1 MiB")
            params["data_base64"] = base64.b64encode(content).decode("ascii")
        if args.action == "info":
            result = client.info()
        else:
            request_id = args.request_id or str(uuid.uuid4())
            print(f"Request ID: {request_id}", file=sys.stderr, flush=True)
            result = client.action(args.action, params, request_id)
        if result.get("ok") and args.action in ("screenshot", "read"):
            payload = result["result"]
            content = base64.b64decode(payload.pop("data_base64"), validate=True)
            # Local output also defaults to exclusive creation.
            with args.output.open("xb") as stream:
                stream.write(content)
            payload["saved_to"] = str(args.output)
            payload["bytes"] = len(content)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if not result.get("ok"):
            return 1
        if args.action == "shell":
            return 0 if result["result"]["exit_code"] == 0 and not result["result"]["timed_out"] else 1
        return 0
    except (ClientError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    # Relay/account modules import this module by its package name. Reuse it
    # when invoked with -m so ClientError retains one identity and stays terse.
    sys.modules.setdefault("remote222.client", sys.modules[__name__])
    sys.exit(main())
