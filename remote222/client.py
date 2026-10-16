"""Linux/Windows controller; credentials are read from env or a local file."""

import argparse
import base64
import json
import os
from pathlib import Path
import sys
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
    return url.rstrip("/")


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
                raw = response.read(8 * 1024 * 1024 + 1)
                if len(raw) > 8 * 1024 * 1024:
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
        timeout = min(340, args.get("timeout", 30) + 25) if action == "shell" else 60
        return self.request("/v1/actions", {"id": request_id, "action": action, "args": args}, timeout)


def parser_for_cli():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.environ.get("REMOTE222_URL"))
    parser.add_argument("--token-file", type=Path)
    parser.add_argument("--request-id", help="Reuse this ID after an uncertain network result")
    sub = parser.add_subparsers(dest="action", required=True)
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


def main(argv=None):
    parser = parser_for_cli()
    args = parser.parse_args(argv)
    if not args.url:
        parser.error("Set REMOTE222_URL or pass --url")
    try:
        token = args.token_file.read_text(encoding="ascii").strip() if args.token_file else os.environ.get("REMOTE222_TOKEN", "")
        client = Client(args.url, token)
        params = {key: value for key, value in vars(args).items()
                  if key not in {"url", "token_file", "request_id", "action", "input", "output"} and value is not None}
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


if __name__ == "__main__":
    sys.exit(main())
