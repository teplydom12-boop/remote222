"""Build one Windows EXE with Python, Tk, agent, and a verified cloudflared."""

import hashlib
import os
from pathlib import Path
import platform
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from remote222.session import CLOUDFLARED_SHA256, CLOUDFLARED_VERSION


def download(url, target, expected_hash=None):
    temporary = target.with_suffix(target.suffix + ".part")
    try:
        with urllib.request.urlopen(url, timeout=60) as response, temporary.open("wb") as stream:
            while chunk := response.read(1024 * 1024):
                stream.write(chunk)
        with temporary.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if expected_hash and digest != expected_hash:
            raise RuntimeError("Official artifact checksum mismatch; refusing to build")
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    if os.name != "nt":
        raise SystemExit("Build this EXE on Windows; use the GitHub Actions workflow from Linux.")
    vendor = ROOT / "vendor"
    vendor.mkdir(exist_ok=True)
    binary = vendor / "cloudflared.exe"
    download(f"https://github.com/cloudflare/cloudflared/releases/download/{CLOUDFLARED_VERSION}/cloudflared-windows-amd64.exe",
             binary, CLOUDFLARED_SHA256)
    download(f"https://raw.githubusercontent.com/cloudflare/cloudflared/{CLOUDFLARED_VERSION}/LICENSE", vendor / "CLOUDFLARED-LICENSE.txt")
    download(f"https://raw.githubusercontent.com/python/cpython/v{platform.python_version()}/LICENSE", vendor / "PYTHON-LICENSE.txt")
    subprocess.run([
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--windowed",
        "--name", "Remote222", "--noupx", "--paths", str(ROOT),
        "--distpath", str(ROOT / "dist"), "--workpath", str(ROOT / "build"),
        "--specpath", str(ROOT / "build"),
        "--add-binary", f"{binary}{os.pathsep}.",
        "--add-data", f"{vendor / 'CLOUDFLARED-LICENSE.txt'}{os.pathsep}.",
        "--add-data", f"{vendor / 'PYTHON-LICENSE.txt'}{os.pathsep}.",
        str(ROOT / "scripts" / "desktop_entry.py")], cwd=ROOT, check=True)
    output = ROOT / "dist" / "Remote222.exe"
    with output.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    output.with_suffix(".exe.sha256").write_text(f"{digest}  Remote222.exe\n", encoding="ascii")
    print(f"Built {output.name}: {output.stat().st_size} bytes, SHA256 {digest}")


if __name__ == "__main__":
    main()
