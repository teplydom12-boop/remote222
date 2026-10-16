"""Build a source bundle with an explicit allowlist; never include local secrets."""

import hashlib
from pathlib import Path
import zipfile

root = Path(__file__).resolve().parents[1]
files = [root / name for name in ("README.md", "pyproject.toml", "START.cmd", ".gitignore", "AGENTS.md")]
for directory, extensions in (("remote222", {".py"}), ("scripts", {".ps1", ".py"}), ("tests", {".py"})):
    files.extend(path for path in (root / directory).iterdir() if path.is_file() and path.suffix in extensions)
destination = root / "dist" / "remote222-windows.zip"
destination.parent.mkdir(exist_ok=True)
with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
    for path in sorted(files):
        archive.write(path, Path("remote222") / path.relative_to(root))
digest = hashlib.sha256(destination.read_bytes()).hexdigest()
destination.with_suffix(".zip.sha256").write_text(f"{digest}  {destination.name}\n")
print(destination)
print(f"SHA256 {digest}")
