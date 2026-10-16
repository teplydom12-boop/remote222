"""Run tests and expose actionable failures as GitHub check annotations."""

import os
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
result = unittest.TextTestRunner(verbosity=2).run(suite)
if os.environ.get("GITHUB_ACTIONS") == "true":
    for test, traceback in [*result.failures, *result.errors]:
        # Never expose random test credentials in public check annotations.
        message = re.sub(r"[A-Za-z0-9_-]{43,}", "[redacted-long-value]", traceback)[-5000:]
        escaped = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::error title={test.id()}::{escaped}", flush=True)
raise SystemExit(0 if result.wasSuccessful() else 1)
