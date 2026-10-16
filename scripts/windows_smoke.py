"""Run manually on Windows; opens Notepad, types text, captures a screenshot."""

import sys
from pathlib import Path
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from remote222.actions import execute

print(execute("open", {"target": "notepad.exe"}))
print("Click the Notepad window within five seconds; a test message will be typed.", flush=True)
time.sleep(5)
print(execute("text", {"text": "Remote222 desktop test"}))
result = execute("screenshot", {})
assert result["image_width"] > 0
print("Screenshot captured:", result["image_width"], result["image_height"])
