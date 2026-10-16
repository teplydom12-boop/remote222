"""Windows desktop operations. No service or elevated desktop is used."""

import ctypes
from ctypes import wintypes
import subprocess

from .actions import ActionError, int_arg, powershell, text_arg


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD),
                ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD),
                ("dwExtraInfo", ctypes.c_size_t)]


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [("dx", wintypes.LONG), ("dy", wintypes.LONG),
                ("mouseData", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("time", wintypes.DWORD), ("dwExtraInfo", ctypes.c_size_t)]


class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [("uMsg", wintypes.DWORD), ("wParamL", wintypes.WORD), ("wParamH", wintypes.WORD)]


class INPUTUNION(ctypes.Union):
    _fields_ = [("ki", KEYBDINPUT), ("mi", MOUSEINPUT), ("hi", HARDWAREINPUT)]


class INPUT(ctypes.Structure):
    _anonymous_ = ("value",)
    _fields_ = [("type", wintypes.DWORD), ("value", INPUTUNION)]


def user32():
    api = ctypes.WinDLL("user32", use_last_error=True)
    api.SendInput.argtypes = (wintypes.UINT, ctypes.POINTER(INPUT), ctypes.c_int)
    api.SendInput.restype = wintypes.UINT
    api.SetCursorPos.argtypes = (ctypes.c_int, ctypes.c_int)
    api.SetCursorPos.restype = wintypes.BOOL
    # Physical coordinates across monitors, including displays with scaling enabled.
    api.SetThreadDpiAwarenessContext.argtypes = [wintypes.HANDLE]
    api.SetThreadDpiAwarenessContext.restype = wintypes.HANDLE
    api.SetThreadDpiAwarenessContext(ctypes.c_void_p(-4))
    return api


def send(events):
    if not events:
        return
    packet = (INPUT * len(events))(*events)
    if user32().SendInput(len(events), packet, ctypes.sizeof(INPUT)) != len(events):
        raise ActionError("Windows rejected input; check the active desktop and elevation level")


def key(vk=0, scan=0, flags=0):
    return INPUT(type=1, ki=KEYBDINPUT(vk, scan, flags, 0, 0))


def type_text(args):
    value = text_arg(args, "text", limit=10000)
    encoded = value.replace("\r\n", "\n").replace("\r", "\n").encode("utf-16-le")
    events = []
    for offset in range(0, len(encoded), 2):
        code = int.from_bytes(encoded[offset:offset + 2], "little")
        if code == 10:  # Enter rather than a literal control character.
            events.extend([key(vk=13), key(vk=13, flags=2)])
        else:
            events.extend([key(scan=code, flags=4), key(scan=code, flags=6)])
    for offset in range(0, len(events), 200):
        send(events[offset:offset + 200])
    return {"characters_sent": len(value)}


KEYS = {"ctrl": 0x11, "alt": 0x12, "shift": 0x10, "win": 0x5B,
        "enter": 0x0D, "tab": 0x09, "esc": 0x1B, "space": 0x20,
        "backspace": 0x08, "delete": 0x2E, "insert": 0x2D,
        "left": 0x25, "up": 0x26, "right": 0x27, "down": 0x28,
        "home": 0x24, "end": 0x23, "pageup": 0x21, "pagedown": 0x22,
        **{f"f{i}": 0x6F + i for i in range(1, 25)},
        **{c.lower(): ord(c) for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"}}
EXTENDED = {0x5B, 0x2E, 0x2D, 0x25, 0x26, 0x27, 0x28, 0x24, 0x23, 0x21, 0x22}


def hotkey(args):
    names = text_arg(args, "keys", limit=100).lower().split("+")
    if not 1 <= len(names) <= 5 or any(name not in KEYS for name in names):
        raise ActionError("Use keys such as ctrl+s, alt+tab, win+r, enter, or f5")
    codes = [KEYS[name] for name in names]
    send([key(vk=code, flags=1 if code in EXTENDED else 0) for code in codes]
         + [key(vk=code, flags=2 | (1 if code in EXTENDED else 0)) for code in reversed(codes)])
    return {"sent": names}


def mouse(args):
    x = int_arg(args, "x", None, -100000, 100000)
    y = int_arg(args, "y", None, -100000, 100000)
    button = args.get("button", "none")
    if button not in ("none", "left", "right", "middle"):
        raise ActionError("button must be none, left, right, or middle")
    count = int_arg(args, "clicks", 1, 1, 2)
    scroll = int_arg(args, "scroll", 0, -100, 100)
    api = user32()
    left, top, width, height = [api.GetSystemMetrics(i) for i in (76, 77, 78, 79)]
    if not left <= x < left + width or not top <= y < top + height:
        raise ActionError("Coordinates are outside the virtual desktop")
    if not api.SetCursorPos(x, y):
        raise ActionError("Cannot move pointer on this desktop")
    flags = {"left": (2, 4), "right": (8, 16), "middle": (32, 64)}
    if button != "none":
        for _ in range(count):
            send([INPUT(type=0, mi=MOUSEINPUT(0, 0, 0, flag, 0, 0)) for flag in flags[button]])
    if scroll:
        send([INPUT(type=0, mi=MOUSEINPUT(0, 0, scroll * 120 & 0xFFFFFFFF, 0x0800, 0, 0))])
    return {"x": x, "y": y, "button": button, "clicks": count if button != "none" else 0,
            "scroll": scroll}


def screenshot(args):
    # Return original coordinates separately; image can be resized for transmission.
    max_width = int_arg(args, "max_width", 1600, 320, 3840)
    script = r'''
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class Dpi { [DllImport("user32.dll")] public static extern IntPtr SetThreadDpiAwarenessContext(IntPtr value); }'
[void][Dpi]::SetThreadDpiAwarenessContext([IntPtr]::new(-4))
$bounds = [System.Windows.Forms.SystemInformation]::VirtualScreen
$bitmap = [System.Drawing.Bitmap]::new($bounds.Width, $bounds.Height)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$stream = [System.IO.MemoryStream]::new()
$small = $null
try {
    $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
    $image = $bitmap
    if ($bounds.Width -gt MAX_WIDTH) {
        $height = [Math]::Max(1, [int]($bounds.Height * MAX_WIDTH / $bounds.Width))
        $small = [System.Drawing.Bitmap]::new($bitmap, MAX_WIDTH, $height)
        $image = $small
    }
    $image.Save($stream, [System.Drawing.Imaging.ImageFormat]::Jpeg)
    @{mime_type='image/jpeg'; data_base64=[Convert]::ToBase64String($stream.ToArray());
      left=$bounds.Left; top=$bounds.Top; desktop_width=$bounds.Width; desktop_height=$bounds.Height;
      image_width=$image.Width; image_height=$image.Height} | ConvertTo-Json -Compress
} finally {
    if ($small) { $small.Dispose() }
    $stream.Dispose(); $graphics.Dispose(); $bitmap.Dispose()
}
'''.replace("MAX_WIDTH", str(max_width))
    result = subprocess.run(powershell(script), capture_output=True, timeout=30)
    if result.returncode:
        raise ActionError(result.stderr.decode("utf-8", errors="replace")[-2000:])
    import json
    return json.loads(result.stdout.decode("utf-8-sig"))


def perform(action, args):
    return {"screenshot": screenshot, "text": type_text, "keys": hotkey, "mouse": mouse}[action](args)
