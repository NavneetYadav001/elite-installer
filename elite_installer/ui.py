"""Terminal interface: blue->purple gradient, ASCII logo, animated progress bar. Standard library only."""
from __future__ import annotations

import getpass
import os
import re
import shutil
import sys
import threading
import time

BLUE = (59, 130, 246)
INDIGO = (99, 102, 241)
PURPLE = (168, 85, 247)
GREEN = (74, 222, 128)
AMBER = (251, 191, 36)
RED = (248, 113, 113)
MUTED = (148, 163, 184)
WHITE = (241, 245, 249)

LOGO_ELITE = [
    "███████╗██╗     ██╗████████╗███████╗",
    "██╔════╝██║     ██║╚══██╔══╝██╔════╝",
    "█████╗  ██║     ██║   ██║   █████╗  ",
    "██╔══╝  ██║     ██║   ██║   ██╔══╝  ",
    "███████╗███████╗██║   ██║   ███████╗",
    "╚══════╝╚══════╝╚═╝   ╚═╝   ╚══════╝",
]
LOGO_HOSTING = [
    "██╗  ██╗ ██████╗ ███████╗████████╗██╗███╗   ██╗ ██████╗ ",
    "██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██║████╗  ██║██╔════╝ ",
    "███████║██║   ██║███████╗   ██║   ██║██╔██╗ ██║██║  ███╗",
    "██╔══██║██║   ██║╚════██║   ██║   ██║██║╚██╗██║██║   ██║",
    "██║  ██║╚██████╔╝███████║   ██║   ██║██║ ╚████║╚██████╔╝",
    "╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝╚═╝  ╚═══╝ ╚═════╝ ",
]
LOGO_WIDTH = 56
SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def gradient_at(t: float):
    """Blue at 0, indigo in the middle, purple at 1."""
    t = max(0.0, min(1.0, t))
    return lerp(BLUE, INDIGO, t * 2) if t < 0.5 else lerp(INDIGO, PURPLE, (t - 0.5) * 2)


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


class Ui:
    def __init__(self, out=None, color: bool | None = None, animate: bool | None = None, width: int | None = None):
        self.out = out or sys.stdout
        is_tty = bool(getattr(self.out, "isatty", lambda: False)())
        dumb = os.environ.get("TERM", "") == "dumb"
        self.color = (is_tty and not dumb and "NO_COLOR" not in os.environ) if color is None else color
        self.animate = (is_tty and not dumb) if animate is None else animate
        self.truecolor = os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit")
        self._width = width
        self._lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._step: dict | None = None
        self.total_steps = 0
        self.done_steps = 0
        self.sub = 0.0          # 0..1 progress inside the current step (downloads)
        self.warnings: list[str] = []

    # ------------------------------------------------------------------ colour helpers
    @property
    def width(self) -> int:
        return self._width or shutil.get_terminal_size((80, 24)).columns

    def fg(self, text: str, rgb, bold: bool = False) -> str:
        if not self.color:
            return text
        b = "1;" if bold else ""
        if self.truecolor:
            return f"\x1b[{b}38;2;{rgb[0]};{rgb[1]};{rgb[2]}m{text}\x1b[0m"
        r, g, bl = (round(c / 255 * 5) for c in rgb)
        return f"\x1b[{b}38;5;{16 + 36 * r + 6 * g + bl}m{text}\x1b[0m"

    def grad(self, text: str, bold: bool = False) -> str:
        if not self.color:
            return text
        n = max(len(text) - 1, 1)
        return "".join(self.fg(ch, gradient_at(i / n), bold) if ch != " " else ch for i, ch in enumerate(text))

    def dim(self, text: str) -> str:
        return self.fg(text, MUTED)

    # ------------------------------------------------------------------ plain output
    def _write(self, text: str) -> None:
        with self._lock:
            self.out.write(text)
            self.out.flush()

    def line(self, text: str = "") -> None:
        with self._lock:
            if self._step and self.animate:
                self._write("\r\x1b[2K" + text + "\n")
                self._draw()
            else:
                self._write(text + "\n")

    def logo(self, version: str, subtitle: str = "ELITE INSTALLER") -> None:
        self.line()
        if self.width >= LOGO_WIDTH + 2:
            rows = LOGO_ELITE + [""] + LOGO_HOSTING
            for r, row in enumerate(rows):
                pad = " " if row else ""
                self.line("  " + self._grad_row(row.ljust(LOGO_WIDTH) if row else "", r / max(len(rows) - 1, 1)) + pad)
        else:
            self.line("  " + self.grad("◆ E L I T E   H O S T I N G ◆", bold=True))
        self.line()
        self.line("  " + self.fg(subtitle, WHITE, True) + self.dim(f"  ·  v{version}  ·  Ubuntu 24.04 LTS"))
        self.line("  " + self.dim("─" * min(self.width - 4, LOGO_WIDTH)))

    def _grad_row(self, row: str, vt: float) -> str:
        if not self.color or not row:
            return row
        n = max(len(row) - 1, 1)
        out = []
        for i, ch in enumerate(row):
            out.append(ch if ch == " " else self.fg(ch, gradient_at(0.65 * i / n + 0.35 * vt)))
        return "".join(out)

    def heading(self, text: str) -> None:
        self.line()
        self.line("  " + self.grad(text, bold=True))

    def kv(self, key: str, value: str, width: int = 14) -> None:
        self.line("  " + self.dim(key.ljust(width)) + value)

    def ok(self, text: str) -> None:
        self.line("  " + self.fg("✔", GREEN, True) + " " + text)

    def warn(self, text: str) -> None:
        self.warnings.append(text)
        self.line("  " + self.fg("!", AMBER, True) + " " + text)

    def fail(self, text: str) -> None:
        self.line("  " + self.fg("✘", RED, True) + " " + text)

    def info(self, text: str) -> None:
        self.line("  " + self.fg("•", BLUE) + " " + text)

    def box(self, lines: list[str], title: str = "") -> None:
        inner = max([len(strip_ansi(x)) for x in lines] + [len(title) + 2, 30])
        inner = min(inner, max(self.width - 6, 30))
        top = "╭─" + (f" {title} " if title else "") + "─" * (inner - len(title) - (2 if title else -2)) + "─╮"
        self.line("  " + self.fg(top, INDIGO))
        for x in lines:
            pad = " " * max(inner - len(strip_ansi(x)), 0)
            self.line("  " + self.fg("│", INDIGO) + " " + x + pad + " " + self.fg("│", INDIGO))
        self.line("  " + self.fg("╰" + "─" * (inner + 2) + "╯", INDIGO))

    # ------------------------------------------------------------------ prompts
    @staticmethod
    def _tty_input():
        if sys.stdin and sys.stdin.isatty():
            return sys.stdin
        try:
            return open("/dev/tty")
        except OSError:
            return None

    @property
    def interactive(self) -> bool:
        return self._tty_input() is not None

    def confirm(self, question: str, default: bool = False, assume_yes: bool = False) -> bool:
        if assume_yes:
            return True
        tty = self._tty_input()
        if tty is None:
            raise RuntimeError("No terminal available for confirmation; re-run with --yes to proceed non-interactively.")
        hint = "Y/n" if default else "y/N"
        self._write("  " + self.fg("?", PURPLE, True) + f" {question} " + self.dim(f"[{hint}]") + " ")
        answer = tty.readline().strip().lower()
        if not answer:
            return default
        return answer in ("y", "yes")

    def secret(self, prompt: str) -> str:
        return getpass.getpass("  " + prompt)

    # ------------------------------------------------------------------ progress
    def begin(self, total_steps: int) -> None:
        self.total_steps, self.done_steps = total_steps, 0

    def step_start(self, title: str) -> None:
        with self._lock:
            self.sub = 0.0
            self._step = {"title": title, "status": "", "t0": time.monotonic(), "i": 0}
            index = self.done_steps + 1
            if not self.animate:
                self._write(f"  [{index}/{self.total_steps}] {title} ...\n")
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
            self._draw()

    def status(self, text: str) -> None:
        text = strip_ansi(text).strip()
        if self._step is not None:
            self._step["status"] = text

    def progress(self, fraction: float) -> None:
        self.sub = max(0.0, min(1.0, fraction))

    def step_end(self, ok: bool = True, note: str = "") -> None:
        with self._lock:
            step, self._step = self._step, None
            self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)
            self._thread = None
        if step is None:
            return
        took = time.monotonic() - step["t0"]
        if ok:
            self.done_steps += 1
        mark = self.fg("✔", GREEN, True) if ok else self.fg("✘", RED, True)
        extra = self.dim(f"  {note}" if note else "") + self.dim(f"  {took:.1f}s" if took >= 0.5 else "")
        with self._lock:
            if self.animate:
                self._write("\r\x1b[2K")
            self._write(f"  {mark} {step['title']}{extra}\n")
            if self.animate and ok and self.done_steps < self.total_steps:
                pass

    def _spin(self) -> None:
        while not self._stop.wait(0.1):
            with self._lock:
                if self._step is not None:
                    self._step["i"] += 1
                    self._draw()

    def percent(self) -> float:
        if not self.total_steps:
            return 0.0
        return min((self.done_steps + self.sub) / self.total_steps, 1.0)

    def bar(self, fraction: float, width: int = 24) -> str:
        filled = int(round(fraction * width))
        if not self.color:
            return "[" + "#" * filled + "-" * (width - filled) + "]"
        cells = [self.fg("█", gradient_at(i / max(width - 1, 1))) for i in range(filled)]
        return "[" + "".join(cells) + self.fg("░" * (width - filled), (51, 65, 85)) + "]"

    def _draw(self) -> None:
        if not (self.animate and self._step):
            return
        s = self._step
        frac = self.percent()
        spin = SPINNER[s["i"] % len(SPINNER)]
        elapsed = f"{time.monotonic() - s['t0']:.0f}s"
        head_plain = f"  {spin} [{'#' * 24}] {frac * 100:3.0f}%  {s['title']}"
        room = max(self.width - len(head_plain) - len(elapsed) - 6, 0)
        status = s["status"]
        status = (status[: room - 1] + "…") if room and len(status) > room else status if room else ""
        tail = self.dim(" · " + status) if status else ""
        self._write(
            "\r\x1b[2K  " + self.fg(spin, PURPLE, True) + " " + self.bar(frac) + f" {frac * 100:3.0f}%  "
            + self.fg(s["title"], WHITE, True) + tail + self.dim(f"  {elapsed}")
        )

    def finish(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)
            self._thread = None
        self._step = None
