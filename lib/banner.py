#airecon2 banner - self-generated ASCII logo + TUI helpers
import os
import random


def clear():
    os.system("cls" if os.name == "nt" else "clear")


LOGO = r"""
    _ ___ _   _  _____  ___  _   _
   ( ) __( )_( )(_   _)/ __) ) ) )
   | | |  |  _) |  |_( |__ \ /_/ /
   |_|_|  |_|   _| |_ (___/  \_\
               (___/
     ai recon + pentest console  v0.3
"""

# small random accent: one of several taglines on each launch
TAGLINES = [
    "recon smarter, not harder",
    "the lab does the heavy lifting",
    "leads, not guarantees - verify everything",
    "own your targets, or don't touch them",
]


def show_banner():
    clear()
    accent = random.choice(["\033[96m", "\033[92m", "\033[95m"])  # cyan/green/magenta
    dim = "\033[2m"
    reset = "\033[0m"
    print(f"{accent}{LOGO}{reset}")
    print(f"  {dim}~ {random.choice(TAGLINES)} ~{reset}")
    print()


def _disp_width(s: str) -> int:
    """Terminal columns a string occupies: emoji/wide glyphs render 2 wide,
    variation selectors 0 - keeps menu boxes aligned with emoji labels."""
    w = 0
    for ch in s:
        cp = ord(ch)
        if ch == "\ufe0f" or 0x200d <= cp <= 0x200f:
            continue
        if 0x1f000 <= cp <= 0x1faff or 0x2600 <= cp <= 0x27bf:
            w += 2
        else:
            w += 1
    return w


def _wrap(text: str, width: int) -> list:
    """Word-wrap a plain (no-color) string to a column width."""
    words, lines, cur = text.split(), [], ""
    for w in words:
        if cur and _disp_width(cur) + 1 + _disp_width(w) > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines


def menu_box(title: str, options: list, footer: str = ""):
    """Draw a wifite-style boxed menu.
    options: list of (key, label) or (key, label, description) tuples.
    The description renders dimmed, word-wrapped under its entry."""
    C, dim, reset = "\033[96m", "\033[2m", "\033[0m"
    width = max([_disp_width(t) + _disp_width(str(k)) + 8 for k, t, *rest in options]
                + [_disp_width(title) + 4])
    inner = width - 2                     # usable columns inside '| ... |'
    desc_width = inner - 5                # '      ' indent for wrapped desc lines
    print(f"  {C}+{'-' * width}+{reset}")
    print(f"  {C}|{reset} {title + ' ' * max(width - 3 - _disp_width(title), 0)}{C}|{reset}")
    print(f"  {C}+{'-' * width}+{reset}")
    for opt in options:
        key, label = opt[0], opt[1]
        desc = opt[2] if len(opt) > 2 else ""
        pad = max(width - _disp_width(str(key)) - 6 - _disp_width(label), 0)
        print(f"  {C}|{reset} {dim}[{key}]{reset} {label + ' ' * pad}{C}|{reset}")
        for dl in _wrap(desc, desc_width):
            dpad = max(inner - 6 - _disp_width(dl), 0)
            print(f"  {C}|{reset}       {dim}{dl}{' ' * dpad}{reset}{C}|{reset}")
    print(f"  {C}+{'-' * width}+{reset}")
    if footer:
        print(f"  {dim}{footer}{reset}")
    print()


def info(msg):  print(f"  \033[92m[+]\033[0m {msg}")
def warn(msg):  print(f"  \033[93m[!]\033[0m {msg}")
def err(msg):   print(f"  \033[91m[x]\033[0m {msg}")
def action(msg): print(f"  \033[96m[>]\033[0m {msg}")
