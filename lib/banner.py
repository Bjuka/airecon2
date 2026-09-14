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


def menu_box(title: str, options: list, footer: str = ""):
    """Draw a wifite-style boxed menu. options: list of (key, label) tuples."""
    C, dim, reset = "\033[96m", "\033[2m", "\033[0m"
    width = max([len(t) + len(str(k)) + 8 for k, t in options] + [len(title) + 4])
    print(f"  {C}+{'-' * width}+{reset}")
    print(f"  {C}|{reset} {title.ljust(width - 3)}{C}|{reset}")
    print(f"  {C}+{'-' * width}+{reset}")
    for key, label in options:
        print(f"  {C}|{reset} {dim}[{key}]{reset} {label.ljust(width - len(str(key)) - 6)}{C}|{reset}")
    print(f"  {C}+{'-' * width}+{reset}")
    if footer:
        print(f"  {dim}{footer}{reset}")
    print()


def info(msg):  print(f"  \033[92m[+]\033[0m {msg}")
def warn(msg):  print(f"  \033[93m[!]\033[0m {msg}")
def err(msg):   print(f"  \033[91m[x]\033[0m {msg}")
def action(msg): print(f"  \033[96m[>]\033[0m {msg}")
