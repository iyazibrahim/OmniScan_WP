"""Colored terminal output and interactive menu for the OmniScan."""

import os
import sys


def is_ci() -> bool:
    """Detect headless/CI mode via CI env var or --ci flag."""
    return bool(os.environ.get("CI")) or "--ci" in sys.argv

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    # Fallback if colorama is not installed
    class _Dummy:
        def __getattr__(self, _):
            return ""
    Fore = _Dummy()
    Style = _Dummy()

# ── Banner ──────────────────────────────────────────────────────────────────────

def print_banner():
    print()
    print(f"{Fore.CYAN}  ==============================================")
    print(f"{Fore.CYAN}    OmniScan v2.0")
    print(f"{Fore.CYAN}    Multi-Tool Automated Security Pipeline")
    print(f"{Fore.CYAN}    Python Edition")
    print(f"{Fore.CYAN}  ==============================================")
    print()


# ── Status helpers ──────────────────────────────────────────────────────────────

def section(title: str):
    print(f"\n{Fore.CYAN}--- {title} ---{Style.RESET_ALL}")

def status(msg: str):
    print(f"  {Fore.YELLOW}[*]{Style.RESET_ALL} {msg}")

def ok(msg: str):
    print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {msg}")

def warn(msg: str):
    print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")

def err(msg: str):
    print(f"  {Fore.RED}[-]{Style.RESET_ALL} {msg}", file=sys.stderr)

def info(msg: str):
    print(f"  {Fore.BLUE}[i]{Style.RESET_ALL} {msg}")


# ── Interactive menu ────────────────────────────────────────────────────────────

def show_menu():
    """Display the main interactive menu and return the user's choice."""
    section("Main Menu")
    options = [
        ("1", "Scan a target"),
        ("2", "Manage targets"),
        ("3", "Configure API tokens"),
        ("4", "Check installed tools"),
        ("5", "Install missing tools"),
        ("6", "View previous reports"),
        ("7", "Run demo (sample report)"),
        ("8", "Configure email notifications"),
        ("9", "Configure performance profile"),
        ("Q", "Quit"),
    ]
    for key, label in options:
        color = Fore.RED if key == "Q" else Fore.WHITE
        print(f"  {Fore.CYAN}[{key}]{Style.RESET_ALL} {color}{label}{Style.RESET_ALL}")

    print()
    choice = input(f"  {Fore.CYAN}Select option: {Style.RESET_ALL}").strip()
    return choice


def show_targets_menu():
    """Display the targets sub-menu."""
    section("Target Management")
    options = [
        ("1", "Show saved targets"),
        ("2", "Add new target"),
        ("3", "Remove a target"),
        ("B", "Back to main menu"),
    ]
    for key, label in options:
        print(f"  {Fore.CYAN}[{key}]{Style.RESET_ALL} {label}")
    print()
    return input(f"  {Fore.CYAN}Select option: {Style.RESET_ALL}").strip()


def select_scan_mode() -> str:
    """Let user pick passive / active / full scan mode."""
    section("Scan Mode")
    modes = [
        ("1", "Passive", "Non-intrusive recon only (safe)"),
        ("2", "Active", "Includes SQLMap, brute-force checks (intrusive)"),
        ("3", "Full", "Passive + Active combined"),
    ]
    for key, name, desc in modes:
        print(f"  {Fore.CYAN}[{key}]{Style.RESET_ALL} {Fore.WHITE}{name}{Style.RESET_ALL} - {Fore.LIGHTBLACK_EX}{desc}{Style.RESET_ALL}")
    print()
    choice = input(f"  {Fore.CYAN}Select mode [1/2/3]: {Style.RESET_ALL}").strip()
    mode_map = {"1": "passive", "2": "active", "3": "full"}
    return mode_map.get(choice, "passive")
