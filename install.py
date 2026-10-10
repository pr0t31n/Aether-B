#!/usr/bin/env python3
# install.py — Aether-B Bluetooth Penetration Test Orchestrator
# VERSION: 1.0.1 (referenced from /opt/pr0t31n/Aether-B/VERSION — do not bump here)
# Installs all dependencies for aether_b.py and configures the system.

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------
RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"


def _pip_installed(pkg_spec):
    """Check if a pip package is already importable."""
    import importlib.util
    name = pkg_spec.split(">=")[0].split("==")[0].split("[")[0].split("<")[0].strip()
    _IMPORT_MAP = {
        "python-whois": "whois", "beautifulsoup4": "bs4", "python-docx": "docx",
        "pyOpenSSL": "OpenSSL", "dnspython": "dns", "pyyaml": "yaml",
        "Pillow": "PIL", "charset-normalizer": "charset_normalizer",
        "flask-cors": "flask_cors", "flask-socketio": "flask_socketio",
        "flask-login": "flask_login", "python-engineio": "engineio",
        "python-socketio": "socketio", "python-dotenv": "dotenv",
        "python-nmap": "nmap", "python-dateutil": "dateutil",
        "scikit-learn": "sklearn", "service_identity": "service_identity",
    }
    mod = _IMPORT_MAP.get(name, name.replace("-", "_"))
    try:
        return importlib.util.find_spec(mod) is not None
    except (ModuleNotFoundError, ValueError):
        return False


def cprint(msg: str, colour: str = RESET, bold: bool = False) -> None:
    prefix = BOLD if bold else ""
    print(f"{prefix}{colour}{msg}{RESET}")


def phase_header(title: str) -> None:
    bar = "=" * 60
    print()
    cprint(bar, CYAN, bold=True)
    cprint(f"  {title}", CYAN, bold=True)
    cprint(bar, CYAN, bold=True)


def info(msg: str)    -> None: cprint(f"  [*] {msg}", BLUE)
def success(msg: str) -> None: cprint(f"  [+] {msg}", GREEN)
def warn(msg: str)    -> None: cprint(f"  [!] {msg}", YELLOW)
def error(msg: str)   -> None: cprint(f"  [-] {msg}", RED)
def step(msg: str)    -> None: cprint(f"  --> {msg}", CYAN)


# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------

def detect_os() -> str:
    """Return one of: macos | kali | ubuntu | rhel | suse | windows | unknown"""
    system = platform.system()
    if system == "Windows":
        return "windows"
    if system == "Darwin":
        return "macos"
    if system == "Linux":
        release_files = ["/etc/os-release", "/usr/lib/os-release"]
        release_info: dict = {}
        for rf in release_files:
            if os.path.exists(rf):
                with open(rf) as fh:
                    for line in fh:
                        line = line.strip()
                        if "=" in line:
                            k, _, v = line.partition("=")
                            release_info[k] = v.strip('"').lower()
                break
        name = release_info.get("ID", "")
        like = release_info.get("ID_LIKE", "")
        if "kali" in name:
            return "kali"
        if "ubuntu" in name or "ubuntu" in like:
            return "ubuntu"
        if name in ("rhel", "centos", "rocky", "almalinux", "fedora") or \
                "rhel" in like or "fedora" in like:
            return "rhel"
        if name in ("opensuse", "sles", "suse") or "suse" in like:
            return "suse"
        if "debian" in name or "debian" in like:
            return "ubuntu"
    return "unknown"


# ---------------------------------------------------------------------------
# Command runner
# ---------------------------------------------------------------------------

def run(cmd: list, check: bool = False, dry_run: bool = False,
        env: dict = None, cwd: str = None) -> int:
    """Run a command; return exit code. If dry_run, just print and return 0."""
    display = " ".join(str(c) for c in cmd)
    if dry_run:
        cprint(f"    [DRY-RUN] {display}", MAGENTA)
        return 0
    info(f"Running: {display}")
    try:
        result = subprocess.run(
            cmd,
            env={**os.environ, **(env or {})},
            cwd=cwd,
        )
        if check and result.returncode != 0:
            error(f"Command failed (exit {result.returncode}): {display}")
        return result.returncode
    except FileNotFoundError:
        error(f"Executable not found for command: {display}")
        return 127
    except Exception as exc:
        error(f"Unexpected error running {display}: {exc}")
        return 1


# ---------------------------------------------------------------------------
# Privilege helpers
# ---------------------------------------------------------------------------

def is_root() -> bool:
    return hasattr(os, "getuid") and os.getuid() == 0


def require_root() -> None:
    if not is_root():
        error("This installer must be run as root (or with sudo) on Linux.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Phase 0 — OS detection display
# ---------------------------------------------------------------------------

def phase_os_detection() -> str:
    phase_header("PHASE 0 — OS Detection")
    os_id = detect_os()
    info(f"Detected OS: {os_id}")
    info(f"Python     : {sys.version.split()[0]}")
    info(f"Platform   : {platform.platform()}")
    if os_id == "windows":
        error("Aether-B requires Linux for full Bluetooth hardware access.")
        error("BlueZ (hcitool, hciconfig, gatttool) is Linux-only.")
        warn("Windows: only limited BLE scanning via PowerShell/WinRT is possible.")
        warn("         Consider running Aether-B in WSL2 with a USB BT adapter passthrough.")
    elif os_id == "macos":
        warn("macOS detected. BlueZ is Linux-only — full functionality requires Linux.")
        warn("Ubertooth tools and gatttool are not available on macOS.")
        warn("Homebrew will install available support tools only.")
    elif os_id in ("kali", "ubuntu"):
        success("Kali/Debian/Ubuntu detected — full Bluetooth stack support available.")
    elif os_id == "rhel":
        success("RHEL/Fedora/CentOS detected — most tools available via dnf.")
        warn("Some BlueZ tools may need manual compilation on older RHEL versions.")
    else:
        warn(f"OS '{os_id}' — will attempt installation with best-guess package manager.")
    return os_id


# ---------------------------------------------------------------------------
# Package lists
# ---------------------------------------------------------------------------

APT_PACKAGES = [
    "bluez",
    "bluetooth",
    "ubertooth",
    "tshark",
    "binwalk",
    "openocd",
    "python3-pip",
    "git",
    "build-essential",
    "libusb-1.0-0-dev",
    "libpcap-dev",
    "pkg-config",
    "btscanner",
    "bluez-tools",
    "wireshark",
    "nodejs",
    "npm",
    "make",
]

DNF_PACKAGES = [
    "epel-release",
    "bluez",
    "python3-pip",
    "git",
    "gcc",
    "gcc-c++",
    "make",
    "libusbx-devel",
    "libpcap-devel",
    "tshark",
    "wireshark",
    "openocd",
    "nodejs",
    "npm",
    "binwalk",
]

BREW_PACKAGES = [
    "libusb",
    "openocd",
    "node",
    "binwalk",
    "wireshark",
]


# ---------------------------------------------------------------------------
# Phase 1 — System packages
# ---------------------------------------------------------------------------

def phase_apt(dry_run: bool) -> None:
    phase_header("PHASE 1 — System Packages (apt)")
    require_root()
    info("Updating package lists...")
    run(["apt-get", "update", "-y"], check=True, dry_run=dry_run)
    info(f"Installing: {' '.join(APT_PACKAGES)}")
    run(["apt-get", "install", "-y"] + APT_PACKAGES, check=True, dry_run=dry_run)
    # wireshark non-interactive: allow non-root capture
    if not dry_run:
        run(["bash", "-c",
             "echo 'wireshark-common wireshark-common/install-setuid boolean true'"
             " | debconf-set-selections"],
            dry_run=dry_run)
    warn("Note: 'bluez' installs hcitool, hciconfig, sdptool, gatttool, bluetoothctl.")
    warn("      'ubertooth' installs ubertooth-scan, ubertooth-btle, ubertooth-rx.")
    success("APT phase complete.")


def phase_dnf(dry_run: bool) -> None:
    phase_header("PHASE 1 — System Packages (dnf)")
    require_root()
    run(["dnf", "install", "-y", "epel-release"], dry_run=dry_run)
    run(["dnf", "upgrade", "-y"], dry_run=dry_run)
    info(f"Installing: {' '.join(DNF_PACKAGES)}")
    run(["dnf", "install", "-y"] + DNF_PACKAGES, check=True, dry_run=dry_run)
    warn("ubertooth may need manual install on RHEL: https://github.com/greatscottgadgets/ubertooth")
    warn("btscanner may need manual install on RHEL: compile from source")
    success("DNF phase complete.")


def phase_brew(dry_run: bool) -> None:
    phase_header("PHASE 1 — System Packages (Homebrew / macOS)")
    warn("macOS: BlueZ is Linux-only. Full Bluetooth pentest functionality requires Linux.")
    warn("Installing only cross-platform support tools via Homebrew.")

    brew_bin = shutil.which("brew")
    if not brew_bin:
        error("Homebrew not found. Install from https://brew.sh and re-run.")
        return

    if is_root():
        sudo_user = os.environ.get("SUDO_USER", "")
        if not sudo_user:
            warn("Running as root but SUDO_USER is not set — skipping brew install "
                 "to avoid corrupting Homebrew. Re-run as your normal user.")
            return
        base_cmd = ["sudo", "-u", sudo_user, brew_bin]
    else:
        base_cmd = [brew_bin]

    try:
        _installed = set(subprocess.run(
            base_cmd + ["list", "--formula", "-1"],
            capture_output=True, text=True, check=True).stdout.strip().splitlines())
    except (subprocess.CalledProcessError, FileNotFoundError):
        _installed = set()
    _missing = [p for p in BREW_PACKAGES if p not in _installed]
    for p in BREW_PACKAGES:
        if p in _installed:
            info(f"✓ {p} already installed")
    if _missing:
        info(f"Installing brew packages: {' '.join(_missing)}")
        run(base_cmd + ["install"] + _missing, dry_run=dry_run)
    else:
        info("All brew packages already installed.")
    warn("bluez is not available on macOS — hcitool/gatttool/sdptool not installable.")
    warn("Use a Linux VM or Kali on a dedicated machine for full Bluetooth pentesting.")
    success("Homebrew phase complete.")


# ---------------------------------------------------------------------------
# Phase 2 — Pip packages
# ---------------------------------------------------------------------------

def phase_pip(dry_run: bool) -> None:
    phase_header("PHASE 2 — Python Packages (pip)")
    info("Aether-B uses only Python standard-library modules — no pip packages required.")
    info("All Bluetooth-facing logic is handled via system tools (hcitool, gatttool, etc.).")
    info("BlueToolkit pip requirements are handled in the Git phase post-install step.")
    success("Pip phase complete (nothing to install at this stage).")


# ---------------------------------------------------------------------------
# Phase 3 — External tools from git / package manager
# ---------------------------------------------------------------------------

GIT_REPOS = [
    {
        "label":    "crackle",
        "url":      "https://github.com/mikeryan/crackle",
        "dest":     "/opt/crackle",
        "post_cmd": ["make"],
        "post_cwd": "/opt/crackle",
        "post_install_bin": "/opt/crackle/crackle",
        "post_install_link": "/usr/local/bin/crackle",
        "notes":    "BLE LTK recovery from pcap captures (passive pairing eavesdrop)",
    },
    {
        "label":    "GATTacker",
        "url":      "https://github.com/securing/GATTacker",
        "dest":     "/opt/GATTacker",
        "post_cmd": ["npm", "install"],
        "post_cwd": "/opt/GATTacker",
        "post_install_bin": None,
        "post_install_link": None,
        "notes":    "BLE device cloning and MITM proxy (requires Node.js)",
    },
    {
        "label":    "BlueToolkit",
        "url":      "https://github.com/sgxgsx/BlueToolkit",
        "dest":     "/opt/bluetoolkit",
        "post_cmd": "__pip_check_requirements__",
        "post_cwd": None,
        "post_install_bin": None,
        "post_install_link": None,
        "notes":    "CVE-based Bluetooth exploit framework",
    },
]

APT_EXTRA_TOOLS = {
    "bettercap": ["apt-get", "install", "-y", "bettercap"],
    "btscanner": ["apt-get", "install", "-y", "btscanner"],
}


def clone_or_update(repo: dict, dry_run: bool) -> None:
    url   = repo["url"]
    dest  = repo["dest"]
    label = repo["label"]
    dest_path = Path(dest)

    if dest_path.exists():
        info(f"{label}: directory exists — pulling latest changes...")
        rc = run(["git", "-C", dest, "pull", "--ff-only"], dry_run=dry_run)
        if rc != 0:
            warn(f"{label}: git pull failed — continuing with existing clone.")
    else:
        info(f"{label}: cloning {url} → {dest}")
        rc = run(["git", "clone", "--depth=1", url, dest], check=True, dry_run=dry_run)
        if rc != 0:
            error(f"{label}: clone failed — skipping post-install steps.")
            return

    if repo.get("post_cmd"):
        if repo["post_cmd"] == "__pip_check_requirements__":
            req_file = Path(repo["dest"]) / "requirements.txt"
            if req_file.exists() and not dry_run:
                info(f"{label}: installing pip requirements (checking each first)...")
                pip = ["pip3"]
                for line in req_file.read_text().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    if _pip_installed(line):
                        info(f"  ✓ {line} already installed")
                    else:
                        info(f"  pip install {line} …")
                        subprocess.run(
                            pip + ["install", "--break-system-packages", line],
                            timeout=120,
                        )
            elif dry_run:
                cprint(f"    [DRY-RUN] Would install pip requirements from {repo['dest']}/requirements.txt", MAGENTA)
        else:
            info(f"{label}: running post-install step: {' '.join(repo['post_cmd'])}")
            run(repo["post_cmd"], cwd=repo.get("post_cwd"), dry_run=dry_run)

    # Create symlink for compiled binaries
    if repo.get("post_install_bin") and repo.get("post_install_link"):
        src = Path(repo["post_install_bin"])
        link = Path(repo["post_install_link"])
        if not dry_run and src.exists():
            if link.is_symlink() or link.exists():
                try:
                    link.unlink()
                except OSError as exc:
                    error(f"Could not remove {link}: {exc}")
            try:
                link.symlink_to(src)
                src.chmod(0o755)
                success(f"Symlink: {link} → {src}")
            except OSError as exc:
                error(f"Could not create symlink {link}: {exc}")
        elif dry_run:
            cprint(f"    [DRY-RUN] Would symlink {repo['post_install_link']} → {repo['post_install_bin']}", MAGENTA)

    if repo.get("notes"):
        info(f"{label}: {repo['notes']}")


def phase_git(os_id: str, dry_run: bool) -> None:
    phase_header("PHASE 3 — External Tools (git + build)")

    if os_id == "windows":
        warn("Skipping git tool clones on Windows — not supported.")
        return

    if os_id == "macos":
        warn("macOS: skipping crackle (Linux libpcap dependency).")
        warn("macOS: GATTacker can be installed but requires Linux BLE stack to function.")
        warn("macOS: BlueToolkit requires Linux Bluetooth stack.")
        warn("Cloning BlueToolkit for reference only...")

    # crackle: skip on macOS (requires Linux libpcap + pcap raw socket)
    for repo in GIT_REPOS:
        if repo["label"] == "crackle" and os_id == "macos":
            warn("crackle: skipping on macOS — requires Linux and raw pcap access.")
            continue
        clone_or_update(repo, dry_run)

    # bettercap and btscanner via apt if on Debian-based
    if os_id in ("kali", "ubuntu"):
        for tool_name, apt_cmd in APT_EXTRA_TOOLS.items():
            if not shutil.which(tool_name):
                info(f"Installing {tool_name} via apt...")
                run(apt_cmd, dry_run=dry_run)
            else:
                info(f"{tool_name} already installed at {shutil.which(tool_name)}")
    elif os_id == "rhel":
        # bettercap via go install on RHEL if not available via dnf
        bettercap_path = shutil.which("bettercap")
        if not bettercap_path:
            warn("bettercap not available via dnf on RHEL — attempting go install...")
            if shutil.which("go"):
                run(["go", "install", "github.com/bettercap/bettercap@latest"], dry_run=dry_run)
            else:
                warn("go not found — install bettercap manually: https://www.bettercap.org/installation/")
    else:
        warn(f"bettercap: manual installation required on {os_id}")
        warn("  See: https://www.bettercap.org/installation/")

    success("Git / external tools phase complete.")


# ---------------------------------------------------------------------------
# Phase 4 — Verify all tools present
# ---------------------------------------------------------------------------

VERIFY_TOOLS_IMPORTANT = [
    "hcitool",
    "hciconfig",
    "bluetoothctl",
    "sdptool",
    "gatttool",
    "git",
    "python3",
    "make",
    "node",
]

VERIFY_TOOLS_OPTIONAL = [
    "ubertooth-scan",
    "ubertooth-btle",
    "ubertooth-rx",
    "btscanner",
    "crackle",
    "bettercap",
    "tshark",
    "binwalk",
    "openocd",
    "npm",
]

VERIFY_GIT_REPOS = [
    ("/opt/crackle",      "crackle"),
    ("/opt/GATTacker",    "GATTacker"),
    ("/opt/bluetoolkit",  "BlueToolkit"),
]


def phase_verify(os_id: str) -> bool:
    phase_header("PHASE 4 — Tool Verification")
    all_ok = True

    for tool in VERIFY_TOOLS_IMPORTANT:
        found = shutil.which(tool)
        if found:
            success(f"{tool:30s} found at {found}")
        else:
            warn(f"{tool:30s} NOT FOUND — run: sudo python3 install.py")
            all_ok = False

    print()
    for tool in VERIFY_TOOLS_OPTIONAL:
        found = shutil.which(tool)
        if found:
            success(f"{tool:30s} (optional) found at {found}")
        else:
            warn(f"{tool:30s} (optional) NOT FOUND")

    print()
    for repo_path, label in VERIFY_GIT_REPOS:
        if Path(repo_path).exists():
            success(f"{label:30s} cloned at {repo_path}")
        else:
            warn(f"{label:30s} NOT cloned at {repo_path}")
            all_ok = False

    if all_ok:
        print()
        success("All important tools and repositories verified.")
    else:
        print()
        warn("Some tools were not found. Check output above.")
        warn("Re-run:  sudo python3 install.py  to retry installation.")

    return all_ok


# ---------------------------------------------------------------------------
# Phase 5 — Service setup: verify hci0 is up
# ---------------------------------------------------------------------------

def phase_service(os_id: str, dry_run: bool) -> None:
    phase_header("PHASE 5 — Service Setup and HCI Interface Verification")

    if os_id == "windows":
        warn("Windows: HCI device verification not supported — use WSL2.")
        return

    if os_id == "macos":
        info("macOS: Bluetooth hardware is managed by macOS CoreBluetooth framework.")
        info("No daemon configuration is needed for Aether-B on macOS.")
        success("Service phase complete (no action needed on macOS).")
        return

    # Ensure bluetooth.service is enabled and running on Linux
    info("Ensuring bluetooth.service is enabled and running...")
    if shutil.which("systemctl"):
        # unmask first — a masked service rejects enable/start silently
        run(["systemctl", "unmask", "bluetooth"], dry_run=dry_run)
        run(["systemctl", "enable", "bluetooth"], dry_run=dry_run)
        run(["systemctl", "start",  "bluetooth"], dry_run=dry_run)
    else:
        warn("systemctl not found — start bluetooth daemon manually: bluetoothd")

    # Check hci0 interface is up
    hciconfig_bin = shutil.which("hciconfig")
    if hciconfig_bin:
        info("Checking HCI device status...")
        if not dry_run:
            result = subprocess.run(
                [hciconfig_bin],
                capture_output=True, text=True,
            )
            output = result.stdout + result.stderr
            if "hci0" in output:
                success("hci0 interface found.")
                if "UP RUNNING" in output:
                    success("hci0 is UP and RUNNING.")
                else:
                    warn("hci0 found but not UP — attempting to bring up...")
                    run([hciconfig_bin, "hci0", "up"], dry_run=dry_run)
                    run([hciconfig_bin, "hci0", "piscan"], dry_run=dry_run)
            else:
                warn("hci0 not found. Check that a Bluetooth adapter is attached.")
                warn("List HCI devices: hciconfig -a")
                warn("If using USB adapter: check 'dmesg | grep -i bluetooth'")
        else:
            cprint("    [DRY-RUN] Would run: hciconfig && hciconfig hci0 up", MAGENTA)
    else:
        warn("hciconfig not found — install bluez: apt-get install bluez")

    # Verify Ubertooth if present
    ubertooth_bin = shutil.which("ubertooth-util")
    if ubertooth_bin:
        info("Ubertooth One detected — running firmware version check...")
        if not dry_run:
            result = subprocess.run(
                [ubertooth_bin, "-v"],
                capture_output=True, text=True, timeout=10,
            )
            version_out = result.stdout + result.stderr
            if version_out.strip():
                success(f"Ubertooth firmware: {version_out.strip()[:80]}")
            else:
                warn("Ubertooth version check returned no output — device may need re-plug.")
        else:
            cprint("    [DRY-RUN] Would run: ubertooth-util -v", MAGENTA)
    else:
        info("ubertooth-util not found — Ubertooth One not detected or not installed.")
        info("Install Ubertooth: apt-get install ubertooth  OR  https://github.com/greatscottgadgets/ubertooth")

    info("Aether-B does not require a system daemon — all phases are run on demand.")
    success("Service setup phase complete.")


# ---------------------------------------------------------------------------
# Syntax check
# ---------------------------------------------------------------------------

def run_check() -> bool:
    """Run a quick syntax check on aether_b.py. Returns True on success."""
    aether_b = Path(__file__).parent / "aether_b.py"
    if not aether_b.exists():
        warn(f"aether_b.py not found at {aether_b}")
        return False
    result = subprocess.run(
        [sys.executable, "-m", "py_compile", str(aether_b)],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        success("aether_b.py syntax check: PASS")
        return True
    else:
        error(f"aether_b.py syntax check: FAIL\n{result.stderr}")
        return False


def print_summary(os_id: str) -> None:
    phase_header("POST-INSTALL SUMMARY")
    phase_verify(os_id)
    print()
    run_check()


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Aether-B installer — Bluetooth penetration testing orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 install.py
  sudo python3 install.py --check
  sudo python3 install.py --skip-apt
  sudo python3 install.py --skip-git
  python3 install.py --check   # dry-run without root
""",
    )
    p.add_argument("--skip-apt",  action="store_true",
                   help="Skip system package installation (Phase 1)")
    p.add_argument("--skip-pip",  action="store_true",
                   help="Skip pip package installation (Phase 2)")
    p.add_argument("--skip-go",   action="store_true",
                   help="Skip Go tool installation (no-op for Aether-B)")
    p.add_argument("--skip-git",  action="store_true",
                   help="Skip git repository cloning and external tool installation (Phase 3)")
    p.add_argument("--check",     action="store_true",
                   help="Dry-run — print commands without executing (implies non-root safe)")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()
    dry_run = args.check

    cprint("\n" + "=" * 60, GREEN, bold=True)
    cprint("  Aether-B Installer  —  v1.0.0", GREEN, bold=True)
    cprint("  Bluetooth Penetration Test Orchestrator", GREEN, bold=True)
    cprint("=" * 60 + "\n", GREEN, bold=True)

    if dry_run:
        warn("DRY-RUN MODE — no changes will be made to this system.\n")

    # Phase 0 — OS Detection
    os_id = phase_os_detection()

    # Windows gate
    if os_id == "windows":
        error("Aether-B is designed for Linux. Windows is not fully supported.")
        error("BlueZ (hcitool, hciconfig, gatttool) is Linux-only.")
        warn("Consider running Aether-B in WSL2 with USB Bluetooth passthrough.")
        warn("Proceeding with limited installation...\n")

    # Phase 1 — System packages
    if not args.skip_apt:
        if os_id in ("kali", "ubuntu"):
            phase_apt(dry_run)
        elif os_id == "rhel":
            phase_dnf(dry_run)
        elif os_id == "macos":
            phase_brew(dry_run)
        else:
            warn(f"Unknown OS '{os_id}' — skipping system package phase. Install manually.")
    else:
        info("Skipping system package phase (--skip-apt).")

    # Phase 2 — Pip (no-op for Aether-B)
    if not args.skip_pip:
        phase_pip(dry_run)
    else:
        info("Skipping pip phase (--skip-pip).")

    # Phase 3 — Git + external tools
    if not args.skip_git:
        phase_git(os_id, dry_run)
    else:
        info("Skipping git/external tools phase (--skip-git).")

    # Phase 4 — Verify (always runs, even in dry-run)
    if not dry_run:
        phase_verify(os_id)
    else:
        info("Skipping live verification in dry-run mode.")

    # Phase 5 — Service setup
    if is_root() or dry_run:
        phase_service(os_id, dry_run)
    else:
        warn("Not running as root — skipping HCI interface setup.")
        warn("Re-run with sudo to complete HCI configuration.")

    # Summary
    print_summary(os_id)

    print()
    cprint("  Aether-B installation complete.", GREEN, bold=True)
    cprint("  Run:  sudo python3 aether_b.py --help  to get started.", CYAN)
    cprint("  Docs: /Users/pr0t31n/Aether-B/README.md\n", CYAN)


if __name__ == "__main__":
    main()
