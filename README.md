# Aether-B — Bluetooth Penetration Test Orchestrator

Aether-B is a multi-phase Bluetooth and BLE security assessment tool that orchestrates
passive reconnaissance, service enumeration, key recovery, active exploitation, and
firmware analysis into a single, structured workflow. It integrates with the Spectre
management platform via protocol tokens emitted to stdout.

---

## Overview

Aether-B automates Bluetooth Classic (BR/EDR) and Bluetooth Low Energy (BLE) penetration
testing using industry-standard tools (hcitool, sdptool, gatttool, crackle, bettercap,
GATTacker, BlueToolkit, Ubertooth One) orchestrated through a structured phase-based engine.

All phases emit Spectre protocol tokens for real-time dashboard integration. Findings are
written to `findings_spectre.json` for import into reporting pipelines.

---

## Hardware Requirements

| Hardware | Purpose |
|---|---|
| Ubertooth One | BR/EDR piconet survey, raw pcap capture, BLE targeted capture |
| USB Bluetooth adapter (BLE) | hcitool lescan, gatttool, bettercap |
| J-Link / CMSIS-DAP probe | JTAG/SWD firmware extraction (Phase 4, requires physical access) |

---

## Software Prerequisites

| Requirement | Notes |
|---|---|
| Linux (Kali, Ubuntu, Debian) | BlueZ stack is Linux-only; macOS has limited functionality |
| Python 3.9+ | Standard library only; no pip packages required |
| BlueZ (bluez package) | Provides hcitool, hciconfig, sdptool, gatttool, bluetoothctl |
| ubertooth package | Provides ubertooth-scan, ubertooth-btle, ubertooth-rx |
| crackle | BLE LTK recovery; installed to /opt/crackle by install.py |
| bettercap | BLE MITM and network analysis |
| GATTacker | BLE device cloning MITM; installed to /opt/GATTacker by install.py |
| BlueToolkit | CVE-based Bluetooth exploit framework; installed to /opt/bluetoolkit |
| tshark | Packet capture decoding (KNOB entropy analysis) |
| binwalk | Firmware entropy and signature analysis |
| openocd | JTAG/SWD firmware extraction |

Install all dependencies:

```bash
sudo python3 install.py
```

---

## Phases

| Phase | Name | Description | Key Tools |
|---|---|---|---|
| 0 | `passive_recon` | Passive BR/EDR piconet survey + BLE advertising scan + raw pcap capture | ubertooth-scan, hcitool lescan, btscanner, ubertooth-rx |
| 1 | `enumeration` | SDP service record browsing + GATT service and characteristic enumeration | sdptool, gatttool, hcitool info |
| 2 | `key_recovery` | BLE LTK recovery via crackle; Just Works detection; KNOB entropy analysis | crackle, ubertooth-btle, tshark |
| 3 | `exploitation` | BLE MITM (bettercap, GATTacker); CVE testing (BlueToolkit); BIAS attack; DoS flood | bettercap, GATTacker, BlueToolkit, hcitool |
| 4 | `firmware` | JTAG/SWD firmware dump (openocd); binwalk static analysis for embedded keys | openocd, binwalk |

### Authorization Gates

Phase 3 and 4 sub-tests are gated by explicit authorization flags:

| Flag | Enables |
|---|---|
| `injection_authorized: true` | bettercap MITM, GATTacker clone, BIAS attack sequence |
| `dos_authorized: true` | ACL/SCO flood DoS testing |
| `pairing_authorized: true` | Active pairing attempts for Just Works detection |
| `cve_testing_authorized: true` | BlueToolkit CVE exploit testing |
| `physical_access: true` | openocd JTAG/SWD firmware extraction |

---

## Findings Catalogue

| ID | Title | Severity | CVSS | CVE |
|---|---|---|---|---|
| AETHB-001 | KNOB Attack — Bluetooth Entropy Reduction | CRITICAL | 9.3 | CVE-2019-9506 |
| AETHB-002 | BIAS Attack — Bluetooth Impersonation | CRITICAL | 9.1 | CVE-2020-10135 |
| AETHB-003 | BLUFFS Attack — Forward Secrecy Broken | HIGH | 8.2 | CVE-2023-24023 |
| AETHB-004 | BLE Legacy Pairing — Crackable TK | HIGH | 8.0 | CVE-2019-19192 |
| AETHB-005 | Bluetooth PIN Brute Force | HIGH | 7.5 | — |
| AETHB-006 | Unauthenticated GATT Characteristics | MEDIUM | 6.5 | — |
| AETHB-007 | GATT Write Without Response | MEDIUM | 6.8 | — |
| AETHB-008 | BlueToolkit CVE Exploitation | HIGH | 8.5 | — |
| AETHB-009 | SDP Information Disclosure | LOW | 4.0 | — |
| AETHB-010 | Bluetooth Eavesdropping | MEDIUM | 6.5 | — |
| AETHB-011 | BLE Beacon Tracking — Static MAC | LOW | 3.7 | — |
| AETHB-012 | Insecure BLE Pairing — Just Works | MEDIUM | 5.9 | — |
| AETHB-013 | GATTacker MITM — BLE Device Cloning | HIGH | 7.8 | — |
| AETHB-014 | Bluetooth DoS — ACL/SCO Flooding | MEDIUM | 5.3 | — |
| AETHB-015 | Firmware Extraction via JTAG/SWD | HIGH | 7.2 | — |

---

## Usage

### Run all enabled phases

```bash
sudo python3 aether_b.py --config config.json --project my_assessment
```

### Target a specific BD address

```bash
sudo python3 aether_b.py \
  --target-bdaddr AA:BB:CC:DD:EE:FF \
  --project bt_assessment_$(date +%Y%m%d)
```

### Run a single phase

```bash
sudo python3 aether_b.py --phase enumeration --target-bdaddr AA:BB:CC:DD:EE:FF
sudo python3 aether_b.py --phase key_recovery --hci hci0
sudo python3 aether_b.py --phase firmware --physical-access
```

### Enable exploitation (requires authorization)

```bash
sudo python3 aether_b.py \
  --target-bdaddr AA:BB:CC:DD:EE:FF \
  --phase exploitation \
  --injection-authorized \
  --cve-testing-authorized \
  --pairing-authorized \
  --project authorized_engagement_$(date +%Y%m%d)
```

### Scope restriction (only test whitelisted devices)

```bash
sudo python3 aether_b.py \
  --scope-bdaddr AA:BB:CC:DD:EE:FF \
  --scope-bdaddr 11:22:33:44:55:66 \
  --project scoped_assessment
```

### List available phases

```bash
python3 aether_b.py --list-phases
```

### Spectre managed mode

```bash
SPECTRE_MANAGED=1 sudo python3 aether_b.py --config config.json --project managed_run
```

---

## Config Reference

| Key | Type | Default | Description |
|---|---|---|---|
| `hci_device` | string | `"hci0"` | HCI adapter to use for BLE/BR/EDR operations |
| `ubertooth_device` | string | `"/dev/ttyACM0"` | Ubertooth One device path |
| `target_bdaddrs` | list | `[]` | List of BD addresses to target; empty = discover all in range |
| `target_uuids` | list | `[]` | BLE service UUIDs to filter for |
| `timeout_per_phase` | int | `300` | Per-phase timeout in seconds |
| `capture_duration` | int | `3600` | Maximum capture duration for long-running captures |
| `phases.*` | bool | varies | Enable/disable individual phases |
| `tools.*` | string | see config.json | Override tool paths/commands |
| `scope.bdaddrs` | list | `[]` | BD address whitelist; empty = no scope restriction |
| `scope.uuids` | list | `[]` | UUID whitelist |
| `output_dir` | string | `"aether_b_output"` | Subdirectory within project for all output files |
| `physical_access` | bool | `false` | Enable JTAG/SWD firmware extraction |
| `injection_authorized` | bool | `false` | Enable MITM and injection attacks |
| `dos_authorized` | bool | `false` | Enable DoS testing |
| `pairing_authorized` | bool | `false` | Enable active pairing attempts |
| `cve_testing_authorized` | bool | `false` | Enable BlueToolkit CVE testing |

---

## Output Structure

```
<project_dir>/
  aether_b_output/
    passive_recon/
      ubertooth_scan.txt
      hcitool_lescan.txt
      btscanner.txt
      ubertooth_raw.pcap
      discovered_devices.json
    enumeration/
      hcitool_info_<bdaddr>.txt
      sdptool_<bdaddr>.txt
      gatttool_primary_<bdaddr>.txt
      gatttool_chars_<bdaddr>.txt
      enumeration_results.json
    key_recovery/
      crackle_<pcap>.txt
      ltk_<pcap>.bin
      ubertooth_btle_<bdaddr>.pcap
      knob_analysis_<pcap>.txt
      recovered_keys.json
    exploitation/
      bettercap_ble.txt
      gattacker_<bdaddr>.txt
      bluetoolkit_<bdaddr>.txt
      bias_<bdaddr>.txt
      dos_<bdaddr>.txt
    firmware/
      bt_firmware.bin
      openocd_output.txt
      binwalk_<fw>.txt
      binwalk_extract_<fw>/
    findings_spectre.json
    assessment_meta.json
```

---

## Spectre Integration

When `SPECTRE_MANAGED=1` is set, Aether-B emits structured tokens to stdout:

| Token | Format | Description |
|---|---|---|
| `__SPECTRE_LOG__` | `<message>` | Progress log line |
| `__SPECTRE_ERR__` | `<message>` | Non-fatal error message |
| `__SPECTRE_STATUS__` | `{"phase": ..., "status": ..., "step": ..., "ts": ...}` | Phase lifecycle event |
| `__SPECTRE_FINDING__` | Full finding JSON record | Security finding discovered |
| `__SPECTRE_PROMPT__` | `<message>` | User prompt (suppressed in managed mode) |

Findings are also written to `findings_spectre.json` for offline import.

---

## Legal Disclaimer

**Aether-B is for use ONLY on Bluetooth devices and networks for which you have
explicit written permission from the owner. Unauthorized testing of Bluetooth
devices is illegal in most jurisdictions and may violate computer fraud and
abuse laws, telecommunications regulations, and privacy legislation.**

The following activities require explicit written authorization scoped to the
specific devices under test, obtained before any assessment begins:

- Passive capture of Bluetooth advertising or connection traffic
- Active connection to any Bluetooth device
- MITM proxy attacks
- DoS or flooding tests
- Physical firmware extraction
- CVE exploit testing

This tool is provided for authorized security professionals conducting
legitimate penetration tests. The authors accept no responsibility for
misuse or unauthorized use of this software.
