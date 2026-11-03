<details>
<summary><strong>FULL DISCLOSURE</strong> — AI Development & Legal Notice</summary>

---

### AI Development Disclosure

This tool is part of the **pr0t31n toolkit**, a collection of security testing and penetration testing automation tools. The toolkit was created through AI-assisted development, guided by the professional experience and domain expertise of a cybersecurity consultant and penetration tester. Ya, I named it after myself - but to be fair, AI is horrible at naming things.

**The pr0t31n toolkit exists to serve two purposes:**

1. **Automate repetitive penetration testing workflow steps.** Security assessments involve significant amounts of repetitive, procedural work — running sequential tool chains, parsing outputs, correlating findings across tools, and managing engagement data. Automating these steps frees testers to focus on the work that requires human judgment: manual testing, creative attack paths, analysis, and reporting.

2. **Demonstrate the benefits and failures of AI-assisted development.** This toolkit is a real-world case study in building production security tooling with AI assistance. It demonstrates both what AI-assisted development can accomplish and where it falls short. The quality of AI-generated code varies significantly — between context refreshes, the output can range from senior/principal-level software engineering to the work of a still-in-school intern. This inconsistency is itself part of the demonstration.

In the interest of transparency, every tool in the pr0t31n toolkit carries this disclosure. The creator believes that AI-assisted development should be acknowledged openly, not concealed. Users, reviewers, and anyone examining this code should know how it was built so they can evaluate it accordingly.

---

### Legal & Authorization Notice

> **⚠ WARNING: AUTHORIZED USE ONLY**

This tool is designed and intended **exclusively** for use in **authorized security testing engagements**. "Authorized" means **all** of the following conditions are met:

- **Explicit Written Permission.** You possess explicit, documented, written authorization from the owner or authorized representative of the target system(s), network(s), or application(s) to conduct security testing. Verbal agreements are not sufficient.
- **Defined Scope.** The authorization clearly defines the scope of testing, including which systems, networks, IP ranges, applications, and/or endpoints are included. You must not exceed the boundaries of this defined scope under any circumstances.
- **Defined Timeframe.** The authorization specifies the dates and times during which testing is permitted. Testing outside the authorized window is unauthorized testing.
- **Rules of Engagement.** You are operating under a set of rules of engagement (RoE) or equivalent governing document that establishes acceptable testing methods, escalation procedures, emergency contacts, and any restrictions or exclusions.
- **Legal Compliance.** Your testing complies with all applicable local, state, national, and international laws and regulations, including but not limited to the Computer Fraud and Abuse Act (CFAA), the General Data Protection Regulation (GDPR), and equivalent legislation in your jurisdiction.

**Prohibited uses** include but are not limited to: unauthorized access to or testing of any system; testing against systems without explicit written authorization; any activity that violates applicable laws; use for malicious purposes including data theft, extortion, sabotage, or disruption of services; distribution intended to facilitate unauthorized access; and use without a clear legal basis.

**THIS TOOL IS PROVIDED "AS IS," WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.**

The creator(s) and contributor(s) accept no responsibility or liability for any damage, loss, legal consequence, or other harm resulting from the use or misuse of this tool — including damage to systems or data, legal penalties or prosecution, loss of data or revenue, and any direct, indirect, incidental, special, consequential, or punitive damages.

**By using this tool, you acknowledge that you are solely responsible for ensuring that your use is authorized, lawful, and within the defined scope of your engagement. You assume all risk associated with the use of this tool.**

Security testing is a professional discipline with significant ethical and legal obligations. Users operating in a professional capacity are expected to adhere to the standards and codes of conduct established by recognized industry bodies, including PTES, OWASP, NIST, and any certifying body under which they hold credentials.

---

</details>

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
