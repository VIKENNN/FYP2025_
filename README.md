# Web Server Vulnerability Scanner

**Enhancing Web Server Security with a Custom Vulnerability Scanner**

A lightweight, modular vulnerability scanner for web servers, written in Python. It combines reconnaissance, misconfiguration detection, and real-time CVE correlation into a single menu-driven tool, and produces clean text and PDF reports for every scan.

- **Author:** Chukwuebuka Mamah
- **Supervisor:** Dr. Ibukun Dapo Adewale
- **Institution:** University of Lagos — Final Year Project (2025)

---

## Overview

Rather than trying to replicate bulky commercial scanners, this tool focuses on fast, precise scanning with real-time CVE correlation backed by a custom reverse-index database. It gathers information about a target, checks for common web-server security issues, matches detected software versions against known CVEs, and compiles the findings into a report.

The design is modular by intent: each capability lives in its own module, results are collected in a shared session store, and the reporting layer turns that session into a formatted text and PDF report. This makes the tool easy to extend as new checks or vulnerability sources are added.

---

## Features

- **WHOIS reconnaissance** — domain/registration details via both the Python `whois` module and raw terminal WHOIS, for reliability.
- **Port & service scanning** — `python-nmap` version and OS detection with structured, readable output.
- **Misconfiguration detection** — checks for missing security headers, open directory listings, and verbose error messages.
- **Insecure HTTP method detection** — flags unsafe methods (PUT, DELETE, TRACE) via `OPTIONS` analysis.
- **SSL/TLS inspection** — reviews certificate validity, expiration, and protocol versions.
- **CVE correlation** — matches detected software versions against a local CVE database using a custom reverse-index system, with support for exact and version-range matching and sub-second lookups even across large datasets.
- **Report generation** — exports each session to both a `.txt` and a styled `.pdf` report.

---

## Technology Stack

- **Language:** Python 3
- **Platform:** Linux (recommended — relies on the system `whois` and `nmap` binaries)
- **Key libraries:** `python-nmap`, `python-whois`, `requests`, `certifi`, `prettytable`, `reportlab`, `tabulate`
- **Architecture:** Modular, session-based

---

## Project Structure

| File | Responsibility |
|------|----------------|
| `main.py` | Entry point. Menu-driven interface: reconnaissance, scanning, report generation. |
| `misc_modules.py` | Shared helpers — target cleaning/normalization, URL-to-IP resolution, display utilities. |
| `reconnaissance.py` | WHOIS lookup and Nmap port/service/OS scanning. |
| `vuln_FINAL.py` | Vulnerability scanning — misconfiguration checks, insecure methods, SSL/TLS, and CVE correlation. |
| `READING_CVE_DATABASE_LOOKUP.py` | Current CVE lookup engine (reverse-index, tree-structured database). |
| `reading_cve_valid.py` | Legacy flat-file CVE parser (superseded by the reverse-index approach; kept for reference). |
| `utilities/REVERSE_INDEX_BUILD_1.py` | Builds the `reverse_index.json` used for fast CVE lookups. |
| `Session.py` | Shared in-memory session store that collects results across modules for reporting. |
| `report_generator.py` | Generates the text and PDF scan reports. |

---

## How CVE Correlation Works

The first iteration of CVE correlation parsed large monolithic JSON files on every query (implemented in `reading_cve_valid.py`). This worked but was slow — 5+ minutes per query — with no version-range support.

The current implementation replaces that with a **reverse-index, tree-structured CVE database**. An index (`reverse_index.json`) is built once with `REVERSE_INDEX_BUILD_1.py` and queried at scan time by `READING_CVE_DATABASE_LOOKUP.py`. This brings lookups down to under a second, adds full version-range matching, and scales to large datasets (500,000+ CVEs).

The CVE data itself is sourced from the [fkie-cad/nvd-json-data-feeds](https://github.com/fkie-cad/nvd-json-data-feeds) repository, which provides NVD data in a per-year, per-range directory layout:

```
cve_data/
├── CVE-2021/
│   ├── CVE-2021-41xxx/
│   │   ├── CVE-2021-41773.json
│   │   └── ...
│   └── CVE-2021-42xxx/
└── CVE-2022/
    └── CVE-2022-42xxx/
```

---

## Installation

**Prerequisites:** Python 3, and the system `whois` and `nmap` binaries installed (on Debian/Ubuntu: `sudo apt install whois nmap`).

```bash
git clone https://github.com/VIKENNN/FYP2025_.git
cd FYP2025_
pip install -r requirements.txt
```

---

## Setting Up the CVE Database

1. Download the CVE dataset from [fkie-cad/nvd-json-data-feeds](https://github.com/fkie-cad/nvd-json-data-feeds) and place it in a folder named `cve_data` (the default name the tool expects).
2. Open `utilities/REVERSE_INDEX_BUILD_1.py`, set the path to your `cve_data` directory at the top of the file, and run it. This produces `reverse_index.json`.
3. Place the generated `reverse_index.json` in the main project directory alongside the source files.
4. (Optional) If you named the database something other than `cve_data`, update the name in the `VulnerabilityScanner` class inside `READING_CVE_DATABASE_LOOKUP.py`.

---

## Usage

```bash
python main.py
```

You'll be prompted for a target URL or hostname once, then presented with a menu:

1. **Perform Reconnaissance** — WHOIS and Nmap scans
2. **Perform Scanning** — misconfiguration, insecure methods, SSL/TLS, and CVE correlation
3. **Generate Report** — writes text and PDF reports of the session to `scan_reports/`
4. **Quit**

Run reconnaissance and/or scanning first so there's data in the session, then generate the report.

---

## Legal & Ethical Notice

This tool is intended for **authorized security testing and educational use only**. Only scan systems you own or have explicit written permission to test. Unauthorized scanning of systems you do not own may be illegal.

---

## License

Released under the MIT License. See `LICENSE` for details.
