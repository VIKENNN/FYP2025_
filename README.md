# FYP2025_
Modules created for project vulnerablity scanner.


# Web Server Vulnerability Scanner

## Project Title

**Enhancing Web Server Security with a Custom Vulnerability Scanner**

**Author:** Chukwuebuka Mamah
**Supervisor:** Dr. Ibukun Dapo Adewale
**Matric No.:** 190408503

---

## Overview

This project delivers a lightweight, extensible vulnerability scanner tailored for web servers. Built entirely in Python, it focuses on uncovering real-world issues like outdated server versions, misconfigurations, insecure HTTP methods, and weak SSL/TLS setups. Instead of trying to replicate bulky commercial scanners, this tool zeroes in on fast, precise scanning with real-time CVE correlation using a custom reverse index system. The modular design ensures flexibility, scalability, and ease of extension as new vulnerabilities emerge.

---

## Technology Stack

* **Language:** Python
* **Platform:** Linux
* **Architecture:** Modular (extensible and scalable)

---

## Modules Here so FAR

### 1. WHOIS Lookup

* Retrieves domain registration details for reconnaissance.
* Dual approach: Python `whois` module + raw terminal WHOIS queries.

### 2. Nmap Integration (Passive Scanning)

* Uses `python-nmap` to conduct version detection (`-sV -O`) and port scans.
* Custom wrappers output structured, human-readable results.

### 3. HTTP Header Analysis & Misconfiguration Detection

* Evaluates HTTP headers for missing or insecure configurations.
* Detects open directories and verbose error messages.

### 4. Insecure HTTP Method Detection

* Identifies unsafe HTTP methods (PUT, DELETE, TRACE) using `OPTIONS` request analysis.

### 5. SSL/TLS Inspection

* Passively inspects TLS configurations, certificate expiration, and protocol versions.
* Avoids full socket inspection for performance and stealth.

### 6. CVE-Based Vulnerability Correlation

* Matches discovered software versions with known vulnerabilities using:

  * **Reverse Indexing System**
  * **Tree-Structured CVE Database**
* Extremely fast lookup (milliseconds per query) even with large datasets (>500,000 CVEs).
* Handles version ranges and exact matches with high precision.

---

## Module File Organization

Modules 1 (WHOIS Lookup) and 2 (Nmap Integration) are located in reconnaissance.py.

Modules 3 (HTTP Header Analysis), 4 (HTTP Method Detection), and 5 (SSL/TLS Inspection) are implemented in **vuln_THEONE.py**.

CVE Correlation Module Evolution

Initially, CVE correlation was handled using a simple flat-file parser implemented in **reading_cve_valid.py**. This approach parsed large monolithic JSON files for every query which was extracted from NVD website with the **extract nvd data.py** script found in the `utilities` folder, resulting in long query times (5+ minutes) and no support for version range matching.

The new and currently implemented approach is a highly optimized system that uses reverse indexing and a tree-structured CVE database titled `cve_data` for this program, built with **REVERSE_INDEX_BUILD_1.py** (which can be found in the `utilities` folder) and queried with **READING_CVE_DATABASE_LOOKUP.py**. This design allows instant CVE lookups, full version range support, and scalable performance, reducing query time to under a second even with extensive datasets.

## Directory Structure (Example for CVE Database)

This was gotten from [https://github.com/fkie-cad/nvd-json-data-feeds](https://github.com/fkie-cad/nvd-json-data-feeds) to look like below.

```
cve_data/
├── CVE-2021/
│   ├── CVE-2021-41xxx/
│   │   ├── CVE-2021-41773.json
│   │   └── ...
│   └── CVE-2021-42xxx/
└── CVE-2022/
    ├── CVE-2022-42xxx/
    └── ...
```
## Steps Involved to run

Step 1: Download the local database shown above (https://github.com/fkie-cad/nvd-json-data-feeds) and make sure it's "cve_data" (can be anything but for consistency sake)
Step 2: Run **REVERSE_INDEX_BUILD_1.py** but make sure to edit where your "cve_data" directory is placed at the beginning of the code, paste your file path there.
Step 3: After running the code you'd have an output file **reverse_index.json**, make sure it's placed in the main directory where the main source codes are.
Step 4: Before starting the main program, go to the **READING_CVE_DATABASE_LOOKUP.py** file and scroll to the `VulnerabilityScanner` class and confirm the name of the local database you downloaded (if you left it as cve_data there's no need to follow this step as that's the default name there)
Step 5: run **main.py**

## NOTE
Incase you're not getting generated reports, go to **report_generator.py** and scroll to the function `save_report` i.e. `def save_report` and change the `output_dir` to the folder name for this program in your system.
---
