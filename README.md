# RansomTrace

RansomTrace is an **Integrated Digital Forensic Response Framework** prototype designed to automate the triage, analysis, and correlation of ransomware-related artifacts. 

This repository contains the core analytical engine for an automated forensic pipeline. It is capable of taking raw memory dumps or network traces, calculating evidence integrity metrics, and querying internal threat intelligence dictionaries to attribute malicious behavior.

## Theoretical Framework

This project is built upon the 5-layer forensic framework proposed in academic research (e.g., Shivaji Patil et al.). The layers are:

1. **Detection Layer** (Network / EDR Hooks) - *Future Scope*
2. **Acquisition Layer** (Memory / Disk Dumping) - *Partially Implemented (file upload)*
3. **Analysis Layer** (Pattern & Entropy Analysis) - **Implemented**
4. **Correlation Layer** (Threat Intelligence) - **Implemented**
5. **Reporting Layer** (Automated HTML Exports) - **Implemented**

## Core Features

### 1. Evidence Integrity & Payload Heuristics
- **Cryptographic Hashing:** Automatically calculates the `SHA-256` hash of any ingested artifact to establish a firm chain-of-custody.
- **Shannon Entropy Analysis:** Computes the mathematical entropy of the data payload. Scores approaching `8.0` are flagged as highly randomized, serving as a heuristic indicator for encrypted ransomware payloads.

### 2. Artifact & Indicator Search
- Uses pattern matching to identify Known Indicators of Compromise (IoCs).
- Built-in signatures detect WannaCry-specific processes (`mssecsvc.exe`, `tasksche.exe`), exploit vectors (SMBv1, `CVE-2017-0144`), and known kill-switch domains.

### 3. Cyber Threat Intelligence (CTI) Correlation
- **Severity Scoring:** Calculates a weighted Threat Severity Score (0-100) based on the volume and criticality of identified IoCs.
- **Attribution & Mapping:** Maps detected IoCs to suspected Threat Actors (e.g., Lazarus Group) and formal MITRE ATT&CK tactics (e.g., T1486 - Data Encrypted for Impact).

### 4. Automated Forensic Reporting
- Extracts all findings, metrics, and correlation tables into a standalone, timestamped HTML report suitable for incident response teams.

## Getting Started

The repository provides both a Command-Line Interface (CLI) and an interactive Web Dashboard GUI.

### Prerequisites
- Python 3.8+
- Zero external dependencies (uses standard built-in Python libraries).

### Running the Web Dashboard (Recommended)
We provide a sleek, zero-dependency local web server to visualize the analysis in real-time.

```bash
python web_app.py
```
*Navigate to `http://localhost:8080` in your web browser.*

### Running the CLI Demo
To run a controlled simulation in your terminal (ideal for rapid testing):
```bash
python demo.py
```

### Running the Test Suite
To verify the integrity of the analysis engine, execute the automated unit tests:
```bash
python -m unittest test_ransom_tracer.py
```

## Repository Structure

- `ransom_tracer.py`: The core object-oriented analysis engine.
- `web_app.py`: Built-in HTTP server providing a REST-like API for the frontend.
- `static/index.html`: The interactive Web GUI frontend.
- `demo.py`: Command-line simulation script.
- `test_ransom_tracer.py`: Automated testing suite.

## Disclaimer
This prototype is an academic proof-of-concept for digital forensics and incident response (DFIR) research.
