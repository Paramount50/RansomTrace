# RansomTrace

RansomTrace is an Integrated Digital Forensic Response Framework prototype for ransomware.
This repository contains the project core analytical engine, which demonstrates automated evidence hashing, entropy calculation, threat intelligence correlation, and forensic reporting.

## Features
- **Evidence Analysis**: Computes SHA-256 and Shannon Entropy on ingested traces.
- **Threat Correlation**: Maps Indicators of Compromise (IoCs) to known Threat Actors and MITRE ATT&CK tactics.
- **Reporting**: Generates automated HTML forensic incident reports.
- **Web Dashboard**: Includes a zero-dependency local web GUI to visualize the analysis in real-time.

## Usage
1. Clone the repository.
2. Run the Web Dashboard: `python web_app.py`
3. Navigate to `http://localhost:8080`.
4. Or run the CLI demo: `python demo.py`.
5. Run the test suite: `python -m unittest test_ransom_tracer.py`.

*Note: This prototype is based on the 5-layer framework proposed by Shivaji Patil et al.*
