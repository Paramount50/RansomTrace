"""
RansomTrace - Lightweight Digital Forensic Response Framework
Partial Implementation Prototype for Academic Use
"""

import os
import re
import math
import hashlib
import json
from datetime import datetime

class RansomTracer:
    """
    RansomTrace Core Engine (Vercel Aesthetic):
    1. Acquisition & Hashing (SHA-256 + Entropy Calculation)
    2. Pattern & Artifact Inspection (WannaCry, EternalBlue CVE-2017-0144)
    3. Threat Intelligence Correlation (IoC Mapping & MITRE ATT&CK)
    4. Forensic Reporting & Evidence Integrity Verification
    """

    KNOWN_THREAT_PATTERNS = {
        "mssecsvc.exe": "WannaCry Process Service Payload",
        "tasksche.exe": "WannaCry Task Scheduler Executable",
        "@WanaDecryptor@.exe": "WannaCry Decryptor GUI Component",
        "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com": "WannaCry Kill-Switch Domain",
        "CVE-2017-0144": "EternalBlue SMBv1 Remote Code Execution Vulnerability",
        "SMBv1": "Vulnerable Server Message Block Protocol v1",
        ".WNCRY": "WannaCry Encrypted File Extension",
        "192.168.1.45": "Host targeted by lateral SMB exploit spread"
    }

    KNOWN_IOC_DB = {
        "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com": {
            "type": "Domain",
            "threat_actor": "Lazarus Group (APT38)",
            "malware_family": "WannaCry / WanaCrypt0r",
            "severity": "CRITICAL",
            "mitre_tactic": "Command & Control (T1071)"
        },
        "CVE-2017-0144": {
            "type": "CVE Exploit",
            "threat_actor": "Shadow Brokers / Lazarus Group",
            "malware_family": "EternalBlue",
            "severity": "CRITICAL",
            "mitre_tactic": "Exploitation of Remote Services (T1210)"
        },
        "mssecsvc.exe": {
            "type": "File Name / Process",
            "threat_actor": "Lazarus Group",
            "malware_family": "WannaCry",
            "severity": "HIGH",
            "mitre_tactic": "Data Encrypted for Impact (T1486)"
        }
    }

    def __init__(self):
        self.evidence_log = []

    def calculate_entropy(self, data_bytes: bytes) -> float:
        """Calculate Shannon entropy to detect encrypted/compressed payload data."""
        if not data_bytes:
            return 0.0
        entropy = 0.0
        length = len(data_bytes)
        byte_counts = {}
        for b in data_bytes:
            byte_counts[b] = byte_counts.get(b, 0) + 1
        
        for count in byte_counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    def calculate_sha256(self, data_bytes: bytes) -> str:
        """Calculate cryptographic SHA-256 hash for Evidence Integrity Record."""
        return hashlib.sha256(data_bytes).hexdigest()

    def analyze_artifact(self, artifact_name: str, content: str | bytes) -> dict:
        """Run 4-stage forensic triage on provided evidence artifact."""
        if isinstance(content, str):
            data_bytes = content.encode("utf-8")
            text_content = content
        else:
            data_bytes = content
            text_content = content.decode("utf-8", errors="ignore")

        # Step 1: Acquisition & Hashing
        sha256_hash = self.calculate_sha256(data_bytes)
        entropy = self.calculate_entropy(data_bytes)
        is_high_entropy = entropy > 7.2

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        custody_entry = {
            "timestamp": timestamp,
            "artifact_name": artifact_name,
            "sha256": sha256_hash,
            "size_bytes": len(data_bytes),
            "entropy": entropy
        }
        self.evidence_log.append(custody_entry)

        # Step 2: Artifact & Pattern Search
        matched_indicators = []
        for pattern, desc in self.KNOWN_THREAT_PATTERNS.items():
            if re.search(re.escape(pattern), text_content, re.IGNORECASE):
                matched_indicators.append({"pattern": pattern, "description": desc})

        # Step 3: Threat Intelligence Correlation
        correlated_iocs = []
        for item in matched_indicators:
            pattern = item["pattern"]
            if pattern in self.KNOWN_IOC_DB:
                ioc_info = self.KNOWN_IOC_DB[pattern]
                correlated_iocs.append({
                    "pattern": pattern,
                    **ioc_info
                })

        detection_score = 0.0
        if matched_indicators:
            detection_score = min(95.0, 50.0 + len(matched_indicators) * 15.0)
            if is_high_entropy:
                detection_score = min(98.5, detection_score + 5.0)

        results = {
            "artifact_name": artifact_name,
            "timestamp": timestamp,
            "sha256": sha256_hash,
            "size_bytes": len(data_bytes),
            "entropy": entropy,
            "is_encrypted_payload": is_high_entropy,
            "matched_indicators": matched_indicators,
            "correlated_iocs": correlated_iocs,
            "threat_severity_score": round(detection_score, 1),
            "threat_family": "WannaCry / EternalBlue" if matched_indicators else "Unknown",
            "chain_of_custody": custody_entry
        }

        return results

    def generate_html_report(self, results: dict, output_filepath: str):
        """Generates a sleek Vercel-style HTML Forensic Analysis Report."""
        os.makedirs(os.path.dirname(output_filepath), exist_ok=True)
        
        indicators_html = ""
        for ind in results["matched_indicators"]:
            indicators_html += f"<tr><td><code>{ind['pattern']}</code></td><td>{ind['description']}</td></tr>"

        ioc_html = ""
        for ioc in results["correlated_iocs"]:
            ioc_html += f"""
            <tr>
                <td><code>{ioc['pattern']}</code></td>
                <td><span class="badge badge-crit">{ioc['severity']}</span></td>
                <td>{ioc['threat_actor']}</td>
                <td>{ioc['malware_family']}</td>
                <td>{ioc['mitre_tactic']}</td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>RansomTrace Forensic Report</title>
    <style>
        :root {{
            --bg: #000000;
            --surface: #0a0a0a;
            --surface-hover: #121212;
            --border: #222222;
            --border-light: #333333;
            --text-primary: #ffffff;
            --text-secondary: #a1a1aa;
            --text-tertiary: #71717a;
            --accent-red: #ef4444;
            --accent-green: #10b981;
            --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            --font-mono: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: var(--font-sans); background-color: var(--bg); color: var(--text-primary); padding: 48px 24px; -webkit-font-smoothing: antialiased; line-height: 1.5; }}
        .container {{ max-width: 860px; margin: 0 auto; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 36px; }}
        
        .header {{ display: flex; justify-content: space-between; align-items: flex-start; padding-bottom: 24px; border-bottom: 1px solid var(--border); margin-bottom: 32px; }}
        .brand-title {{ font-size: 18px; font-weight: 600; letter-spacing: -0.02em; color: var(--text-primary); }}
        .brand-subtitle {{ font-size: 13px; color: var(--text-secondary); margin-top: 4px; }}
        .badge-status {{ display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 9999px; font-size: 11px; font-weight: 500; font-family: var(--font-mono); border: 1px solid var(--border-light); background: #111; color: #fff; }}
        .badge-dot {{ width: 6px; height: 6px; border-radius: 50%; background-color: var(--accent-red); }}

        .grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 32px; }}
        .card {{ background: #000; border: 1px solid var(--border); border-radius: 6px; padding: 20px; text-align: left; }}
        .card-label {{ font-size: 12px; color: var(--text-tertiary); text-transform: uppercase; letter-spacing: 0.05em; font-family: var(--font-mono); }}
        .card-value {{ font-size: 28px; font-weight: 600; color: var(--text-primary); margin-top: 8px; letter-spacing: -0.03em; }}
        .card-value.alert {{ color: var(--accent-red); }}

        h2 {{ font-size: 14px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); margin: 32px 0 16px 0; font-family: var(--font-mono); }}

        table {{ width: 100%; border-collapse: collapse; margin-top: 8px; border: 1px solid var(--border); border-radius: 6px; overflow: hidden; background: #000; }}
        th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border); font-size: 13px; }}
        th {{ background: #0a0a0a; color: var(--text-tertiary); font-weight: 500; font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; }}
        td {{ color: var(--text-secondary); }}
        tr:last-child td {{ border-bottom: none; }}

        code {{ font-family: var(--font-mono); background: #111; border: 1px solid var(--border-light); padding: 2px 6px; border-radius: 4px; font-size: 12px; color: #fff; }}
        
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; font-family: var(--font-mono); letter-spacing: 0.05em; text-transform: uppercase; }}
        .badge-crit {{ background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.4); color: var(--accent-red); }}

        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--border); display: flex; justify-content: space-between; font-size: 12px; color: var(--text-tertiary); font-family: var(--font-mono); }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <div class="brand-title">RansomTrace Automated Forensic Report</div>
                <div class="brand-subtitle">Artifact: {results['artifact_name']} | Timestamp: {results['timestamp']}</div>
            </div>
            <div class="badge-status">
                <span class="badge-dot"></span> SEVERITY HIGH
            </div>
        </div>
        
        <div class="grid">
            <div class="card">
                <div class="card-label">Threat Severity</div>
                <div class="card-value alert">{results['threat_severity_score']} / 100</div>
            </div>
            <div class="card">
                <div class="card-label">Shannon Entropy</div>
                <div class="card-value">{results['entropy']}</div>
            </div>
            <div class="card">
                <div class="card-label">Associated Family</div>
                <div class="card-value" style="font-size: 20px; margin-top: 14px;">{results['threat_family']}</div>
            </div>
        </div>

        <h2>Evidence Integrity Record</h2>
        <table>
            <tr><th>SHA-256 Hash</th><td><code>{results['sha256']}</code></td></tr>
            <tr><th>Artifact Size</th><td>{results['size_bytes']} bytes</td></tr>
            <tr><th>High-Entropy Payload</th><td>{'YES (Encrypted)' if results['is_encrypted_payload'] else 'NO'}</td></tr>
        </table>

        <h2>Identified Artifacts & Signatures</h2>
        <table>
            <thead><tr><th>Pattern</th><th>Description</th></tr></thead>
            <tbody>{indicators_html}</tbody>
        </table>

        <h2>Threat Intelligence Correlation</h2>
        <table>
            <thead><tr><th>IoC Indicator</th><th>Severity</th><th>Suspected Threat Actor</th><th>Malware Family</th><th>MITRE ATT&CK</th></tr></thead>
            <tbody>{ioc_html}</tbody>
        </table>

        <div class="footer">
            <span>RansomTrace Engine v0.2.0</span>
            <span>Forensic Analysis Prototype</span>
        </div>
    </div>
</body>
</html>
"""
        with open(output_filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        return output_filepath
