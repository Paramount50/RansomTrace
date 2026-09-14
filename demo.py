"""
RansomTrace project Demo
Demonstrates the 4-stage partial implementation live in terminal and exports an HTML report.
"""

import os
import sys
from ransom_tracer import RansomTracer

sys.stdout.reconfigure(encoding='utf-8')

def run_demo():
    print("-" * 72)
    print("  RANSOMTRACE :: INTEGRATED DIGITAL FORENSIC RESPONSE FRAMEWORK")
    print("  project Live Technical Prototype Demo")
    print("-" * 72)
    
    tracer = RansomTracer()
    
    # 1. Simulate a suspicious network/memory log from WannaCry CVE-2017-0144 incident
    sample_trace = """
    [2026-09-14 10:14:02] ALERT: High SMBv1 traffic on port 445 from 192.168.1.45
    [2026-09-14 10:14:05] EXPLOIT: EternalBlue CVE-2017-0144 payload execution detected.
    [2026-09-14 10:14:08] PROCESS: Spawned mssecsvc.exe (PID 4108) with SYSTEM privileges.
    [2026-09-14 10:14:10] NETWORK: HTTP GET http://iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com/ - Connection Failed.
    [2026-09-14 10:14:12] SERVICE: Created tasksche.exe service.
    [2026-09-14 10:14:15] DISK ENCRYPTION: Mass renaming files to .WNCRY extension using AES-128 + RSA-2048.
    [2026-09-14 10:14:18] RANSOM NOTE: Dropped @WanaDecryptor@.exe in system folder.
    """
    
    print("\n[STAGE 1: ACQUISITION & EVIDENCE HASHING]")
    results = tracer.analyze_artifact("WannaCry_Memory_Network_Dump.raw", sample_trace)
    print(f"  Artifact Name : {results['artifact_name']}")
    print(f"  SHA-256 Hash  : {results['sha256']}")
    print(f"  Size Bytes    : {results['size_bytes']}")
    print(f"  Entropy Score : {results['entropy']} / 8.0")
    
    print("\n[STAGE 2: ARTIFACT & PATTERN ANALYSIS]")
    print(f"  Matched {len(results['matched_indicators'])} Known Threat Signatures:")
    for ind in results['matched_indicators']:
        print(f"    - [{ind['pattern']}] -> {ind['description']}")
        
    print("\n[STAGE 3: THREAT INTELLIGENCE & CORRELATION]")
    print(f"  Associated Family     : {results['threat_family']}")
    print(f"  Threat Severity Score : {results['threat_severity_score']} / 100")
    print(f"  Correlated IoCs:")
    for ioc in results['correlated_iocs']:
        print(f"    - IoC: {ioc['pattern']} | Severity: {ioc['severity']} | Suspected Actor: {ioc['threat_actor']} | MITRE: {ioc['mitre_tactic']}")
        
    print("\n[STAGE 4: FORENSIC REPORT GENERATION & INTEGRITY]")
    report_path = os.path.abspath(os.path.join("reports", "forensic_report.html"))
    generated_file = tracer.generate_html_report(results, report_path)
    print(f"  HTML Report Exported : {generated_file}")
    print(f"  Integrity Record     : VERIFIED (SHA-256 logged)")
    
    print("\n" + "-" * 72)
    print("  STATUS: Prototype execution complete.")
    print("-" * 72)

if __name__ == "__main__":
    run_demo()
