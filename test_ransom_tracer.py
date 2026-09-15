import unittest
import os
from ransom_tracer import RansomTracer

class TestRansomTracer(unittest.TestCase):
    def setUp(self):
        self.tracer = RansomTracer()

    def test_entropy_calculation(self):
        # Low entropy text
        low_entropy = self.tracer.calculate_entropy(b"AAAAAAA")
        self.assertEqual(low_entropy, 0.0)

        # High entropy random-like data
        high_entropy_bytes = bytes([i % 256 for i in range(1000)])
        high_entropy = self.tracer.calculate_entropy(high_entropy_bytes)
        self.assertGreater(high_entropy, 7.0)

    def test_sha256(self):
        data = b"RansomTrace Test Data"
        sha256_hash = self.tracer.calculate_sha256(data)
        self.assertEqual(len(sha256_hash), 64)

    def test_artifact_analysis(self):
        sample = "Detected mssecsvc.exe with CVE-2017-0144"
        results = self.tracer.analyze_artifact("test_sample.log", sample)
        self.assertGreater(len(results["matched_indicators"]), 0)
        self.assertGreater(results["threat_severity_score"], 50.0)

    def test_wanna_cry_deduplication(self):
        sample = "mssecsvc.exe iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
        results = self.tracer.analyze_artifact("test_sample.log", sample)
        threat_family = results["threat_family"]
        # It should match WannaCry / WanaCrypt0r (from domain) and WannaCry (from mssecsvc.exe)
        # Should become "WannaCry / WanaCrypt0r" since "WannaCry" is a duplicate.
        # Wait, if domain matched first, it's WannaCry / WanaCrypt0r.
        # Ensure 'WannaCry' only appears once if split by ' / '
        families = threat_family.split(" / ")
        self.assertEqual(len(families), len(set(families)))
        self.assertIn("WannaCry", families)

    def test_new_signatures(self):
        sample_cve = "EXPLOIT: SMBGhost CVE-2020-0796 buffer overflow attempt detected."
        results = self.tracer.analyze_artifact("test_cve.log", sample_cve)
        self.assertGreater(len(results["matched_indicators"]), 0)
        self.assertGreater(len(results["correlated_iocs"]), 0)
        self.assertGreater(results["threat_severity_score"], 0)
        self.assertNotIn("WannaCry", results["threat_family"])
        self.assertIn("SMBGhost", results["threat_family"])

        sample_note = "FILE: Ransom note dropped - DECRYPT_INSTRUCTIONS.txt written to D:\\Shares\\."
        results2 = self.tracer.analyze_artifact("test_note.log", sample_note)
        self.assertGreater(len(results2["matched_indicators"]), 0)
        self.assertGreater(len(results2["correlated_iocs"]), 0)
        self.assertGreater(results2["threat_severity_score"], 0)
        self.assertIn("Generic Ransomware", results2["threat_family"])

    def test_report_generation(self):
        sample = "Detected mssecsvc.exe and iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
        results = self.tracer.analyze_artifact("test_sample.log", sample)
        report_path = "reports/test_report.html"
        generated_file = self.tracer.generate_html_report(results, report_path)
        self.assertTrue(os.path.exists(generated_file))

if __name__ == "__main__":
    unittest.main()
