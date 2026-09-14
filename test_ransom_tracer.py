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

    def test_report_generation(self):
        sample = "Detected mssecsvc.exe and iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
        results = self.tracer.analyze_artifact("test_sample.log", sample)
        report_path = "reports/test_report.html"
        generated_file = self.tracer.generate_html_report(results, report_path)
        self.assertTrue(os.path.exists(generated_file))

if __name__ == "__main__":
    unittest.main()
