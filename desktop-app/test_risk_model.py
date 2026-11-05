"""Unit tests for the SEDWTIAR File Sensitivity Risk Classifier model."""

from __future__ import annotations

import unittest

from risk_model import (
    RISK_TIERS,
    compute_device_risk_score,
    extract_features,
    predict_category_risk,
    predict_risk,
)


class RiskModelTests(unittest.TestCase):
    def test_feature_extraction_dimensions(self):
        features = extract_features(".key", file_size=1024, is_hidden=True)
        self.assertEqual(len(features), 12)
        self.assertEqual(features[1], 1.0)  # is_hidden
        self.assertEqual(features[3], 1.0)  # is_crypto

    def test_critical_risk_files(self):
        for ext in [".key", ".pem", ".kdbx", ".pfx", ".env"]:
            res = predict_risk(ext, file_size=2048, is_hidden=False)
            self.assertEqual(res["label"], "CRITICAL", f"Failed for {ext}: got {res['label']}")
            self.assertEqual(res["tier"], 4)
            self.assertGreaterEqual(res["confidence"], 0.70)

    def test_high_risk_files(self):
        for ext in [".db", ".sqlite", ".sql", ".xlsx", ".csv"]:
            res = predict_risk(ext, file_size=50000, is_hidden=False)
            self.assertIn(res["label"], ("HIGH", "CRITICAL"), f"Failed for {ext}: got {res['label']}")
            self.assertGreaterEqual(res["tier"], 3)

    def test_medium_risk_documents(self):
        for ext in [".pdf", ".docx", ".pptx", ".odt"]:
            res = predict_risk(ext, file_size=25000, is_hidden=False)
            self.assertEqual(res["label"], "MEDIUM", f"Failed for {ext}: got {res['label']}")
            self.assertEqual(res["tier"], 2)

    def test_low_risk_media(self):
        for ext in [".jpg", ".png", ".mp3", ".mp4"]:
            res = predict_risk(ext, file_size=1000000, is_hidden=False)
            self.assertEqual(res["label"], "LOW", f"Failed for {ext}: got {res['label']}")
            self.assertEqual(res["tier"], 1)

    def test_negligible_risk_system_files(self):
        for ext in [".dll", ".sys", ".tmp"]:
            res = predict_risk(ext, file_size=5000, is_hidden=False)
            self.assertEqual(res["label"], "NEGLIGIBLE", f"Failed for {ext}: got {res['label']}")
            self.assertEqual(res["tier"], 0)

    def test_device_risk_score_clean(self):
        score = compute_device_risk_score([])
        self.assertEqual(score["score"], 0)
        self.assertEqual(score["level"], "CLEAN")

    def test_device_risk_score_critical_elevated(self):
        categories = [
            {"category": "Keys & security-related formats", "files": 5, "bytes": 10000},
            {"category": "Databases & structured data", "files": 10, "bytes": 5000000},
            {"category": "Photos & images", "files": 2, "bytes": 2000000},
        ]
        score = compute_device_risk_score(categories)
        self.assertGreaterEqual(score["score"], 60)
        self.assertIn(score["level"], ("HIGH", "CRITICAL"))
        self.assertEqual(len(score["breakdown"]), 3)


if __name__ == "__main__":
    unittest.main()
