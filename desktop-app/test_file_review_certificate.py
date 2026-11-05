import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path

from PySide6.QtWidgets import QApplication
import app

# Ensure single QApplication instance for Qt tests
qapp = QApplication.instance() or QApplication([])


class FileReviewCertificateTests(unittest.TestCase):
    def setUp(self):
        # Create MainWindow instance without triggering background threads
        with patch.object(app.MainWindow, "refresh_all"), \
             patch.object(app.MainWindow, "refresh_devices"):
            self.window = app.MainWindow()

        # Mock an external volume candidate
        self.mock_device = {
            "letter": "E",
            "fingerprint": "TESTFP123456",
            "disk_number": 2,
            "device_name": "SanDisk Ultra USB 3.0",
            "size_bytes": 32000000000,
            "partition_letters": ["E"],
        }
        self.window.scan_volume_combo.clear()
        self.window.scan_volume_combo.addItem("E: - SanDisk Ultra USB 3.0", self.mock_device)

    def test_certificate_buttons_initially_locked(self):
        self.window._update_file_review_cert_ui()
        self.assertFalse(self.window.file_cert_btn.isEnabled())
        self.assertFalse(self.window.file_download_cert_btn.isEnabled())
        self.assertIn("Certificate Locked", self.window.file_cert_status.text())

    def test_unlock_after_hidden_file_pruning(self):
        # Simulate hidden-file pruning completion
        self.window._record_sanitization_action(
            action_type="prune",
            device_info=self.mock_device,
            details={
                "deleted_count": 3,
                "failed_count": 0,
                "message": "Zero-overwrote and unlinked 3 hidden file(s).",
            },
        )

        self.assertTrue(self.window.file_cert_btn.isEnabled())
        self.assertTrue(self.window.file_download_cert_btn.isEnabled())
        self.assertIn("Sanitization Completed", self.window.file_cert_status.text())
        self.assertIn("Hidden-File Pruning", self.window.file_cert_status.text())

    def test_unlock_after_whole_device_overwrite(self):
        # Simulate whole-device overwrite completion
        self.window._record_sanitization_action(
            action_type="overwrite",
            device_info=self.mock_device,
            details={
                "bytes_overwritten": 32000000000,
                "write_seconds": 120,
                "verify_seconds": 110,
                "transfer_size": 16777216,
                "message": "Wrote and read back zeroes for 32 GB.",
            },
        )

        self.assertTrue(self.window.file_cert_btn.isEnabled())
        self.assertTrue(self.window.file_download_cert_btn.isEnabled())
        self.assertIn("Full-Device Overwrite", self.window.file_cert_status.text())

    def test_certificate_generation_creates_pdf_and_updates_status(self):
        self.window._record_sanitization_action(
            action_type="prune",
            device_info=self.mock_device,
            details={"deleted_count": 2, "failed_count": 0, "message": "Cleaned."},
        )

        # Mock viewer dialog and webbrowser so UI popups don't block tests
        with patch.object(app.CertificateViewerDialog, "exec"), \
             patch("webbrowser.open"), \
             patch("os.startfile", create=True):
            self.window.generate_file_review_certificate()

        record = self.window._get_sanitization_record_for_selection(self.mock_device)
        self.assertIsNotNone(record)
        self.assertTrue(record.get("certificate_generated"))
        self.assertTrue(record.get("certificate_number").startswith("SEDWTIAR-SEC-E-"))
        self.assertIsNotNone(record.get("evidence_hash"))
        self.assertTrue(record.get("pdf_path").exists())
        self.assertIn("Official Certificate Generated", self.window.file_cert_status.text())

        # Clean up generated test PDF
        try:
            record.get("pdf_path").unlink()
        except Exception:
            pass


if __name__ == "__main__":
    unittest.main()
