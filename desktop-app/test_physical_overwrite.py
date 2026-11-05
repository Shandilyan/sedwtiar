import os
import struct
import tempfile
import unittest
from unittest.mock import patch

from physical_overwrite import (
    FSCTL_LOCK_VOLUME,
    IOCTL_DISK_GET_DRIVE_GEOMETRY,
    IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
    IOCTL_STORAGE_QUERY_PROPERTY,
    PhysicalOverwriteError,
    _open_volume_lock,
    _query_logical_sector_size,
    _selected_disk,
    _write_and_verify_fd,
    confirmation_phrase,
    overwrite_removable_disk,
    recommended_transfer_size,
    SSD_TRANSFER_SIZE,
    TRANSFER_SIZE,
)


class PhysicalOverwriteTests(unittest.TestCase):
    def test_confirmation_phrase_identifies_disk_and_size(self):
        phrase = confirmation_phrase({"number": 3, "name": "HP v220w", "size_bytes": 8 * 1024**3})
        self.assertEqual(phrase, "OVERWRITE DISK 3 HP_V220W 8.0GB")

    def test_zero_write_and_readback_on_temporary_file(self):
        progress = []
        with tempfile.TemporaryFile("w+b") as stream:
            stream.write(b"synthetic test data" * 64 + b"x" * 832)
            stream.flush()
            size = stream.seek(0, os.SEEK_END)
            stream.seek(0)
            performance = _write_and_verify_fd(stream.fileno(), size, 512, lambda phase, done, total: progress.append((phase, done, total)))
            stream.seek(0)
            self.assertEqual(stream.read(), bytes(size))
        self.assertTrue(any(phase == "overwrite" for phase, _, _ in progress))
        self.assertTrue(any(phase == "verify" for phase, _, _ in progress))
        self.assertEqual(performance["transfer_size"], TRANSFER_SIZE)
        self.assertGreaterEqual(performance["elapsed_seconds"], 0)

    def test_ssd_uses_a_larger_bounded_transfer_buffer(self):
        self.assertEqual(recommended_transfer_size("SSD"), SSD_TRANSFER_SIZE)
        self.assertEqual(recommended_transfer_size("Unknown", "Seagate Portable SSD"), SSD_TRANSFER_SIZE)
        self.assertEqual(recommended_transfer_size("HDD"), TRANSFER_SIZE)

    def test_usb_attached_external_ssd_is_eligible_but_internal_disk_is_blocked(self):
        external = {
            "number": 7, "name": "External SSD", "size_bytes": 64 * 1024**3,
            "fingerprint": "EXTSSD", "protected": False, "external_attached": True,
            "partitions": [{"drive_letter": "F"}],
        }
        internal = dict(external, fingerprint="INTERNAL", external_attached=False, connection="Internal / fixed bus")
        with patch("physical_overwrite.get_storage_inventory", return_value={"disks": [external]}):
            self.assertEqual(_selected_disk("F", "EXTSSD")["number"], 7)
        with patch("physical_overwrite.get_storage_inventory", return_value={"disks": [internal]}):
            with self.assertRaisesRegex(PhysicalOverwriteError, "Internal HDD/SSD disks"):
                _selected_disk("F", "INTERNAL")

    def test_wrong_typed_confirmation_blocks_before_opening_device(self):
        disk = {"number": 3, "name": "HP v220w", "size_bytes": 8 * 1024**3}
        with patch("physical_overwrite._selected_disk", return_value=disk), patch(
            "physical_overwrite._configure_kernel32"
        ) as configure_kernel:
            with self.assertRaises(PhysicalOverwriteError):
                overwrite_removable_disk("F", "TEST", "OVERWRITE DISK 3")
        configure_kernel.assert_not_called()

    def test_non_elevated_process_is_stopped_before_opening_device(self):
        disk = {"number": 3, "name": "HP v220w", "size_bytes": 8 * 1024**3}
        phrase = confirmation_phrase(disk)
        with patch("physical_overwrite._selected_disk", return_value=disk), patch(
            "physical_overwrite._is_elevated", return_value=False
        ), patch("physical_overwrite._configure_kernel32") as configure_kernel:
            with self.assertRaisesRegex(PhysicalOverwriteError, "Administrator permission"):
                overwrite_removable_disk("F", "TEST", phrase)
        configure_kernel.assert_not_called()

    def test_volume_lock_access_denied_gives_safe_actionable_message(self):
        class FakeKernel32:
            def CreateFileW(self, *args):
                return 123

            def CloseHandle(self, handle):
                self.closed_handle = handle

        kernel32 = FakeKernel32()
        with patch("physical_overwrite._device_io", side_effect=OSError(5, "access denied")) as device_io:
            with self.assertRaisesRegex(PhysicalOverwriteError, "exclusively lock volume F:") as raised:
                _open_volume_lock(kernel32, "F")

        device_io.assert_called_once()
        self.assertEqual(device_io.call_args.args[2], FSCTL_LOCK_VOLUME)
        self.assertIn("No disk bytes were overwritten", str(raised.exception))
        self.assertEqual(kernel32.closed_handle, 123)

    def test_sector_size_uses_geometry_when_usb_rejects_storage_property(self):
        calls = []

        def device_io(_kernel32, _handle, code, in_buffer=None, in_size=0, out_buffer=None, out_size=0):
            calls.append(code)
            if code == IOCTL_STORAGE_QUERY_PROPERTY:
                raise OSError(1, "function not supported by USB bridge")
            if code == IOCTL_DISK_GET_DRIVE_GEOMETRY_EX:
                struct.pack_into("<I", out_buffer, 20, 512)
                return 24
            raise AssertionError(f"Unexpected control code: {code:#x}")

        with patch("physical_overwrite._device_io", side_effect=device_io):
            sector_size = _query_logical_sector_size(object(), 123)

        self.assertEqual(sector_size, 512)
        self.assertEqual(calls, [IOCTL_STORAGE_QUERY_PROPERTY, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX])

    def test_sector_size_property_is_used_when_supported(self):
        def device_io(_kernel32, _handle, code, in_buffer=None, in_size=0, out_buffer=None, out_size=0):
            self.assertEqual(code, IOCTL_STORAGE_QUERY_PROPERTY)
            struct.pack_into("<I", out_buffer, 16, 4096)
            return 28

        with patch("physical_overwrite._device_io", side_effect=device_io):
            sector_size = _query_logical_sector_size(object(), 123)

        self.assertEqual(sector_size, 4096)

    def test_legacy_geometry_is_used_when_usb_rejects_newer_queries(self):
        calls = []

        def device_io(_kernel32, _handle, code, in_buffer=None, in_size=0, out_buffer=None, out_size=0):
            calls.append(code)
            if code in (IOCTL_STORAGE_QUERY_PROPERTY, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX):
                raise OSError(1, "unsupported by test device")
            if code == IOCTL_DISK_GET_DRIVE_GEOMETRY:
                struct.pack_into("<I", out_buffer, 20, 512)
                return 24
            raise AssertionError(f"Unexpected control code: {code:#x}")

        with patch("physical_overwrite._device_io", side_effect=device_io):
            sector_size = _query_logical_sector_size(object(), 123)

        self.assertEqual(sector_size, 512)
        self.assertEqual(
            calls,
            [IOCTL_STORAGE_QUERY_PROPERTY, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, IOCTL_DISK_GET_DRIVE_GEOMETRY],
        )


if __name__ == "__main__":
    unittest.main()
