import ctypes
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import media_pruning
from media_pruning import (
    MediaPruningError,
    FILE_ATTRIBUTE_HIDDEN,
    FILE_ATTRIBUTE_SYSTEM,
    list_hidden_user_files,
    prune_hidden_user_files,
    _safe_relative_parts,
)


class MediaPruningTests(unittest.TestCase):
    @staticmethod
    def _set_attributes(path: Path, attributes: int):
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.SetFileAttributesW.argtypes = (ctypes.c_wchar_p, ctypes.c_uint32)
        kernel32.SetFileAttributesW.restype = ctypes.c_int
        if not kernel32.SetFileAttributesW(str(path), attributes):
            raise OSError(ctypes.get_last_error(), "SetFileAttributesW failed")

    def test_prune_overwrites_before_unlinking_only_previewed_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            folder = root / "hidden"
            folder.mkdir()
            target = folder / "private.txt"
            target.write_bytes(b"synthetic test content that must be zeroed before unlink")
            self._set_attributes(folder, FILE_ATTRIBUTE_HIDDEN)
            self._set_attributes(target, FILE_ATTRIBUTE_HIDDEN)
            disk = {"name": "Test USB", "fingerprint": "TEST", "protected": False}
            with patch("media_pruning._validated_volume", return_value=(root, disk)):
                preview = list_hidden_user_files("F", "TEST")
                relative_paths = [item["relative_path"] for item in preview["candidates"]]
                self.assertEqual(relative_paths, ["hidden/private.txt"])
                original_overwrite = media_pruning._overwrite_file_and_verify

                def overwrite_then_assert(path, size):
                    original_overwrite(path, size)
                    self.assertEqual(path.read_bytes(), bytes(size))

                with patch("media_pruning._overwrite_file_and_verify", side_effect=overwrite_then_assert) as overwrite:
                    result = prune_hidden_user_files("F", "TEST", relative_paths)

            overwrite.assert_called_once()
            self.assertEqual(len(result["deleted"]), 1)
            self.assertFalse(result["secure_sanitization"])
            self.assertTrue(result["host_visible_overwrite_verified"])
            self.assertFalse(target.exists())

    def test_system_marked_hidden_file_is_excluded_from_preview(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "protected.sys"
            target.write_text("protected", encoding="utf-8")
            self._set_attributes(target, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)
            disk = {"name": "Test USB", "fingerprint": "TEST", "protected": False}
            with patch("media_pruning._validated_volume", return_value=(root, disk)):
                preview = list_hidden_user_files("F", "TEST")
            self.assertEqual(preview["candidates"], [])
            self.assertEqual(preview["protected_system_items_skipped"], 1)
            self.assertEqual(target.read_text(encoding="utf-8"), "protected")

    def test_prune_path_rejects_parent_traversal(self):
        with self.assertRaises(MediaPruningError):
            _safe_relative_parts("..\\outside.txt")


if __name__ == "__main__":
    unittest.main()
