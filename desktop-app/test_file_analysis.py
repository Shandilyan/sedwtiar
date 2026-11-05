import unittest

from file_analysis import (
    WINDOWS_FILE_ATTRIBUTE_HIDDEN,
    WINDOWS_FILE_ATTRIBUTE_SYSTEM,
    WINDOWS_SYSTEM_ITEM_CATEGORY,
    classify_file_metadata,
    describe_volume_scan_error,
    is_system_directory,
    is_system_file,
)


class FileMetadataClassificationTests(unittest.TestCase):
    def test_system_directories_are_identified(self):
        self.assertTrue(is_system_directory("$RECYCLE.BIN"))
        self.assertTrue(is_system_directory("System Volume Information"))
        self.assertTrue(is_system_directory("recycler"))
        self.assertTrue(is_system_directory(".Trashes"))
        self.assertTrue(is_system_directory("found.000"))
        self.assertTrue(is_system_directory("custom_sys_dir", WINDOWS_FILE_ATTRIBUTE_SYSTEM))
        self.assertFalse(is_system_directory("MyDocuments"))
        self.assertFalse(is_system_directory("Photos"))

    def test_system_metadata_files_are_identified(self):
        self.assertTrue(is_system_file("desktop.ini"))
        self.assertTrue(is_system_file("thumbs.db"))
        self.assertTrue(is_system_file("IndexerVolumeGuid"))
        self.assertTrue(is_system_file("WPSettings.dat"))
        self.assertTrue(is_system_file("custom.sys", WINDOWS_FILE_ATTRIBUTE_SYSTEM))
        self.assertFalse(is_system_file("report.pdf"))
        self.assertFalse(is_system_file("photo.jpg"))

    def test_hidden_system_entry_is_not_classified_as_unknown_user_file(self):
        category, extension = classify_file_metadata(
            "opaque.sys",
            WINDOWS_FILE_ATTRIBUTE_HIDDEN | WINDOWS_FILE_ATTRIBUTE_SYSTEM,
        )

        self.assertEqual(category, WINDOWS_SYSTEM_ITEM_CATEGORY)
        self.assertIsNone(extension)

    def test_hidden_non_system_file_remains_grouped_by_type(self):
        category, extension = classify_file_metadata("notes.pdf", WINDOWS_FILE_ATTRIBUTE_HIDDEN)

        self.assertEqual(category, "Hidden files · Documents & office files")
        self.assertEqual(extension, ".pdf")

    def test_regular_file_keeps_its_extension_category(self):
        category, extension = classify_file_metadata("notes.pdf")

        self.assertEqual(category, "Documents & office files")
        self.assertEqual(extension, ".pdf")

    def test_unrecognized_filesystem_error_is_explained_without_claiming_a_scan(self):
        error = OSError(1005, "The volume does not contain a recognized file system")
        error.winerror = 1005

        message = describe_volume_scan_error("F", error)

        self.assertIn("no recognized file system", message)
        self.assertIn("no files were read or changed", message)


if __name__ == "__main__":
    unittest.main()
