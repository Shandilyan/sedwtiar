import unittest
from pathlib import Path
from PySide6.QtWidgets import QApplication
import app

class BackgroundUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_background_image_exists(self):
        bg_path = Path(app.__file__).resolve().parent / "background.png"
        self.assertTrue(bg_path.exists(), "background.png does not exist in desktop-app")
        self.assertGreater(bg_path.stat().st_size, 1000, "background.png is empty")

    def test_background_widget_loads_pixmap(self):
        bg_path = Path(app.__file__).resolve().parent / "background.png"
        widget = app.BackgroundWidget(bg_path)
        self.assertFalse(widget.bg_pixmap.isNull(), "bg_pixmap failed to load")
        self.assertGreater(widget.bg_pixmap.width(), 0)
        self.assertGreater(widget.bg_pixmap.height(), 0)

    def test_stylesheet_translucency(self):
        self.assertIn("centralRoot", app.STYLESHEET)
        self.assertIn("rgba(36, 47, 73", app.STYLESHEET)
        self.assertIn("rgba(22, 30, 47", app.STYLESHEET)

if __name__ == "__main__":
    unittest.main()

