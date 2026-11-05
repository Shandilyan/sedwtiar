"""SEDWTIAR Dedicated Windows Desktop Application.

Runs the classy, high-detail SEDWTIAR client as a native desktop window
without browser chrome, tabs, or address bars.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

# Eliminate Chromium GPU compositing surface flicker on Windows
os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (
    "--disable-gpu-compositing "
    "--disable-features=TouchTextSelectionStrategy "
    "--enable-features=WebContentsForceDark "
    "--no-sandbox "
    "--disable-logging"
)

from PySide6.QtCore import QUrl, Qt
from PySide6.QtGui import QColor, QIcon
from PySide6.QtWidgets import QApplication, QMainWindow, QMessageBox
from PySide6.QtWebEngineWidgets import QWebEngineView

ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend"
FRONTEND_DIST = ROOT_DIR / "frontend" / "dist"
BACKEND_URL = "http://127.0.0.1:8000"
HEALTH_URL = f"{BACKEND_URL}/health"


def is_backend_running() -> bool:
    """Check if local FastAPI backend is reachable."""
    try:
        with urllib.request.urlopen(HEALTH_URL, timeout=1.5) as resp:
            return resp.status == 200
    except Exception:
        return False


def start_backend_process() -> subprocess.Popen | None:
    """Start uvicorn backend as a background process if not already running."""
    if is_backend_running():
        print("[Desktop App] Backend is already running.", flush=True)
        return None

    print("[Desktop App] Launching SEDWTIAR backend server...", flush=True)
    # Check for backend venv or use current python
    backend_venv = BACKEND_DIR / ".venv" / "Scripts" / "python.exe"
    python_exe = str(backend_venv) if backend_venv.is_file() else sys.executable
    backend_proc = subprocess.Popen(
        [python_exe, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"],
        cwd=str(BACKEND_DIR),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )

    # Wait for backend to become ready
    deadline = time.time() + 15
    while time.time() < deadline:
        if is_backend_running():
            print("[Desktop App] Backend is ready.", flush=True)
            return backend_proc
        time.sleep(0.3)

    print("[Desktop App Warning] Backend launch timed out. Proceeding anyway...", flush=True)
    return backend_proc


class DesktopMainWindow(QMainWindow):
    def __init__(self, backend_proc: subprocess.Popen | None = None):
        super().__init__()
        self.backend_proc = backend_proc
        self.setWindowTitle("SEDWTIAR | Desktop Asset Assurance")
        self.resize(1380, 860)
        self.setMinimumSize(1100, 680)

        # Center on screen
        screen = QApplication.primaryScreen().geometry()
        x = (screen.width() - self.width()) // 2
        y = (screen.height() - self.height()) // 2
        self.move(max(20, x), max(20, y))

        # Dark background prevents white flash during initial page load
        palette = self.palette()
        palette.setColor(self.backgroundRole(), QColor("#161E2F"))
        self.setPalette(palette)

        # WebEngine View
        self.browser = QWebEngineView(self)
        self.browser.setStyleSheet("background-color: #161E2F;")
        self.browser.page().setBackgroundColor(QColor("#161E2F"))
        self.browser.load(QUrl(BACKEND_URL))
        self.setCentralWidget(self.browser)

    def closeEvent(self, event):
        """Cleanly terminate backend if spawned by this desktop app."""
        if self.backend_proc is not None:
            try:
                self.backend_proc.terminate()
                self.backend_proc.wait(timeout=3)
            except Exception:
                try:
                    self.backend_proc.kill()
                except Exception:
                    pass
        event.accept()


def main():
    backend_proc = start_backend_process()

    app = QApplication(sys.argv)
    app.setApplicationName("SEDWTIAR Desktop")
    app.setOrganizationName("SEDWTIAR")

    window = DesktopMainWindow(backend_proc=backend_proc)
    window.show()
    print("[Desktop App] Window opened.", flush=True)

    exit_code = app.exec()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
