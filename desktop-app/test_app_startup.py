import unittest
from unittest.mock import patch

import app


class BackendStartupTests(unittest.TestCase):
    def test_unavailable_local_backend_is_started_and_waited_for(self):
        with patch(
            "app.request_json",
            side_effect=[app.ApiError("offline"), {"status": "ok"}],
        ), patch("app.Path.is_file", return_value=True), patch("app.subprocess.Popen") as launch:
            message = app.ensure_local_backend()

        self.assertEqual(message, "Local backend started automatically.")
        command = launch.call_args.args[0]
        self.assertEqual(command[1:4], ["-m", "uvicorn", "app.main:app"])
        self.assertIn("--port", command)
        self.assertIn("8000", command)


if __name__ == "__main__":
    unittest.main()
