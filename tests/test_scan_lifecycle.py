import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend import main


class ScanLifecycleTests(unittest.TestCase):
    def setUp(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.object(main, "SCANS_DIR", root))
        self.enterContext(patch.object(main, "SCAN_STATUS_FILE", root / "status.json"))
        self.enterContext(patch.object(main, "scan_status_store", {}))

    def status(self, **kwargs):
        status = main.ScanStatus(scan_id="test", target="127.0.0.1", **kwargs)
        main.scan_status_store["test"] = status
        return status

    def test_poll_preserves_discovery_stage(self):
        status = self.status(status="running", message="Discovering alive hosts...")
        self.assertEqual(main.get_scan_status("test").message, status.message)

    def test_timeout_fails_both_runners_and_removes_partial_output(self):
        for runner, target in ((main.run_nmap_scan, "127.0.0.1"),
                               (main.run_nmap_scan_multi, ["127.0.0.1"])):
            with self.subTest(runner=runner.__name__):
                self.status(status="pending")
                def timeout(cmd, **kwargs):
                    self.assertEqual(kwargs["timeout"], main.NMAP_TIMEOUT_SECONDS)
                    Path(cmd[cmd.index("-oX") + 1]).write_text("partial" * 30)
                    raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])
                with patch.object(main.subprocess, "run", side_effect=timeout) as run:
                    runner("test", target)
                self.assertEqual(run.call_count, 1)
                self.assertEqual(main.get_scan_status("test").status, "failed")
                self.assertFalse((main.SCANS_DIR / "test.xml").exists())
                self.assertFalse((main.SCANS_DIR / "test.xml.tmp").exists())

    def test_standard_failure_is_not_retried(self):
        with patch.object(main.subprocess, "run", side_effect=subprocess.CalledProcessError(1, [])) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                main._run_nmap_command(["nmap", "-sV"])
        self.assertEqual(run.call_count, 1)

    def test_success_publishes_output_only_after_process_exits(self):
        self.status(status="pending", gobuster_status="skipped")
        def complete(cmd, **kwargs):
            Path(cmd[cmd.index("-oX") + 1]).write_text("<nmaprun>" + " " * 100 + "</nmaprun>")
            self.assertFalse((main.SCANS_DIR / "test.xml").exists())
            self.assertEqual(main.get_scan_status("test").status, "running")
        with patch.object(main.subprocess, "run", side_effect=complete):
            main.run_nmap_scan("test", "127.0.0.1")
        self.assertEqual(main.get_scan_status("test").status, "completed")

    def test_restart_marks_interrupted_scan_failed(self):
        self.status(status="running", message="Discovering alive hosts...")
        main._save_scan_status_store()
        main.scan_status_store.clear()
        main._load_scan_status_store()
        self.assertEqual(main.get_scan_status("test").status, "failed")
        saved = json.loads(main.SCAN_STATUS_FILE.read_text())
        self.assertEqual(saved["test"]["status"], "failed")


if __name__ == "__main__":
    unittest.main()
