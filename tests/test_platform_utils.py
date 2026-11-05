"""Testes de robustez da integração PowerShell e da extração de JSON."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("SENTINEL_HOME", tempfile.mkdtemp(prefix="sentinel_ptest_home_"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import platform_utils as pu


class JsonExtractionTests(unittest.TestCase):
    def test_plain_json(self):
        self.assertEqual(pu._extract_json('{"a": 1}'), {"a": 1})
        self.assertEqual(pu._extract_json("[1, 2]"), [1, 2])

    def test_warnings_before_json_are_tolerated(self):
        text = "AVISO: algo aconteceu\nmais uma linha\n[{\"Path\": \"x\", \"Status\": \"Valid\"}]"
        self.assertEqual(pu._extract_json(text), [{"Path": "x", "Status": "Valid"}])

    def test_empty_returns_none(self):
        self.assertIsNone(pu._extract_json(""))
        self.assertIsNone(pu._extract_json("   "))

    def test_invalid_raises(self):
        with self.assertRaises(ValueError):
            pu._extract_json("isto não é json")


class PowerShellRunnerTests(unittest.TestCase):
    def test_non_windows_is_rejected(self):
        with mock.patch.object(pu, "IS_WINDOWS", False):
            with self.assertRaises(pu.PowerShellError):
                pu.run_powershell("Get-Date")

    def test_timeout_becomes_powershell_error(self):
        with mock.patch.object(pu, "IS_WINDOWS", True), \
                mock.patch("core.platform_utils.subprocess.run",
                           side_effect=subprocess.TimeoutExpired("powershell", 5)):
            with self.assertRaises(pu.PowerShellError):
                pu.run_powershell("Get-Date")

    def test_missing_executable_becomes_powershell_error(self):
        with mock.patch.object(pu, "IS_WINDOWS", True), \
                mock.patch("core.platform_utils.subprocess.run", side_effect=OSError("não encontrado")):
            with self.assertRaises(pu.PowerShellError):
                pu.run_powershell("Get-Date")

    def test_json_runner_handles_empty_output(self):
        proc = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with mock.patch("core.platform_utils.run_powershell", return_value=proc):
            self.assertIsNone(pu.run_powershell_json("x"))

    def test_json_runner_raises_on_invalid_output(self):
        proc = subprocess.CompletedProcess([], 0, stdout="lixo", stderr="")
        with mock.patch("core.platform_utils.run_powershell", return_value=proc):
            with self.assertRaises(pu.PowerShellError):
                pu.run_powershell_json("x")

    def test_json_runner_reports_stderr_on_failure_without_output(self):
        proc = subprocess.CompletedProcess([], 1, stdout="", stderr="Access denied")
        with mock.patch("core.platform_utils.run_powershell", return_value=proc):
            with self.assertRaises(pu.PowerShellError) as ctx:
                pu.run_powershell_json("x")
            self.assertIn("Access denied", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
