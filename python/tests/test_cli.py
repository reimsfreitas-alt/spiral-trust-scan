import os
import re
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from spiral_trust import __version__, cli  # noqa: E402


def fake_bin(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


class WrapperTests(unittest.TestCase):
    def test_versions_agree(self):
        pyproject = (HERE.parent / "pyproject.toml").read_text()
        py_version = re.search(r'^version = "([^"]+)"', pyproject, re.M).group(1)
        self.assertEqual(py_version, __version__)
        self.assertEqual(py_version, cli.NODE_PACKAGE_VERSION)
        package_json = HERE.parent.parent / "package.json"
        if package_json.exists():
            import json

            node = json.loads(package_json.read_text())
            self.assertEqual(node["version"], py_version)
            self.assertEqual(node["name"], cli.NODE_PACKAGE)

    def test_npx_is_pinned_and_args_pass_through(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_bin(Path(tmp), "npx", 'echo "$@"; exit 0')
            cmd = cli.build_command(["scan-dir", "--fail-on", "none"], {"PATH": tmp})
            self.assertEqual(cmd[1:], ["--yes", f"@spiralcodes/trust-scanner@{cli.NODE_PACKAGE_VERSION}", "scan-dir", "--fail-on", "none"])

    def test_override_wins_and_exit_code_is_passed_through(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_bin(Path(tmp), "fake-scan", 'echo "args: $@"; exit 1')
            env = {"PATH": tmp, "SPIRAL_TRUST_BIN": "fake-scan --extra"}
            with mock.patch.dict(os.environ, env, clear=True):
                self.assertEqual(cli.main(["x"]), 1)
            cmd = cli.build_command(["x"], env)
            self.assertEqual(cmd, ["fake-scan", "--extra", "x"])

    def test_falls_back_to_installed_trust_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_bin(Path(tmp), "trust-scan", "exit 0")
            cmd = cli.build_command(["x"], {"PATH": tmp})
            self.assertTrue(cmd[0].endswith("trust-scan"))

    def test_missing_runtime_is_reported_not_hidden(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"PATH": tmp}, clear=True):
                self.assertEqual(cli.main(["x"]), 127)


if __name__ == "__main__":
    unittest.main()
