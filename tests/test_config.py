import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import yaml

from podman_kube_lint import main
from test_cli import VALID_POD


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config_path = self.root / "settings.yaml"
        self.scan = self.root / "scan"
        self.scan.mkdir()
        (self.scan / "good.yaml").write_text(VALID_POD, encoding="utf-8")

    def write_config(self, **settings):
        self.config_path.write_text(yaml.safe_dump(settings), encoding="utf-8")

    def run_cli(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(["--config", str(self.config_path), *args])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_scanning_paths_exclusions_and_skipped_directories(self):
        (self.scan / "excluded.yaml").write_text(VALID_POD, encoding="utf-8")
        generated = self.scan / "generated"
        generated.mkdir()
        (generated / "skip.yaml").write_text(VALID_POD, encoding="utf-8")
        self.write_config(paths=[str(self.scan)], exclude=["excluded.yaml"],
                          skip_dirs=["generated"], format="json")

        code, stdout, stderr = self.run_cli()

        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(json.loads(stdout)["stats"]["yaml"], 1)

    def test_cli_options_override_config(self):
        other = self.root / "other.yaml"
        other.write_text(VALID_POD, encoding="utf-8")
        self.write_config(paths=[str(self.scan)], exclude=["good.yaml"], format="text")

        code, stdout, _ = self.run_cli(str(other), "--format", "json", "-x", "other-pattern")

        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["stats"]["yaml"], 1)

    def test_fail_threshold_and_kinds_can_be_overridden(self):
        manifest = self.scan / "service.yaml"
        manifest.write_text("apiVersion: v1\nkind: Service\nmetadata:\n  name: demo\n", encoding="utf-8")
        self.write_config(paths=[str(self.scan)], all_kinds=True, fail_on="warning", format="json")

        code, stdout, _ = self.run_cli()
        self.assertEqual(code, 1)
        self.assertIn("PK-KIND-UNSUPPORTED", stdout)

        code, stdout, _ = self.run_cli("--no-all-kinds", "--fail-on", "error")
        self.assertEqual(code, 0)
        self.assertNotIn("PK-KIND-UNSUPPORTED", stdout)

    def test_invalid_or_missing_config_returns_usage_error(self):
        cases = [
            "paths: []\n",
            "paths: not-a-list\n",
            "skip_dirs: ['../other']\n",
            "fail_on: warn\n",
            "format: xml\n",
            "all_kinds: 'false'\n",
            "unexpected: true\n",
            "format: text\nformat: json\n",
            "[broken\n",
        ]
        for content in cases:
            with self.subTest(content=content):
                self.config_path.write_text(content, encoding="utf-8")
                code, _, stderr = self.run_cli()
                self.assertEqual(code, 2)
                self.assertIn("Configuration error:", stderr)

        self.config_path.unlink()
        code, _, stderr = self.run_cli()
        self.assertEqual(code, 2)
        self.assertIn("Configuration error:", stderr)


if __name__ == "__main__":
    unittest.main()
