import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from podman_kube_lint import main


VALID_POD = """\
apiVersion: v1
kind: Pod
metadata:
  name: example
spec:
  containers:
    - name: app
      image: quay.io/example/app:latest
"""

SECRET_WITH_INVALID_TYPE = """\
apiVersion: v1
kind: Secret
metadata:
  name: example
stringData:
  token: [sensitive-test-value]
"""


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.manifest = Path(self.temp_dir.name) / "manifest.yaml"

    def run_cli(self, *args):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = main([str(self.manifest), *args])
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def test_valid_manifest_succeeds(self):
        self.manifest.write_text(VALID_POD, encoding="utf-8")

        exit_code, stdout, stderr = self.run_cli()

        self.assertEqual(exit_code, 0)
        self.assertIn("No issues found", stdout)
        self.assertEqual(stderr, "")

    def test_json_report_omits_source_snippets_by_default(self):
        self.manifest.write_text(SECRET_WITH_INVALID_TYPE, encoding="utf-8")

        exit_code, stdout, _ = self.run_cli("--format", "json")

        report = json.loads(stdout)
        self.assertEqual(exit_code, 1)
        self.assertNotIn("sensitive-test-value", stdout)
        self.assertTrue(report["findings"])
        self.assertNotIn("snippet", report["findings"][0])

    def test_snippet_option_includes_source_line_in_json(self):
        self.manifest.write_text(SECRET_WITH_INVALID_TYPE, encoding="utf-8")

        exit_code, stdout, _ = self.run_cli("--format", "json", "--snippet")

        report = json.loads(stdout)
        self.assertEqual(exit_code, 1)
        self.assertIn("sensitive-test-value", stdout)
        self.assertIn("snippet", report["findings"][0])

    def test_text_report_omits_source_snippets_by_default(self):
        self.manifest.write_text(SECRET_WITH_INVALID_TYPE, encoding="utf-8")

        exit_code, stdout, _ = self.run_cli()

        self.assertEqual(exit_code, 1)
        self.assertNotIn("sensitive-test-value", stdout)
        self.assertIn("PK-TYPE", stdout)

    def test_snippet_option_includes_source_line_in_text(self):
        self.manifest.write_text(SECRET_WITH_INVALID_TYPE, encoding="utf-8")

        exit_code, stdout, _ = self.run_cli("--snippet")

        self.assertEqual(exit_code, 1)
        self.assertIn("sensitive-test-value", stdout)

    def test_missing_path_returns_usage_error(self):
        missing_path = str(Path(self.temp_dir.name) / "missing.yaml")
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = main([missing_path])

        self.assertEqual(exit_code, 2)
        self.assertIn("Path not found", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
