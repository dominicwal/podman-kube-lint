import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from podman_kube_lint import main


REALISTIC_MANIFEST = """\
apiVersion: v1
kind: ConfigMap
metadata:
  name: web-settings
data:
  LOG_LEVEL: info
---
apiVersion: v1
kind: Secret
metadata:
  name: web-credentials
stringData:
  API_TOKEN: example-token
---
apiVersion: v1
kind: Pod
metadata:
  name: web
spec:
  containers:
    - name: web
      image: docker.io/library/nginx:alpine
      ports:
        - containerPort: 80
          hostPort: 8080
      env:
        - name: LOG_LEVEL
          valueFrom:
            configMapKeyRef:
              name: web-settings
              key: LOG_LEVEL
        - name: API_TOKEN
          valueFrom:
            secretKeyRef:
              name: web-credentials
              key: API_TOKEN
      volumeMounts:
        - name: cache
          mountPath: /var/cache/nginx
  volumes:
    - name: cache
      emptyDir: {}
"""


class ManifestTests(unittest.TestCase):
    def run_manifest(self, content, suffix=".yaml", *options):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ("manifest" + suffix)
            path.write_text(content, encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main([str(path), "--format", "json", *options])
            return code, json.loads(output.getvalue())

    def test_supported_resource_kinds(self):
        manifests = {
            "Pod": "apiVersion: v1\nkind: Pod\nmetadata: {name: demo}\nspec:\n  containers: [{name: app, image: image}]\n",
            "Deployment": "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: demo}\nspec:\n  selector: {matchLabels: {app: demo}}\n  template:\n    metadata: {labels: {app: demo}}\n    spec:\n      containers: [{name: app, image: image}]\n",
            "DaemonSet": "apiVersion: apps/v1\nkind: DaemonSet\nmetadata: {name: demo}\nspec:\n  selector: {matchLabels: {app: demo}}\n  template:\n    metadata: {labels: {app: demo}}\n    spec:\n      containers: [{name: app, image: image}]\n",
            "Job": "apiVersion: batch/v1\nkind: Job\nmetadata: {name: demo}\nspec:\n  template:\n    spec:\n      restartPolicy: Never\n      containers: [{name: app, image: image}]\n",
            "PersistentVolumeClaim": "apiVersion: v1\nkind: PersistentVolumeClaim\nmetadata: {name: demo}\nspec:\n  resources:\n    requests: {storage: 1Gi}\n",
            "ConfigMap": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: demo}\ndata: {key: value}\n",
            "Secret": "apiVersion: v1\nkind: Secret\nmetadata: {name: demo}\ndata: {key: dmFsdWU=}\n",
        }
        for kind, manifest in manifests.items():
            with self.subTest(kind=kind):
                code, report = self.run_manifest(manifest)
                self.assertEqual(code, 0, report)
                self.assertEqual(report["stats"]["podman"], 1)

    def test_duplicate_keys_and_invalid_values(self):
        code, report = self.run_manifest(
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: demo\n  name: other\n"
            "spec:\n  containers:\n    - name: app\n      image: example\n      ports: [{containerPort: 99999}]\n"
        )
        self.assertEqual(code, 1)
        self.assertTrue({"PK-DUP-KEY", "PK-PORT"} <= {f["rule"] for f in report["findings"]})

    def test_jinja_template_is_not_rendered(self):
        code, report = self.run_manifest(
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: '{{ name }}'\n"
            "spec:\n  containers:\n    - name: app\n      image: '{{ image }}'\n",
            ".yaml.j2",
        )
        self.assertEqual(code, 0, report)
        self.assertEqual(report["stats"]["podman"], 1)

    def test_realistic_multi_document_manifest(self):
        code, report = self.run_manifest(REALISTIC_MANIFEST, ".yaml", "--verbose")
        self.assertEqual(code, 0, report)
        self.assertEqual(report["stats"]["podman"], 1)
        self.assertEqual(report["findings"], [])

    def test_realistic_manifest_detects_port_and_mount_errors(self):
        invalid = REALISTIC_MANIFEST.replace("containerPort: 80", "containerPort: 70000")
        invalid = invalid.replace("name: cache\n          mountPath", "name: missing\n          mountPath")
        code, report = self.run_manifest(invalid)
        self.assertEqual(code, 1)
        rules = {finding["rule"] for finding in report["findings"]}
        self.assertTrue({"PK-PORT", "PK-MOUNT-NO-VOLUME"} <= rules, report)


if __name__ == "__main__":
    unittest.main()
