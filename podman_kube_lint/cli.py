"""Command-line interface."""

import argparse
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

from ._version import __version__
from .config import Config, ConfigError, load_config
from .findings import Finding
from .report import Col, render_text
from .rules import DEFAULT_SKIP_DIRS, DOC_VERSION, SEV_RANK
from .scanner import ParsedFile, analyze, iter_files, parse_file
from .yaml_loader import LDict

def main(argv=None):
    ap = argparse.ArgumentParser(description=f"Lint Podman kube play manifests (YAML / YAML.J2) against the podman kube play {DOC_VERSION} documentation.")
    ap.add_argument("--version", action="version", version=f"podman-kube-lint {__version__}",
                    help="Show the installed tool version and exit")
    ap.add_argument("paths", nargs="*", help="Files or directories to scan (default: current directory)")
    ap.add_argument("--config", metavar="FILE", help="Load scan settings from a YAML configuration file")
    ap.add_argument("-x", "--exclude", action="append", metavar="GLOB",
                    help="Exclude a path, filename, or directory name (may be repeated)")
    ap.add_argument("-v", "--verbose", action="store_true", help="Also show INFO findings")
    ap.add_argument("--format", choices=("text", "json"))
    ap.add_argument("-o", "--output", help="Write the report to a file instead of stdout")
    ap.add_argument("--fail-on", choices=("error", "warning", "never"),
                    help="Exit with code 1 at or above this severity (default: error)")
    ap.add_argument("--all-kinds", action=argparse.BooleanOptionalAction, default=None,
                    help="Also report files containing only unsupported Kubernetes kinds (Service, Ingress, ...)")
    ap.add_argument("--snippet", action="store_true",
                    help="Include source lines in reports (may expose sensitive values)")
    ap.add_argument("--no-color", action="store_true", help="Disable colored text output")
    a = ap.parse_args(argv)

    try:
        config = load_config(a.config) if a.config else Config()
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    a.paths = a.paths or config.paths
    a.exclude = a.exclude if a.exclude is not None else config.exclude
    a.format = a.format or config.format
    a.fail_on = a.fail_on or config.fail_on
    a.all_kinds = a.all_kinds if a.all_kinds is not None else config.all_kinds
    skip_dirs = DEFAULT_SKIP_DIRS | set(config.skip_dirs)

    for p in a.paths:
        if not Path(p).exists():
            print(f"Path not found: {p}", file=sys.stderr)
            return 2
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    if os.name == "nt":
        os.system("")  # Enable ANSI colors in the Windows console.
    color = Col(sys.stdout.isatty() and not a.no_color and not a.output and "NO_COLOR" not in os.environ)

    stats = {"yaml": 0, "podman": 0, "skipped": 0}
    parsed: list[ParsedFile] = []
    for p, root in iter_files(a.paths, a.exclude, skip_dirs):
        stats["yaml"] += 1
        rel = p.relative_to(root).as_posix() if p.is_relative_to(root) else str(p)
        if Path(a.paths[0]).is_dir() and len(a.paths) > 1:
            rel = p.as_posix()
        pf = parse_file(p, rel, a.all_kinds)
        if pf is None:
            stats["skipped"] += 1
        else:
            parsed.append(pf)
    stats["podman"] = len(parsed)

    index = set()
    for pf in parsed:
        for ch in pf.chunks:
            d = ch.data
            if isinstance(d, LDict) and d.get("kind") in ("ConfigMap", "Secret", "PersistentVolumeClaim"):
                md = d.get("metadata")
                if isinstance(md, LDict) and isinstance(md.get("name"), str):
                    index.add((d["kind"], md["name"]))

    findings: list[Finding] = []
    for pf in parsed:
        analyze(pf, index, findings, a.all_kinds)

    min_sev = "INFO" if a.verbose else "WARNING"
    if a.format == "json":
        shown = [asdict(f) for f in findings if SEV_RANK[f.severity] >= SEV_RANK[min_sev]]
        if not a.snippet:
            for finding in shown:
                finding.pop("snippet")
        report = json.dumps({"podman_doc_version": DOC_VERSION, "stats": stats, "findings": shown}, indent=2, ensure_ascii=False)
    else:
        report = render_text(findings, stats, color, min_sev, a.snippet)

    if a.output:
        Path(a.output).write_text(report + "\n", encoding="utf-8")
        print(f"Report written to: {a.output}")
    else:
        print(report)

    if a.fail_on == "never":
        return 0
    limit = SEV_RANK["ERROR" if a.fail_on == "error" else "WARNING"]
    return 1 if any(SEV_RANK[f.severity] >= limit for f in findings) else 0
