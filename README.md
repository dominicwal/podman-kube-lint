# podman-kube-lint

`podman-kube-lint` checks Kubernetes-style YAML manifests for compatibility with
[`podman kube play`](https://docs.podman.io/en/v5.8.0/markdown/podman-kube-play.1.html).
It scans YAML and YAML-based Jinja templates without rendering templates or
requiring Podman to be installed.

The checks are based on the Podman **5.8.0** documentation. This tool is a
best-effort static checker, not a replacement for testing a manifest with the
Podman version you deploy.

## Features

- Recursively scans `.yaml` and `.yml` files, including YAML Jinja templates
  such as `.yaml.j2`, `.yml.j2`, `.yaml.jinja`, and `.yaml.jinja2`.
- Recognizes Pod, Deployment, DaemonSet, Job, PersistentVolumeClaim, ConfigMap,
  and Secret resources.
- Checks YAML syntax, duplicate keys, required fields, types, enums, references,
  and documented Podman field support.
- Produces readable text or machine-readable JSON reports with file and line
  locations.
- Does not include source-line snippets in reports unless explicitly requested.

## Requirements

- Python 3.10 or later
- PyYAML 6.x (installed automatically with the package)

Podman is not required to run the linter.

## Install

After the package has been published to PyPI, install the command with
[`pipx`](https://pipx.pypa.io/):

```console
pipx install podman-kube-lint
```

Or install it in the active Python environment:

```console
python -m pip install podman-kube-lint
```

To install from a source checkout:

```console
python -m pip install .
```

## Usage

Scan the current directory:

```console
podman-kube-lint
```

Scan selected files or directories:

```console
podman-kube-lint deploy/ infra/
```

Show informational findings, emit JSON, or write a report:

```console
podman-kube-lint --verbose
podman-kube-lint --format json
podman-kube-lint --format json --output report.json
```

Warnings can optionally fail a CI job. The default is to fail on errors only:

```console
podman-kube-lint --fail-on warning
```

Source lines can contain credentials or other sensitive values. They are omitted
from both text and JSON reports by default. Use `--snippet` only when you have
reviewed the data being scanned and are comfortable including source lines in
terminal output, CI logs, and report files:

```console
podman-kube-lint --snippet
podman-kube-lint --format json --snippet
```

Run `podman-kube-lint --help` for all options.

## Configuration

Use the optional [example configuration](examples/podman-kube-lint.yaml) as a
starting point. Configuration is loaded only when explicitly requested:

```console
podman-kube-lint --config path/to/podman-kube-lint.yaml
```

The file is a YAML mapping. All settings are optional:

| Key | Default | Description |
| --- | --- | --- |
| `paths` | `["."]` | Files or directories to scan; relative paths are resolved from the current working directory. |
| `exclude` | `[]` | Glob patterns matched against paths relative to each scan root, filenames, or directory-name components. |
| `skip_dirs` | `[]` | Additional directory names to skip anywhere below a scan root. Built-in skipped directories remain enabled. |
| `fail_on` | `error` | Exit threshold: `error`, `warning`, or `never`. |
| `all_kinds` | `false` | Also report unsupported Kubernetes kinds. |
| `format` | `text` | Report format: `text` or `json`. |

Explicit positional paths, `--exclude`, `--fail-on`, `--format`, `--all-kinds`,
and `--no-all-kinds` override the corresponding settings in the file. Repeated
`--exclude` options replace, rather than extend, the file's exclude list.
`skip_dirs` extends the built-in skip list; it is not controlled by the CLI.
Invalid or unreadable configuration files cause exit code `2`.

## Publish a release

The GitHub Actions workflow publishes a distribution to PyPI when a GitHub
Release is published. Before the first release:

1. Create the public GitHub repository and push this project.
2. Confirm that `podman-kube-lint` is available on PyPI. If it is not, choose
   another distribution name and update `pyproject.toml`, the workflow, and
   these installation instructions.
3. Configure a PyPI trusted publisher for the GitHub owner, repository,
   `.github/workflows/publish.yml` workflow, and the `pypi` environment. Do not
   store a PyPI API token in the repository.
4. Update the version in `pyproject.toml` and `CHANGELOG.md`, create a matching
   Git tag, and publish a GitHub Release for that tag.
5. After publishing, verify the package page and install it in a clean
   environment.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No findings at or above the configured `--fail-on` threshold |
| `1` | At least one finding meets the configured threshold |
| `2` | Command-line usage error, such as a path that does not exist |

`--fail-on` accepts `error` (default), `warning`, or `never`. Findings below
the selected threshold can still be displayed.

## Scope and limitations

- The supported kinds, fields, and behavior descriptions are tied to the
  Podman 5.8.0 documentation. Other Podman versions may differ.
- Jinja templates are inspected without rendering. Dynamic content is
  approximated, so some checks are relaxed and results may need manual review.
- Kubernetes resources outside the supported Podman kinds are skipped by
  default. Use `--all-kinds` to report them as unsupported.
- A static check cannot establish that images, volumes, host paths, or external
  resources are available on the target machine.

## Development

Run the test suite with the Python standard library:

```console
python -m unittest discover -s tests -v
```

Build and install locally:

```console
python -m pip install .
podman-kube-lint --help
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines and
[SECURITY.md](SECURITY.md) for vulnerability reporting.

The Python package separates CLI and configuration handling, file discovery,
YAML parsing, validation rules, findings, and report rendering into modules.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
