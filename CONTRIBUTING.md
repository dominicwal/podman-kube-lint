# Contributing

Thanks for your interest in improving `podman-kube-lint`.

## Before opening an issue or pull request

- Search existing issues and pull requests for related work.
- For behavior tied to Podman support, include the Podman version and the
  relevant documentation reference.
- Never include real credentials, private manifests, or other sensitive data in
  issues, tests, or pull requests. Use synthetic examples.

## Development setup

Use Python 3.10 or later. From the repository root:

```console
python -m pip install -e .
python -m unittest discover -s tests -v
```

Please add or update tests for behavior changes. Keep changes focused, preserve
the existing command-line interface unless a change is intentional, and update
the README when user-visible behavior changes.

## Pull requests

Pull requests should explain the problem and the proposed change, list
verification performed, and call out any compatibility or documentation-version
changes. All user-facing documentation and messages should be written in
English.
