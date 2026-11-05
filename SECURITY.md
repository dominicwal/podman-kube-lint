# Security policy

## Reporting a vulnerability

Please do not report security vulnerabilities in public issues. Once this
project is hosted on GitHub, use the repository's **Report a vulnerability**
feature to send a private report. Include the affected version, impact, and
reproduction details using synthetic data.

If private vulnerability reporting has not been enabled yet, contact the
maintainer privately through the contact method listed on the repository
profile. Do not include secrets or private manifests in the report.

## Sensitive report data

Source-line snippets are omitted from text and JSON reports by default. The
`--snippet` option explicitly includes them and should be used with care,
especially in CI environments where logs and artifacts may be retained.
