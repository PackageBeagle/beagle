# Security Policy

## Reporting a vulnerability

Please report security issues using GitHub's private vulnerability
reporting for this repository:

<https://github.com/packagebeagle/beagle/security/advisories/new>

Do not file public issues for security-sensitive findings.

## Supported versions

Only the most recent minor release receives security fixes.

## Threat model

`beagle` is a read-only filesystem walker. It:

- does not execute discovered packages,
- does not download package contents or fetch threat intelligence at
  runtime,
- does not parse source code,
- does not require elevated privileges.

Scans run with the privileges of the invoking user. Exposure catalogs
supplied via `--exposure-catalog` are treated as trusted operator input;
the operator is responsible for the integrity of the catalog file.
