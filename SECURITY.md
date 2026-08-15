# Security Policy

TRACE is a forensically sound evidence collector and analyzer for AI
tooling. It runs with the privileges of the invoking user and reads sensitive
local artifacts (configs, credentials, session data). We take the security of
the tool — and of the evidence it handles — seriously.

## Supported Versions

Only the latest release receives security fixes. Patch and minor releases may
be cut for security issues on the current major line, but we do not maintain
older branches.

| Version | Supported          |
|---------|--------------------|
| 0.4.x   | ✅                 |
| < 0.4   | ❌                 |

If you cannot upgrade to a supported version, we still welcome the report (see
below) so a fix can be backported where practical.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately to **security@ionsec.io**. Please include as
much of the following as possible to help us reproduce and fix it quickly:

- **Component & version** — which component (Python CLI, Go binary, Velociraptor
  artifact, report generators) and which version.
- **Impact** — what an attacker could do, and under what assumptions about
  privilege / environment.
- **Steps to reproduce** — minimal, concrete steps, ideally with a sample
  file/evidence tree.
- **Environment** — OS, Python/Go versions, and whether you ran the Python CLI
  or the Go binary.

You may also encrypt the report with our PGP key if you have it (contact us at
the same address to arrange one). If you prefer, you can alternatively use
GitHub's **private vulnerability reporting** flow on this repository.

### What we ask of you

- Give us a reasonable time window (by default **90 days**) to triage and fix
  before you disclose publicly.
- Do not test against production systems, other users' evidence, or shared
  infrastructure.
- Do not exfiltrate real credentials or personal data — use dummy values.

### What we commit to

- Acknowledgment of receipt within **3 business days**.
- A triage decision (accepted / declined / won't-fix with rationale) within
  **14 days**.
- Regular status updates until the issue is resolved.
- Public credit in the release notes (unless you ask to remain anonymous).

## Scope

In scope: the Python package (`ionsec_trace`), the Go binary (`go/`), the
Velociraptor artifacts (`velociraptor/`), and the HTML/JSON/STIX report
generators.

Out of scope / considered acceptable:

- Findings that require already-root or already-elevated privileges on the
  target endpoint (TRACE is an evidence-collection tool and does not sandbox
  the endpoint it runs on).
- Performance issues that do not cause memory corruption or code execution.
- Vulnerabilities in third-party dependencies — please report those upstream.

## Coordinated Disclosure

We practice coordinated disclosure. Once a fix is released, we publish a
security advisory in the repository's release notes and, where appropriate, a
GitHub Security Advisory. We will not disclose the vulnerability before a fix
is available unless there is evidence of active exploitation in the wild, in
which case we will work with you on a responsible timeline.

## Handling of Evidence & Secrets

TRACE is designed to be read-only and forensically sound:

- Collected files are never modified; SQLite databases are opened read-only.
- Every file is hashed (SHA-256) and recorded in a chain-of-custody manifest.
- API keys and credentials are **redacted** (`[REDACTED]`) in parsed artifacts.
- Evidence output is local and append-only — TRACE never transmits collected
  evidence off the endpoint.

If you discover any path by which the tool transmits, weakens, or fails to
redact evidence, that is a security vulnerability and should be reported as
above.
