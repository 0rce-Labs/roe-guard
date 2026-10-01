# Changelog

All notable changes to roe-guard are documented here.  The format is
based on [Keep a Changelog](https://keepachangelog.com/), and this
project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Top-level public API exports (`from roe_guard import Engagement, guarded, ...`) and a working `Engagement.from_file()`.
- `py.typed` marker (PEP 561) and a `mypy --strict` CI step.

## [0.1.0a1] — Unreleased

First public alpha.  v0.1.0a1 ships the core policy-enforcement
surface; breaking changes are possible before 0.1.0.

### Added

- **Policy loading and validation** — Declarative YAML policies parsed
  with `yaml.safe_load` (no RCE surface).  Validates required fields,
  ISO-8601 timestamps, CIDR ranges, and scope-entry structure.
- **8-step fail-closed decision engine** — `enforce()` evaluates every
  action through a strict priority chain: time window → blackout
  window → explicit deny → scope allow → action deny →
  approval-required → action allow → default deny.  Deny always
  overrides allow.
- **Hash-chained audit log** — Append-only JSONL log with SHA-256
  hash chain.  `AuditLog.record()` and `AuditLog.verify()` detect
  tampering or deletion in any line.
- **`@guarded` decorator** — Wraps an existing function with a policy
  check.  DENY raises `OutOfScopeError`; REQUIRES_APPROVAL raises
  `ApprovalRequiredError`; the wrapped function never runs.
- **`engagement.window()` context manager** — Activates an engagement
  scope for a code block; raises `PolicyExpiredError` at entry if
  the policy is outside its time window.
- **CLI** — `roe-guard validate | check | audit-verify` subcommands
  with stable exit codes (0/1/2 for ALLOW/DENY/REQUIRES_APPROVAL;
  0/1 for audit-verify valid/broken).  Stdlib `argparse` only — no
  heavy framework dependencies.
- **Scope matching** — CIDR (`ipaddress.ip_network`) and hostname
  wildcards (`fnmatch.fnmatchcase`, case-insensitive).
- **Single dependency** — Only `pyyaml`; standard library does the
  rest.

### Security

- `yaml.safe_load` is used everywhere; no `yaml.load` / `unsafe` paths.
- Fail-closed defaults: a misconfigured or expired policy denies
  every action rather than allowing.
- Audit log integrity is verifiable: any tampering or deletion
  changes a hash and is detected by `verify()`.

### Known limitations (per spec §7)

- roe-guard is an SDK-level discipline layer, not a network firewall.
  A tool that doesn't call `enforce()` / `@guarded` can still bypass
  the policy.
- Audit log tampering detection requires filesystem write access to
  be limited.  An attacker with log-write access can still delete the
  log entirely.
- Policy files must come from a trusted source.  File permissions are
  the operator's responsibility.
