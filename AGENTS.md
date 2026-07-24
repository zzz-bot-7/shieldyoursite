# Shield Engineering Guide

TLDR: Keep the CLI quiet, entrypoints thin, scan behavior explicit, and outbound networking safe.

## Ownership

| Owner | Path | Responsibility |
|---|---|---|
| Scanner core | `crates/scanner-core` | URL policy, HTTP fetch, header policy, platform and resource analysis |
| Report | `crates/scanner-report` | Deterministic self-contained HTML |
| CLI | `crates/scanner-cli` | Commands, minimal output, atomic local state |
| Documentation | `README.md`, `docs` | Public behavior, policy, architecture, limitations |

## Data Flow

```text
CLI input
  -> target normalization
  -> public-network-only fetch
  -> deterministic analysis
  -> atomic latest-scan state
  -> optional local report
```

## Rules

- The CLI is the only user interface.
- Default scans print the result first, then compact report detail.
- `--json` prints JSON only.
- `--quiet` prints nothing on success.
- Errors are one line on stderr.
- Scanner policy must be deterministic and source-backed.
- Header values must be evaluated. Presence alone is insufficient.
- Context-dependent headers cannot be presented as universally required.
- Redirects and every DNS resolution must retain SSRF protection.
- Response bodies must be streamed into a strict byte budget.
- No contact crawling, lead generation, payments, provider credentials, or automatic fixes.
- Shared abstractions require a real second consumer or a safety boundary.

## Validation

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
```

Real-network acceptance tests must use public targets and must include:

- a normal scan
- JSON-only output
- quiet output
- report generation from saved state
- a blocked private-network target
