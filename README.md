# Shield

CLI security-header scanner with local HTML reports.

## Requirements

- Rust 1.88 or newer
- Linux is verified in CI; other operating systems are outside the maintained test matrix

## Install From Source

```bash
git clone https://github.com/JDRV-space/shieldyoursite.git
cd shieldyoursite
cargo install --locked --path crates/scanner-cli
```

Pin the checkout to a reviewed commit before installing in automation.

## Use

```bash
shield scan example.com
shield report
```

The scan prints the result first, followed by compact header, environment, and resource detail.

Machine-readable output:

```bash
shield scan example.com --json
```

JSON schema version 2 represents earned points as numbers, including half-points.

No output:

```bash
shield scan example.com --quiet
```

Write the latest report to a chosen path:

```bash
shield report --output report.html
```

## Scope

Shield checks the final successful HTTP response, validates important security-header values, detects common hosting platforms, and inventories known third-party resources in fetched HTML.

A score describes that response under the documented [scan policy](docs/POLICY.md). It is not evidence for every page, endpoint, or resource on the site, and heuristic platform or resource results can be incomplete or incorrect.

It does not:

- exploit the target
- crawl contact pages
- collect email addresses
- modify the target
- claim compliance certification

## Local Data and Privacy

Every successful scan, including `--json` and `--quiet`, atomically replaces `latest-scan.json` in the platform-local application data directory. Set `SHIELD_DATA_DIR` to choose a different directory, and remove that file to clear the saved scan. Files are created owner-only on Unix.

Shield sends HTTP requests only to the target and its redirects; it has no telemetry. Saved state and reports can contain full URLs, including query strings, assessed header values, and detected platform or resource evidence. Review them before sharing. Generated reports are self-contained and make no network requests.

## Project Layout

```text
crates/
  scanner-core/     Safe HTTP fetch and scan analysis.
  scanner-report/   Self-contained HTML report renderer.
  scanner-cli/      Commands, output, and local scan state.
docs/
  ARCHITECTURE.md
  POLICY.md
```

Repository guidance lives in [AGENTS.md](AGENTS.md). Scanner policy and architecture live in [docs/POLICY.md](docs/POLICY.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
Contribution and vulnerability-reporting paths live in [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
Update the owning document instead of copying its rules.

## Checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
cargo test -p shield-scanner-cli --test network_acceptance -- --ignored
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
