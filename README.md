# Shield

CLI security-header scanner with local HTML reports.

## Install

```bash
git clone https://github.com/JDRV-space/shieldyoursite.git
cd shieldyoursite
cargo install --path crates/scanner-cli
```

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

No output:

```bash
shield scan example.com --quiet
```

Write the latest report to a chosen path:

```bash
shield report --output report.html
```

## Scope

Shield checks HTTP response security headers, validates important values, detects common hosting platforms, and inventories known third-party resources in HTML.

It does not:

- exploit the target
- crawl contact pages
- collect email addresses
- modify the target
- claim compliance certification

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

## Checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
