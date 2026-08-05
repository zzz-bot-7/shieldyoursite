# Contributing

Keep changes inside the module that owns the behavior.

Use Rust 1.88 or newer. Read [AGENTS.md](AGENTS.md) for repository rules, and use GitHub Issues for current work and implementation gaps. Do not put vulnerability details or sensitive data in an issue; follow [SECURITY.md](SECURITY.md).

Before opening a pull request:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
```

Scanner policy changes must update `docs/POLICY.md` and include focused tests.
Changes to networking or complete CLI workflows must also run:

```bash
cargo test -p shield-scanner-cli --test network_acceptance -- --ignored
```
