# Contributing

Keep changes inside the module that owns the behavior.

Before opening a pull request:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
```

Scanner policy changes must update `docs/POLICY.md` and include focused tests.
