# Architecture

Shield is a Cargo workspace with three owners.

## Scanner Core

`scanner-core` owns scanner behavior and has no CLI or report dependencies.

```text
input
  -> normalize and validate URL
  -> resolve public IP addresses only
  -> fetch with redirect, timeout, and body limits
  -> evaluate response headers
  -> detect platform and HTML resources
  -> return ScanResult
```

Analysis modules are pure where possible. Network behavior stays under `network`.

## Scanner Report

`scanner-report` converts `ScanResult` into one deterministic, self-contained HTML document. It performs no networking and loads no external assets.

## Scanner CLI

`scanner-cli` is the only user interface.

- `shield scan` runs a scan and atomically saves the latest result.
- `shield report` renders the latest saved result.
- normal output shows the result first, then compact report detail
- JSON and quiet modes never include status prose

Local state can be redirected with `SHIELD_DATA_DIR`. This supports isolated automation and tests.

## Dependency Direction

```text
scanner-cli -> scanner-core
scanner-cli -> scanner-report
scanner-report -> scanner-core
scanner-core -> no workspace crate
```
