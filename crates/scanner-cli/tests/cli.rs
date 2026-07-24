use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::json;
use tempfile::tempdir;

fn saved_scan() -> serde_json::Value {
    json!({
        "schema_version": 1,
        "requested_url": "https://example.com/",
        "final_url": "https://example.com/",
        "scanned_at": "2026-07-24T12:00:00Z",
        "duration_ms": 10,
        "grade": "B",
        "score": 82,
        "summary": {
            "passed": 1,
            "warnings": 0,
            "failed": 0,
            "informational": 0
        },
        "headers": [{
            "id": "content-type-options",
            "header": "X-Content-Type-Options",
            "status": "pass",
            "value": "nosniff",
            "summary": "MIME sniffing is disabled.",
            "recommendation": null,
            "weight": 15,
            "earned": 15
        }],
        "platform": {
            "platform": "unknown",
            "confidence": 0,
            "evidence": []
        },
        "resources": [],
        "response": {
            "status": 200,
            "content_type": "text/html",
            "body_bytes": 100,
            "body_truncated": false
        }
    })
}

#[test]
fn help_is_short() {
    let mut command = Command::cargo_bin("shield").expect("binary should build");
    command
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Security-header scanner."))
        .stdout(predicate::str::contains("scan"))
        .stdout(predicate::str::contains("report"));
}

#[test]
fn report_writes_latest_scan_and_prints_only_path() {
    let state = tempdir().expect("state directory should be created");
    let output = tempdir().expect("output directory should be created");
    fs::write(
        state.path().join("latest-scan.json"),
        serde_json::to_vec(&saved_scan()).expect("fixture should serialize"),
    )
    .expect("fixture should be written");

    let mut command = Command::cargo_bin("shield").expect("binary should build");
    command
        .env("SHIELD_DATA_DIR", state.path())
        .current_dir(output.path())
        .args(["report", "--output", "report.html"])
        .assert()
        .success()
        .stdout("report.html\n")
        .stderr("");

    let report =
        fs::read_to_string(output.path().join("report.html")).expect("report should exist");
    assert!(report.contains("example.com"));
    assert!(report.contains("Print / PDF"));
}

#[test]
fn report_requires_a_saved_scan() {
    let state = tempdir().expect("state directory should be created");
    let mut command = Command::cargo_bin("shield").expect("binary should build");
    command
        .env("SHIELD_DATA_DIR", state.path())
        .arg("report")
        .assert()
        .failure()
        .stdout("")
        .stderr("No scan found.\n");
}

#[test]
fn json_and_quiet_are_mutually_exclusive() {
    let mut command = Command::cargo_bin("shield").expect("binary should build");
    command
        .args(["scan", "example.com", "--json", "--quiet"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}
