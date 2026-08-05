use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

#[test]
#[ignore = "requires public network access"]
fn public_network_cli_workflow() {
    let workspace = tempdir().expect("temporary workspace should be created");
    let normal_state = workspace.path().join("normal-state");

    let mut normal = Command::cargo_bin("shield").expect("binary should build");
    normal
        .env("SHIELD_DATA_DIR", &normal_state)
        .args(["scan", "example.com"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Report: shield report"))
        .stderr("");

    let mut json = Command::cargo_bin("shield").expect("binary should build");
    let json_output = json
        .env("SHIELD_DATA_DIR", workspace.path().join("json-state"))
        .args(["scan", "example.com", "--json"])
        .assert()
        .success()
        .stderr("")
        .get_output()
        .stdout
        .clone();
    let scan: serde_json::Value =
        serde_json::from_slice(&json_output).expect("JSON output should be valid");
    assert_eq!(scan["schema_version"], 2);
    assert_eq!(scan["final_url"], "https://example.com/");

    let mut quiet = Command::cargo_bin("shield").expect("binary should build");
    quiet
        .env("SHIELD_DATA_DIR", workspace.path().join("quiet-state"))
        .args(["scan", "example.com", "--quiet"])
        .assert()
        .success()
        .stdout("")
        .stderr("");

    let report_path = workspace.path().join("report.html");
    let mut report = Command::cargo_bin("shield").expect("binary should build");
    report
        .env("SHIELD_DATA_DIR", &normal_state)
        .arg("report")
        .arg("--output")
        .arg(&report_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("report.html"))
        .stderr("");
    assert!(fs::read_to_string(report_path)
        .expect("report should be readable")
        .contains("Shield security report"));

    let mut blocked = Command::cargo_bin("shield").expect("binary should build");
    blocked
        .env("SHIELD_DATA_DIR", workspace.path().join("blocked-state"))
        .args(["scan", "http://127.0.0.1"])
        .assert()
        .failure()
        .code(1)
        .stdout("")
        .stderr("Blocked target.\n");
}
