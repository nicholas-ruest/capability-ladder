use assert_cmd::Command;
use predicates::prelude::*;

#[allow(deprecated)]
fn command() -> Command {
    Command::cargo_bin("capability-ladder").expect("binary exists")
}

#[test]
fn valid_fixture_passes() {
    command()
        .args(["examples/valid-chain.json", "--at", "2026-10-07T21:30:00Z"])
        .assert()
        .success()
        .stdout(predicate::str::contains("PASS task=release-42 grants=3"));
}

#[test]
fn expanded_fixture_exits_two() {
    command()
        .args([
            "examples/expanded-chain.json",
            "--at",
            "2026-10-07T21:30:00Z",
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("CONSTRAINT_EXPANSION"))
        .stdout(predicate::str::contains("BROKEN_DELEGATION_LINK"));
}

#[test]
fn json_output_is_machine_readable() {
    let output = command()
        .args([
            "examples/valid-chain.json",
            "--at",
            "2026-10-07T21:30:00Z",
            "--format",
            "json",
        ])
        .output()
        .expect("command runs");
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(value["valid"], true);
    assert_eq!(value["grant_count"], 3);
}

#[test]
fn unknown_fields_fail_closed() {
    let file = tempfile::NamedTempFile::new().expect("temp file");
    std::fs::write(
        file.path(),
        r#"{"version":1,"task_id":"x","grants":[],"surprise":true}"#,
    )
    .expect("write fixture");

    command()
        .arg(file.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown field `surprise`"));
}
