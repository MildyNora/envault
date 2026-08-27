use assert_cmd::Command;

#[test]
fn version_flag_works() {
    Command::cargo_bin("envault")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::contains("envault"));
}
