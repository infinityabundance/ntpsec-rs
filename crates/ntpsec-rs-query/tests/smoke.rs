use std::process::Command;

fn binary_path() -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); path.pop(); // workspace root
    path.push("target"); path.push("debug"); path.push("ntpsec-rs-query");
    if path.exists() { return path; }
    std::path::PathBuf::from("ntpsec-rs-query")
}

#[test]
fn test_help_succeeds() {
    let output = Command::new(binary_path())
        .arg("--help")
        .output()
        .expect("failed to execute ntpq-rs --help");
    assert!(output.status.success(), "ntpq-rs --help failed: {output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("NTP query tool"));
}
