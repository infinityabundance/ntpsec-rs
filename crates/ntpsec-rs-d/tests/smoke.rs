use std::process::Command;

/// Find the binary relative to the workspace root.
fn binary_path() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR = .../ntpsec-rs/crates/ntpsec-rs-d
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // remove ntpsec-rs-d
    path.pop(); // remove crates — now at workspace root
    path.push("target");
    path.push("debug");
    path.push("ntpsec-rs-d");
    if path.exists() {
        return path;
    }
    // Fallback: try the name directly (for cargo install --path)
    std::path::PathBuf::from("ntpsec-rs-d")
}

#[test]
fn test_help_succeeds() {
    let output = Command::new(binary_path())
        .arg("--help")
        .output()
        .expect("failed to execute ntpd-rs --help");
    assert!(output.status.success(), "ntpd-rs --help failed: {output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("NTP daemon"),
        "help should contain 'NTP daemon'"
    );
}

#[test]
fn test_version_output() {
    let output = Command::new(binary_path())
        .arg("--version")
        .output()
        .expect("failed to execute ntpd-rs --version");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("1.3.3"), "version should contain 1.3.3");
}
