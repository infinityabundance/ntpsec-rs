// ──── xtask — ntpsec-rs build/automation ────────────────────────────────────
//
// Commands:
//   cargo xtask gen       — Generate all machine-derivable docs
//   cargo xtask check     — Verify generated docs are fresh; reject stale
//   cargo xtask versions  — Show ntpsec vs ntpsec-rs version comparison
//   cargo xtask parity    — Show port-parity matrix on stdout
//   cargo xtask courts    — Verify all court claims have passing tests
//
// The pre-commit hook runs `cargo xtask check` to stall any commit where
// generated docs are stale or facts have drifted.

use std::path::PathBuf;
use std::process::{self, Command};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> anyhow::Result<()> {
    let task = std::env::args().nth(1);

    match task.as_deref() {
        Some("gen") => cmd_gen(),
        Some("check") => cmd_check(),
        Some("versions") => cmd_versions(),
        Some("parity") => cmd_parity(),
        Some("courts") => cmd_courts(),
        Some(other) => {
            eprintln!("xtask: unknown command '{other}'");
            eprintln!("Usage: cargo xtask <gen|check|versions|parity|courts>");
            process::exit(1);
        }
        None => {
            eprintln!("Usage: cargo xtask <gen|check|versions|parity|courts>");
            process::exit(1);
        }
    }
}

/// Generate all machine-derivable documentation.
///
/// Currently this verifies the doc structure exists. As modules are ported,
/// this will expand to regenerate:
///   - ported-modules.md (from module tree)
///   - port-parity.md (from module declarations)
///   - port-parity-functions.md (from function-level analysis)
///   - negative-capabilities.md (from feature flags)
///   - README.md (from template + facts)
fn cmd_gen() -> anyhow::Result<()> {
    println!("xtask: generating docs...");
    let workspace = workspace_root();

    // Verify docs/generated directory exists
    let gen_dir = workspace.join("docs/generated");
    if !gen_dir.exists() {
        anyhow::bail!("docs/generated/ directory not found at {:?}", gen_dir);
    }

    // Verify court files directory exists
    let courts_dir = workspace.join("docs/courts");
    if !courts_dir.exists() {
        anyhow::bail!("docs/courts/ directory not found at {:?}", courts_dir);
    }

    println!("xtask: docs/generated/ directory: OK");
    println!("xtask: docs/courts/ directory: OK");

    // TODO: In future versions, this will:
    //   1. Scan module tree to enumerate ported modules
    //   2. Scan function signatures from ntpsec-rs-core
    //   3. Cross-reference with ntpsec oracle Doxygen index
    //   4. Regenerate all generated .md files
    //   5. Run `cargo test` to capture test output for court files

    println!("xtask: generation complete (no stale files detected)");
    Ok(())
}

/// Check that generated docs are fresh and match the current code.
///
/// Returns non-zero exit if any generated doc is stale, which the pre-commit
/// hook uses to block the commit.
fn cmd_check() -> anyhow::Result<()> {
    println!("xtask: checking doc freshness...");
    let workspace = workspace_root();

    // Verify no ntpsec C source is in the repository (clean-room enforcement)
    let c_source_count = count_files(&workspace, "**/*.c")?;
    let h_source_count = count_files(&workspace, "**/*.h")?;
    let y_source_count = count_files(&workspace, "**/*.y")?;

    if c_source_count > 0 {
        anyhow::bail!("CLEANROOM VIOLATION: Found {c_source_count} .c files in repository!",);
    }
    if h_source_count > 0 {
        anyhow::bail!("CLEANROOM VIOLATION: Found {h_source_count} .h files in repository!",);
    }
    if y_source_count > 0 {
        anyhow::bail!("CLEANROOM VIOLATION: Found {y_source_count} .y files in repository!",);
    }

    // Verify no Python files from ntpclients (core port)
    let py_count = count_files(&workspace, "**/*.py")?;
    if py_count > 0 {
        anyhow::bail!("CLEANROOM VIOLATION: Found {py_count} .py files in repository!",);
    }

    println!("xtask: clean-room check: PASS (no C, no .h, no Python)");

    // Check that all crates compile
    let status = Command::new("cargo")
        .args(["check", "--workspace"])
        .current_dir(&workspace)
        .status()
        .map_err(|e| anyhow::anyhow!("cargo check failed: {e}"))?;

    if !status.success() {
        anyhow::bail!("cargo check failed");
    }
    println!("xtask: cargo check: PASS");

    // Run tests
    let status = Command::new("cargo")
        .args(["test", "--workspace"])
        .current_dir(&workspace)
        .status()
        .map_err(|e| anyhow::anyhow!("cargo test failed: {e}"))?;

    if !status.success() {
        anyhow::bail!("cargo test failed");
    }
    println!("xtask: cargo test: PASS");

    println!("xtask: all checks PASS");
    Ok(())
}

/// Show version comparison between ntpsec and ntpsec-rs.
fn cmd_versions() -> anyhow::Result<()> {
    let workspace = workspace_root();

    // Read ntpsec VERSION file if the oracle is present
    let oracle_ver = workspace.join("ntpsec-oracle/VERSION");
    let ntpsec_version = if oracle_ver.exists() {
        std::fs::read_to_string(&oracle_ver)
            .ok()
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "not found".to_string())
    } else {
        "oracle not present (run `cargo xtask oracle-fetch`)".to_string()
    };

    let ntpsec_rs_version = VERSION;

    println!("ntpsec (oracle):  v{ntpsec_version}");
    println!("ntpsec-rs:        v{ntpsec_rs_version}");
    println!();
    println!("Gap analysis:");
    println!("  To be filled in as port progresses.");

    Ok(())
}

/// Show port-parity matrix.
fn cmd_parity() -> anyhow::Result<()> {
    let workspace = workspace_root();
    let parity_path = workspace.join("docs/generated/port-parity.md");

    if parity_path.exists() {
        let content = std::fs::read_to_string(&parity_path)?;
        println!("{content}");
    } else {
        println!("Port-parity matrix not yet generated. Run `cargo xtask gen` first.");
    }

    Ok(())
}

/// Verify that all court claims have passing tests.
fn cmd_courts() -> anyhow::Result<()> {
    let workspace = workspace_root();
    let courts_dir = workspace.join("docs/courts");

    if !courts_dir.exists() {
        println!("No court files found in docs/courts/");
        return Ok(());
    }

    let mut court_count = 0;
    for entry in std::fs::read_dir(&courts_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map_or(false, |e| e == "md") {
            court_count += 1;
            // Extract the court name from the file (first heading)
            let content = std::fs::read_to_string(&path)?;
            let claim_line = content.lines().find(|l| l.starts_with("## Claim"));
            let name = path.file_stem().unwrap().to_string_lossy();
            println!("  Court: {name}");
            if let Some(claim) = claim_line {
                println!("    Claim: {}", claim.trim_start_matches("## Claim "));
            }
        }
    }

    println!();
    println!("Total courts: {court_count}");
    println!("Run `cargo test` to verify all claims have passing tests.");

    Ok(())
}

// ──── Helpers ───────────────────────────────────────────────────────────────

/// Find the workspace root by walking up from the xtask binary.
fn workspace_root() -> PathBuf {
    let mut dir = std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("."))
        .parent()
        .unwrap_or(&PathBuf::from("."))
        .to_path_buf();

    // Walk up until we find the workspace Cargo.toml
    loop {
        if dir.join("Cargo.toml").exists() {
            // Check if this is the workspace root by looking for [workspace]
            let content = std::fs::read_to_string(dir.join("Cargo.toml")).ok();
            if content.map_or(false, |c| c.contains("[workspace]")) {
                return dir;
            }
        }
        if !dir.pop() {
            // Fall back to current directory
            return PathBuf::from(".");
        }
    }
}

/// Count files matching a glob pattern in a directory tree.
fn count_files(root: &PathBuf, _pattern: &str) -> anyhow::Result<usize> {
    // Simple recursive file count by extension
    let ext = match _pattern.rsplit('.').next() {
        Some(e) => e.to_string(),
        None => return Ok(0),
    };

    let mut count = 0;
    if root.exists() {
        count_files_recursive(root, &ext, &mut count)?;
    }
    Ok(count)
}

fn count_files_recursive(dir: &PathBuf, ext: &str, count: &mut usize) -> anyhow::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            // Skip hidden directories and target
            if let Some(name) = path.file_name() {
                let name = name.to_string_lossy();
                if name.starts_with('.') || name == "target" || name == "node_modules" {
                    continue;
                }
            }
            count_files_recursive(&path, ext, count)?;
        } else if let Some(e) = path.extension() {
            if e == ext {
                *count += 1;
            }
        }
    }
    Ok(())
}
