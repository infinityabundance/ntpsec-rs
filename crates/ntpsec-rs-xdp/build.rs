/// Build script for ntpsec-rs-xdp.
///
/// Compiles the eBPF XDP program (`xdp/ntp_timestamp.rs`) into a BPF ELF object
/// using `cargo build` with the `bpfel-unknown-none` target.
///
/// ## Prerequisites
///
/// ```bash
/// rustup target add bpfel-unknown-none
/// ```
///
/// The resulting BPF object file is referenced via the `XDP_BPF_ELF` env var
/// and loaded at runtime by the `aya` loader.
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Only rebuild if the XDP source changes
    println!("cargo::rerun-if-changed=xdp/Cargo.toml");
    println!("cargo::rerun-if-changed=xdp/src/ntp_timestamp.rs");

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set"));

    // Path to the XDP sub-crate
    let xdp_dir = manifest_dir.join("xdp");

    // Check if the bpfel-unknown-none target is available.
    let target_available = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .any(|l| l.contains("bpfel-unknown-none"))
        })
        .unwrap_or(false);

    // Try to build the eBPF program.
    let build_ok = if target_available {
        let status = Command::new(&cargo)
            .args([
                "build",
                "--release",
                "--target",
                "bpfel-unknown-none",
                "--manifest-path",
            ])
            .arg(xdp_dir.join("Cargo.toml").to_string_lossy().as_ref())
            .env("CARGO_CFG_BPF_TARGET_ARCH", "bpf")
            .status()
            .expect("Failed to run cargo for XDP eBPF build");

        status.success()
    } else {
        eprintln!(
            "NOTE: bpfel-unknown-none target not installed. \
             Run `rustup target add bpfel-unknown-none` to compile the eBPF program.\n\
             For now, checking for a pre-built BPF ELF..."
        );
        false
    };

    // The expected path for the compiled BPF ELF
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR must be set"));

    let bpf_elf: PathBuf = if build_ok {
        // Find the ELF from a successful build
        manifest_dir
            .parent() // crates/
            .and_then(|p| p.parent()) // ntpsec-rs/
            .map(|p| p.join("target"))
            .unwrap_or_else(|| out_dir.clone())
            .join("bpfel-unknown-none")
            .join("release")
            .join("ntpsec_xdp_ebpf")
    } else {
        // Look for a pre-existing BPF ELF (development scenario)
        let candidates = [
            manifest_dir.parent().and_then(|p| p.parent()).map(|p| {
                p.join("target")
                    .join("bpfel-unknown-none")
                    .join("release")
                    .join("ntpsec_xdp_ebpf")
            }),
            Some(
                manifest_dir
                    .join("xdp")
                    .join("target")
                    .join("bpfel-unknown-none")
                    .join("release")
                    .join("ntpsec_xdp_ebpf"),
            ),
            Some(manifest_dir.join("xdp").join("ntpsec_xdp_ebpf")),
        ];

        candidates
            .into_iter()
            .flatten()
            .find(|p| p.exists())
            .unwrap_or_else(|| manifest_dir.join("xdp").join("ntpsec_xdp_ebpf"))
    };

    if bpf_elf.exists() {
        println!("cargo::rustc-env=XDP_BPF_ELF={}", bpf_elf.display());
        println!("cargo::warning=XDP BPF ELF found at {}", bpf_elf.display());
    } else {
        // Last resort: emit the path even if it doesn't exist, so the crate can
        // at least be checked for compilation errors (it will fail at runtime).
        println!("cargo::rustc-env=XDP_BPF_ELF={}", bpf_elf.display());
        println!(
            "cargo::warning=XDP BPF ELF not found at {:?} — set XDP_BPF_ELF env var or \
             build the eBPF program manually. The crate will compile but fail at \
             runtime until the BPF ELF is available.",
            bpf_elf
        );
    }
}
