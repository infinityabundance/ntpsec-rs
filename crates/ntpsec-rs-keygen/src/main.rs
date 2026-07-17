// ──── ntpkeygen-rs — NTP key generator ──────────────────────────────────────
//
// Forensic Rust reconstruction of ntpkeygen.
//
// # Usage
//
//   ntpkeygen-rs                    # generate default keys
//   ntpkeygen-rs -o /etc/ntp.keys   # specify output file
//   ntpkeygen-rs -n 10              # generate 10 keys
//
// ## Oracle
//   - ntpsec ntpclients/ntpkeygen.py (4K)
// =============================================================================

use clap::Parser;

/// NTP key generator — forensic Rust reconstruction of ntpkeygen.
#[derive(Parser, Debug)]
#[command(name = "ntpkeygen-rs", about = "NTP key generator", version)]
struct Cli {
    /// Output file path
    #[arg(short = 'o', long, default_value = "/etc/ntp.keys")]
    output: String,

    /// Number of keys to generate
    #[arg(short = 'n', long, default_value = "10")]
    count: u32,

    /// Digest type: MD5, SHA1, AES-128-CMAC
    #[arg(short = 'd', long, default_value = "MD5")]
    digest: String,

    /// Key length in bytes
    #[arg(short = 'l', long, default_value = "16")]
    key_length: u32,
}

fn main() {
    let cli = Cli::parse();
    println!(
        "ntpkeygen-rs v{} — Key generator (Rust)",
        env!("CARGO_PKG_VERSION")
    );
    println!("Output: {}", cli.output);
    println!(
        "Keys: {} (digest: {}, key length: {} bytes)",
        cli.count, cli.digest, cli.key_length
    );

    // Generate keys (stub)
    for i in 1..=cli.count {
        let key = generate_key(cli.key_length);
        println!("{i} {digest} {key}", digest = cli.digest, key = key);
    }
}

fn generate_key(length: u32) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut key = String::with_capacity(length as usize * 2);
    let mut rng = seed;
    for _ in 0..length {
        rng = rng
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let byte = ((rng >> 32) & 0xFF) as u8;
        // Use only hex chars for readability
        let idx = (byte % 16) as usize;
        key.push("0123456789abcdef".as_bytes()[idx] as char);
    }
    key
}
