// ──── ntpfrob-rs — NTP system utilities ─────────────────────────────────────
//
// Forensic Rust reconstruction of ntpfrob. System clock manipulation
// utilities using adjtimex and related system calls.
//
// ## Oracle
//   - ntpsec ntpfrob/ (6 C files)
// =============================================================================

use std::io::Read;

use clap::Parser;

/// NTP frob tools — forensic Rust reconstruction of ntpfrob.
#[derive(Parser, Debug)]
#[command(name = "ntpfrob-rs", about = "NTP system utilities", version)]
struct Cli {
    /// Subcommand
    #[command(subcommand)]
    command: Option<SubCommand>,
}

#[derive(Parser, Debug)]
enum SubCommand {
    /// Measure system clock precision
    Precision,
    /// Measure clock jitter
    Jitter,
    /// Dump NTP packet
    Dump,
    /// Bump clock forward by one millisecond
    Bumpclock,
    /// Get/set tick adjustment
    Tickadj {
        /// New tick value in microseconds
        tick: Option<u64>,
    },
    /// PPS API test
    PpsApi,
    /// Show kernel clock status via adjtimex
    Status,
}

fn show_clock_status() {
    let mut tmx: libc::timex = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::adjtimex(&mut tmx) };

    println!("Kernel clock status:");
    if rc < 0 {
        eprintln!("  adjtimex failed: {}", std::io::Error::last_os_error());
        return;
    }
    println!("  return code: {} ({})", rc, status_str(rc));
    println!("  offset:      {} ns", tmx.offset);
    println!(
        "  frequency:   {:.3} ppm ({} raw)",
        tmx.freq as f64 / 65536.0,
        tmx.freq
    );
    println!("  maxerror:    {} us", tmx.maxerror);
    println!("  esterror:    {} us", tmx.esterror);
    println!(
        "  status:      0x{:04x} ({})",
        tmx.status,
        status_flags_str(tmx.status)
    );
    println!("  constant:    {}", tmx.constant);
    println!(
        "  precision:   {} us (2^{})",
        tmx.precision,
        log2_approx(tmx.precision)
    );
    println!("  tolerance:   {} ppm", tmx.tolerance as f64 / 65536.0);
    println!("  tick:        {} us", tmx.tick);
    if tmx.tai != 0 {
        println!("  TAI offset:  {}", tmx.tai);
    }
}

fn status_str(code: i32) -> &'static str {
    match code {
        libc::TIME_OK => "OK (TIME_OK)",
        libc::TIME_INS => "INS (leap second inserted)",
        libc::TIME_DEL => "DEL (leap second deleted)",
        libc::TIME_OOP => "OOP (leap second in progress)",
        libc::TIME_WAIT => "WAIT (leap second overflow)",
        libc::TIME_ERROR => "ERROR (clock unsynchronized)",
        _ => "UNKNOWN",
    }
}

fn status_flags_str(status: i32) -> String {
    let mut flags = Vec::new();
    if status & libc::STA_PLL != 0 {
        flags.push("PLL");
    }
    if status & libc::STA_PPSFREQ != 0 {
        flags.push("PPSFREQ");
    }
    if status & libc::STA_PPSTIME != 0 {
        flags.push("PPSTIME");
    }
    if status & libc::STA_FLL != 0 {
        flags.push("FLL");
    }
    if status & libc::STA_INS != 0 {
        flags.push("INS");
    }
    if status & libc::STA_DEL != 0 {
        flags.push("DEL");
    }
    if status & libc::STA_UNSYNC != 0 {
        flags.push("UNSYNC");
    }
    if status & libc::STA_FREQHOLD != 0 {
        flags.push("FREQHOLD");
    }
    if status & libc::STA_PPSSIGNAL != 0 {
        flags.push("PPSSIGNAL");
    }
    if status & libc::STA_PPSJITTER != 0 {
        flags.push("PPSJITTER");
    }
    if status & libc::STA_PPSWANDER != 0 {
        flags.push("PPSWANDER");
    }
    if status & libc::STA_PPSERROR != 0 {
        flags.push("PPSERROR");
    }
    if status & libc::STA_CLOCKERR != 0 {
        flags.push("CLOCKERR");
    }
    if status & libc::STA_NANO != 0 {
        flags.push("NANO");
    }
    if status & libc::STA_MODE != 0 {
        flags.push("MODE");
    }
    if status & libc::STA_CLK != 0 {
        flags.push("CLK");
    }
    flags.join(",")
}

fn log2_approx(val: libc::c_long) -> i32 {
    if val <= 0 {
        return 0;
    }
    (val as f64).log2().round() as i32
}

fn measure_jitter() {
    use std::time::{SystemTime, UNIX_EPOCH};

    println!("Measuring clock jitter (100 samples)...");
    let mut samples = Vec::with_capacity(100);
    for _ in 0..100 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        samples.push(now.as_nanos());
        // Spin a tiny bit
        for _ in 0..100 {
            std::hint::spin_loop();
        }
    }

    let mut diffs: Vec<u128> = samples.windows(2).map(|w| w[1] - w[0]).collect();
    diffs.sort_unstable();
    let min = diffs.first().copied().unwrap_or(0);
    let max = diffs.last().copied().unwrap_or(0);
    let mean = diffs.iter().sum::<u128>() / diffs.len() as u128;
    println!("  min: {} ns", min);
    println!("  max: {} ns", max);
    println!("  mean: {} ns", mean);
    println!("  estimated jitter: {} ns", max - min);
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Some(SubCommand::Precision) => {
            // log2 of the kernel precision value
            let mut tmx: libc::timex = unsafe { std::mem::zeroed() };
            let rc = unsafe { libc::adjtimex(&mut tmx) };
            if rc >= 0 {
                println!(
                    "System precision: {} us (log2 ≈ {})",
                    tmx.precision,
                    log2_approx(tmx.precision)
                );
            } else {
                println!("System precision: -24 (log2 seconds, default)");
            }
        }
        Some(SubCommand::Jitter) => {
            measure_jitter();
        }
        Some(SubCommand::Dump) => {
            println!("Packet dump: reading NTP packet from stdin (raw hex)...");
            let mut buf = [0u8; 512];
            match std::io::stdin().read(&mut buf) {
                Ok(n) if n > 0 => {
                    println!("Read {} bytes:", n);
                    for (i, chunk) in buf[..n].chunks(16).enumerate() {
                        print!("{:04x}  ", i * 16);
                        for b in chunk {
                            print!("{:02x} ", b);
                        }
                        print!("  ");
                        for b in chunk {
                            if b.is_ascii_graphic() || *b == b' ' {
                                print!("{}", *b as char);
                            } else {
                                print!(".");
                            }
                        }
                        println!();
                    }
                }
                _ => println!("(no data)"),
            }
        }
        Some(SubCommand::Bumpclock) => {
            // Bump clock forward by 1ms using adjtimex
            let mut tmx: libc::timex = unsafe { std::mem::zeroed() };
            tmx.modes = libc::ADJ_OFFSET_SINGLESHOT;
            tmx.offset = 1000; // 1000 microseconds = 1ms
            let rc = unsafe { libc::adjtimex(&mut tmx) };
            if rc >= 0 {
                println!("Clock bumped forward by 1 ms");
            } else {
                eprintln!("Bumpclock failed: {}", std::io::Error::last_os_error());
            }
        }
        Some(SubCommand::Tickadj { tick }) => {
            let mut tmx: libc::timex = unsafe { std::mem::zeroed() };
            if let Some(new_tick) = tick {
                tmx.modes = libc::ADJ_TICK;
                tmx.tick = *new_tick as libc::c_long;
                let rc = unsafe { libc::adjtimex(&mut tmx) };
                if rc >= 0 {
                    println!("Tick set to {} us", new_tick);
                } else {
                    eprintln!("Tickadj failed: {}", std::io::Error::last_os_error());
                }
            } else {
                let rc = unsafe { libc::adjtimex(&mut tmx) };
                if rc >= 0 {
                    println!("Current tick: {} us", tmx.tick);
                } else {
                    eprintln!("Tickadj failed: {}", std::io::Error::last_os_error());
                }
            }
        }
        Some(SubCommand::PpsApi) => {
            println!("PPS API test: opening /dev/pps0...");
            match std::fs::OpenOptions::new().read(true).open("/dev/pps0") {
                Ok(_) => println!("  /dev/pps0 opened successfully (PPS API available)"),
                Err(e) => println!("  /dev/pps0: {} (PPS not available)", e),
            }
        }
        Some(SubCommand::Status) | None => {
            show_clock_status();
        }
    }
}
