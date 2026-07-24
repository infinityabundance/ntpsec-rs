// ──── ntptime-rs — NTP kernel time management ───────────────────────────────
//
// Forensic Rust reconstruction of ntptime. Reads and displays kernel
// timekeeping state via adjtimex/ntp_adjtime.
//
// ## Oracle
//   - ntpsec ntptime/ntptime.c (13K)
// =============================================================================

use clap::Parser;

/// NTP kernel time management — forensic Rust reconstruction of ntptime.
#[derive(Parser, Debug)]
#[command(name = "ntptime-rs", about = "NTP kernel time management", version)]
struct Cli {
    /// Verbose output
    #[arg(short = 'v', long)]
    verbose: bool,
}

fn status_str(code: i32) -> &'static str {
    match code {
        libc::TIME_OK => "OK",
        libc::TIME_INS => "INS",
        libc::TIME_DEL => "DEL",
        libc::TIME_OOP => "OOP",
        libc::TIME_WAIT => "WAIT",
        libc::TIME_ERROR => "ERROR",
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

fn main() {
    let cli = Cli::parse();

    let mut tmx: libc::timex = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::adjtimex(&mut tmx) };

    if rc < 0 {
        eprintln!("adjtimex failed: {}", std::io::Error::last_os_error());
        std::process::exit(1);
    }

    // --- ntp_gettime() equivalent output ---
    println!("ntp_gettime() returns code {} ({})", rc, status_str(rc));

    // Determine if NANO flag is set
    let nano = (tmx.status & libc::STA_NANO) != 0;
    let unit_str = if nano { "ns" } else { "us" };

    // For the "time" line, we can read the current wall clock
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as i64;

    let ut = unsafe { libc::localtime(&secs) };
    if !ut.is_null() {
        let tm = unsafe { *ut };
        println!(
            "  time {:08x}.{:08x}  {:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}",
            secs as u64,
            if nano {
                now.subsec_nanos()
            } else {
                now.subsec_micros()
            },
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            if nano {
                now.subsec_nanos() / 1_000_000
            } else {
                now.subsec_micros()
            },
        );
    }

    println!(
        "  maximum error {} us, estimated error {} us",
        tmx.maxerror, tmx.esterror
    );
    println!("  TAI offset: {}", tmx.tai);

    let freq_ppm = tmx.freq as f64 / 65536.0;
    println!(
        "  status: 0x{:04x} ({})",
        tmx.status,
        status_flags_str(tmx.status),
    );

    println!(
        "  pll offset: {} {}, frequency: {:.3} ppm, maximum jitter: {} {}",
        tmx.offset,
        unit_str,
        freq_ppm,
        if nano { tmx.jitter / 1000 } else { tmx.jitter },
        unit_str,
    );
    println!(
        "  interval: {} s, sanity: {}",
        tmx.constant,
        if rc == libc::TIME_OK as i32 {
            "PASS"
        } else {
            "FAIL"
        }
    );

    // --- Verbose: ntp_adjtime() equivalent ---
    if cli.verbose {
        println!();
        println!("ntp_adjtime() returns code {} ({})", rc, status_str(rc));
        println!("  mode: 0x{:x} (none)", tmx.modes);
        println!(
            "  offset: {}, freq: {}, maxerror: {}, esterror: {}",
            tmx.offset, tmx.freq, tmx.maxerror, tmx.esterror
        );
        println!(
            "  status: 0x{:04x}, constant: {}, precision: {}",
            tmx.status, tmx.constant, tmx.precision
        );
        println!(
            "  tolerance: {:.3} ppm, ppsfrequency: {}, jitter: {}",
            tmx.tolerance as f64 / 65536.0,
            tmx.ppsfreq,
            tmx.jitter,
        );
        println!(
            "  shift: {}, stabil: {}, jitcnt: {}, calcnt: {}, errcnt: {}, stbcnt: {}",
            tmx.shift, tmx.stabil, tmx.jitcnt, tmx.calcnt, tmx.errcnt, tmx.stbcnt,
        );
    }
}
