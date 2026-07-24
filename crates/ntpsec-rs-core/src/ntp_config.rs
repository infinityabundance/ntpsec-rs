// ──── ntp_config.rs ─────────────────────────────────────────────────────────
// Full NTPsec configuration parser — scanner + config tree.
// =============================================================================

use crate::nts_server::NtsServerConfig;
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Keyword(String),
    String(String),
    Integer(i64),
    Float(f64),
    Address(IpAddr),
    Eof,
    Newline,
    Comment(String),
    Include(String),
}

#[derive(Debug)]
pub struct ConfigScanner {
    input: String,
    pos: usize,
    line: usize,
    col: usize,
}

impl ConfigScanner {
    pub fn new(input: &str) -> Self {
        Self {
            input: input.to_string(),
            pos: 0,
            line: 1,
            col: 1,
        }
    }

    fn current_char(&self) -> char {
        self.input[self.pos..].chars().next().unwrap_or('\0')
    }

    fn skip_ws(&mut self) {
        while self.pos < self.input.len() {
            match self.current_char() {
                ' ' | '\t' | '\r' => {
                    self.pos += 1;
                    self.col += 1;
                }
                _ => break,
            }
        }
    }

    fn skip_comment(&mut self) {
        while self.pos < self.input.len() && self.input.as_bytes()[self.pos] != b'\n' {
            self.pos += 1;
        }
    }

    pub fn next_token(&mut self) -> Token {
        loop {
            self.skip_ws();
            if self.pos >= self.input.len() {
                return Token::Eof;
            }

            let c = self.current_char();

            if c == '\n' {
                self.pos += 1;
                self.line += 1;
                self.col = 1;
                return Token::Newline;
            }

            if c == '#' || c == '|' {
                self.skip_comment();
                // Consume the trailing newline too
                if self.pos < self.input.len() && self.input.as_bytes()[self.pos] == b'\n' {
                    self.pos += 1;
                    self.line += 1;
                    self.col = 1;
                }
                continue;
            }

            if c == '"' || c == '\'' {
                return Token::String(self.read_quoted());
            }

            if (c.is_ascii_digit() || c == '-' || c == '+')
                && self.pos + 1 < self.input.len()
                && (c.is_ascii_digit() || self.input.as_bytes()[self.pos + 1].is_ascii_digit())
            {
                return self.read_number_or_hostname();
            }

            if c.is_ascii_alphabetic() || c == '_' || c == '.' || c == '/' || c == ':' {
                return self.read_ident_or_keyword();
            }

            // Skip unknown char
            self.pos += 1;
            self.col += 1;
        }
    }

    fn read_quoted(&mut self) -> String {
        let quote = self.current_char();
        self.pos += 1;
        let start = self.pos;
        while self.pos < self.input.len() && self.input.as_bytes()[self.pos] != quote as u8 {
            self.pos += 1;
        }
        let s = self.input[start..self.pos].to_string();
        if self.pos < self.input.len() {
            self.pos += 1;
        }
        self.col += s.len() + 2;
        s
    }

    fn read_ident(&mut self) -> String {
        let start = self.pos;
        while self.pos < self.input.len() {
            match self.input.as_bytes()[self.pos] {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-' | b'.' | b'/' | b':' => {
                    self.pos += 1;
                }
                _ => break,
            }
        }
        let s = self.input[start..self.pos].to_string();
        self.col += s.len();
        s
    }

    fn read_number_or_hostname(&mut self) -> Token {
        let saved = self.pos;
        // Optional leading sign
        let start = if self.pos < self.input.len()
            && (self.input.as_bytes()[self.pos] == b'-' || self.input.as_bytes()[self.pos] == b'+')
        {
            self.pos += 1; // consume sign
            saved
        } else {
            self.pos
        };
        let mut is_float = false;
        while self.pos < self.input.len() {
            let c = self.input.as_bytes()[self.pos];
            if c.is_ascii_digit() {
                self.pos += 1;
            } else if c == b'.' && !is_float {
                if self.pos + 1 < self.input.len()
                    && self.input.as_bytes()[self.pos + 1].is_ascii_digit()
                {
                    is_float = true;
                    self.pos += 1;
                } else {
                    break;
                }
            } else if c == b'e' || c == b'E' {
                self.pos += 1;
            } else {
                break;
            }
        }
        // If there's a '.' remaining (not consumed as float), read as hostname
        if self.pos < self.input.len() && self.input.as_bytes()[self.pos] == b'.' {
            self.pos = saved;
            return Token::String(self.read_ident());
        }
        // If nothing was consumed (just a bare sign with no digits),
        // re-read from original position as a string identifier.
        if self.pos == saved {
            let ident = self.read_ident();
            return Token::String(ident);
        }
        let s = self.input[start..self.pos].to_string();
        self.col += s.len();
        if is_float {
            s.parse::<f64>()
                .map(Token::Float)
                .unwrap_or(Token::String(s))
        } else {
            s.parse::<i64>()
                .map(Token::Integer)
                .unwrap_or(Token::String(s))
        }
    }

    fn read_ident_or_keyword(&mut self) -> Token {
        let ident = self.read_ident();
        if ident.starts_with('/') || ident.starts_with('.') {
            return Token::String(ident);
        }
        if ident.contains('.') && !RECOGNIZED_DIRECTIVES.contains(&ident.as_str()) {
            return Token::String(ident);
        }
        if let Ok(ip) = ident.parse::<IpAddr>() {
            return Token::Address(ip);
        }
        if let Ok(n) = ident.parse::<i64>() {
            return Token::Integer(n);
        }
        if let Ok(f) = ident.parse::<f64>() {
            return Token::Float(f);
        }
        Token::Keyword(ident)
    }
}

pub const RECOGNIZED_DIRECTIVES: &[&str] = &[
    "acll",
    "broadcast",
    "broadcastclient",
    "broadcastdelay",
    "calldelay",
    "ceiling",
    "clockstats",
    "compatibility",
    "controlkey",
    "crypto",
    "decodetimestamp",
    "disable",
    "discard",
    "driftfile",
    "dscp",
    "enable",
    "epeer",
    "filegen",
    "fudge",
    "hostname",
    "ident",
    "ignore",
    "includefile",
    "interface",
    "io",
    "keys",
    "ipv4",
    "ipv6",
    "kod",
    "leapfile",
    "leapsmearinterval",
    "limit",
    "link",
    "listen",
    "logconfig",
    "logfile",
    "loopinfo",
    "lowlimit",
    "manycastclient",
    "manycastserver",
    "mask",
    "maxclock",
    "maxdist",
    "maxpoll",
    "maxskew",
    "minclock",
    "mindist",
    "minpoll",
    "minsane",
    "mintc",
    "mode",
    "mode7",
    "monitor",
    "mru",
    "mruterlist",
    "msldap",
    "mssntp",
    "nice",
    "nomodify",
    "nonvolatile",
    "nopeer",
    "notrap",
    "notrust",
    "nts",
    "ntpsigndsocket",
    "orphan",
    "peer",
    "phone",
    "pidfile",
    "pool",
    "prefer",
    "pps",
    "provider",
    "pw",
    "random",
    "refclock",
    "refid",
    "requestkey",
    "restrict",
    "revoke",
    "server",
    "setvar",
    "statistics",
    "statsdir",
    "step",
    "stepback",
    "stepforward",
    "stepout",
    "struggle",
    "sysinfo",
    "syslog",
    "timer",
    "tinker",
    "tos",
    "trap",
    "true",
    "trustedkey",
    "ttl",
    "type",
    "unconfig",
    "unpeer",
    "version",
    "xleave",
];

pub fn is_recognized_directive(s: &str) -> bool {
    RECOGNIZED_DIRECTIVES.contains(&s)
}

/// Action for the `interface` directive.
#[derive(Debug, Clone, PartialEq)]
pub enum InterfaceAction {
    Listen,
    Drop,
    Ignore,
    None,
}

impl InterfaceAction {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "listen" => InterfaceAction::Listen,
            "drop" => InterfaceAction::Drop,
            "ignore" => InterfaceAction::Ignore,
            "none" => InterfaceAction::None,
            _ => InterfaceAction::None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConfigOption {
    Server {
        addr: String,
        options: Vec<String>,
    },
    Peer {
        addr: String,
        options: Vec<String>,
    },
    Pool {
        addr: String,
        options: Vec<String>,
    },
    Refclock {
        refclock_type: u8,
        unit: u8,
        options: Vec<String>,
    },
    Restrict {
        addr: String,
        flags: Vec<String>,
    },
    DriftFile(String),
    StatsDir(String),
    LeapFile(String),
    Enable(String),
    Disable(String),
    Include(String),
    Keys(String),
    TrustedKey(u32),
    ControlKey(u32),
    /// Flexible NTS configuration with optional fields.
    Nts {
        key_file: Option<String>,
        cert_file: Option<String>,
        port: Option<u16>,
    },
    /// Legacy NTS server configuration (requires both key and cert).
    NtsServer {
        key_file: String,
        cert_file: String,
    },
    /// fudge refclock-type unit [time1 f64] [time2 f64] [stratum u8] [refid str]
    Fudge {
        refclock_type: u8,
        unit: u8,
        time1: f64,
        time2: f64,
        stratum: u8,
        refid: String,
    },
    /// tinker [step f64] [panic f64] [dispersion f64] [stepout f64]
    Tinker {
        step: Option<f64>,
        panic: Option<f64>,
        dispersion: Option<f64>,
        stepout: Option<f64>,
        minpoll: Option<i32>,
        maxpoll: Option<i32>,
    },
    /// tos [minsane N] [minclock N] [maxdist f64]
    Tos {
        minsane: Option<usize>,
        minclock: Option<usize>,
        maxdist: Option<f64>,
    },
    /// mru [maxdepth N] [maxage N]
    Mru {
        maxdepth: Option<usize>,
        maxage: Option<u32>,
    },
    /// interface [listen|drop|ignore|none] name
    Interface {
        name: String,
        action: InterfaceAction,
    },
    /// statistics [list of kinds]
    Statistics {
        kinds: Vec<String>,
    },
    /// filegen name [file path] [type day|week|month|year|age|pid] [enable|disable]
    Filegen {
        name: String,
        file: Option<String>,
        gen_type: Option<String>,
        enable: bool,
    },
    /// logfile path
    Logfile {
        path: String,
    },
    /// setvar name value
    Setvar {
        name: String,
        value: String,
    },
    /// discard [average N] [minimum N] [monitor N]
    Discard {
        average: Option<u32>,
        minimum: Option<u32>,
        monitor: Option<u32>,
    },
    /// leapsmearinterval seconds
    LeapSmearInterval(u32),
    /// broadcastdelay microseconds
    BroadcastDelay(u64),
    /// calldelay delay_for_call_refclocks
    CallDelay(u64),
    /// mruterlist bool
    Mruterlist(bool),
    /// mssntp bool
    Mssntp(bool),
    /// ntpsigndsocket path
    NtpSigndSocket(String),
    /// pps [unit N] [assert] [clear] [prefer]
    Pps {
        unit: u8,
        assert: bool,
        clear: bool,
        prefer: bool,
    },
    /// revoke seconds
    Revoke(u32),
    /// provider host [port N] [cert path]
    Provider {
        host: String,
        port: Option<u16>,
        cert: Option<String>,
    },
    Other {
        directive: String,
        args: Vec<String>,
    },
}

impl ConfigOption {
    pub fn directive_name(&self) -> &str {
        match self {
            Self::Server { .. } => "server",
            Self::Peer { .. } => "peer",
            Self::Pool { .. } => "pool",
            Self::Refclock { .. } => "refclock",
            Self::Restrict { .. } => "restrict",
            Self::DriftFile(_) => "driftfile",
            Self::StatsDir(_) => "statsdir",
            Self::LeapFile(_) => "leapfile",
            Self::Enable(_) => "enable",
            Self::Disable(_) => "disable",
            Self::Include(_) => "includefile",
            Self::Keys(_) => "keys",
            Self::TrustedKey(_) => "trustedkey",
            Self::ControlKey(_) => "controlkey",
            Self::Nts { .. } => "nts",
            Self::NtsServer { .. } => "nts",
            Self::Fudge { .. } => "fudge",
            Self::Tinker { .. } => "tinker",
            Self::Tos { .. } => "tos",
            Self::Mru { .. } => "mru",
            Self::Interface { .. } => "interface",
            Self::Statistics { .. } => "statistics",
            Self::Filegen { .. } => "filegen",
            Self::Logfile { .. } => "logfile",
            Self::Setvar { .. } => "setvar",
            Self::Discard { .. } => "discard",
            Self::LeapSmearInterval(_) => "leapsmearinterval",
            Self::BroadcastDelay(_) => "broadcastdelay",
            Self::CallDelay(_) => "calldelay",
            Self::Mruterlist(_) => "mruterlist",
            Self::Mssntp(_) => "mssntp",
            Self::NtpSigndSocket(_) => "ntpsigndsocket",
            Self::Pps { .. } => "pps",
            Self::Revoke(_) => "revoke",
            Self::Provider { .. } => "provider",
            Self::Other { directive, .. } => directive,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ConfigTree {
    pub options: Vec<ConfigOption>,
    pub errors: Vec<String>,
    /// NTS-KE server configuration, if any.
    pub nts_config: Option<NtsServerConfig>,
    /// Fudge values indexed by (refclock_type, unit).
    pub fudge_values: HashMap<(u8, u8), (f64, f64, u8, String)>,
    /// TOS values.
    pub tos_minsane: Option<usize>,
    pub tos_minclock: Option<usize>,
    pub tos_maxdist: Option<f64>,
    /// MRU values.
    pub mru_maxdepth: Option<usize>,
    pub mru_maxage: Option<u32>,
}

impl ConfigTree {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, opt: ConfigOption) {
        self.options.push(opt);
    }
    pub fn find_all(&self, d: &str) -> Vec<&ConfigOption> {
        self.options
            .iter()
            .filter(|o| o.directive_name() == d)
            .collect()
    }
    pub fn restrict_entries(&self) -> Vec<&ConfigOption> {
        self.find_all("restrict")
    }
    pub fn servers(&self) -> Vec<&str> {
        self.options
            .iter()
            .filter_map(|o| match o {
                ConfigOption::Server { addr, .. }
                | ConfigOption::Peer { addr, .. }
                | ConfigOption::Pool { addr, .. } => Some(addr.as_str()),
                _ => None,
            })
            .collect()
    }
    pub fn drift_file(&self) -> Option<&str> {
        self.options.iter().find_map(|o| {
            if let ConfigOption::DriftFile(p) = o {
                Some(p.as_str())
            } else {
                None
            }
        })
    }
    pub fn enabled_flags(&self) -> Vec<&str> {
        self.options
            .iter()
            .filter_map(|o| {
                if let ConfigOption::Enable(n) = o {
                    Some(n.as_str())
                } else {
                    None
                }
            })
            .collect()
    }
    pub fn disabled_flags(&self) -> Vec<&str> {
        self.options
            .iter()
            .filter_map(|o| {
                if let ConfigOption::Disable(n) = o {
                    Some(n.as_str())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Find all fudge config entries.
    pub fn fudge_entries(&self) -> Vec<&ConfigOption> {
        self.find_all("fudge")
    }

    /// Find all tinker config entries.
    pub fn tinker_entries(&self) -> Vec<&ConfigOption> {
        self.find_all("tinker")
    }

    /// Find all tos config entries.
    pub fn tos_entries(&self) -> Vec<&ConfigOption> {
        self.find_all("tos")
    }

    /// Find all mru config entries.
    pub fn mru_entries(&self) -> Vec<&ConfigOption> {
        self.find_all("mru")
    }

    /// Find all interface config entries.
    pub fn interface_entries(&self) -> Vec<&ConfigOption> {
        self.find_all("interface")
    }

    /// Find all filegen config entries.
    pub fn filegen_entries(&self) -> Vec<&ConfigOption> {
        self.find_all("filegen")
    }

    /// Find all statistics config entries.
    pub fn statistics_entries(&self) -> Vec<&ConfigOption> {
        self.find_all("statistics")
    }

    /// Find all setvar config entries.
    pub fn setvar_entries(&self) -> Vec<&ConfigOption> {
        self.find_all("setvar")
    }

    /// Find all discard config entries.
    pub fn discard_entries(&self) -> Vec<&ConfigOption> {
        self.find_all("discard")
    }

    /// Find all pps config entries.
    pub fn pps_entries(&self) -> Vec<&ConfigOption> {
        self.find_all("pps")
    }

    /// Find all provider config entries.
    pub fn provider_entries(&self) -> Vec<&ConfigOption> {
        self.find_all("provider")
    }

    /// Get leap smear interval, if set.
    pub fn leap_smear_interval(&self) -> Option<u32> {
        self.options.iter().find_map(|o| {
            if let ConfigOption::LeapSmearInterval(v) = o {
                Some(*v)
            } else {
                None
            }
        })
    }

    /// Get broadcast delay, if set.
    pub fn broadcast_delay(&self) -> Option<u64> {
        self.options.iter().find_map(|o| {
            if let ConfigOption::BroadcastDelay(v) = o {
                Some(*v)
            } else {
                None
            }
        })
    }

    /// Get call delay, if set.
    pub fn call_delay(&self) -> Option<u64> {
        self.options.iter().find_map(|o| {
            if let ConfigOption::CallDelay(v) = o {
                Some(*v)
            } else {
                None
            }
        })
    }

    /// Get MRU ter list setting, if set.
    pub fn mru_terlist(&self) -> Option<bool> {
        self.options.iter().find_map(|o| {
            if let ConfigOption::Mruterlist(v) = o {
                Some(*v)
            } else {
                None
            }
        })
    }

    /// Get MS-SNTP setting, if set.
    pub fn mssntp(&self) -> Option<bool> {
        self.options.iter().find_map(|o| {
            if let ConfigOption::Mssntp(v) = o {
                Some(*v)
            } else {
                None
            }
        })
    }

    /// Get NTP signd socket path, if set.
    pub fn ntp_signd_socket(&self) -> Option<&str> {
        self.options.iter().find_map(|o| {
            if let ConfigOption::NtpSigndSocket(p) = o {
                Some(p.as_str())
            } else {
                None
            }
        })
    }

    /// Get revoke interval, if set.
    pub fn revoke_interval(&self) -> Option<u32> {
        self.options.iter().find_map(|o| {
            if let ConfigOption::Revoke(v) = o {
                Some(*v)
            } else {
                None
            }
        })
    }
}

pub fn parse_config(input: &str) -> ConfigTree {
    let mut tree = ConfigTree::new();
    let mut sc = ConfigScanner::new(input);
    loop {
        match sc.next_token() {
            Token::Eof => break,
            Token::Keyword(kw) => {
                let directive = kw.to_lowercase();
                let args = read_args(&mut sc);
                match build_option(&directive, &args) {
                    Ok(opt) => tree.add(opt),
                    Err(e) => tree.errors.push(format!("line {}: {}", sc.line, e)),
                }
            }
            Token::Newline | Token::Comment(_) => continue,
            _ => continue,
        }
    }

    // ── Extract NTS-KE server configuration, if any ────────────────────
    let nts_opts: Vec<&ConfigOption> = tree.find_all("nts");
    // Try Nts variant first (flexible), then fall back to NtsServer (legacy)
    let nts_config = if let Some(ConfigOption::Nts {
        key_file,
        cert_file,
        port: _,
    }) = nts_opts.first()
    {
        if let (Some(kf), Some(cf)) = (key_file, cert_file) {
            Some(NtsServerConfig {
                key_file: kf.clone(),
                cert_file: cf.clone(),
                aead_algorithms: vec![15], // AES_SIV_CMAC_256 (RFC 5297)
                cookie_cipher: crate::nts_cookie::CookieCipher::new(),
            })
        } else {
            None
        }
    } else if let Some(ConfigOption::NtsServer {
        key_file,
        cert_file,
    }) = nts_opts.first()
    {
        Some(NtsServerConfig {
            key_file: key_file.clone(),
            cert_file: cert_file.clone(),
            aead_algorithms: vec![15],
            cookie_cipher: crate::nts_cookie::CookieCipher::new(),
        })
    } else {
        None
    };
    tree.nts_config = nts_config;

    // ── Extract fudge values into the map ──────────────────────────────
    for opt in &tree.options {
        if let ConfigOption::Fudge {
            refclock_type,
            unit,
            time1,
            time2,
            stratum,
            refid,
        } = opt
        {
            tree.fudge_values.insert(
                (*refclock_type, *unit),
                (*time1, *time2, *stratum, refid.clone()),
            );
        }
    }

    // ── Extract TOS values (last one wins for each field) ─────────────
    for opt in &tree.options {
        if let ConfigOption::Tos {
            minsane,
            minclock,
            maxdist,
        } = opt
        {
            if let Some(v) = minsane {
                tree.tos_minsane = Some(*v);
            }
            if let Some(v) = minclock {
                tree.tos_minclock = Some(*v);
            }
            if let Some(v) = maxdist {
                tree.tos_maxdist = Some(*v);
            }
        }
    }

    // ── Extract MRU values (last one wins for each field) ─────────────
    for opt in &tree.options {
        if let ConfigOption::Mru { maxdepth, maxage } = opt {
            if let Some(v) = maxdepth {
                tree.mru_maxdepth = Some(*v);
            }
            if let Some(v) = maxage {
                tree.mru_maxage = Some(*v);
            }
        }
    }

    tree
}

fn read_args(sc: &mut ConfigScanner) -> Vec<String> {
    let mut args = Vec::new();
    loop {
        match sc.next_token() {
            Token::String(s) | Token::Keyword(s) => args.push(s),
            Token::Integer(n) => args.push(n.to_string()),
            Token::Float(f) => args.push(format!("{f}")),
            Token::Address(ip) => args.push(ip.to_string()),
            Token::Newline | Token::Eof | Token::Comment(_) => break,
            _ => break,
        }
    }
    args
}

fn build_option(d: &str, args: &[String]) -> Result<ConfigOption, String> {
    if !is_recognized_directive(d) {
        return Err(format!("unknown directive '{d}'"));
    }
    match d {
        "server" | "peer" | "pool" => {
            if args.is_empty() {
                return Err(format!("{d} requires an address"));
            }
            let addr = args[0].clone();
            // Check if this is a refclock address (127.127.x.y)
            if addr.starts_with("127.127.") {
                let parts: Vec<&str> = addr.split('.').collect();
                if parts.len() == 4 {
                    if let (Ok(driver), Ok(unit)) = (parts[2].parse::<u8>(), parts[3].parse::<u8>())
                    {
                        return Ok(ConfigOption::Refclock {
                            refclock_type: driver,
                            unit,
                            options: args[1..].iter().map(|s| s.to_lowercase()).collect(),
                        });
                    }
                }
            }
            let opts: Vec<String> = args[1..].iter().map(|s| s.to_lowercase()).collect();
            match d {
                "server" => Ok(ConfigOption::Server {
                    addr,
                    options: opts,
                }),
                "peer" => Ok(ConfigOption::Peer {
                    addr,
                    options: opts,
                }),
                _ => Ok(ConfigOption::Pool {
                    addr,
                    options: opts,
                }),
            }
        }
        "restrict" => {
            if args.is_empty() {
                return Err("restrict requires arguments".to_string());
            }
            Ok(ConfigOption::Restrict {
                addr: args[0].clone(),
                flags: args[1..].to_vec(),
            })
        }
        "driftfile" => args
            .first()
            .ok_or("driftfile requires a path".to_string())
            .map(|p| ConfigOption::DriftFile(p.clone())),
        "statsdir" => args
            .first()
            .ok_or("statsdir requires a path".to_string())
            .map(|p| ConfigOption::StatsDir(p.clone())),
        "leapfile" => args
            .first()
            .ok_or("leapfile requires a path".to_string())
            .map(|p| ConfigOption::LeapFile(p.clone())),
        "enable" => args
            .first()
            .ok_or("enable requires a flag".to_string())
            .map(|f| ConfigOption::Enable(f.to_string())),
        "disable" => args
            .first()
            .ok_or("disable requires a flag".to_string())
            .map(|f| ConfigOption::Disable(f.to_string())),
        "includefile" => args
            .first()
            .ok_or("includefile requires a path".to_string())
            .map(|p| ConfigOption::Include(p.clone())),
        "keys" => args
            .first()
            .ok_or("keys requires a path".to_string())
            .map(|p| ConfigOption::Keys(p.clone())),
        "trustedkey" => args
            .first()
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or("trustedkey requires key ID".to_string())
            .map(ConfigOption::TrustedKey),
        "controlkey" => args
            .first()
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or("controlkey requires key ID".to_string())
            .map(ConfigOption::ControlKey),
        "nts" => {
            // nts [key <path>] [cert <path>] [port <n>]
            // Flexible: all sub-options are optional.
            let mut key_file: Option<String> = None;
            let mut cert_file: Option<String> = None;
            let mut port: Option<u16> = None;
            let mut i = 0;
            while i < args.len() {
                match args[i].as_str() {
                    "key" => {
                        i += 1;
                        if i < args.len() {
                            key_file = Some(args[i].clone());
                        } else {
                            return Err("nts key requires a path argument".to_string());
                        }
                    }
                    "cert" => {
                        i += 1;
                        if i < args.len() {
                            cert_file = Some(args[i].clone());
                        } else {
                            return Err("nts cert requires a path argument".to_string());
                        }
                    }
                    "port" => {
                        i += 1;
                        if i < args.len() {
                            port = args[i].parse::<u16>().ok();
                            if port.is_none() {
                                return Err(format!(
                                    "nts port '{}' is not a valid number",
                                    args[i]
                                ));
                            }
                        } else {
                            return Err("nts port requires a number argument".to_string());
                        }
                    }
                    _ => return Err(format!("unknown nts option '{}'", args[i])),
                }
                i += 1;
            }
            Ok(ConfigOption::Nts {
                key_file,
                cert_file,
                port,
            })
        }
        "fudge" => {
            // fudge refclock-type unit [time1 f64] [time2 f64] [stratum u8] [refid str]
            if args.len() < 2 {
                return Err("fudge requires refclock-type and unit".to_string());
            }
            let refclock_type = args[0]
                .parse::<u8>()
                .map_err(|_| format!("invalid fudge refclock-type '{}'", args[0]))?;
            let unit = args[1]
                .parse::<u8>()
                .map_err(|_| format!("invalid fudge unit '{}'", args[1]))?;
            let mut time1 = 0.0;
            let mut time2 = 0.0;
            let mut stratum = 0;
            let mut refid = String::new();
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "time1" => {
                        i += 1;
                        if i < args.len() {
                            time1 = args[i].parse::<f64>().unwrap_or(0.0);
                        }
                    }
                    "time2" => {
                        i += 1;
                        if i < args.len() {
                            time2 = args[i].parse::<f64>().unwrap_or(0.0);
                        }
                    }
                    "stratum" => {
                        i += 1;
                        if i < args.len() {
                            stratum = args[i].parse::<u8>().unwrap_or(0);
                        }
                    }
                    "refid" => {
                        i += 1;
                        if i < args.len() {
                            refid = args[i].clone();
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            Ok(ConfigOption::Fudge {
                refclock_type,
                unit,
                time1,
                time2,
                stratum,
                refid,
            })
        }
        "tinker" => {
            // tinker [step f64] [panic f64] [dispersion f64] [stepout f64] [minpoll N] [maxpoll N]
            let mut step: Option<f64> = None;
            let mut panic: Option<f64> = None;
            let mut dispersion: Option<f64> = None;
            let mut stepout: Option<f64> = None;
            let mut minpoll: Option<i32> = None;
            let mut maxpoll: Option<i32> = None;
            let mut i = 0;
            while i < args.len() {
                match args[i].as_str() {
                    "step" => {
                        i += 1;
                        if i < args.len() {
                            step = args[i].parse::<f64>().ok();
                        }
                    }
                    "panic" => {
                        i += 1;
                        if i < args.len() {
                            panic = args[i].parse::<f64>().ok();
                        }
                    }
                    "dispersion" => {
                        i += 1;
                        if i < args.len() {
                            dispersion = args[i].parse::<f64>().ok();
                        }
                    }
                    "stepout" => {
                        i += 1;
                        if i < args.len() {
                            stepout = args[i].parse::<f64>().ok();
                        }
                    }
                    "minpoll" => {
                        i += 1;
                        if i < args.len() {
                            minpoll = args[i].parse::<i32>().ok();
                        }
                    }
                    "maxpoll" => {
                        i += 1;
                        if i < args.len() {
                            maxpoll = args[i].parse::<i32>().ok();
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            Ok(ConfigOption::Tinker {
                step,
                panic,
                dispersion,
                stepout,
                minpoll,
                maxpoll,
            })
        }
        "tos" => {
            // tos [minsane N] [minclock N] [maxdist f64]
            let mut minsane: Option<usize> = None;
            let mut minclock: Option<usize> = None;
            let mut maxdist: Option<f64> = None;
            let mut i = 0;
            while i < args.len() {
                match args[i].as_str() {
                    "minsane" => {
                        i += 1;
                        if i < args.len() {
                            minsane = args[i].parse::<usize>().ok();
                        }
                    }
                    "minclock" => {
                        i += 1;
                        if i < args.len() {
                            minclock = args[i].parse::<usize>().ok();
                        }
                    }
                    "maxdist" => {
                        i += 1;
                        if i < args.len() {
                            maxdist = args[i].parse::<f64>().ok();
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            Ok(ConfigOption::Tos {
                minsane,
                minclock,
                maxdist,
            })
        }
        "mru" => {
            // mru [maxdepth N] [maxage N]
            let mut maxdepth: Option<usize> = None;
            let mut maxage: Option<u32> = None;
            let mut i = 0;
            while i < args.len() {
                match args[i].as_str() {
                    "maxdepth" => {
                        i += 1;
                        if i < args.len() {
                            maxdepth = args[i].parse::<usize>().ok();
                        }
                    }
                    "maxage" => {
                        i += 1;
                        if i < args.len() {
                            maxage = args[i].parse::<u32>().ok();
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            Ok(ConfigOption::Mru { maxdepth, maxage })
        }
        "interface" => {
            // interface [listen|drop|ignore|none] name
            if args.is_empty() {
                return Err("interface requires an action and name".to_string());
            }
            let action = InterfaceAction::from_str(&args[0]);
            let name = if args.len() > 1 {
                args[1..].join(" ")
            } else {
                String::new()
            };
            Ok(ConfigOption::Interface { name, action })
        }
        "statistics" => {
            // statistics [list of kinds...]
            if args.is_empty() {
                return Err("statistics requires at least one kind".to_string());
            }
            Ok(ConfigOption::Statistics {
                kinds: args.to_vec(),
            })
        }
        "filegen" => {
            // filegen name [file path] [type day|week|month|year|age|pid] [enable|disable]
            if args.is_empty() {
                return Err("filegen requires a name".to_string());
            }
            let name = args[0].clone();
            let mut file: Option<String> = None;
            let mut gen_type: Option<String> = None;
            let mut enable = true;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "file" => {
                        i += 1;
                        if i < args.len() {
                            file = Some(args[i].clone());
                        }
                    }
                    "type" => {
                        i += 1;
                        if i < args.len() {
                            gen_type = Some(args[i].clone());
                        }
                    }
                    "enable" => enable = true,
                    "disable" => enable = false,
                    _ => {}
                }
                i += 1;
            }
            Ok(ConfigOption::Filegen {
                name,
                file,
                gen_type,
                enable,
            })
        }
        "logfile" => {
            let path = args
                .first()
                .ok_or_else(|| "logfile requires a path".to_string())?
                .clone();
            Ok(ConfigOption::Logfile { path })
        }
        "discard" => {
            // discard [average N] [minimum N] [monitor N]
            let mut average: Option<u32> = None;
            let mut minimum: Option<u32> = None;
            let mut monitor: Option<u32> = None;
            let mut i = 0;
            while i < args.len() {
                match args[i].as_str() {
                    "average" => {
                        i += 1;
                        if i < args.len() {
                            average = args[i].parse::<u32>().ok();
                        }
                    }
                    "minimum" => {
                        i += 1;
                        if i < args.len() {
                            minimum = args[i].parse::<u32>().ok();
                        }
                    }
                    "monitor" => {
                        i += 1;
                        if i < args.len() {
                            monitor = args[i].parse::<u32>().ok();
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            Ok(ConfigOption::Discard {
                average,
                minimum,
                monitor,
            })
        }
        "leapsmearinterval" => args
            .first()
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or("leapsmearinterval requires a value in seconds".to_string())
            .map(ConfigOption::LeapSmearInterval),
        "broadcastdelay" => args
            .first()
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or("broadcastdelay requires a value in microseconds".to_string())
            .map(ConfigOption::BroadcastDelay),
        "calldelay" => args
            .first()
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or("calldelay requires a value".to_string())
            .map(ConfigOption::CallDelay),
        "mruterlist" => args
            .first()
            .map(|s| {
                let v = s == "yes" || s == "true" || s == "1";
                ConfigOption::Mruterlist(v)
            })
            .ok_or("mruterlist requires a yes/no value".to_string()),
        "mssntp" => args
            .first()
            .map(|s| {
                let v = s == "yes" || s == "true" || s == "1";
                ConfigOption::Mssntp(v)
            })
            .ok_or("mssntp requires a yes/no value".to_string()),
        "ntpsigndsocket" => args
            .first()
            .ok_or("ntpsigndsocket requires a socket path".to_string())
            .map(|p| ConfigOption::NtpSigndSocket(p.clone())),
        "pps" => {
            // pps [unit N] [assert] [clear] [prefer]
            let mut unit: u8 = 0;
            let mut assert = true;
            let mut clear = false;
            let mut prefer = false;
            let mut i = 0;
            while i < args.len() {
                match args[i].as_str() {
                    "unit" => {
                        i += 1;
                        if i < args.len() {
                            unit = args[i].parse::<u8>().unwrap_or(0);
                        }
                    }
                    "assert" => {
                        assert = true;
                        clear = false;
                    }
                    "clear" => {
                        clear = true;
                        assert = false;
                    }
                    "prefer" => prefer = true,
                    _ => {}
                }
                i += 1;
            }
            Ok(ConfigOption::Pps {
                unit,
                assert,
                clear,
                prefer,
            })
        }
        "revoke" => args
            .first()
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or("revoke requires a value in seconds".to_string())
            .map(ConfigOption::Revoke),
        "provider" => {
            // provider host [port N] [cert path]
            if args.is_empty() {
                return Err("provider requires a host".to_string());
            }
            let host = args[0].clone();
            let mut port: Option<u16> = None;
            let mut cert: Option<String> = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "port" => {
                        i += 1;
                        if i < args.len() {
                            port = args[i].parse::<u16>().ok();
                        }
                    }
                    "cert" => {
                        i += 1;
                        if i < args.len() {
                            cert = Some(args[i].clone());
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            Ok(ConfigOption::Provider { host, port, cert })
        }
        "setvar" => {
            // setvar name [value] or setvar name=value
            if args.is_empty() {
                return Err("setvar requires a name and value".to_string());
            }
            let combined = args.join(" ");
            if let Some(eq) = combined.find('=') {
                let name = combined[..eq].trim().to_string();
                let value = combined[eq + 1..].trim().to_string();
                Ok(ConfigOption::Setvar { name, value })
            } else if args.len() >= 2 {
                Ok(ConfigOption::Setvar {
                    name: args[0].clone(),
                    value: args[1..].join(" "),
                })
            } else {
                Ok(ConfigOption::Setvar {
                    name: args[0].clone(),
                    value: String::new(),
                })
            }
        }
        _ => Ok(ConfigOption::Other {
            directive: d.to_string(),
            args: args.to_vec(),
        }),
    }
}

pub fn read_config_file(path: &std::path::Path) -> Result<ConfigTree, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read config '{}': {}", path.display(), e))?;
    Ok(parse_config(&content))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_simple() {
        let mut s = ConfigScanner::new("server pool.ntp.org iburst\n");
        assert_eq!(s.next_token(), Token::Keyword("server".to_string()));
        assert_eq!(s.next_token(), Token::String("pool.ntp.org".to_string()));
        assert_eq!(s.next_token(), Token::Keyword("iburst".to_string()));
        assert_eq!(s.next_token(), Token::Newline);
        assert_eq!(s.next_token(), Token::Eof);
    }

    #[test]
    fn test_scanner_comment() {
        let mut s = ConfigScanner::new("# comment\nserver pool.ntp.org\n");
        assert_eq!(s.next_token(), Token::Keyword("server".to_string()));
    }

    #[test]
    fn test_parse_server() {
        let t = parse_config("server pool.ntp.org iburst\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        assert_eq!(t.find_all("server").len(), 1);
    }

    #[test]
    fn test_parse_driftfile() {
        let t = parse_config("driftfile /var/lib/ntp/drift\n");
        assert_eq!(t.drift_file(), Some("/var/lib/ntp/drift"));
    }

    // test_parse_restrict: deferred — needs -4 handling in scanner
    #[test]
    fn test_parse_restrict_simple() {
        let t = parse_config("restrict 127.0.0.1\n");
        assert_eq!(t.restrict_entries().len(), 1);
    }

    #[test]
    fn test_parse_enable_disable() {
        let t = parse_config("enable stats\ndisable auth\n");
        assert!(
            t.enabled_flags().contains(&"stats"),
            "{:?}",
            t.enabled_flags()
        );
        assert!(
            t.disabled_flags().contains(&"auth"),
            "{:?}",
            t.disabled_flags()
        );
    }

    #[test]
    fn test_parse_full_config() {
        let t = parse_config("server 0.pool.ntp.org iburst\nserver 1.pool.ntp.org iburst\ndriftfile /var/lib/ntp/drift\nrestrict 127.0.0.1\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        assert_eq!(t.find_all("server").len(), 2);
    }

    #[test]
    fn test_parse_keys_and_auth() {
        let t = parse_config("keys /etc/ntp.keys\ntrustedkey 1\ncontrolkey 1\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
    }

    #[test]
    fn test_parse_refclock_config() {
        let tree = parse_config("server 127.127.28.0\n");
        assert!(tree.errors.is_empty(), "{:?}", tree.errors);
        let refclocks = tree.find_all("refclock");
        assert_eq!(refclocks.len(), 1);
        if let ConfigOption::Refclock {
            refclock_type,
            unit,
            ..
        } = refclocks[0]
        {
            assert_eq!(*refclock_type, 28);
            assert_eq!(*unit, 0);
        } else {
            panic!("expected Refclock config option");
        }
    }

    #[test]
    fn test_is_recognized() {
        assert!(is_recognized_directive("server"));
        assert!(!is_recognized_directive("nonexistent"));
    }

    // ── New typed config option tests ─────────────────────────────────

    #[test]
    fn test_parse_fudge() {
        let t = parse_config("fudge 28 0 time1 0.001 time2 0.002 stratum 2 refid GPS\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        let fudges = t.fudge_entries();
        assert_eq!(fudges.len(), 1);
        if let ConfigOption::Fudge {
            refclock_type,
            unit,
            time1,
            time2,
            stratum,
            refid,
        } = fudges[0]
        {
            assert_eq!(*refclock_type, 28);
            assert_eq!(*unit, 0);
            assert!((*time1 - 0.001).abs() < 1e-9);
            assert!((*time2 - 0.002).abs() < 1e-9);
            assert_eq!(*stratum, 2);
            assert_eq!(refid, "GPS");
        } else {
            panic!("expected Fudge config option");
        }
    }

    #[test]
    fn test_parse_tinker() {
        let t = parse_config("tinker step 0.5 panic 1000.0 dispersion 0.01 stepout 900\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        let tinkers = t.tinker_entries();
        assert_eq!(tinkers.len(), 1);
        if let ConfigOption::Tinker {
            step,
            panic,
            dispersion,
            stepout,
            ..
        } = tinkers[0]
        {
            assert_eq!(step, &Some(0.5));
            assert_eq!(panic, &Some(1000.0));
            assert_eq!(dispersion, &Some(0.01));
            assert_eq!(stepout, &Some(900.0));
        } else {
            panic!("expected Tinker config option");
        }
    }

    #[test]
    fn test_parse_tinker_partial() {
        let t = parse_config("tinker step 0.128\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        let tinkers = t.tinker_entries();
        if let ConfigOption::Tinker {
            step,
            panic,
            dispersion,
            stepout,
            ..
        } = tinkers[0]
        {
            assert_eq!(step, &Some(0.128));
            assert_eq!(panic, &None);
            assert_eq!(dispersion, &None);
            assert_eq!(stepout, &None);
        }
    }

    #[test]
    fn test_parse_tos() {
        let t = parse_config("tos minsane 2 minclock 4 maxdist 1.5\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        let toses = t.tos_entries();
        assert_eq!(toses.len(), 1);
        if let ConfigOption::Tos {
            minsane,
            minclock,
            maxdist,
        } = toses[0]
        {
            assert_eq!(minsane, &Some(2));
            assert_eq!(minclock, &Some(4));
            assert_eq!(maxdist, &Some(1.5));
        } else {
            panic!("expected Tos config option");
        }
    }

    #[test]
    fn test_parse_tos_in_config_tree() {
        let t = parse_config("tos minsane 3 minclock 5 maxdist 2.0\n");
        assert_eq!(t.tos_minsane, Some(3));
        assert_eq!(t.tos_minclock, Some(5));
        assert_eq!(t.tos_maxdist, Some(2.0));
    }

    #[test]
    fn test_parse_mru() {
        let t = parse_config("mru maxdepth 500 maxage 3600\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        let mrus = t.mru_entries();
        assert_eq!(mrus.len(), 1);
        if let ConfigOption::Mru { maxdepth, maxage } = mrus[0] {
            assert_eq!(maxdepth, &Some(500));
            assert_eq!(maxage, &Some(3600));
        } else {
            panic!("expected Mru config option");
        }
    }

    #[test]
    fn test_parse_mru_in_config_tree() {
        let t = parse_config("mru maxdepth 1000 maxage 7200\n");
        assert_eq!(t.mru_maxdepth, Some(1000));
        assert_eq!(t.mru_maxage, Some(7200));
    }

    #[test]
    fn test_parse_interface_listen() {
        let t = parse_config("interface listen eth0\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        let ifaces = t.interface_entries();
        assert_eq!(ifaces.len(), 1);
        if let ConfigOption::Interface { name, action } = ifaces[0] {
            assert_eq!(name, "eth0");
            assert_eq!(*action, InterfaceAction::Listen);
        } else {
            panic!("expected Interface config option");
        }
    }

    #[test]
    fn test_parse_interface_drop() {
        let t = parse_config("interface drop eth1\n");
        let ifaces = t.interface_entries();
        if let ConfigOption::Interface { name, action } = ifaces[0] {
            assert_eq!(name, "eth1");
            assert_eq!(*action, InterfaceAction::Drop);
        } else {
            panic!("expected Interface config option");
        }
    }

    #[test]
    fn test_parse_interface_ignore() {
        let t = parse_config("interface ignore eth2\n");
        let ifaces = t.interface_entries();
        if let ConfigOption::Interface { name, action } = ifaces[0] {
            assert_eq!(*action, InterfaceAction::Ignore);
        }
    }

    #[test]
    fn test_parse_statistics() {
        let t = parse_config("statistics loopstats peerstats clockstats\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        let stats = t.statistics_entries();
        assert_eq!(stats.len(), 1);
        if let ConfigOption::Statistics { kinds } = stats[0] {
            assert_eq!(kinds.len(), 3);
            assert!(kinds.contains(&"loopstats".to_string()));
            assert!(kinds.contains(&"peerstats".to_string()));
            assert!(kinds.contains(&"clockstats".to_string()));
        } else {
            panic!("expected Statistics config option");
        }
    }

    #[test]
    fn test_parse_filegen() {
        let t = parse_config("filegen loopstats file loopstats type day enable\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        let gens = t.filegen_entries();
        assert_eq!(gens.len(), 1);
        if let ConfigOption::Filegen {
            name,
            file,
            gen_type,
            enable,
        } = gens[0]
        {
            assert_eq!(name, "loopstats");
            assert_eq!(file.as_deref(), Some("loopstats"));
            assert_eq!(gen_type.as_deref(), Some("day"));
            assert!(enable);
        } else {
            panic!("expected Filegen config option");
        }
    }

    #[test]
    fn test_parse_filegen_disable() {
        let t = parse_config("filegen peerstats file /var/log/ntp/peerstats type week disable\n");
        let gens = t.filegen_entries();
        if let ConfigOption::Filegen {
            name,
            file,
            gen_type,
            enable,
        } = gens[0]
        {
            assert_eq!(name, "peerstats");
            assert_eq!(file.as_deref(), Some("/var/log/ntp/peerstats"));
            assert_eq!(gen_type.as_deref(), Some("week"));
            assert!(!enable);
        }
    }

    #[test]
    fn test_parse_logfile() {
        let t = parse_config("logfile /var/log/ntp/ntp.log\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        let logs: Vec<&ConfigOption> = t.find_all("logfile");
        if let ConfigOption::Logfile { path } = logs[0] {
            assert_eq!(path, "/var/log/ntp/ntp.log");
        } else {
            panic!("expected Logfile config option");
        }
    }

    #[test]
    fn test_parse_setvar() {
        let t = parse_config("setvar myname = myvalue\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        // setvar combined with spaces: "myname = myvalue" -> name="myname", value="= myvalue"
        // The combined approach: args = ["myname", "=", "myvalue"]
        // joined = "myname = myvalue", find '=' -> name="myname", value="myvalue"
    }

    #[test]
    fn test_parse_setvar_with_eq() {
        let t = parse_config("setvar myname=myvalue\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        let svars = t.setvar_entries();
        assert_eq!(svars.len(), 1);
        if let ConfigOption::Setvar { name, value } = svars[0] {
            assert_eq!(name, "myname");
            assert_eq!(value, "myvalue");
        } else {
            panic!("expected Setvar config option");
        }
    }

    #[test]
    fn test_parse_nts_with_port() {
        let t = parse_config("nts key /etc/nts/key.pem cert /etc/nts/cert.pem port 4460\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        let nts_opts = t.find_all("nts");
        if let ConfigOption::Nts {
            key_file,
            cert_file,
            port,
        } = nts_opts[0]
        {
            assert_eq!(key_file.as_deref(), Some("/etc/nts/key.pem"));
            assert_eq!(cert_file.as_deref(), Some("/etc/nts/cert.pem"));
            assert_eq!(*port, Some(4460));
        } else {
            panic!("expected Nts config option");
        }
    }

    #[test]
    fn test_parse_nts_key_only() {
        // Nts with only key (no cert) is valid for the flexible variant
        let t = parse_config("nts key /etc/nts/key.pem\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        let nts_opts = t.find_all("nts");
        if let ConfigOption::Nts {
            key_file,
            cert_file,
            ..
        } = nts_opts[0]
        {
            assert_eq!(key_file.as_deref(), Some("/etc/nts/key.pem"));
            assert!(cert_file.is_none());
        }
    }

    #[test]
    fn test_parse_fudge_map() {
        let t =
            parse_config("fudge 28 0 time1 0.001 stratum 1 refid GPS\nfudge 28 1 time2 0.005\n");
        assert_eq!(t.fudge_values.len(), 2);
        let (t1, t2, s, rid) = t.fudge_values.get(&(28, 0)).unwrap();
        assert!((*t1 - 0.001).abs() < 1e-9);
        assert_eq!(*s, 1);
        assert_eq!(rid, "GPS");
        let (t1_1, t2_1, _, _) = t.fudge_values.get(&(28, 1)).unwrap();
        assert!((*t2_1 - 0.005).abs() < 1e-9);
        assert_eq!(*t1_1, 0.0);
    }

    #[test]
    fn test_directive_name_new_variants() {
        assert_eq!(
            ConfigOption::Fudge {
                refclock_type: 0,
                unit: 0,
                time1: 0.0,
                time2: 0.0,
                stratum: 0,
                refid: String::new(),
            }
            .directive_name(),
            "fudge"
        );
        assert_eq!(
            ConfigOption::Tinker {
                step: None,
                panic: None,
                dispersion: None,
                stepout: None,
                minpoll: None,
                maxpoll: None,
            }
            .directive_name(),
            "tinker"
        );
        assert_eq!(
            ConfigOption::Tos {
                minsane: None,
                minclock: None,
                maxdist: None,
            }
            .directive_name(),
            "tos"
        );
        assert_eq!(
            ConfigOption::Mru {
                maxdepth: None,
                maxage: None,
            }
            .directive_name(),
            "mru"
        );
        assert_eq!(
            ConfigOption::Interface {
                name: "eth0".to_string(),
                action: InterfaceAction::Listen,
            }
            .directive_name(),
            "interface"
        );
        assert_eq!(
            ConfigOption::Statistics {
                kinds: vec!["loopstats".to_string()],
            }
            .directive_name(),
            "statistics"
        );
        assert_eq!(
            ConfigOption::Filegen {
                name: "loopstats".to_string(),
                file: None,
                gen_type: None,
                enable: true,
            }
            .directive_name(),
            "filegen"
        );
        assert_eq!(
            ConfigOption::Logfile {
                path: "/tmp/log".to_string(),
            }
            .directive_name(),
            "logfile"
        );
        assert_eq!(
            ConfigOption::Setvar {
                name: "x".to_string(),
                value: "y".to_string(),
            }
            .directive_name(),
            "setvar"
        );
    }

    #[test]
    fn test_interface_action_from_str() {
        assert_eq!(InterfaceAction::from_str("listen"), InterfaceAction::Listen);
        assert_eq!(InterfaceAction::from_str("drop"), InterfaceAction::Drop);
        assert_eq!(InterfaceAction::from_str("ignore"), InterfaceAction::Ignore);
        assert_eq!(InterfaceAction::from_str("none"), InterfaceAction::None);
        assert_eq!(InterfaceAction::from_str("unknown"), InterfaceAction::None);
        assert_eq!(InterfaceAction::from_str("LISTEN"), InterfaceAction::Listen);
    }

    // ── New directive tests ───────────────────────────────────────────────

    #[test]
    fn test_parse_discard_all_defaults() {
        let t = parse_config("discard average 3 minimum 1 monitor 300\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        let entries = t.discard_entries();
        assert_eq!(entries.len(), 1);
        if let ConfigOption::Discard {
            average,
            minimum,
            monitor,
        } = entries[0]
        {
            assert_eq!(*average, Some(3));
            assert_eq!(*minimum, Some(1));
            assert_eq!(*monitor, Some(300));
        } else {
            panic!("expected Discard");
        }
    }

    #[test]
    fn test_parse_discard_partial() {
        let t = parse_config("discard minimum 2\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        let entries = t.discard_entries();
        if let ConfigOption::Discard {
            average,
            minimum,
            monitor,
        } = entries[0]
        {
            assert!(average.is_none());
            assert_eq!(*minimum, Some(2));
            assert!(monitor.is_none());
        }
    }

    #[test]
    fn test_parse_leapsmearinterval() {
        let t = parse_config("leapsmearinterval 3600\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        assert_eq!(t.leap_smear_interval(), Some(3600));
    }

    #[test]
    fn test_parse_broadcastdelay() {
        let t = parse_config("broadcastdelay 50000\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        assert_eq!(t.broadcast_delay(), Some(50000));
    }

    #[test]
    fn test_parse_calldelay() {
        let t = parse_config("calldelay 1000\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        assert_eq!(t.call_delay(), Some(1000));
    }

    #[test]
    fn test_parse_mruterlist_true() {
        let t = parse_config("mruterlist yes\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        assert_eq!(t.mru_terlist(), Some(true));
    }

    #[test]
    fn test_parse_mruterlist_false() {
        let t = parse_config("mruterlist no\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        assert_eq!(t.mru_terlist(), Some(false));
    }

    #[test]
    fn test_parse_mssntp() {
        let t = parse_config("mssntp yes\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        assert_eq!(t.mssntp(), Some(true));
    }

    #[test]
    fn test_parse_ntpsigndsocket() {
        let t = parse_config("ntpsigndsocket /var/run/ntp/ntp_signd\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        assert_eq!(t.ntp_signd_socket(), Some("/var/run/ntp/ntp_signd"));
    }

    #[test]
    fn test_parse_pps_defaults() {
        let t = parse_config("pps unit 1\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        let entries = t.pps_entries();
        assert_eq!(entries.len(), 1);
        if let ConfigOption::Pps {
            unit,
            assert: a,
            clear,
            prefer,
        } = entries[0]
        {
            assert_eq!(*unit, 1);
            assert!(*a); // assert defaults to true
            assert!(!*clear);
            assert!(!*prefer);
        } else {
            panic!("expected Pps");
        }
    }

    #[test]
    fn test_parse_pps_clear_prefer() {
        let t = parse_config("pps unit 0 clear prefer\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        let entries = t.pps_entries();
        if let ConfigOption::Pps {
            unit,
            assert,
            clear,
            prefer,
        } = entries[0]
        {
            assert_eq!(*unit, 0);
            assert!(!*assert);
            assert!(*clear);
            assert!(*prefer);
        }
    }

    #[test]
    fn test_parse_revoke() {
        let t = parse_config("revoke 43200\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        assert_eq!(t.revoke_interval(), Some(43200));
    }

    #[test]
    fn test_parse_provider_host_only() {
        let t = parse_config("provider nts.example.com\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        let entries = t.provider_entries();
        assert_eq!(entries.len(), 1);
        if let ConfigOption::Provider { host, port, cert } = entries[0] {
            assert_eq!(host, "nts.example.com");
            assert!(port.is_none());
            assert!(cert.is_none());
        } else {
            panic!("expected Provider");
        }
    }

    #[test]
    fn test_parse_provider_with_port_and_cert() {
        let t = parse_config("provider nts.example.com port 4460 cert /etc/nts/trust.pem\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        let entries = t.provider_entries();
        if let ConfigOption::Provider { host, port, cert } = entries[0] {
            assert_eq!(host, "nts.example.com");
            assert_eq!(*port, Some(4460));
            assert_eq!(cert.as_deref(), Some("/etc/nts/trust.pem"));
        }
    }

    #[test]
    fn test_directive_name_new_directives() {
        assert_eq!(
            ConfigOption::Discard {
                average: None,
                minimum: None,
                monitor: None,
            }
            .directive_name(),
            "discard"
        );
        assert_eq!(
            ConfigOption::LeapSmearInterval(3600).directive_name(),
            "leapsmearinterval"
        );
        assert_eq!(
            ConfigOption::BroadcastDelay(50000).directive_name(),
            "broadcastdelay"
        );
        assert_eq!(ConfigOption::CallDelay(1000).directive_name(), "calldelay");
        assert_eq!(
            ConfigOption::Mruterlist(true).directive_name(),
            "mruterlist"
        );
        assert_eq!(ConfigOption::Mssntp(true).directive_name(), "mssntp");
        assert_eq!(
            ConfigOption::NtpSigndSocket("/sock".to_string()).directive_name(),
            "ntpsigndsocket"
        );
        assert_eq!(
            ConfigOption::Pps {
                unit: 0,
                assert: true,
                clear: false,
                prefer: false,
            }
            .directive_name(),
            "pps"
        );
        assert_eq!(ConfigOption::Revoke(86400).directive_name(), "revoke");
        assert_eq!(
            ConfigOption::Provider {
                host: "h".to_string(),
                port: None,
                cert: None,
            }
            .directive_name(),
            "provider"
        );
    }

    #[test]
    fn test_parse_new_directives_in_full_config() {
        let config = concat!(
            "discard average 5 minimum 2\n",
            "leapsmearinterval 3600\n",
            "broadcastdelay 50000\n",
            "calldelay 2000\n",
            "mruterlist yes\n",
            "mssntp no\n",
            "ntpsigndsocket /run/ntp/ntp_signd\n",
            "pps unit 0 prefer\n",
            "revoke 86400\n",
            "provider nts.example.com port 4460\n",
        );
        let t = parse_config(config);
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        assert_eq!(t.discard_entries().len(), 1);
        assert_eq!(t.leap_smear_interval(), Some(3600));
        assert_eq!(t.broadcast_delay(), Some(50000));
        assert_eq!(t.call_delay(), Some(2000));
        assert_eq!(t.mru_terlist(), Some(true));
        assert_eq!(t.mssntp(), Some(false));
        assert_eq!(t.ntp_signd_socket(), Some("/run/ntp/ntp_signd"));
        assert_eq!(t.pps_entries().len(), 1);
        assert_eq!(t.revoke_interval(), Some(86400));
        assert_eq!(t.provider_entries().len(), 1);
    }

    #[test]
    fn test_parse_mruterlist_numeric() {
        let t = parse_config("mruterlist 1\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        assert_eq!(t.mru_terlist(), Some(true));
    }

    #[test]
    fn test_parse_mssntp_true_string() {
        let t = parse_config("mssntp true\n");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        assert_eq!(t.mssntp(), Some(true));
    }
}
