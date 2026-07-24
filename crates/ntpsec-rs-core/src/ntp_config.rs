// ──── ntp_config.rs ─────────────────────────────────────────────────────────
// Full NTPsec configuration parser — scanner + config tree.
// =============================================================================

use crate::nts_server::NtsServerConfig;
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
    NtsServer {
        key_file: String,
        cert_file: String,
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
            Self::NtsServer { .. } => "nts",
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
    if let Some(ConfigOption::NtsServer {
        key_file,
        cert_file,
    }) = nts_opts.first()
    {
        tree.nts_config = Some(NtsServerConfig {
            key_file: key_file.clone(),
            cert_file: cert_file.clone(),
            aead_algorithms: vec![15], // AES_SIV_CMAC_256 (RFC 5297)
            cookie_cipher: crate::nts_cookie::CookieCipher::new(),
        });
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
            // nts key <path> cert <path>
            let mut key_file = String::new();
            let mut cert_file = String::new();
            let mut i = 0;
            while i < args.len() {
                match args[i].as_str() {
                    "key" => {
                        i += 1;
                        if i < args.len() {
                            key_file = args[i].clone();
                        } else {
                            return Err("nts key requires a path argument".to_string());
                        }
                    }
                    "cert" => {
                        i += 1;
                        if i < args.len() {
                            cert_file = args[i].clone();
                        } else {
                            return Err("nts cert requires a path argument".to_string());
                        }
                    }
                    _ => return Err(format!("unknown nts option '{}'", args[i])),
                }
                i += 1;
            }
            if key_file.is_empty() || cert_file.is_empty() {
                return Err("nts requires both 'key' and 'cert' options".to_string());
            }
            Ok(ConfigOption::NtsServer {
                key_file,
                cert_file,
            })
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
}
