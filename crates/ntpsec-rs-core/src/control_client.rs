// ──── control_client.rs — Mode 6 NTP control client ─────────────────────
//
// Reusable Mode 6 client stack for ntpq-rs, ntpmon, ntptrace, and other
// tools.  Handles wire framing, fragmentation, retransmission, and
// response parsing.
//
// Three layers:
//   1. ControlClient — UDP send/recv with timeout, retries, fragment reassembly
//   2. Typed query model — SystemVariables, PeerVariables, AssociationStatus
//   3. Renderer — ntpq-compatible text output
//
// =============================================================================

use crate::ntp_control::*;
use crate::ntp_types::*;
use std::collections::{BTreeMap, HashMap};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

// ──── Errors ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum QueryError {
    Network(String),
    Timeout,
    BadResponse(String),
    ProtocolError(String),
    AuthFailure,
    NotFound,
    NotSupported(String),
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(s) => write!(f, "network: {s}"),
            Self::Timeout => write!(f, "timeout"),
            Self::BadResponse(s) => write!(f, "bad response: {s}"),
            Self::ProtocolError(s) => write!(f, "protocol: {s}"),
            Self::AuthFailure => write!(f, "authentication failure"),
            Self::NotFound => write!(f, "not found"),
            Self::NotSupported(s) => write!(f, "not supported: {s}"),
        }
    }
}

impl std::error::Error for QueryError {}

// ──── Fragment Collector ──────────────────────────────────────────────

/// Pure fragment reassembly engine.  Collects fragments and validates
/// that the assembled range is contiguous with no holes or overlaps.
#[derive(Debug, Clone)]
pub struct FragmentCollector {
    /// Fragments keyed by offset. BTreeMap guarantees sorted iteration.
    fragments: BTreeMap<u16, Vec<u8>>,
    /// The end offset of the final fragment (set when `more == false`).
    final_end: Option<u16>,
    /// Status word from the first fragment.
    pub status: Option<u16>,
    /// Association ID from the first fragment.
    pub associd: Option<u16>,
}

impl FragmentCollector {
    pub fn new() -> Self {
        Self {
            fragments: BTreeMap::new(),
            final_end: None,
            status: None,
            associd: None,
        }
    }

    /// Add a fragment. Returns Ok(true) if the collection is complete.
    /// Returns Err on length mismatch, overlaps, holes, or inconsistent metadata.
    pub fn add_fragment(
        &mut self,
        offset: u16,
        count: u16,
        data: &[u8],
        more: bool,
        status: u16,
        associd: u16,
    ) -> Result<bool, QueryError> {
        // Validate fragment data length matches declared count exactly
        if data.len() != count as usize {
            return Err(QueryError::BadResponse(format!(
                "fragment count {} != payload length {}",
                count,
                data.len()
            )));
        }
        let payload = data.to_vec();

        // Enforce metadata consistency across all fragments
        if let Some(existing_status) = self.status {
            if status != existing_status {
                return Err(QueryError::BadResponse(
                    "inconsistent status across fragments".to_string(),
                ));
            }
        } else {
            self.status = Some(status);
        }
        if let Some(existing_associd) = self.associd {
            if associd != existing_associd {
                return Err(QueryError::BadResponse(
                    "inconsistent associd across fragments".to_string(),
                ));
            }
        } else {
            self.associd = Some(associd);
        }

        // Check for overflow in offset + count
        let frag_end = match offset.checked_add(count) {
            Some(e) => e,
            None => {
                return Err(QueryError::BadResponse(
                    "fragment offset+count overflows u16".to_string(),
                ))
            }
        };
        for (&existing_offset, existing_data) in &self.fragments {
            let existing_end = match existing_offset.checked_add(existing_data.len() as u16) {
                Some(e) => e,
                None => {
                    return Err(QueryError::BadResponse(
                        "existing fragment overflows u16".to_string(),
                    ))
                }
            };
            if offset < existing_end && frag_end > existing_offset {
                let overlap_start = offset.max(existing_offset);
                let overlap_end = frag_end.min(existing_end);
                if overlap_end > overlap_start {
                    let existing_slice = &existing_data[(overlap_start - existing_offset) as usize
                        ..(overlap_end - existing_offset) as usize];
                    let new_slice = &payload
                        [(overlap_start - offset) as usize..(overlap_end - offset) as usize];
                    if existing_slice != new_slice {
                        return Err(QueryError::BadResponse(
                            "conflicting fragment data at offset".to_string(),
                        ));
                    }
                }
            }
        }

        // If final_end is known, reject fragments that extend past it
        if let Some(fe) = self.final_end {
            if frag_end > fe {
                return Err(QueryError::BadResponse(
                    "fragment extends beyond final response extent".to_string(),
                ));
            }
        }

        self.fragments.insert(offset, payload);

        // Track the final fragment extent
        if !more {
            let current_end = match offset.checked_add(count) {
                Some(e) => e,
                None => {
                    return Err(QueryError::BadResponse(
                        "final fragment offset+count overflows u16".to_string(),
                    ))
                }
            };
            match self.final_end {
                Some(existing) => {
                    if current_end != existing {
                        return Err(QueryError::BadResponse(
                            "inconsistent final fragment extent".to_string(),
                        ));
                    }
                }
                None => self.final_end = Some(current_end),
            }
        }

        Ok(self.is_complete())
    }

    /// Returns true if the collected fragments cover exactly `0..final_end`.
    pub fn is_complete(&self) -> bool {
        let final_end = match self.final_end {
            Some(e) => e,
            None => return false,
        };
        if final_end == 0 {
            return true;
        }
        let mut covered_end = 0u16;
        for (&offset, data) in &self.fragments {
            if offset > covered_end {
                return false;
            }
            let frag_end = match offset.checked_add(data.len() as u16) {
                Some(e) if e <= final_end => e,
                // Fragment extends past final_end (rejected by add_fragment, but defence-in-depth)
                _ => return false,
            };
            if frag_end > covered_end {
                covered_end = frag_end;
            }
        }
        covered_end == final_end
    }

    /// Assemble the collected fragments into a contiguous byte vector.
    pub fn assemble(&self) -> Result<Vec<u8>, QueryError> {
        if !self.is_complete() {
            return Err(QueryError::BadResponse(
                "incomplete fragment set".to_string(),
            ));
        }
        let final_end = self.final_end.unwrap_or(0) as usize;
        let mut result = vec![0u8; final_end];
        for (&offset, data) in &self.fragments {
            let start = offset as usize;
            let end = (start + data.len()).min(final_end);
            result[start..end].copy_from_slice(&data[..end - start]);
        }
        Ok(result)
    }

    /// Number of fragments collected.
    pub fn fragment_count(&self) -> usize {
        self.fragments.len()
    }
}

// ──── Association Status (from binary READSTAT) ───────────────────────

/// Parsed association record from READSTAT binary response.
#[derive(Debug, Clone)]
pub struct AssociationStatus {
    pub associd: u16,
    pub status: u16,
    pub configured: bool,
    pub auth_enabled: bool,
    pub auth_ok: bool,
    pub reachable: bool,
    pub broadcast: bool,
    pub selection: u8,
}

impl AssociationStatus {
    pub fn from_bytes(data: &[u8]) -> Result<Vec<Self>, QueryError> {
        if data.len() % 4 != 0 {
            return Err(QueryError::BadResponse(format!(
                "READSTAT data length {} not multiple of 4",
                data.len()
            )));
        }
        let mut assocs = Vec::with_capacity(data.len() / 4);
        for chunk in data.chunks(4) {
            let associd = u16::from_be_bytes([chunk[0], chunk[1]]);
            let status = u16::from_be_bytes([chunk[2], chunk[3]]);
            let high = (status >> 8) as u8;
            assocs.push(AssociationStatus {
                associd,
                status,
                configured: (high & 0x80) != 0,
                auth_enabled: (high & 0x40) != 0,
                auth_ok: (high & 0x20) != 0,
                reachable: (high & 0x10) != 0,
                broadcast: (high & 0x08) != 0,
                selection: high & 0x07,
            });
        }
        Ok(assocs)
    }

    pub fn tally_char(&self) -> char {
        match self.selection {
            7 => 'o', // PPS peer
            6 => '*', // system peer
            5 => '#', // backup
            4 => '+', // candidate
            3 => '-', // outlier
            2 => 'x', // excess
            1 => 'x', // falsetick
            _ => ' ', // rejected
        }
    }
}

// ──── Mode 6 Variable Text Parser ────────────────────────────────────

/// Parse Mode 6 key=value text with proper quote handling.
/// Splits on `,` outside quotes; strips surrounding quotes from values.
pub fn parse_mode6_vars(text: &str) -> Vec<(String, String)> {
    let mut vars = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;

    for ch in text.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            current.push(ch);
            escaped = true;
            continue;
        }
        if ch == '"' {
            current.push(ch);
            in_quotes = !in_quotes;
            continue;
        }
        if ch == ',' && !in_quotes {
            // End of a variable
            if let Some(eq) = current.find('=') {
                let key = current[..eq].trim().to_string();
                let mut raw_val = current[eq + 1..].trim().to_string();
                // Strip surrounding quotes
                if raw_val.len() >= 2 && raw_val.starts_with('"') && raw_val.ends_with('"') {
                    raw_val = raw_val[1..raw_val.len() - 1].to_string();
                }
                vars.push((key, raw_val));
            }
            current.clear();
            continue;
        }
        current.push(ch);
    }

    // Last variable (no trailing comma)
    if !current.is_empty() {
        if let Some(eq) = current.find('=') {
            let key = current[..eq].trim().to_string();
            let mut raw_val = current[eq + 1..].trim().to_string();
            if raw_val.len() >= 2 && raw_val.starts_with('"') && raw_val.ends_with('"') {
                raw_val = raw_val[1..raw_val.len() - 1].to_string();
            }
            vars.push((key, raw_val));
        }
    }

    vars
}

// ──── System Variables ────────────────────────────────────────────────

/// Typed system variables parsed from Mode 6 text response.
#[derive(Debug, Clone, Default)]
pub struct SystemVariables {
    pub ordered_vars: Vec<(String, String)>,
    pub vars: HashMap<String, String>,
    pub associd: u16,
    pub status: u16,
}

impl SystemVariables {
    pub fn from_text(data: &str, associd: u16, status: u16) -> Self {
        let ordered_vars = parse_mode6_vars(data);
        let vars: HashMap<String, String> = ordered_vars.iter().cloned().collect();
        Self {
            ordered_vars,
            vars,
            associd,
            status,
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.vars.get(key).map(|s| s.as_str())
    }

    pub fn stratum(&self) -> u8 {
        self.get("stratum")
            .and_then(|s| s.parse().ok())
            .unwrap_or(16)
    }

    pub fn leap_str(&self) -> &str {
        match self.get("leap") {
            Some("00") => "leap_none",
            Some("01") => "leap_add_sec",
            Some("10") => "leap_del_sec",
            Some("11") => "leap_alarm",
            _ => "leap_unknown",
        }
    }

    /// Status description matching ntpq output (e.g. "leap_none, sync_ntp").
    pub fn status_description(&self) -> String {
        let leap_desc = match self.get("leap") {
            Some("00") => "leap_none",
            Some("01") => "leap_add_sec",
            Some("10") => "leap_del_sec",
            Some("11") => "leap_alarm",
            _ => "leap_unknown",
        };
        let sync_desc = match self.get("sync") {
            Some("0") | Some("none") => "sync_unspec",
            Some("1") | Some("lcl") => "sync_lcl",
            Some("2") | Some("pps") => "sync_pps",
            Some("3") | Some("ntp") => "sync_ntp",
            _ => "sync_unspec",
        };
        format!("{leap_desc}, {sync_desc}")
    }
}

// ──── Peer Variables ──────────────────────────────────────────────────

/// Typed peer variables parsed from Mode 6 text response.
#[derive(Debug, Clone, Default)]
pub struct PeerVariables {
    pub ordered_vars: Vec<(String, String)>,
    pub vars: HashMap<String, String>,
    pub associd: u16,
    pub status: u16,
}

impl PeerVariables {
    pub fn from_text(data: &str, associd: u16, status: u16) -> Self {
        let ordered_vars = parse_mode6_vars(data);
        let vars: HashMap<String, String> = ordered_vars.iter().cloned().collect();
        Self {
            ordered_vars,
            vars,
            associd,
            status,
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.vars.get(key).map(|s| s.as_str())
    }

    pub fn stratum(&self) -> u8 {
        self.get("stratum")
            .and_then(|s| s.parse().ok())
            .unwrap_or(16)
    }
}

// ──── Control Client ──────────────────────────────────────────────────

/// Mode 6 control protocol client with connected UDP, DNS resolution,
/// fragment reassembly, and response validation.
pub struct ControlClient {
    sequence: u16,
    timeout: Duration,
    retries: u8,
}

impl ControlClient {
    pub fn new(timeout_secs: u32, retries: u8) -> Self {
        Self {
            sequence: 1,
            timeout: Duration::from_secs(timeout_secs as u64),
            retries,
        }
    }

    fn next_sequence(&mut self) -> u16 {
        // RFC 9327: distinct nonzero sequence numbers
        let seq = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);
        // Skip zero if wrap occurs
        if self.sequence == 0 {
            self.sequence = 1;
        }
        seq
    }

    /// Resolve hostname to a SocketAddr, trying IPv4 first, then IPv6.
    fn resolve(host: &str, port: u16) -> Result<SocketAddr, QueryError> {
        // First try parsing as a numeric IP
        if let Ok(addr) = format!("{host}:{port}").parse::<SocketAddr>() {
            return Ok(addr);
        }

        // Try DNS resolution
        let addrs: Vec<SocketAddr> = (host, port)
            .to_socket_addrs()
            .map_err(|e| QueryError::Network(format!("DNS resolution failed for '{host}': {e}")))?
            .collect();

        // Prefer IPv4, fall back to IPv6
        for addr in &addrs {
            if addr.is_ipv4() {
                return Ok(*addr);
            }
        }
        addrs
            .into_iter()
            .next()
            .ok_or_else(|| QueryError::Network(format!("no addresses found for '{host}'")))
    }

    /// Send a Mode 6 request using connected UDP and collect fragments.
    pub fn query(
        &mut self,
        host: &str,
        port: u16,
        msg: ControlMessage,
    ) -> Result<(Vec<u8>, u16, u16), QueryError> {
        let addr = Self::resolve(host, port)?;

        // Create and connect a UDP socket matching the address family
        let local = if addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket =
            UdpSocket::bind(local).map_err(|e| QueryError::Network(format!("bind: {e}")))?;
        socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| QueryError::Network(format!("set timeout: {e}")))?;
        socket
            .connect(addr)
            .map_err(|e| QueryError::Network(format!("connect: {e}")))?;

        let seq = self.next_sequence();
        let req = ControlMessage {
            li_vn_mode: NtpPacket::set_li_vn_mode(
                LeapIndicator::NoWarning,
                NtpVersion::V4,
                NtpMode::NtpControl,
            ),
            opcode: msg.opcode,
            sequence: seq,
            status: 0,
            associd: msg.associd,
            offset: 0,
            count: 0,
        };

        let request_bytes = req.encode();
        let expected_op = ControlOpcode::from_u8(msg.opcode).op;

        for attempt in 0..=self.retries {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(500));
            }

            socket
                .send(&request_bytes)
                .map_err(|e| QueryError::Network(format!("send: {e}")))?;

            // Collect fragments using the pure collector
            let mut collector = FragmentCollector::new();

            loop {
                let mut buf = vec![0u8; 512];
                match socket.recv(&mut buf) {
                    Ok(n) => {
                        let raw = &buf[..n];
                        let (resp, after_header) = ControlMessage::decode(raw)
                            .ok_or_else(|| QueryError::BadResponse("short header".to_string()))?;

                        // === Response validation ===
                        // 1. Sequence must match
                        if resp.sequence != seq {
                            continue;
                        }
                        let oc = resp.decode_opcode();
                        // 2. Must be a response
                        if !oc.response {
                            continue;
                        }
                        // 3. Source validated by connected socket
                        // 4. Opcode must match request
                        if oc.op != expected_op {
                            continue;
                        }
                        // 5. Association ID must match (can be 0 for system)
                        if resp.associd != msg.associd {
                            continue;
                        }
                        // 6. Mode must be Mode 6 (NtpControl)
                        if resp.mode() != NtpMode::NtpControl {
                            continue;
                        }

                        // Handle error responses (RFC 9327 §5.6)
                        // 1=Auth, 2=Format, 3=Opcode, 4=NotFound, 5=NotKnown, 6=BadValue, 7=Admin
                        if oc.error {
                            let err_code = (resp.status >> 8) as u8;
                            return match err_code {
                                1 => Err(QueryError::AuthFailure),
                                2 => Err(QueryError::ProtocolError(
                                    "invalid message format".to_string(),
                                )),
                                3 => Err(QueryError::NotSupported("invalid opcode".to_string())),
                                4 => Err(QueryError::NotFound),
                                5 => Err(QueryError::NotSupported("unknown variable".to_string())),
                                6 => Err(QueryError::ProtocolError(
                                    "invalid variable value".to_string(),
                                )),
                                7 => Err(QueryError::ProtocolError(
                                    "administratively prohibited".to_string(),
                                )),
                                _ => Err(QueryError::ProtocolError(format!("error {err_code}"))),
                            };
                        }

                        // Add fragment to collector (uses offset/count from the header,
                        // but the bytes start at 0 in after_header since each fragment
                        // is self-contained)
                        let count = resp.count as usize;
                        let data = if count <= after_header.len() {
                            after_header[..count].to_vec()
                        } else {
                            return Err(QueryError::BadResponse(
                                "fragment count exceeds datagram".to_string(),
                            ));
                        };

                        let complete = collector.add_fragment(
                            resp.offset,
                            resp.count,
                            &data,
                            oc.more,
                            resp.status,
                            resp.associd,
                        )?;

                        if complete {
                            let assembled = collector.assemble()?;
                            return Ok((
                                assembled,
                                collector.status.unwrap_or(0),
                                collector.associd.unwrap_or(0),
                            ));
                        }
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut
                        {
                            if attempt < self.retries && collector.fragment_count() == 0 {
                                break; // Retry from scratch
                            }
                            if collector.fragment_count() > 0 {
                                // Partial collection with timeout = incomplete
                                return Err(QueryError::BadResponse(
                                    "incomplete fragment collection".to_string(),
                                ));
                            }
                            return Err(QueryError::Timeout);
                        }
                        return Err(QueryError::Network(e.to_string()));
                    }
                }
            }
        }

        Err(QueryError::Timeout)
    }

    /// Read system variables (ntpq -c rv).
    pub fn read_system_vars(
        &mut self,
        host: &str,
        port: u16,
    ) -> Result<SystemVariables, QueryError> {
        let msg = ControlMessage {
            li_vn_mode: 0,
            opcode: ControlOpcode::new(false, false, false, opcodes::OP_READVAR).to_u8(),
            sequence: 0,
            status: 0,
            associd: 0,
            offset: 0,
            count: 0,
        };
        let (data, status, associd) = self.query(host, port, msg)?;
        let text = String::from_utf8_lossy(&data).to_string();
        Ok(SystemVariables::from_text(&text, associd, status))
    }

    /// Read peer variables for a specific association.
    pub fn read_peer_vars(
        &mut self,
        host: &str,
        port: u16,
        associd: u16,
    ) -> Result<PeerVariables, QueryError> {
        let msg = ControlMessage {
            li_vn_mode: 0,
            opcode: ControlOpcode::new(false, false, false, opcodes::OP_READVAR).to_u8(),
            sequence: 0,
            status: 0,
            associd,
            offset: 0,
            count: 0,
        };
        let (data, status, _) = self.query(host, port, msg)?;
        let text = String::from_utf8_lossy(&data).to_string();
        Ok(PeerVariables::from_text(&text, associd, status))
    }

    /// Read associations (ntpq -c as).
    pub fn read_associations(
        &mut self,
        host: &str,
        port: u16,
    ) -> Result<Vec<AssociationStatus>, QueryError> {
        let msg = ControlMessage {
            li_vn_mode: 0,
            opcode: ControlOpcode::new(false, false, false, opcodes::OP_READSTAT).to_u8(),
            sequence: 0,
            status: 0,
            associd: 0,
            offset: 0,
            count: 0,
        };
        let (data, _status, _associd) = self.query(host, port, msg)?;
        AssociationStatus::from_bytes(&data)
    }
}

// ──── Peer Row Model ──────────────────────────────────────────────────

/// A single peer row for the peers billboard.
#[derive(Debug, Clone)]
pub struct PeerRow {
    pub tally: char,
    pub remote: String,
    pub refid: String,
    pub associd: u16,
    pub stratum: u8,
    pub peer_type: char,
    pub when: Option<u64>,
    pub poll: u64,
    pub reach: u8,
    pub delay: f64,
    pub offset: f64,
    pub jitter: f64,
}

impl PeerRow {
    pub fn from_association(pv: &PeerVariables, assoc: &AssociationStatus) -> Self {
        let tally = assoc.tally_char();
        let remote = pv.get("srcaddr").unwrap_or("unknown").to_string();
        let refid = pv.get("refid").unwrap_or("").to_string();
        let stratum = pv.stratum();
        let delay = pv.get("delay").and_then(|s| s.parse().ok()).unwrap_or(0.0);
        let offset = pv.get("offset").and_then(|s| s.parse().ok()).unwrap_or(0.0);
        let jitter = pv.get("jitter").and_then(|s| s.parse().ok()).unwrap_or(0.0);
        let poll = pv
            .get("hpoll")
            .and_then(|s| s.parse::<f64>().ok())
            .map(|p| 1u64 << p as u64)
            .unwrap_or(64);
        let reach = pv
            .get("reach")
            .and_then(|s| u8::from_str_radix(s, 16).ok())
            .unwrap_or(0);
        // Derive `when` from the `recv` variable (seconds since last packet)
        // ntpq computes this client-side from the last receive time in the peer variables.
        let when = pv.get("recv").and_then(|s| s.parse::<u64>().ok());

        Self {
            tally,
            remote,
            refid,
            associd: assoc.associd,
            stratum,
            peer_type: if assoc.broadcast { 'b' } else { 'u' },
            when,
            poll,
            reach,
            delay,
            offset,
            jitter,
        }
    }
}

// ──── Renderers ───────────────────────────────────────────────────────

/// Render system variables in ntpq-compatible format.
pub fn format_readvar(sys: &SystemVariables) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "associd={} status={:04x} {},\n",
        sys.associd,
        sys.status,
        sys.status_description(),
    ));
    // Render preferred system keys first, then any remaining variables from ordered_vars
    let preferred_order = [
        "version",
        "processor",
        "system",
        "leap",
        "stratum",
        "precision",
        "rootdelay",
        "rootdisp",
        "refid",
        "reftime",
        "peer",
        "tc",
        "offset",
        "frequency",
        "sys_jitter",
        "rootdist",
    ];
    let mut rendered = std::collections::HashSet::new();
    for key in &preferred_order {
        if let Some(val) = sys.get(key) {
            let quoted = matches!(*key, "version" | "processor" | "system" | "refid");
            if quoted {
                out.push_str(&format!("{}=\"{}\", ", key, val));
            } else {
                out.push_str(&format!("{}={}, ", key, val));
            }
            rendered.insert(key.to_string());
        }
    }
    // Emit remaining variables in order received (preserving server's grouping)
    for (key, val) in &sys.ordered_vars {
        if !rendered.contains(key) {
            out.push_str(&format!("{}={}, ", key, val));
            rendered.insert(key.clone());
        }
    }
    out.push('\n');
    out
}

/// Render peer READVAR variables in ntpq-compatible format.
pub fn format_peer_readvar(peer: &PeerVariables) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "associd={} status={:04x} 1 event, {},\n",
        peer.associd,
        peer.status,
        peer.get("srcaddr").unwrap_or("unknown"),
    ));
    let preferred = [
        "srcaddr",
        "stratum",
        "offset",
        "delay",
        "dispersion",
        "jitter",
        "hpoll",
        "ppoll",
        "reach",
        "flash",
        "leap",
        "refid",
        "reftime",
        "hmode",
        "pmode",
        "precision",
    ];
    let mut rendered = std::collections::HashSet::new();
    for key in &preferred {
        if let Some(val) = peer.get(key) {
            out.push_str(&format!("{}={}, ", key, val));
            rendered.insert(key.to_string());
        }
    }
    for (key, val) in &peer.ordered_vars {
        if !rendered.contains(key) {
            out.push_str(&format!("{}={}, ", key, val));
            rendered.insert(key.clone());
        }
    }
    out.push('\n');
    out
}

/// Render associations table in ntpq-compatible format.
pub fn format_associations(assocs: &[AssociationStatus]) -> String {
    let mut out = String::new();
    out.push_str("ind assid status  conf reach auth condition  last_event cnt\n");
    out.push_str("===========================================================\n");
    for (i, assoc) in assocs.iter().enumerate() {
        let conf = if assoc.configured { "yes" } else { "no" };
        let reach = if assoc.reachable { "yes" } else { "no" };
        let auth = if assoc.auth_ok {
            "ok"
        } else if assoc.auth_enabled {
            "yes"
        } else {
            "none"
        };
        let cond = match assoc.selection {
            6 => "sys.peer",
            5 => "backup",
            4 => "candidate",
            3 => "outlyer",
            2 => "excess",
            1 => "falsetick",
            _ => "rejected",
        };
        out.push_str(&format!(
            "  {} {:5} {:04x}   {:3}  {:4}  {:4}  {:11}\n",
            i + 1,
            assoc.associd,
            assoc.status,
            conf,
            reach,
            auth,
            cond,
        ));
    }
    out
}

/// Render peers billboard in ntpq-compatible format.
pub fn format_peers(rows: &[PeerRow]) -> String {
    let mut out = String::new();
    out.push_str(
        "     remote           refid      st t when poll reach   delay   offset  jitter\n",
    );
    out.push_str(
        "==============================================================================\n",
    );
    for row in rows {
        let when_str = match row.when {
            Some(s) if s < 1000 => format!("{}", s),
            Some(s) if s < 3600 => format!("{}m", s / 60),
            Some(s) => format!("{}h", s / 3600),
            None => "-".to_string(),
        };
        let reach_str = format!("{:o}", row.reach); // Octal display
        out.push_str(&format!(
            " {}{:16} {:12} {:2} {} {:>4} {:>4} {:>5} {:>7.3} {:>8.3} {:>7.3}\n",
            row.tally,
            row.remote,
            row.refid,
            row.stratum,
            row.peer_type,
            when_str,
            row.poll,
            reach_str,
            row.delay,
            row.offset,
            row.jitter,
        ));
    }
    out
}

// ──── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ──── Fragment Collector Courts ───────────────────────────────────

    #[test]
    fn test_fragment_single() {
        let mut fc = FragmentCollector::new();
        let done = fc
            .add_fragment(0, 10, b"0123456789", false, 0x0622, 0)
            .unwrap();
        assert!(done);
        let assembled = fc.assemble().unwrap();
        assert_eq!(assembled, b"0123456789");
    }

    #[test]
    fn test_fragment_two_parts_in_order() {
        let mut fc = FragmentCollector::new();
        let done = fc.add_fragment(0, 5, b"01234", true, 0x0622, 0).unwrap();
        assert!(!done);
        let done = fc.add_fragment(5, 5, b"56789", false, 0x0622, 0).unwrap();
        assert!(done);
        let assembled = fc.assemble().unwrap();
        assert_eq!(assembled, b"0123456789");
    }

    #[test]
    fn test_fragment_out_of_order() {
        let mut fc = FragmentCollector::new();
        let _ = fc.add_fragment(5, 5, b"56789", false, 0x0622, 0).unwrap();
        assert!(!fc.is_complete());
        let _ = fc.add_fragment(0, 5, b"01234", true, 0x0622, 0).unwrap();
        assert!(fc.is_complete());
        let assembled = fc.assemble().unwrap();
        assert_eq!(assembled, b"0123456789");
    }

    #[test]
    fn test_fragment_hole_detected() {
        let mut fc = FragmentCollector::new();
        let _ = fc.add_fragment(0, 5, b"01234", true, 0x0622, 0).unwrap();
        let _ = fc.add_fragment(10, 5, b"56789", false, 0x0622, 0).unwrap();
        assert!(!fc.is_complete()); // Hole at 5-10
    }

    #[test]
    fn test_fragment_overlap_consistent() {
        let mut fc = FragmentCollector::new();
        let _ = fc.add_fragment(0, 6, b"012345", true, 0x0622, 0).unwrap();
        // Overlapping consistent data
        let r = fc.add_fragment(3, 6, b"345678", false, 0x0622, 0);
        assert!(r.is_ok());
        assert!(fc.is_complete());
    }

    #[test]
    fn test_fragment_overlap_conflict() {
        let mut fc = FragmentCollector::new();
        let _ = fc.add_fragment(0, 5, b"01234", true, 0x0622, 0).unwrap();
        // Overlapping INCONSISTENT data
        let r = fc.add_fragment(2, 5, b"XXXXX", false, 0x0622, 0);
        assert!(r.is_err());
    }

    #[test]
    fn test_fragment_inconsistent_final_end() {
        let mut fc = FragmentCollector::new();
        // First fragment claims more=false at extent 5
        let _ = fc.add_fragment(0, 5, b"01234", false, 0x0622, 0).unwrap();
        // Second fragment also claims more=false but at extent 15 — INCONSISTENT
        let r = fc.add_fragment(5, 10, b"5678901234", false, 0x0622, 0);
        assert!(r.is_err());
    }

    #[test]
    fn test_fragment_empty_response() {
        let mut fc = FragmentCollector::new();
        let done = fc.add_fragment(0, 0, b"", false, 0x0622, 0).unwrap();
        assert!(done);
        let assembled = fc.assemble().unwrap();
        assert!(assembled.is_empty());
    }

    #[test]
    fn test_fragment_three_parts() {
        let mut fc = FragmentCollector::new();
        let _ = fc.add_fragment(0, 3, b"012", true, 0x0622, 0).unwrap();
        let _ = fc.add_fragment(3, 3, b"345", true, 0x0622, 0).unwrap();
        let done = fc.add_fragment(6, 4, b"6789", false, 0x0622, 0).unwrap();
        assert!(done);
        assert_eq!(fc.assemble().unwrap(), b"0123456789");
    }

    #[test]
    fn test_fragment_excess_past_final_rejected() {
        let mut fc = FragmentCollector::new();
        // First fragment more=false at extent 5 → final_end=5
        let _ = fc.add_fragment(0, 5, b"01234", false, 0x0622, 0).unwrap();
        // Non-final fragment at 5..10 extends past final_end=5
        let r = fc.add_fragment(5, 5, b"56789", true, 0x0622, 0);
        assert!(r.is_err());
    }

    #[test]
    fn test_fragment_overflow_rejected() {
        let mut fc = FragmentCollector::new();
        // offset=65535, count=10 would overflow u16
        let r = fc.add_fragment(u16::MAX, 10, b"0123456789", false, 0x0622, 0);
        assert!(r.is_err());
    }

    // ──── Association Status Courts ───────────────────────────────────

    #[test]
    fn test_readstat_bytes_parsing() {
        let data = vec![
            0x00, 0x01, 0x96,
            0x14, // associd=1, status=0x9614 (configured|reachable|sys.peer)
            0x00, 0x02, 0x80, 0x10, // associd=2, status=0x8010 (configured|reachable)
        ];
        let assocs = AssociationStatus::from_bytes(&data).unwrap();
        assert_eq!(assocs.len(), 2);
        assert_eq!(assocs[0].associd, 1);
        assert!(assocs[0].configured);
        assert!(assocs[0].reachable);
        assert_eq!(assocs[0].selection, 6);
        assert_eq!(assocs[0].tally_char(), '*');
        assert_eq!(assocs[1].selection, 0);
        assert_eq!(assocs[1].tally_char(), ' ');
    }

    #[test]
    fn test_wrong_length_rejected() {
        assert!(AssociationStatus::from_bytes(&[0u8; 5]).is_err());
    }

    // ──── Variable Parser Courts ──────────────────────────────────────

    #[test]
    fn test_parse_mode6_vars_simple() {
        let vars = parse_mode6_vars("stratum=2,offset=0.005,leap=00");
        assert_eq!(vars.len(), 3);
        assert_eq!(vars[0], ("stratum".to_string(), "2".to_string()));
        assert_eq!(vars[1], ("offset".to_string(), "0.005".to_string()));
    }

    #[test]
    fn test_parse_mode6_vars_quoted() {
        let vars = parse_mode6_vars(r#"version="ntpd 4.2.8",stratum=2"#);
        assert_eq!(vars.len(), 2);
        assert_eq!(vars[0].0, "version");
        // Quotes should be stripped
        assert_eq!(vars[0].1, "ntpd 4.2.8");
        assert_eq!(vars[1], ("stratum".to_string(), "2".to_string()));
    }

    #[test]
    fn test_parse_mode6_vars_quoted_comma() {
        let vars = parse_mode6_vars(r#"name="a,b",value=42"#);
        assert_eq!(vars.len(), 2);
        assert_eq!(vars[0].1, "a,b"); // Comma inside quotes preserved
        assert_eq!(vars[1], ("value".to_string(), "42".to_string()));
    }

    // ──── System Variables Courts ─────────────────────────────────────

    #[test]
    fn test_system_variables_parsing() {
        let text = r#"version="ntpd 4.2.8",stratum=2,offset=0.005,leap=00"#;
        let sv = SystemVariables::from_text(text, 0, 0x0622);
        assert_eq!(sv.get("version"), Some("ntpd 4.2.8"));
        assert_eq!(sv.get("stratum"), Some("2"));
        assert_eq!(sv.stratum(), 2);
        assert_eq!(sv.leap_str(), "leap_none");
    }

    // ──── Renderer Courts ─────────────────────────────────────────────

    #[test]
    fn test_associations_format() {
        let assocs = vec![AssociationStatus {
            associd: 49723,
            status: 0x9614,
            configured: true,
            auth_enabled: true,
            auth_ok: false,
            reachable: true,
            broadcast: false,
            selection: 6,
        }];
        let out = format_associations(&assocs);
        assert!(out.contains("49723"));
        assert!(out.contains("sys.peer"));
        assert!(out.contains("yes"));
    }

    #[test]
    fn test_peers_format_header() {
        let rows = vec![PeerRow {
            tally: '*',
            remote: "127.0.0.1".to_string(),
            refid: ".LOCL.".to_string(),
            associd: 1,
            stratum: 1,
            peer_type: 'u',
            when: None,
            poll: 64,
            reach: 0o17,
            delay: 0.0,
            offset: 0.0,
            jitter: 0.001,
        }];
        let out = format_peers(&rows);
        assert!(out.contains("127.0.0.1"));
        assert!(out.contains("*127.0.0.1"), "tally should prefix remote");
        assert!(out.contains(".LOCL."));
    }

    #[test]
    fn test_readvar_format() {
        let text = r#"version="ntpd 4.2.8",stratum=2,offset=0.005"#;
        let sv = SystemVariables::from_text(text, 0, 0x0622);
        let out = format_readvar(&sv);
        assert!(out.contains("associd=0"));
        assert!(out.contains("leap_none, sync_unspec"));
        assert!(out.contains("stratum=2"));
    }

    #[test]
    fn test_readvar_contains_all_vars() {
        // Verify that format_readvar includes variables beyond the preferred list
        let text = "version=ntpd,stratum=2,offset=0.005,leap=00,extra_var=42";
        let sv = SystemVariables::from_text(text, 0, 0x0622);
        let out = format_readvar(&sv);
        assert!(out.contains("extra_var=42"), "extra vars must be included");
    }
}
