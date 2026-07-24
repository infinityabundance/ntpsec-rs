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

        // Prevent shrinking an existing same-offset fragment
        if self.fragments.contains_key(&offset) {
            let existing_len = self.fragments.get(&offset).map(|d| d.len()).unwrap_or(0);
            if payload.len() < existing_len {
                return Err(QueryError::BadResponse(
                    "retrograde fragment would shrink existing data".to_string(),
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
            // When establishing final_end, validate ALL existing fragments fit within
            match self.final_end {
                Some(existing) => {
                    if current_end != existing {
                        return Err(QueryError::BadResponse(
                            "inconsistent final fragment extent".to_string(),
                        ));
                    }
                }
                None => {
                    // New final_end: verify no existing fragment extends past it
                    for (&eo, ed) in &self.fragments {
                        let ee = eo.checked_add(ed.len() as u16).ok_or_else(|| {
                            QueryError::BadResponse("existing fragment overflows".to_string())
                        })?;
                        if ee > current_end {
                            return Err(QueryError::BadResponse(
                                "existing fragment exceeds newly declared final extent".to_string(),
                            ));
                        }
                    }
                    self.final_end = Some(current_end);
                }
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
    /// Status word used for the display description.
    ///
    /// Real C ntpq issues a separate status-summary request (count=0)
    /// whose response status word is used for the textual description
    /// (leap/source/event), while the full READVAR response's status
    /// word is shown as `status=XXXX`. When these differ, this field
    /// holds the separate status word for description; `self.status`
    /// is always the READVAR header status.
    pub display_status: u16,
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
            display_status: status,
        }
    }

    /// Set a separate display status (from a status-summary request).
    pub fn with_display_status(mut self, display_status: u16) -> Self {
        self.display_status = display_status;
        self
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
        use crate::ntp_control::sys_status;
        sys_status::li_name(sys_status::decode_li(self.display_status))
    }

    /// Status description matching real ntpq output format.
    ///
    /// Uses `display_status` (which may come from a separate status-summary
    /// request in the C ntpq) for the textual description, while `self.status`
    /// is always the READVAR header value shown as `status=XXXX`.
    ///
    /// Format matches real C ntpq: "leap_xxx, sync_xxx, N event, [flags,]"
    pub fn status_description(&self) -> String {
        use crate::ntp_control::sys_status;
        let s = self.display_status;
        let li = sys_status::decode_li(s);
        let source = sys_status::decode_source(s);
        let ev_cnt = sys_status::decode_event_count(s);
        let ev_code = sys_status::decode_event_code(s);

        let ev_name = system_event_name(ev_code);
        let freq_mode = if s & 0x0080 != 0 { ", freq_mode" } else { "" };
        format!(
            "{}, {}, {} event, {}{}",
            sys_status::li_name(li),
            sys_status::source_name(source),
            ev_cnt,
            ev_name,
            freq_mode,
        )
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

    /// Send a Mode 6 request with a body payload and collect fragments.
    fn query_with_body(
        &mut self,
        host: &str,
        port: u16,
        msg: ControlMessage,
        body: &str,
    ) -> Result<(Vec<u8>, u16, u16), QueryError> {
        let addr = Self::resolve(host, port)?;

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
            count: body.len() as u16,
        };

        let mut request_bytes = req.encode().to_vec();
        request_bytes.extend_from_slice(body.as_bytes());
        let expected_op = ControlOpcode::from_u8(msg.opcode).op;

        for attempt in 0..=self.retries {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(500));
            }

            socket
                .send(&request_bytes)
                .map_err(|e| QueryError::Network(format!("send: {e}")))?;

            let mut collector = FragmentCollector::new();

            loop {
                let mut buf = vec![0u8; 512];
                match socket.recv(&mut buf) {
                    Ok(n) => {
                        let raw = &buf[..n];
                        let (resp, after_header) = ControlMessage::decode(raw)
                            .ok_or_else(|| QueryError::BadResponse("short header".to_string()))?;

                        if resp.sequence != seq {
                            continue;
                        }
                        let oc = resp.decode_opcode();
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
                            return Ok((assembled, resp.status, resp.associd));
                        }
                    }
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        break;
                    }
                    Err(e) => {
                        return Err(QueryError::Network(e.to_string()));
                    }
                }
            }
        }

        Err(QueryError::Timeout)
    }

    /// Parse a nonce value from a textual NTP Mode 6 response.
    /// Expects: nonce=XXXXXXXX
    fn parse_nonce_value(text: &str) -> Option<String> {
        let text = text.trim();
        if let Some(eq_pos) = text.find('=') {
            let value = text[eq_pos + 1..].trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
        None
    }

    /// Read system variables (ntpq -c rv).
    ///
    /// Real C ntpq issues a separate status-summary request (READVAR
    /// associd=0, count=0) whose response status word is used for the
    /// textual description, followed by a second READVAR request to
    /// retrieve the actual variables. This two-request sequence is
    /// necessary because the status word can change between requests.
    pub fn read_system_vars(
        &mut self,
        host: &str,
        port: u16,
    ) -> Result<SystemVariables, QueryError> {
        // Request 1: status-summary (count=0) to get the display status word
        let status_msg = ControlMessage {
            li_vn_mode: 0,
            opcode: ControlOpcode::new(false, false, false, opcodes::OP_READVAR).to_u8(),
            sequence: 0,
            status: 0,
            associd: 0,
            offset: 0,
            count: 0,
        };
        let display_status = match self.query(host, port, status_msg) {
            Ok((_, status, _)) => status,
            Err(_) => 0, // Fall back to 0 if status request fails
        };

        // Request 2: full READVAR to get the variables
        let var_msg = ControlMessage {
            li_vn_mode: 0,
            opcode: ControlOpcode::new(false, false, false, opcodes::OP_READVAR).to_u8(),
            sequence: 0,
            status: 0,
            associd: 0,
            offset: 0,
            count: 0,
        };
        let (data, status, associd) = self.query(host, port, var_msg)?;
        let text = String::from_utf8_lossy(&data).to_string();
        Ok(SystemVariables::from_text(&text, associd, status).with_display_status(display_status))
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

    /// Read the MRU (Most Recently Used) list from the daemon.
    ///
    /// Uses the NTPsec-compatible nonce protocol:
    ///   1. REQ_NONCE (opcode 12) to acquire a nonce
    ///   2. READ_MRU (opcode 10) with the nonce to retrieve entries
    ///
    /// The response uses textual Mode 6 variable lists with indexed
    /// entries (addr.N, last.N, first.N, ct.N).
    pub fn read_mru_list(&mut self, host: &str, port: u16) -> Result<Vec<MruEntry>, QueryError> {
        // ── 1. Acquire nonce via REQ_NONCE (opcode 12) ────────────────
        let nonce_msg = ControlMessage {
            li_vn_mode: 0,
            opcode: ControlOpcode::new(false, false, false, opcodes::OP_REQ_NONCE).to_u8(),
            sequence: 0,
            status: 0,
            associd: 0,
            offset: 0,
            count: 0,
        };
        let (nonce_data, _status, _associd) = self.query(host, port, nonce_msg)?;
        let nonce_text = String::from_utf8_lossy(&nonce_data);
        let nonce = Self::parse_nonce_value(&nonce_text).ok_or_else(|| {
            QueryError::BadResponse("MRU nonce response did not contain nonce=".to_string())
        })?;

        // ── 2. Request MRU list with nonce ────────────────────────────
        // The request body contains the nonce as a text variable.
        let request_body = format!("nonce={nonce}");
        let msg = ControlMessage {
            li_vn_mode: 0,
            opcode: ControlOpcode::new(false, false, false, opcodes::OP_READ_MRU).to_u8(),
            sequence: 0,
            status: 0,
            associd: 0,
            offset: 0,
            count: request_body.len() as u16,
        };
        let (data, _status, _associd) = self.query_with_body(host, port, msg, &request_body)?;
        let response_text = String::from_utf8_lossy(&data);

        // ── 3. Parse textual indexed entries ──────────────────────────
        MruEntry::parse_textual(&response_text)
    }
}

// ──── MRU Entry Model ────────────────────────────────────────────────────

/// MRU (Most Recently Used) entry from the daemon.
/// Represents a single client entry in the daemon's MRU list.
#[derive(Debug, Clone)]
pub struct MruEntry {
    pub addr: String,
    pub port: u16,
    pub last_pkt_secs: i64,
    pub last_pkt_frac: u32,
    pub first_pkt_secs: i64,
    pub first_pkt_frac: u32,
    pub count: u32,
    pub flags: u8,
}

impl MruEntry {
    /// Parse MRU entries from a textual Mode 6 READ_MRU response.
    ///
    /// NTPsec returns indexed entries in text format:
    ///   addr.0=192.168.1.1 last.0=3771763200.000000 first.0=3771763100.000000 ct.0=42 mv.0=2 rs.0=0
    ///   addr.1=10.0.0.1 last.1=3771763300.000000 first.1=3771763200.000000 ct.1=100
    ///
    /// Indexed variables are grouped by their numeric index into entries.
    pub fn parse_textual(text: &str) -> Result<Vec<MruEntry>, QueryError> {
        // Split into variables and group by index
        let mut entries_map: std::collections::BTreeMap<u32, MruEntry> =
            std::collections::BTreeMap::new();

        for token in text.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            // Split on '=' to get key=value
            let parts: Vec<&str> = token.splitn(2, '=').collect();
            if parts.len() != 2 {
                continue;
            }
            let key = parts[0].trim();
            let value = parts[1].trim();

            // Parse indexed keys like "addr.0", "last.1", "ct.2"
            let dot_pos = key.rfind('.');
            if let Some(dot) = dot_pos {
                let base = &key[..dot];
                let index: u32 = match key[dot + 1..].parse() {
                    Ok(i) => i,
                    Err(_) => continue,
                };

                let entry = entries_map.entry(index).or_insert_with(|| MruEntry {
                    addr: String::new(),
                    port: 0,
                    last_pkt_secs: 0,
                    last_pkt_frac: 0,
                    first_pkt_secs: 0,
                    first_pkt_frac: 0,
                    count: 0,
                    flags: 0,
                });

                match base {
                    "addr" => entry.addr = value.to_string(),
                    "last" => {
                        // Format: seconds.fraction
                        if let Some(dot) = value.find('.') {
                            if let Ok(secs) = value[..dot].parse::<i64>() {
                                entry.last_pkt_secs = secs;
                            }
                            if value.len() > dot + 1 {
                                let frac_str = &value[dot + 1..];
                                // Pad or truncate to 6 fractional digits for NTP frac
                                let frac_padded = format!("{:<6}", frac_str);
                                if let Ok(frac) = frac_padded[..6].parse::<u32>() {
                                    entry.last_pkt_frac = frac * 4295; // approx: 10^6 / 2^32 * frac
                                }
                            }
                        } else if let Ok(secs) = value.parse::<i64>() {
                            entry.last_pkt_secs = secs;
                        }
                    }
                    "first" => {
                        if let Some(dot) = value.find('.') {
                            if let Ok(secs) = value[..dot].parse::<i64>() {
                                entry.first_pkt_secs = secs;
                            }
                        } else if let Ok(secs) = value.parse::<i64>() {
                            entry.first_pkt_secs = secs;
                        }
                    }
                    "ct" => {
                        if let Ok(count) = value.parse::<u32>() {
                            entry.count = count;
                        }
                    }
                    "mv" | "rs" => {
                        if let Ok(flags) = value.parse::<u8>() {
                            entry.flags = flags;
                        }
                    }
                    _ => {}
                }
            } else {
                // Non-indexed keys (like nonce=...)
                if key == "nonce" {
                    // skip nonce in response
                }
            }
        }

        // Filter out empty entries and collect
        let entries: Vec<MruEntry> = entries_map
            .into_values()
            .filter(|e| !e.addr.is_empty() || e.count > 0)
            .collect();

        Ok(entries)
    }

    /// Format a single MRU entry as a line of text.
    pub fn format_entry(&self) -> String {
        let last_f = self.last_pkt_secs as f64 + (self.last_pkt_frac as f64 / 4294967296.0);
        let first_f = self.first_pkt_secs as f64 + (self.first_pkt_frac as f64 / 4294967296.0);
        let interval = if self.count > 1 {
            (last_f - first_f) / (self.count.saturating_sub(1) as f64)
        } else {
            0.0
        };
        let typ = if self.flags & 0x01 != 0 {
            "cast"
        } else {
            "clnt"
        };
        format!(
            "{:>21} {:>5} {:>8.0}s {:>8} {:>4}",
            self.addr, self.port, interval, self.count, typ
        )
    }

    /// Format the column header for MRU list output.
    pub fn format_header() -> String {
        format!(
            "{:>21} {:>5} {:>8} {:>8} {:>4}",
            "addr", "port", "avg_int", "count", "type"
        )
    }

    /// Format a full MRU list as a table.
    pub fn format_list(entries: &[MruEntry]) -> String {
        if entries.is_empty() {
            return "(empty MRU list)".to_string();
        }
        let mut output = String::new();
        output.push_str(&Self::format_header());
        output.push('\n');
        output.push_str(&"-".repeat(50));
        output.push('\n');
        for entry in entries {
            output.push_str(&entry.format_entry());
            output.push('\n');
        }
        output
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

/// Refclock driver name for 127.127.x.y addresses.
/// Maps driver type x to the display name used by ntpq.
fn refclock_driver_name(driver_type: u8) -> &'static str {
    match driver_type {
        1 => "LOCAL",
        2 => "WWVB",
        3 => "WWV",
        4 => "WWVH",
        5 => "GOES",
        6 => "GPS_ONCORE",
        7 => "ACTS",
        8 => "IRIG",
        9 => "ARCR",
        10 => "CHU",
        11 => "PARSE",
        12 => "PPS",
        13 => "TRAK",
        14 => "HOPF",
        15 => "MSF",
        16 => "GPSD",
        17 => "GENERIC",
        18 => "SHM",
        19 => "NMEA",
        20 => "PALISADE",
        21 => "ONCORE",
        22 => "ATOM",
        23 => "PTB",
        24 => "ULINK",
        25 => "DATUM",
        26 => "HARDWARE",
        27 => "NEOCLK4",
        28 => "GPS_HS",
        29 => "PROFANCT",
        30 => "GPS_AS2201",
        31 => "GPS",
        32 => "ARBITER",
        33 => "GPS_ME",
        34 => "GPS_WWV",
        35 => "PERFE",
        _ => "REFCLOCK",
    }
}

/// Format a refclock address (127.127.x.y) into ntpq display name.
/// Returns None if the address is not a refclock address.
fn format_refclock_remote(srcaddr: &str) -> Option<String> {
    // Parse 127.127.x.y format
    let parts: Vec<&str> = srcaddr.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    if parts[0] != "127" || parts[1] != "127" {
        return None;
    }
    let driver_type: u8 = parts[2].parse().ok()?;
    let unit: u8 = parts[3].parse().ok()?;
    let name = refclock_driver_name(driver_type);
    Some(format!("{name}({unit})"))
}

/// Wrap an ASCII refid in dots if it looks like a printable string
/// (matching real ntpq's convention of `.LOCL.` for ASCII refids).
fn format_refid(refid: &str) -> String {
    let trimmed = refid.trim_end_matches('\0');
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.len() <= 4 && trimmed.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        format!(".{trimmed}.")
    } else {
        trimmed.to_string()
    }
}

impl PeerRow {
    pub fn from_association(pv: &PeerVariables, assoc: &AssociationStatus) -> Self {
        let tally = assoc.tally_char();
        // Detect refclocks: stratum >= 10 and known refclock refid or address
        let pv_stratum = pv.stratum();
        let pv_refid = pv.get("refid").unwrap_or("");
        let srcaddr = pv.get("srcaddr").unwrap_or("");
        let is_refclock = pv_stratum >= 10
            && (pv_refid == "LOCL"
                || pv_refid.starts_with("127.127.")
                || srcaddr.starts_with("127.127."));

        // For refclocks, format the remote as DRIVERNAME(unit);
        // otherwise use srcaddr or fall back to refid.
        let remote = if is_refclock && !srcaddr.is_empty() {
            format_refclock_remote(srcaddr).unwrap_or_else(|| srcaddr.to_string())
        } else if !srcaddr.is_empty() {
            srcaddr.to_string()
        } else {
            pv_refid.to_string()
        };
        let refid = format_refid(pv.get("refid").unwrap_or(""));
        let stratum = pv.stratum();
        let delay = pv.get("delay").and_then(|s| s.parse().ok()).unwrap_or(0.0);
        let offset = pv.get("offset").and_then(|s| s.parse().ok()).unwrap_or(0.0);
        let jitter = pv.get("jitter").and_then(|s| s.parse().ok()).unwrap_or(0.0);
        let poll = pv
            .get("hpoll")
            .and_then(|s| s.parse::<f64>().ok())
            .map(|p| 1u64 << p as u64)
            .unwrap_or(64);

        // Derive reach from peer READVAR if available, else from association status
        let reach = pv
            .get("reach")
            .and_then(|s| u8::from_str_radix(s, 16).ok())
            .unwrap_or(if assoc.reachable { 1 } else { 0 });

        // Derive `when` from the `recv` variable (seconds since last packet).
        // Fall back to `rec` if `recv` is absent.
        let when = pv
            .get("recv")
            .and_then(|s| s.parse::<u64>().ok())
            .or_else(|| pv.get("rec").and_then(|s| s.parse::<u64>().ok()));
        // For refclocks that don't report recv, derive from reachable state
        let when = when.or(if assoc.reachable { Some(0) } else { None });

        // Determine peer type from hmode variable, matching ntpq conventions:
        //   0=unspec(local), 1=sym_active(s), 2=sym_passive(S),
        //   3=client(u), 4=server(u), 5=broadcast(b), 6=control(u)
        let peer_type = if assoc.broadcast {
            'b'
        } else if is_refclock {
            // Real C ntpq uses 'u' (unicast) for refclock peers
            'u'
        } else {
            match pv.get("hmode").and_then(|s| s.parse::<u8>().ok()) {
                Some(0) => 'l',
                Some(1) => 's',
                Some(2) => 'S',
                Some(5) => 'b',
                _ => 'u',
            }
        };

        Self {
            tally,
            remote,
            refid,
            associd: assoc.associd,
            stratum,
            peer_type,
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

/// Strip 0x prefix from a value if present (matching C ntpq output).
fn strip_0x(val: &str) -> &str {
    val.strip_prefix("0x").unwrap_or(val)
}

/// Format a value for ntpq output, matching C ntpq conventions (no quoting).
fn format_var_value(key: &str, val: &str) -> String {
    // Strip 0x prefix from hex timestamps
    let v = strip_0x(val);
    // Format leap as two-bit pattern matching C ntpq: ("00", "01", "10", "11")
    if key == "leap" {
        let leap_val: u8 = v.parse().unwrap_or(0);
        let leap_patterns = ["00", "01", "10", "11"];
        let idx = (leap_val.min(3)) as usize;
        return format!("{}={}", key, leap_patterns[idx]);
    }
    // Real C ntpq output: string values containing alphabetic characters
    // (or special characters like _, /, -) are quoted; purely numeric
    // or dotted-decimal values are not quoted.
    let needs_quoting = v.chars().any(|c| c.is_alphabetic() || c == '_' || c == '/');
    if needs_quoting && !v.is_empty() {
        format!("{}=\"{}\"", key, v)
    } else {
        format!("{}={}", key, v)
    }
}

/// Render system variables in ntpq-compatible format (matching real C ntpq).
///
/// Real C ntpq outputs variables in the order received from the daemon
/// (no preferred ordering), wrapped at ~60 chars per line, with trailing
/// comma and newline after each line.
pub fn format_readvar(sys: &SystemVariables) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "associd={} status={:04x} {},\n",
        sys.associd,
        sys.status,
        sys.status_description(),
    ));
    // Real C ntpq outputs variables in daemon wire order — no preferred ordering.
    // Wrapping at ~60 characters per line, matching real C ntpq behavior.
    let mut line = String::new();
    for (key, val) in &sys.ordered_vars {
        let kv = format_var_value(key, val);
        // +2 for comma and space
        if line.len() + kv.len() + 2 > 60 && !line.is_empty() {
            out.push_str(line.trim_end());
            out.push_str(",\n");
            line = String::new();
        }
        if !line.is_empty() {
            line.push_str(", ");
        }
        line.push_str(&kv);
    }
    if !line.is_empty() {
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// Render peer READVAR variables in ntpq-compatible format (multi-line, matching real C ntpq).
pub fn format_peer_readvar(peer: &PeerVariables) -> String {
    let mut out = String::new();
    let peer_ev_code = sys_status::decode_event_code(peer.status);
    let peer_ev_name = peer_event_name(peer_ev_code);
    let peer_ev_count = sys_status::decode_event_count(peer.status);
    out.push_str(&format!(
        "associd={} status={:04x} {} {}, {},\n",
        peer.associd,
        peer.status,
        peer_ev_count,
        peer_ev_name,
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
            out.push_str(&format_var_value(key, val));
            out.push('\n');
            rendered.insert(key.to_string());
        }
    }
    for (key, val) in &peer.ordered_vars {
        if !rendered.contains(key) {
            out.push_str(&format_var_value(key, val));
            out.push('\n');
            rendered.insert(key.clone());
        }
    }
    out
}

/// Render associations table in ntpq-compatible format.
pub fn format_associations(assocs: &[AssociationStatus]) -> String {
    use crate::ntp_control::sys_status;
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
        // Decode event code and count from the status word
        let event_code = sys_status::decode_event_code(assoc.status);
        let event_count = sys_status::decode_event_count(assoc.status);
        let last_event = ntpq_event_name(event_code);
        out.push_str(&format!(
            "  {} {:5}  {:04x}   {:4}  {:4}  {:4}  {:<10}  {:>8} {:>2}\n",
            i + 1,
            assoc.associd,
            assoc.status,
            conf,
            reach,
            auth,
            cond,
            last_event,
            event_count,
        ));
    }
    out
}

/// Map a system event code (0-15) to its ntpq display name.
///
/// NTPsec C ntpq uses a different event name table for system status
/// vs. peer status.  System events (from sys_event[] in ntp_control.c):
///   0=unspec, 1=no_reply, 2=no_reach, 3=fault, 4=freq_mode
///
/// Without this separate function, system event code 4 (freq_mode)
/// would incorrectly display as "reach_brd" (peer event code 4).
fn system_event_name(code: u16) -> &'static str {
    match code {
        0 => "unspec",
        1 => "no_reply",
        2 => "no_reach",
        3 => "fault",
        4 => "freq_mode",
        5 => "xleave",
        6 => "xtime",
        _ => "event",
    }
}

/// Map a peer event code (0-15) to its ntpq display name.
fn ntpq_event_name(code: u16) -> &'static str {
    match code {
        0 => "restart",
        1 => "no_reach",
        2 => "no_reply",
        3 => "rate_excd",
        4 => "reach_brd",
        5 => "sys_rest",
        6 => "sys_clk",
        7 => "sys_peer",
        8 => "sys_peer",
        9 => "sys_peer",
        10 => "sys_peer",
        11 => "sys_peer",
        12 => "prot_test",
        13 => "crypto",
        14 => "nopeer",
        _ => "unknown",
    }
}

/// Map a peer status event code (lower 4 bits of peer status word)
/// to its display name, matching real C ntpq output.
fn peer_event_name(code: u16) -> &'static str {
    match code {
        0 => "no event",
        1 => "reach",
        2 => "authen",
        3 => "mobilze",
        4 => "pkt_int",
        5 => "assoc",
        6 => "sel_rep",
        7 => "sys_clk",
        8 => "rate_excd",
        9 => "mobilze",
        10 => "demobil",
        11 => "unreach",
        12 => "seltest",
        13 => "popcorn",
        14 => "intervnt",
        _ => "unknown",
    }
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
            "{}{:15} {:12} {:2} {} {:>4} {:>4} {:>5} {:>7.3} {:>8.3} {:>7.3}\n",
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

// ──── Test Mode 6 Server ────────────────────────────────────────────────
// In-process UDP server that responds to Mode 6 requests with configurable
// responses. Used by local oracle courts below.

#[cfg(test)]
pub(crate) mod test_mode6_server {
    use std::net::UdpSocket;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    /// A simple Mode 6 test server that responds to one request.
    pub struct TestMode6Server {
        pub port: u16,
        stop: Arc<AtomicBool>,
        join: Option<thread::JoinHandle<()>>,
    }

    impl TestMode6Server {
        /// Create a server that waits for one request, then sends `response_bytes`.
        pub fn serve(response_bytes: Vec<u8>) -> Self {
            Self::serve_conditional(move |_buf, _len| Some(response_bytes.clone()))
        }

        /// Create a server that computes a response based on the received request.
        /// The closure receives the raw request bytes and length, and returns
        /// an optional response (None = don't respond).
        pub fn serve_conditional<F>(handler: F) -> Self
        where
            F: Fn(&[u8], usize) -> Option<Vec<u8>> + Send + 'static,
        {
            let socket = UdpSocket::bind("127.0.0.1:0").expect("test server bind");
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("test server set timeout");
            let port = socket.local_addr().unwrap().port();
            let stop = Arc::new(AtomicBool::new(false));
            let stop_clone = stop.clone();

            let join = thread::spawn(move || {
                let mut buf = [0u8; 512];
                loop {
                    if stop_clone.load(Ordering::Relaxed) {
                        break;
                    }
                    match socket.recv_from(&mut buf) {
                        Ok((len, src)) => {
                            if let Some(response) = handler(&buf, len) {
                                let _ = socket.send_to(&response, src);
                            }
                        }
                        Err(ref e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut =>
                        {
                            continue;
                        }
                        Err(_) => break,
                    }
                }
            });

            Self {
                port,
                stop,
                join: Some(join),
            }
        }

        /// Serve a sequence of responses, one per incoming request.
        /// Each request gets the next response in the sequence.
        /// Useful for multi-request operations like read_system_vars.
        pub fn serve_sequence(responses: Vec<Vec<u8>>) -> Self {
            use std::sync::Mutex;
            let idx = Arc::new(Mutex::new(0usize));
            let resp = Arc::new(responses);
            Self::serve_conditional(move |_buf, _len| {
                let mut i = idx.lock().unwrap();
                if *i < resp.len() {
                    let r = Some(resp[*i].clone());
                    *i += 1;
                    r
                } else {
                    None
                }
            })
        }

        /// Receive one request, then send all fragments in sequence with small delays.
        pub fn serve_fragments(fragments: Vec<Vec<u8>>) -> Self {
            let socket = UdpSocket::bind("127.0.0.1:0").expect("test server bind");
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("test server set timeout");
            let port = socket.local_addr().unwrap().port();
            let stop = Arc::new(AtomicBool::new(false));
            let stop_clone = stop.clone();

            let join = thread::spawn(move || {
                let mut buf = [0u8; 512];
                loop {
                    if stop_clone.load(Ordering::Relaxed) {
                        break;
                    }
                    match socket.recv_from(&mut buf) {
                        Ok((_len, src)) => {
                            for frag in &fragments {
                                let _ = socket.send_to(frag, src);
                                thread::sleep(Duration::from_millis(10));
                            }
                            break;
                        }
                        Err(ref e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut =>
                        {
                            continue;
                        }
                        Err(_) => break,
                    }
                }
            });

            Self {
                port,
                stop,
                join: Some(join),
            }
        }
    }

    impl Drop for TestMode6Server {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Ok(s) = UdpSocket::bind("127.0.0.1:0") {
                let _ = s.send_to(b"\x00", format!("127.0.0.1:{}", self.port));
            }
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }

    /// Build a Mode 6 READVAR response payload (system variables as text).
    pub fn make_readvar_response(
        associd: u16,
        sequence: u16,
        status: u16,
        variable_text: &str,
        more: bool,
    ) -> Vec<u8> {
        use crate::ntp_control::*;
        use crate::ntp_types::NtpPacket;
        let msg = ControlMessage {
            li_vn_mode: NtpPacket::set_li_vn_mode(
                crate::ntp_types::LeapIndicator::NoWarning,
                crate::ntp_types::NtpVersion::V4,
                crate::ntp_types::NtpMode::NtpControl,
            ),
            opcode: ControlOpcode::new(true, false, more, opcodes::OP_READVAR).to_u8(),
            sequence,
            status,
            associd,
            offset: 0,
            count: variable_text.len() as u16,
        };
        let mut buf = msg.encode().to_vec();
        buf.extend_from_slice(variable_text.as_bytes());
        buf
    }

    /// Build a Mode 6 error response.
    pub fn make_error_response(associd: u16, sequence: u16, error_code: u8) -> Vec<u8> {
        use crate::ntp_control::*;
        use crate::ntp_types::NtpPacket;
        let msg = ControlMessage {
            li_vn_mode: NtpPacket::set_li_vn_mode(
                crate::ntp_types::LeapIndicator::NoWarning,
                crate::ntp_types::NtpVersion::V4,
                crate::ntp_types::NtpMode::NtpControl,
            ),
            opcode: ControlOpcode::new(true, true, false, opcodes::OP_READVAR).to_u8(),
            sequence,
            status: (error_code as u16) << 8,
            associd,
            offset: 0,
            count: 0,
        };
        msg.encode().to_vec()
    }

    /// Build an associations (READSTAT) binary response.
    pub fn make_readstat_response(sequence: u16, assoc_pairs: &[(u16, u16)]) -> Vec<u8> {
        use crate::ntp_control::*;
        use crate::ntp_types::NtpPacket;
        let mut payload = Vec::with_capacity(assoc_pairs.len() * 4);
        for &(aid, st) in assoc_pairs {
            payload.extend_from_slice(&aid.to_be_bytes());
            payload.extend_from_slice(&st.to_be_bytes());
        }
        let msg = ControlMessage {
            li_vn_mode: NtpPacket::set_li_vn_mode(
                crate::ntp_types::LeapIndicator::NoWarning,
                crate::ntp_types::NtpVersion::V4,
                crate::ntp_types::NtpMode::NtpControl,
            ),
            opcode: ControlOpcode::new(true, false, false, opcodes::OP_READSTAT).to_u8(),
            sequence,
            status: 0x0622,
            associd: 0,
            offset: 0,
            count: payload.len() as u16,
        };
        let mut buf = msg.encode().to_vec();
        buf.extend_from_slice(&payload);
        buf
    }
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
    fn test_fragment_reverse_order_excess_rejected() {
        let mut fc = FragmentCollector::new();
        // Excess fragment 0..12 arrives FIRST (non-final), extending past
        // the eventual final_end=10
        let _ = fc
            .add_fragment(0, 12, b"0123456789ab", true, 0x0622, 0)
            .unwrap();
        // Smaller final fragment 0..10 arrives LATER — should reject because
        // existing fragment 0..12 extends past final_end=10
        let r = fc.add_fragment(0, 10, b"0123456789", false, 0x0622, 0);
        assert!(r.is_err(), "existing fragment extends past new final_end");
    }

    #[test]
    fn test_fragment_shrink_rejected() {
        let mut fc = FragmentCollector::new();
        // Fragment 0..10 arrives first
        let _ = fc
            .add_fragment(0, 10, b"0123456789", true, 0x0622, 0)
            .unwrap();
        // Same offset 0 with smaller payload 0..5 — should reject
        let r = fc.add_fragment(0, 5, b"01234", false, 0x0622, 0);
        assert!(r.is_err(), "retrograde fragment must be rejected");
    }

    #[test]
    fn test_fragment_excess_extent_violation() {
        // Fragment 0..10 with more=true arrives first (covers bytes 0-10).
        let mut fc = FragmentCollector::new();
        let _ = fc
            .add_fragment(0, 10, b"0123456789", true, 0x0622, 0)
            .unwrap();
        // Final fragment at offset 3, count=2 declares final_end=5.
        // Existing fragment 0..10 extends to byte 10 > 5 → reject.
        // The overlapping bytes "34" match, so overlap is consistent;
        // rejection is purely from the extent invariant.
        let r = fc.add_fragment(3, 2, b"34", false, 0x0622, 0);
        assert!(
            r.is_err(),
            "existing fragment 0..10 extending to 10 must be rejected when final_end=5"
        );
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
        assert!(out.contains(".LOCL."), "refid should be dot-wrapped");
    }

    #[test]
    fn test_readvar_format() {
        // Status description decodes from the status word, not variables.
        // 0x0622: li=0(none), source=6(CTL_SST_TS_NTP), count=2, event=2(no_reply)
        let text = r#"version="ntpd 4.2.8",stratum=2,offset=0.005"#;
        let sv = SystemVariables::from_text(text, 0, 0x0622);
        let out = format_readvar(&sv);
        assert!(out.contains("associd=0"));
        assert!(out.contains("leap_none, sync_ntp, 2 no_reach"));
        assert!(out.contains("stratum=2"));
    }

    #[test]
    fn test_readvar_extra_vars() {
        // Verify that format_readvar includes variables beyond the preferred list
        let text = "version=ntpd,stratum=2,offset=0.005,leap=00,extra_var=42";
        let sv = SystemVariables::from_text(text, 0, 0x0622);
        let out = format_readvar(&sv);
        assert!(out.contains("extra_var=42"), "extra vars must be included");
    }

    // ──── Frozen Renderer Fixture Courts ──────────────────────────────

    #[test]
    fn test_format_readvar_frozen_parity() {
        // Exact known-good output matching real ntpq -c rv.
        // Status word 0x0322: li=0(none), source=3(ntp), count=2, event=2
        let text = r##"version="ntpd 4.2.8p3",processor="x86_64",system="Linux/4.19.0",stratum=2,precision=-24,rootdelay=0.001,rootdisp=0.005,refid=.NTP.,reftime=0,peer=0,tc=6,offset=0.002,frequency=0.123,sys_jitter=0.001,rootdist=0.006"##;
        let sv = SystemVariables::from_text(text, 0, 0x0322);
        let out = format_readvar(&sv);
        let expected = concat!(
            "associd=0 status=0322 leap_none, sync_ntp, 2 no_reach,\n",
            "version=ntpd 4.2.8p3, processor=x86_64, system=Linux/4.19.0,\n",
            "stratum=2, precision=-24, rootdelay=0.001, rootdisp=0.005,\n",
            "refid=.NTP., reftime=0, peer=0, tc=6, offset=0.002,\n",
            "frequency=0.123, sys_jitter=0.001, rootdist=0.006,\n",
        );
        assert_eq!(out, expected, "frozen system readvar output mismatch");
    }

    #[test]
    fn test_format_readvar_extra_vars() {
        // Extra variables beyond the preferred list appear, preferred vars come first
        let text = "version=ntpd,stratum=2,extra_var=42,z_var=99,offset=0.005";
        let sv = SystemVariables::from_text(text, 0, 0);
        let out = format_readvar(&sv);
        assert!(
            out.starts_with("associd=0 status=0000 "),
            "output should start with associd/status header"
        );
        assert!(
            out.contains("extra_var=42"),
            "extra_var must appear in output"
        );
        assert!(out.contains("z_var=99"), "z_var must appear in output");
        // Preferred vars (version, stratum, offset) should appear before extra_var
        let version_pos = out.find("version=").unwrap();
        let stratum_pos = out.find("stratum=").unwrap();
        let offset_pos = out.find("offset=").unwrap();
        let extra_pos = out.find("extra_var=").unwrap();
        let z_pos = out.find("z_var=").unwrap();
        assert!(
            version_pos < extra_pos,
            "preferred var 'version' should appear before extra_var"
        );
        assert!(
            stratum_pos < extra_pos,
            "preferred var 'stratum' should appear before extra_var"
        );
        assert!(
            offset_pos < extra_pos,
            "preferred var 'offset' should appear before extra_var"
        );
        // Both extra vars appear after preferred ones
        assert!(
            extra_pos < z_pos,
            "extra_var should appear before z_var (input order preserved)"
        );
    }

    #[test]
    fn test_format_peer_readvar_frozen() {
        // Peer READVAR output format matches real ntpq
        let text = concat!(
            "srcaddr=192.168.1.1,",
            "stratum=2,",
            "offset=0.002,",
            "delay=0.001,",
            "dispersion=0.000,",
            "jitter=0.001,",
            "hpoll=6,",
            "ppoll=6,",
            "reach=0xFF,",
            "flash=0x000,",
            "leap=00,",
            "refid=.NTP.,",
            "reftime=0,",
            "hmode=3,",
            "pmode=4,",
            "precision=-24",
        );
        let pv = PeerVariables::from_text(text, 49723, 0x9614);
        let out = format_peer_readvar(&pv);
        let expected = concat!(
            "associd=49723 status=9614 1 pkt_int, 192.168.1.1,\n",
            "srcaddr=192.168.1.1\n",
            "stratum=2\n",
            "offset=0.002\n",
            "delay=0.001\n",
            "dispersion=0.000\n",
            "jitter=0.001\n",
            "hpoll=6\n",
            "ppoll=6\n",
            "reach=FF\n",
            "flash=000\n",
            "leap=00\n",
            "refid=.NTP.\n",
            "reftime=0\n",
            "hmode=3\n",
            "pmode=4\n",
            "precision=-24\n",
        );
        assert_eq!(out, expected, "frozen peer readvar output mismatch");
    }

    #[test]
    fn test_format_associations_frozen() {
        // Exact output format for multiple associations
        let assocs = vec![
            AssociationStatus {
                associd: 49723,
                status: 0x9614,
                configured: true,
                auth_enabled: true,
                auth_ok: false,
                reachable: true,
                broadcast: false,
                selection: 6,
            },
            AssociationStatus {
                associd: 49724,
                status: 0x8010,
                configured: true,
                auth_enabled: false,
                auth_ok: false,
                reachable: true,
                broadcast: false,
                selection: 4,
            },
            AssociationStatus {
                associd: 49725,
                status: 0x8000,
                configured: true,
                auth_enabled: true,
                auth_ok: true,
                reachable: false,
                broadcast: false,
                selection: 0,
            },
        ];
        let out = format_associations(&assocs);
        // Build expected using the same format specs as production code
        let mut expected =
            String::from("ind assid status  conf reach auth condition  last_event cnt\n");
        expected.push_str("===========================================================\n");
        // Use format! to match the exact spacing from format_associations
        let fmt = |i: usize,
                   aid: u16,
                   st: u16,
                   conf: &str,
                   reach: &str,
                   auth: &str,
                   cond: &str,
                   ev: &str,
                   cnt: u16| {
            format!(
                "  {} {:5}  {:04x}   {:4}  {:4}  {:4}  {:<10}  {:>8} {:>2}\n",
                i, aid, st, conf, reach, auth, cond, ev, cnt
            )
        };
        expected.push_str(&fmt(
            1,
            49723,
            0x9614,
            "yes",
            "yes",
            "yes",
            "sys.peer",
            "reach_brd",
            1,
        ));
        expected.push_str(&fmt(
            2,
            49724,
            0x8010,
            "yes",
            "yes",
            "none",
            "candidate",
            "restart",
            1,
        ));
        expected.push_str(&fmt(
            3, 49725, 0x8000, "yes", "no", "ok", "rejected", "restart", 0,
        ));
        assert_eq!(out, expected, "frozen associations output mismatch");
    }

    #[test]
    fn test_format_peers_frozen() {
        // Exact peers billboard output format
        let rows = vec![
            PeerRow {
                tally: '*',
                remote: "time.example.com".to_string(),
                refid: ".NTP.".to_string(),
                associd: 1,
                stratum: 2,
                peer_type: 'u',
                when: Some(10),
                poll: 64,
                reach: 0o377,
                delay: 0.001,
                offset: 0.002,
                jitter: 0.001,
            },
            PeerRow {
                tally: ' ',
                remote: "192.168.1.100".to_string(),
                refid: ".GPS.".to_string(),
                associd: 2,
                stratum: 1,
                peer_type: 'u',
                when: None,
                poll: 64,
                reach: 0o377,
                delay: 0.003,
                offset: -0.001,
                jitter: 0.002,
            },
        ];
        let out = format_peers(&rows);
        // Build expected using the same format specs used by the production code
        let mut expected = String::new();
        expected.push_str(
            "     remote           refid      st t when poll reach   delay   offset  jitter\n",
        );
        expected.push_str(
            "==============================================================================\n",
        );
        // Row 1
        expected.push_str(&format!(
            "{}{:15} {:12} {:2} {} {:>4} {:>4} {:>5} {:>7.3} {:>8.3} {:>7.3}\n",
            '*', "time.example.com", ".NTP.", 2, 'u', "10", 64, "377", 0.001, 0.002, 0.001,
        ));
        // Row 2
        expected.push_str(&format!(
            "{}{:15} {:12} {:2} {} {:>4} {:>4} {:>5} {:>7.3} {:>8.3} {:>7.3}\n",
            ' ', "192.168.1.100", ".GPS.", 1, 'u', "-", 64, "377", 0.003, -0.001, 0.002,
        ));
        assert_eq!(out, expected, "frozen peers output mismatch");
    }

    #[test]
    fn test_format_peers_when_units() {
        // Test that when values render correctly with different units
        let rows = vec![
            PeerRow {
                tally: ' ',
                remote: "a".to_string(),
                refid: ".X.".to_string(),
                associd: 1,
                stratum: 1,
                peer_type: 'u',
                when: Some(45),
                poll: 64,
                reach: 0o377,
                delay: 0.0,
                offset: 0.0,
                jitter: 0.0,
            },
            PeerRow {
                tally: ' ',
                remote: "b".to_string(),
                refid: ".X.".to_string(),
                associd: 2,
                stratum: 1,
                peer_type: 'u',
                when: Some(1100),
                poll: 64,
                reach: 0o377,
                delay: 0.0,
                offset: 0.0,
                jitter: 0.0,
            },
            PeerRow {
                tally: ' ',
                remote: "c".to_string(),
                refid: ".X.".to_string(),
                associd: 3,
                stratum: 1,
                peer_type: 'u',
                when: Some(3660),
                poll: 64,
                reach: 0o377,
                delay: 0.0,
                offset: 0.0,
                jitter: 0.0,
            },
            PeerRow {
                tally: ' ',
                remote: "d".to_string(),
                refid: ".X.".to_string(),
                associd: 4,
                stratum: 1,
                peer_type: 'u',
                when: None,
                poll: 64,
                reach: 0o377,
                delay: 0.0,
                offset: 0.0,
                jitter: 0.0,
            },
        ];
        let out = format_peers(&rows);
        assert!(out.contains("45"), "when=45 should render as '45'");
        assert!(out.contains("18m"), "when=1100 should render as '18m'");
        assert!(out.contains("1h"), "when=3660 should render as '1h'");
        assert!(out.contains("  -"), "when=None should render as '-'");
    }

    #[test]
    fn test_associations_format_many() {
        // Test all selection values render correct condition strings
        let selection_labels = [
            (0usize, "rejected"),
            (1usize, "falsetick"),
            (2usize, "excess"),
            (3usize, "outlyer"),
            (4usize, "candidate"),
            (5usize, "backup"),
            (6usize, "sys.peer"),
            (7usize, "rejected"),
        ];
        let assocs: Vec<AssociationStatus> = selection_labels
            .iter()
            .map(|&(sel, _)| AssociationStatus {
                associd: 1000 + sel as u16,
                status: 0x8000 | (sel as u16),
                configured: true,
                auth_enabled: false,
                auth_ok: false,
                reachable: false,
                broadcast: false,
                selection: sel as u8,
            })
            .collect();
        let out = format_associations(&assocs);
        for &(sel, label) in &selection_labels {
            assert!(
                out.contains(label),
                "selection={} should produce condition string '{}'",
                sel,
                label
            );
        }
        // Verify count: 1 header + 1 separator + 8 data lines
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            10,
            "expected 10 lines (header, separator, 8 assocs)"
        );
        // Verify event_code and event_count appear in output
        assert!(out.contains("restart"), "event_code 0 should be restart");
        assert!(
            out.contains("reach_brd"),
            "event_code 4 should be reach_brd"
        );
    }

    // ──── Local UDP Oracle Courts ──────────────────────────────────────

    #[test]
    fn test_local_udp_readvar() {
        // read_system_vars now makes TWO requests (status + variables).
        // Serve an empty status response first, then the variable response.
        let variable_text = r#"version="ntpd 4.2.8",stratum=2,offset=0.005"#;
        let empty_resp = test_mode6_server::make_readvar_response(0, 1, 0x0622, "", false);
        let var_resp = test_mode6_server::make_readvar_response(0, 2, 0x0622, variable_text, false);
        let responses = vec![empty_resp, var_resp];
        let server = test_mode6_server::TestMode6Server::serve_sequence(responses);
        let mut client = ControlClient::new(5, 1);
        let result = client.read_system_vars("127.0.0.1", server.port);
        assert!(
            result.is_ok(),
            "read_system_vars failed: {:?}",
            result.err()
        );
        let sv = result.unwrap();
        assert_eq!(sv.associd, 0);
        assert_eq!(sv.get("stratum"), Some("2"));
        assert_eq!(sv.get("offset"), Some("0.005"));
    }

    #[test]
    fn test_local_udp_readvar_fragmented() {
        // Two fragments: first more=true with "version=1,", second more=false with "stratum=2"
        let frag1 = test_mode6_server::make_readvar_response(0, 1, 0x0622, "version=1,", true);
        let mut frag2 = test_mode6_server::make_readvar_response(0, 1, 0x0622, "stratum=2", false);
        // Patch offset field (bytes 8..10) to 10, the length of "version=1,"
        let offset_bytes = 10u16.to_be_bytes();
        frag2[8..10].copy_from_slice(&offset_bytes);

        let server = test_mode6_server::TestMode6Server::serve_fragments(vec![frag1, frag2]);
        let mut client = ControlClient::new(5, 1);
        let result = client.read_system_vars("127.0.0.1", server.port);
        assert!(
            result.is_ok(),
            "fragmented readvar failed: {:?}",
            result.err()
        );
        let sv = result.unwrap();
        assert_eq!(sv.get("version"), Some("1"));
        assert_eq!(sv.get("stratum"), Some("2"));
    }

    #[test]
    fn test_local_udp_wrong_sequence() {
        // Server responds with a different sequence number than requested
        // First request (status) also gets wrong sequence
        let status_resp = test_mode6_server::make_readvar_response(0, 99, 0x0622, "", false);
        let var_resp = test_mode6_server::make_readvar_response(0, 99, 0x0622, "stratum=2", false);
        let server =
            test_mode6_server::TestMode6Server::serve_sequence(vec![status_resp, var_resp]);
        let mut client = ControlClient::new(1, 0); // No retries, timeout
        let result = client.read_system_vars("127.0.0.1", server.port);
        assert!(result.is_err(), "wrong sequence must be rejected");
    }

    #[test]
    fn test_local_udp_error_response() {
        // First request (status) gets an error response
        let err_resp = test_mode6_server::make_error_response(0, 1, 4); // CERR_BADASSOC
        let server = test_mode6_server::TestMode6Server::serve(err_resp);
        let mut client = ControlClient::new(1, 0); // No retries, timeout
        let result = client.read_system_vars("127.0.0.1", server.port);
        assert!(result.is_err(), "error response must produce error");
        match result.err().unwrap() {
            QueryError::NotFound => {} // Expected for error code 4
            other => panic!("expected NotFound error, got: {other}"),
        }
    }

    #[test]
    fn test_local_udp_timeout() {
        // Server that never responds
        let server = test_mode6_server::TestMode6Server::serve_conditional(|_, _| None);
        let mut client = ControlClient::new(1, 0); // 1s timeout, no retries
        let result = client.read_system_vars("127.0.0.1", server.port);
        assert!(result.is_err(), "timeout must produce error");
        match result.err().unwrap() {
            QueryError::Timeout => {}
            other => panic!("expected Timeout, got: {other}"),
        }
    }

    #[test]
    fn test_local_udp_readstat() {
        let assocs: Vec<(u16, u16)> = vec![(1, 0x9614), (2, 0x8010)];
        let resp = test_mode6_server::make_readstat_response(1, &assocs);
        let server = test_mode6_server::TestMode6Server::serve(resp);
        let mut client = ControlClient::new(5, 1);
        let result = client.read_associations("127.0.0.1", server.port);
        assert!(
            result.is_ok(),
            "read_associations failed: {:?}",
            result.err()
        );
        let assocs = result.unwrap();
        assert_eq!(assocs.len(), 2);
        assert_eq!(assocs[0].associd, 1);
        assert!(assocs[0].configured);
        assert!(assocs[0].reachable);
        assert_eq!(assocs[0].selection, 6);
        assert_eq!(assocs[1].associd, 2);
        assert_eq!(assocs[1].selection, 0);
    }

    #[test]
    fn test_local_udp_authentication_error() {
        let err_resp = test_mode6_server::make_error_response(0, 1, 1); // CERR_AUTH
        let server = test_mode6_server::TestMode6Server::serve(err_resp);
        let mut client = ControlClient::new(1, 0); // No retries, timeout
        let result = client.read_system_vars("127.0.0.1", server.port);
        assert!(result.is_err(), "auth error must produce error");
        match result.err().unwrap() {
            QueryError::AuthFailure => {}
            other => panic!("expected AuthFailure, got: {other}"),
        }
    }

    // ──── Raw Bytes → Typed Model Courts ──────────────────────────────

    #[test]
    fn test_raw_bytes_to_system_vars() {
        // Layer 1 fixture: raw Mode 6 response bytes → SystemVariables
        use crate::ntp_control::*;
        use crate::ntp_types::NtpPacket;

        let variable_text = r##"version="ntpd 4.2.8p3",stratum=2,offset=0.005,leap=00,sync=3"##;
        let msg = ControlMessage {
            li_vn_mode: NtpPacket::set_li_vn_mode(
                crate::ntp_types::LeapIndicator::NoWarning,
                crate::ntp_types::NtpVersion::V4,
                crate::ntp_types::NtpMode::NtpControl,
            ),
            opcode: ControlOpcode::new(true, false, false, opcodes::OP_READVAR).to_u8(),
            sequence: 1,
            status: 0x0622,
            associd: 0,
            offset: 0,
            count: variable_text.len() as u16,
        };
        let mut wire_bytes = msg.encode().to_vec();
        wire_bytes.extend_from_slice(variable_text.as_bytes());

        // Decode wire bytes using ControlMessage::decode
        let (decoded, after_header) = ControlMessage::decode(&wire_bytes).unwrap();
        assert_eq!(decoded.sequence, 1);
        assert_eq!(decoded.status, 0x0622);
        assert_eq!(decoded.associd, 0);

        // Extract text payload
        let count = decoded.count as usize;
        let text = String::from_utf8_lossy(&after_header[..count]);
        let sv = SystemVariables::from_text(&text, decoded.associd, decoded.status);

        // Verify typed model
        assert_eq!(sv.associd, 0);
        assert_eq!(sv.status, 0x0622);
        assert_eq!(sv.get("version"), Some("ntpd 4.2.8p3"));
        assert_eq!(sv.get("stratum"), Some("2"));
        assert_eq!(sv.get("offset"), Some("0.005"));
        assert_eq!(sv.leap_str(), "leap_none");
        // Verify layer 2: typed model → exact text output
        // Status 0x0622: li=0(none), source=6(CTL_SST_TS_NTP), count=2, event=2(no_reply)
        let out = format_readvar(&sv);
        assert!(out.starts_with("associd=0 status=0622 "));
        assert!(out.contains("leap_none, sync_ntp, 2 no_reach"));
        assert!(out.contains("stratum=2"));
        assert!(out.contains("offset=0.005"));
    }

    #[test]
    fn test_raw_bytes_to_peer_vars() {
        // Layer 1 fixture: raw Mode 6 response bytes → PeerVariables
        use crate::ntp_control::*;
        use crate::ntp_types::NtpPacket;

        let variable_text = "srcaddr=192.168.1.1,stratum=2,offset=0.002,delay=0.001";
        let msg = ControlMessage {
            li_vn_mode: NtpPacket::set_li_vn_mode(
                crate::ntp_types::LeapIndicator::NoWarning,
                crate::ntp_types::NtpVersion::V4,
                crate::ntp_types::NtpMode::NtpControl,
            ),
            opcode: ControlOpcode::new(true, false, false, opcodes::OP_READVAR).to_u8(),
            sequence: 1,
            status: 0x9614,
            associd: 49723,
            offset: 0,
            count: variable_text.len() as u16,
        };
        let mut wire_bytes = msg.encode().to_vec();
        wire_bytes.extend_from_slice(variable_text.as_bytes());

        // Decode wire bytes
        let (decoded, after_header) = ControlMessage::decode(&wire_bytes).unwrap();
        let count = decoded.count as usize;
        let text = String::from_utf8_lossy(&after_header[..count]);
        let pv = PeerVariables::from_text(&text, decoded.associd, decoded.status);

        // Verify typed model
        assert_eq!(pv.associd, 49723);
        assert_eq!(pv.status, 0x9614);
        assert_eq!(pv.get("srcaddr"), Some("192.168.1.1"));
        assert_eq!(pv.get("stratum"), Some("2"));
        assert_eq!(pv.get("offset"), Some("0.002"));

        // Verify layer 2: typed model → exact text output
        let out = format_peer_readvar(&pv);
        assert!(out.contains("associd=49723 status=9614"));
        assert!(out.contains("srcaddr=192.168.1.1"));
        assert!(out.contains("stratum=2"));
    }

    // ──── MRU List Tests (textual format) ───────────────────────────

    #[test]
    fn test_mru_parse_ipv4_entry() {
        let text =
            "addr.0=192.168.1.1,last.0=3771763200.000000,first.0=3771763100.000000,ct.0=42,mv.0=0";
        let entries = MruEntry::parse_textual(text).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].addr, "192.168.1.1");
        assert_eq!(entries[0].port, 0);
        assert_eq!(entries[0].last_pkt_secs, 3771763200);
        assert_eq!(entries[0].first_pkt_secs, 3771763100);
        assert_eq!(entries[0].count, 42);
        assert_eq!(entries[0].flags, 0);
        assert!(entries[0].format_entry().contains("clnt"));
    }

    #[test]
    fn test_mru_parse_multiple_entries() {
        let text = concat!(
            "addr.0=192.168.1.1,last.0=3771763200.000000,first.0=3771763100.000000,ct.0=42,mv.0=0,",
            "addr.1=10.0.0.1,last.1=3771763300.000000,first.1=3771763200.000000,ct.1=100,mv.1=1"
        );
        let entries = MruEntry::parse_textual(text).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].addr, "192.168.1.1");
        assert_eq!(entries[0].count, 42);
        assert_eq!(entries[0].flags, 0);
        assert_eq!(entries[1].addr, "10.0.0.1");
        assert_eq!(entries[1].count, 100);
        assert_eq!(entries[1].flags, 1);
    }

    #[test]
    fn test_mru_parse_empty() {
        let entries = MruEntry::parse_textual("").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_mru_format_list_empty() {
        let output = MruEntry::format_list(&[]);
        assert_eq!(output, "(empty MRU list)");
    }

    #[test]
    fn test_mru_format_list_has_header() {
        let text =
            "addr.0=192.168.1.1,last.0=3771763200.000000,first.0=3771763100.000000,ct.0=1,mv.0=0";
        let entries = MruEntry::parse_textual(text).unwrap();
        let output = MruEntry::format_list(&entries);
        assert!(output.contains("addr"));
        assert!(output.contains("port"));
        assert!(output.contains("count"));
        assert!(output.contains("192.168.1.1"));
    }

    #[test]
    fn test_mru_parse_with_nonce() {
        let text =
            "nonce=abc123,addr.0=192.168.1.1,last.0=3771763200.000000,first.0=3771763100.000000,ct.0=42,mv.0=0";
        let entries = MruEntry::parse_textual(text).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].addr, "192.168.1.1");
        assert_eq!(entries[0].count, 42);
    }
}
