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
use std::collections::HashMap;
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
            6 => '*', // sys.peer
            5 => '#', // backup
            4 => '+', // candidate
            3 => '-', // outlier
            2 => 'x', // overflow discard
            1 => 'x', // intersection discard
            _ => ' ', // rejected
        }
    }
}

// ──── System Variables ────────────────────────────────────────────────

/// Typed system variables parsed from Mode 6 text response.
#[derive(Debug, Clone, Default)]
pub struct SystemVariables {
    pub vars: HashMap<String, String>,
    pub associd: u16,
    pub status: u16,
}

impl SystemVariables {
    pub fn from_text(data: &str, associd: u16, status: u16) -> Self {
        let mut vars = HashMap::new();
        for part in data.split(',') {
            if let Some(eq) = part.find('=') {
                let key = part[..eq].trim().to_string();
                let val = part[eq + 1..].trim().to_string();
                vars.insert(key, val);
            }
        }
        Self {
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
}

// ──── Peer Variables ──────────────────────────────────────────────────

/// Typed peer variables parsed from Mode 6 text response.
#[derive(Debug, Clone, Default)]
pub struct PeerVariables {
    pub vars: HashMap<String, String>,
    pub associd: u16,
    pub status: u16,
}

impl PeerVariables {
    pub fn from_text(data: &str, associd: u16, status: u16) -> Self {
        let mut vars = HashMap::new();
        for part in data.split(',') {
            if let Some(eq) = part.find('=') {
                let key = part[..eq].trim().to_string();
                let val = part[eq + 1..].trim().to_string();
                vars.insert(key, val);
            }
        }
        Self {
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

/// Mode 6 control protocol client.
pub struct ControlClient {
    sequence: u16,
    timeout: Duration,
    retries: u8,
    local_addr: std::net::SocketAddr,
}

impl ControlClient {
    pub fn new(timeout_secs: u32, retries: u8) -> Self {
        Self {
            sequence: 0,
            timeout: Duration::from_secs(timeout_secs as u64),
            retries,
            local_addr: "0.0.0.0:0".parse().unwrap(),
        }
    }

    fn next_sequence(&mut self) -> u16 {
        let seq = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);
        seq
    }

    /// Send a Mode 6 request and collect the complete response (with fragment reassembly).
    pub fn query(
        &mut self,
        host: &str,
        port: u16,
        msg: ControlMessage,
    ) -> Result<(Vec<u8>, u16, u16), QueryError> {
        let addr: std::net::SocketAddr = format!("{host}:{port}")
            .parse()
            .map_err(|e| QueryError::Network(format!("addr: {e}")))?;

        let socket = std::net::UdpSocket::bind(self.local_addr)
            .map_err(|e| QueryError::Network(format!("bind: {e}")))?;
        socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| QueryError::Network(format!("timeout: {e}")))?;

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

        for attempt in 0..=self.retries {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(500));
            }

            socket
                .send_to(&request_bytes, addr)
                .map_err(|e| QueryError::Network(format!("send: {e}")))?;

            // Collect fragments
            let mut fragments: Vec<(u16, u16, Vec<u8>)> = Vec::new();
            let mut max_offset = 0u16;
            // Save the first fragment header bytes for status/associd extraction
            let mut first_hdr_saved: Option<[u8; 12]> = None;

            loop {
                let mut buf = vec![0u8; 512];
                match socket.recv_from(&mut buf) {
                    Ok((n, _src)) => {
                        let resp_data = &buf[..n];
                        let (resp, after_header) = ControlMessage::decode(resp_data)
                            .ok_or_else(|| QueryError::BadResponse("short header".to_string()))?;

                        // Save first header for status/associd
                        if first_hdr_saved.is_none() && n >= 12 {
                            let mut hdr = [0u8; 12];
                            hdr.copy_from_slice(&buf[..12]);
                            first_hdr_saved = Some(hdr);
                        }

                        // Verify this is a response to our request
                        if resp.sequence != seq {
                            continue;
                        }

                        let oc = resp.decode_opcode();
                        if !oc.response {
                            continue;
                        }

                        if oc.error {
                            let err_code = (resp.status >> 8) as u8;
                            let msg = format!("error code {}", err_code);
                            // Map known errors
                            if err_code == 1 {
                                return Err(QueryError::AuthFailure);
                            }
                            if err_code == 4 {
                                return Err(QueryError::NotFound);
                            }
                            return Err(QueryError::ProtocolError(msg));
                        }

                        let payload_end = resp.offset as usize + resp.count as usize;
                        if payload_end > after_header.len() {
                            return Err(QueryError::BadResponse(
                                "payload exceeds data".to_string(),
                            ));
                        }
                        let payload = after_header[resp.offset as usize..payload_end].to_vec();

                        fragments.push((resp.offset, resp.count, payload));

                        if resp.offset + resp.count > max_offset {
                            max_offset = resp.offset + resp.count;
                        }

                        if !oc.more {
                            break; // Last fragment
                        }
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut
                        {
                            if attempt < self.retries {
                                break; // Retry
                            }
                            return Err(QueryError::Timeout);
                        }
                        return Err(QueryError::Network(e.to_string()));
                    }
                }
            }

            if !fragments.is_empty() {
                fragments.sort_by_key(|(offset, _, _)| *offset);
                let mut assembled = Vec::with_capacity(max_offset as usize);
                for (_, _, data) in &fragments {
                    assembled.extend_from_slice(data);
                }
                // Status and associd from the first fragment header
                if let Some(hdr_bytes) = first_hdr_saved {
                    if let Some((first_hdr, _)) = ControlMessage::decode(&hdr_bytes) {
                        return Ok((assembled, first_hdr.status, first_hdr.associd));
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

// ──── Renderer ─────────────────────────────────────────────────────────

/// Render system variables in ntpq-compatible format.
pub fn format_readvar(sys: &SystemVariables) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "associd={} status={:04x} {},\n",
        sys.associd,
        sys.status,
        sys.leap_str()
    ));
    if let Some(ver) = sys.get("version") {
        out.push_str(&format!("version=\"{}\",\n", ver));
    }
    for key in [
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
    ] {
        if let Some(val) = sys.get(key) {
            out.push_str(&format!("{}={},\n", key, val));
        }
    }
    out
}

/// Render associations table in ntpq-compatible format.
pub fn format_associations(assocs: &[AssociationStatus]) -> String {
    let mut out = String::new();
    out.push_str("\nind assid status  conf reach auth condition  last_event cnt\n");
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
            "  {} {:5} {:04x}   {:3}  {:4}  {:4}  {:11}  {}  {}\n",
            i + 1,
            assoc.associd,
            assoc.status,
            conf,
            reach,
            auth,
            cond,
            "",
            "",
        ));
    }
    out
}

/// Render peers billboard in ntpq-compatible format.
pub fn format_peers(vars: &[(char, String, String, u8, f64, f64, f64)]) -> String {
    // Each entry: (tally, remote, refid, stratum, delay, offset, jitter)
    let mut out = String::new();
    out.push_str(
        "     remote           refid      st t when poll reach   delay   offset  jitter\n",
    );
    out.push_str(
        "==============================================================================\n",
    );
    for (tally, remote, refid, stratum, delay, offset, jitter) in vars {
        out.push_str(&format!(
            " {}{:16} {:12} {:2} u    -   64    1 {:7.3} {:8.3} {:7.3}\n",
            tally, remote, refid, stratum, delay, offset, jitter,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_readstat_bytes_parsing() {
        // Binary READSTAT response: 2 associations
        let data = vec![
            0x00, 0x01, // associd=1
            0x96, 0x14, // status = configured | reachable | sys.peer = 0x9614
            0x00, 0x02, // associd=2
            0x80, 0x10, // status = configured | reachable = 0x8010
        ];
        let assocs = AssociationStatus::from_bytes(&data).unwrap();
        assert_eq!(assocs.len(), 2);
        assert_eq!(assocs[0].associd, 1);
        assert!(assocs[0].configured);
        assert!(assocs[0].reachable);
        assert_eq!(assocs[0].selection, 6); // sys.peer
        assert_eq!(assocs[0].tally_char(), '*');
        assert_eq!(assocs[1].selection, 0); // rejected (no reachable bit in low bits)
        assert_eq!(assocs[1].tally_char(), ' ');
    }

    #[test]
    fn test_system_variables_parsing() {
        let text = "version=\"ntpd 4.2.8\",stratum=2,offset=0.005,leap=00";
        let sv = SystemVariables::from_text(text, 0, 0x0622);
        assert_eq!(sv.get("version"), Some("\"ntpd 4.2.8\""));
        assert_eq!(sv.get("stratum"), Some("2"));
        assert_eq!(sv.get("offset"), Some("0.005"));
        assert_eq!(sv.stratum(), 2);
        assert_eq!(sv.leap_str(), "leap_none");
    }

    #[test]
    fn test_peers_format() {
        let rows = vec![
            (
                '*',
                "127.0.0.1".to_string(),
                ".LOCL.".to_string(),
                1,
                0.000,
                0.000,
                0.001,
            ),
            (
                '+',
                "192.168.1.1".to_string(),
                "GPS".to_string(),
                2,
                1.234,
                0.567,
                2.345,
            ),
        ];
        let out = format_peers(&rows);
        assert!(out.contains("127.0.0.1"));
        assert!(out.contains("*"));
        assert!(out.contains("192.168.1.1"));
        assert!(out.contains("+"));
        assert!(out.contains("0.000"));
        assert!(out.contains("1.234"));
    }

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
    fn test_wrong_length_rejected() {
        let data = vec![0u8; 5]; // Not a multiple of 4
        assert!(AssociationStatus::from_bytes(&data).is_err());
    }
}
