// ──── daemon_engine.rs — Deterministic NTP daemon state machine ──────────
//
// The DaemonEngine is a pure, side-effect-free transition function:
//
//   handle(event) → Vec<DaemonAction>
//
// It takes a DaemonEvent (packet received, timer fired, shutdown) and
// returns a list of DaemonActions (send packet, adjust clock, persist
// state, log).  The actions are executed by the caller (real daemon or
// lab harness), keeping the engine itself deterministic and testable.
//
// ## Pipeline for each packet receive:
//
//   recv → validate → authenticate → clock_filter → clock_select →
//   clock_combine → local_clock → poll_update → transmit
//
// ## Phase 2.3B closure fixes
//
//   - PendingRequest struct keys on (originate_ts, source_addr) to prevent
//     multi-peer cross-talk when two peers poll in the same tick()
//   - IPv4 sockaddr_to_netaddr uses host-byte-order conversion
//   - Poll timers are one-shot; re-armed only on transmit, not on response.
//     Prevents timer multiplication over time.
//   - System state fully reset on selection failure (no stale offset)
//   - Contextual mode validation: server responses are only accepted from
//     expected-mode peers; client requests are the only accepted inbound mode
//   - Exhaustive restrict_action matching
//
// =============================================================================

use crate::ntp_auth::*;
use crate::ntp_config::*;
use crate::ntp_fp;
use crate::ntp_io::*;
use crate::ntp_leapsec::*;
use crate::ntp_loopfilter::*;
use crate::ntp_monitor::*;
use crate::ntp_peer::*;
use crate::ntp_proto::*;
use crate::ntp_restrict::*;
use crate::ntp_timer::*;
use crate::ntp_types::*;

/// A pending NTP request awaiting a server response.
/// Keyed by (originate_ts, destination) to prevent cross-peer confusion
/// when multiple peers poll in the same tick().
#[derive(Debug, Clone)]
struct PendingRequest {
    /// Peer index this request was sent to.
    peer_id: usize,
    /// Wire-format originate timestamp (T1).
    wire_t1: NtpTs,
    /// Full-resolution T1 timestamp.
    full_t1: NtpTs64,
    /// Expected source address of the response.
    destination: NetAddr,
    /// Expected response mode (Server for client polls, SymPassive for SymActive).
    expected_mode: NtpMode,
}

/// The deterministic daemon state machine.
#[derive(Debug)]
pub struct DaemonEngine {
    pub system: SystemState,
    pub peers: PeerTable,
    pub loop_filter: LoopFilter,
    pub timers: TimerQueue,
    pub auth: AuthKeyStore,
    pub restrictions: RestrictList,
    pub monitor: MonList,
    pub leap_table: LeapTable,
    pub config: ConfigTree,
    pub precision: i8,

    /// Minimum number of sane peers for the clock to synchronize.
    pub minsane: usize,

    /// Association ID of the system peer, or None if unsynchronized.
    pub system_peer_associd: Option<u16>,

    /// Index of the system peer (legacy, use associd instead).
    pub system_peer_id: Option<usize>,

    /// Monotonic counter for allocating association IDs.
    next_associd: u16,

    /// Pending requests awaiting server responses.
    pending_requests: Vec<PendingRequest>,
}

impl DaemonEngine {
    pub fn new(config: ConfigTree) -> Self {
        let mut engine = Self {
            system: SystemState::new(),
            peers: PeerTable::new(),
            loop_filter: LoopFilter::new(DisciplineType::PllFll),
            timers: TimerQueue::new(),
            auth: AuthKeyStore::new(),
            restrictions: RestrictList::new(),
            monitor: MonList::new(),
            leap_table: LeapTable::new(),
            precision: -20, // ~1 us typical
            minsane: 1,
            config: ConfigTree::new(),
            system_peer_associd: None,
            system_peer_id: None,
            next_associd: 1,
            pending_requests: Vec::new(),
        };
        engine.apply_config(config);
        engine
    }

    /// Apply configuration to the engine.
    fn apply_config(&mut self, config: ConfigTree) {
        self.config = config;
        for opt in &self.config.options {
            match opt {
                ConfigOption::Server {
                    ref addr,
                    ref options,
                }
                | ConfigOption::Peer {
                    ref addr,
                    ref options,
                }
                | ConfigOption::Pool {
                    ref addr,
                    ref options,
                } => {
                    let mode = match opt.directive_name() {
                        "peer" => NtpMode::SymActive,
                        _ => NtpMode::Client,
                    };
                    let (minpoll, maxpoll, iburst) = parse_assoc_options(options);

                    let srcaddr = addr.parse::<std::net::IpAddr>().ok().map(|ip| {
                        let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                        match ip {
                            std::net::IpAddr::V4(v4) => {
                                let sin =
                                    unsafe { &mut *(&mut sa as *mut _ as *mut libc::sockaddr_in) };
                                sin.sin_family = libc::AF_INET as libc::sa_family_t;
                                sin.sin_port = 123u16.to_be();
                                sin.sin_addr = libc::in_addr {
                                    s_addr: u32::from_ne_bytes(v4.octets()),
                                };
                            }
                            std::net::IpAddr::V6(v6) => {
                                let sin6 =
                                    unsafe { &mut *(&mut sa as *mut _ as *mut libc::sockaddr_in6) };
                                sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                                sin6.sin6_port = 123u16.to_be();
                                sin6.sin6_addr = libc::in6_addr {
                                    s6_addr: v6.octets(),
                                };
                            }
                        }
                        sa
                    });

                    if let Some(sa) = srcaddr {
                        let mut peer = Peer::new(sa, mode, NtpVersion::V4, minpoll, maxpoll);
                        peer.flags |= PeerFlags::CONFIGURED;
                        if iburst {
                            peer.flags |= PeerFlags::IBURST;
                        }
                        // Assign a unique association ID (collision-free across wrap)
                        if let Some(aid) =
                            Self::allocate_associd(&mut self.next_associd, &self.peers)
                        {
                            peer.associd = aid;
                        } else {
                            // ID space exhausted; skip this peer
                            continue;
                        }
                        let peer_id = self.peers.len();
                        self.peers.add(peer);
                        // Schedule initial poll as one-shot (re-armed on transmit)
                        self.timers.schedule_poll(peer_id, 0, 0);
                    }
                }
                ConfigOption::DriftFile(_) => {}
                ConfigOption::LeapFile(_path) => {}
                ConfigOption::TrustedKey(kid) => {
                    self.auth.add_trusted_key(*kid);
                }
                ConfigOption::ControlKey(kid) => {
                    self.auth.set_control_key(*kid);
                }
                ConfigOption::Keys(_path) => {
                    // Key file loading is done by the shell (main.rs).
                }
                ConfigOption::Restrict {
                    ref addr,
                    ref flags,
                } => {
                    let ipv4 = addr == "-4" || addr == "default";
                    let mut rflags = RestrictFlags::empty();
                    for f in flags {
                        rflags |= match f.as_str() {
                            "ignore" => RestrictFlags::IGNORE,
                            "nomodify" => RestrictFlags::NOMODIFY,
                            "nopeer" => RestrictFlags::NOPEER,
                            "noquery" => RestrictFlags::NOQUERY,
                            "notrap" => RestrictFlags::NOTRAP,
                            "notrust" => RestrictFlags::NOTRUST,
                            "limited" => RestrictFlags::LIMITED,
                            "kod" => RestrictFlags::KOD,
                            "noserve" => RestrictFlags::IGNORE,
                            "server" => RestrictFlags::SERVER,
                            _ => RestrictFlags::NONE,
                        };
                    }
                    if ipv4 || addr == "-6" {
                        if ipv4 {
                            self.restrictions.set_default_v4(rflags);
                        } else {
                            self.restrictions.set_default_v6(rflags);
                        }
                    } else {
                        // Parse an IP/mask restrict entry
                        if let Ok(ip) = addr.parse::<std::net::IpAddr>() {
                            let mut entry_addr: libc::sockaddr_storage =
                                unsafe { std::mem::zeroed() };
                            let mut entry_mask: libc::sockaddr_storage =
                                unsafe { std::mem::zeroed() };
                            match ip {
                                std::net::IpAddr::V4(v4) => {
                                    let sin = unsafe {
                                        &mut *(&mut entry_addr as *mut _ as *mut libc::sockaddr_in)
                                    };
                                    sin.sin_family = libc::AF_INET as libc::sa_family_t;
                                    sin.sin_addr = libc::in_addr {
                                        s_addr: u32::from_ne_bytes(v4.octets()),
                                    };
                                    let mask = unsafe {
                                        &mut *(&mut entry_mask as *mut _ as *mut libc::sockaddr_in)
                                    };
                                    mask.sin_family = libc::AF_INET as libc::sa_family_t;
                                    mask.sin_addr = libc::in_addr { s_addr: !0u32 };
                                }
                                std::net::IpAddr::V6(v6) => {
                                    let sin6 = unsafe {
                                        &mut *(&mut entry_addr as *mut _ as *mut libc::sockaddr_in6)
                                    };
                                    sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                                    sin6.sin6_addr = libc::in6_addr {
                                        s6_addr: v6.octets(),
                                    };
                                    let mask6 = unsafe {
                                        &mut *(&mut entry_mask as *mut _ as *mut libc::sockaddr_in6)
                                    };
                                    mask6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                                    mask6.sin6_addr = libc::in6_addr {
                                        s6_addr: [0xff; 16],
                                    };
                                }
                            }
                            self.restrictions
                                .add_entry(crate::ntp_restrict::RestrictEntry {
                                    addr: entry_addr,
                                    mask: entry_mask,
                                    flags: rflags,
                                    mru_depth: 0,
                                });
                        }
                    }
                }
                _ => {}
            }
        }
        // Schedule housekeeping and reachability timers (repeating)
        self.timers
            .add(TimerEntry::new(TimerEvent::Housekeeping, 64, 64));
        self.timers
            .add(TimerEntry::new(TimerEvent::Reachability, 64, 64));
    }

    /// Handle a single event. Returns actions for the shell to execute.
    pub fn handle(&mut self, event: DaemonEvent) -> Vec<DaemonAction> {
        match event {
            DaemonEvent::Shutdown => {
                vec![DaemonAction::Log("shutdown".to_string())]
            }
            DaemonEvent::TimerFired(timer_id) => self.handle_timer(timer_id),
            DaemonEvent::PacketReceived(dgram) => self.handle_packet(dgram),
        }
    }

    /// Allocate a unique association ID using a predicate for used-ID checking.
    /// Separated from the concrete PeerTable lookup so courts can test exhaustion
    /// without constructing 65,535 peers.
    fn allocate_associd_with<F>(next: &mut u16, mut is_used: F) -> Option<u16>
    where
        F: FnMut(u16) -> bool,
    {
        for _ in 0..u16::MAX {
            let c = *next;
            let candidate = if c == 0 { 1 } else { c };
            *next = if candidate == u16::MAX {
                1
            } else {
                candidate + 1
            };
            if !is_used(candidate) {
                return Some(candidate);
            }
        }
        None
    }

    /// Allocate a unique association ID for a new peer.
    /// Scans active IDs on wrap, delegates to the predicate-based allocator.
    fn allocate_associd(next: &mut u16, peers: &PeerTable) -> Option<u16> {
        Self::allocate_associd_with(next, |candidate| {
            peers.iter().any(|p| p.associd == candidate)
        })
    }

    /// Drain all due timers and return their actions.
    pub fn tick(&mut self, now: NtpTs64) -> Vec<DaemonAction> {
        let mut actions = Vec::new();
        for event in self.timers.pop_due(now) {
            match event {
                TimerEvent::Poll(id) => {
                    if let Some(peer) = self.peers.get_mut(id) {
                        let pkt = build_request(peer, &self.system, now, self.precision);

                        let dest = sockaddr_to_netaddr(&peer.srcaddr)
                            .unwrap_or(NetAddr::ipv4(0x7f000001, 123));

                        // Determine expected response mode
                        let expected_mode = if peer.hmode == NtpMode::SymActive {
                            NtpMode::SymPassive
                        } else {
                            NtpMode::Server
                        };

                        // Record pending request for response matching
                        self.pending_requests.push(PendingRequest {
                            peer_id: id,
                            wire_t1: pkt.transmit_ts,
                            full_t1: now,
                            destination: dest,
                            expected_mode,
                        });

                        // Limit pending to avoid unbounded growth
                        if self.pending_requests.len() > 1000 {
                            self.pending_requests.remove(0);
                        }

                        // Re-arm the next poll as one-shot with current poll interval
                        let interval = (1u64 << peer.hpoll) as u32;
                        self.timers
                            .schedule_poll_once(id, now.seconds + interval as i64);

                        actions.push(DaemonAction::Send {
                            destination: dest,
                            bytes: pkt.encode_header().to_vec(),
                        });
                    }
                }
                TimerEvent::Housekeeping => {
                    actions.extend(self.run_selection(now));
                }
                TimerEvent::Reachability => {
                    for i in 0..self.peers.len() {
                        if let Some(peer) = self.peers.get_mut(i) {
                            peer.reach.record_failure();
                        }
                    }
                }
                _ => {}
            }
        }
        actions
    }

    /// Run the clock selection / combine / discipline pipeline.
    fn run_selection(&mut self, now: NtpTs64) -> Vec<DaemonAction> {
        let mut actions = Vec::new();

        let peer_count = self.peers.len();
        if peer_count == 0 {
            return actions;
        }

        // Collect all peers into a Vec for the selection pipeline
        let mut peers_vec: Vec<Peer> = self.peers.iter().cloned().collect();

        // Run the full selection pipeline
        let sys_peer_idx = self.system.update_from_peers(&mut peers_vec, now);

        // Track system peer by both index (legacy) and association ID
        if sys_peer_idx < self.peers.len() {
            self.system_peer_id = Some(sys_peer_idx);
            self.system_peer_associd = self.peers.get(sys_peer_idx).map(|p| p.associd);
        } else {
            self.system_peer_id = None;
            self.system_peer_associd = None;
        }

        // Write updated peer state back
        for (i, p) in peers_vec.iter().enumerate() {
            if let Some(peer) = self.peers.get_mut(i) {
                peer.offset = p.offset;
                peer.delay = p.delay;
                peer.dispersion = p.dispersion;
                peer.jitter = p.jitter;
                peer.stratum = p.stratum;
                peer.leap = p.leap;
                peer.flash = p.flash;
            }
        }

        if self.system.peer_count > 0 {
            // Apply loop filter
            let adj = self.loop_filter.local_clock(self.system.sys_offset, now);
            actions.push(DaemonAction::AdjustClock(adj));

            // Persist drift periodically
            if self.loop_filter.update_count % 100 == 0 {
                actions.push(DaemonAction::PersistDrift(self.loop_filter.frequency_ppm()));
            }

            // Log status periodically
            if self.loop_filter.update_count % 10 == 0 {
                actions.push(DaemonAction::Log(format!(
                    "status peers={} stratum={} offset={:.6}s freq={:.3}ppm jitter={:.6}s",
                    self.system.peer_count,
                    self.system.stratum,
                    self.system.sys_offset,
                    self.loop_filter.frequency_ppm(),
                    self.system.sys_jitter,
                )));
            }
        }

        actions
    }

    /// Handle a received NTP packet.
    fn handle_packet(&mut self, dgram: ReceivedDatagram) -> Vec<DaemonAction> {
        // 0. Extract mode from raw byte 0 BEFORE deciding which decoder to use.
        // Mode 6 control protocol uses a 12-byte header, not 48-byte NTP.
        if dgram.bytes.is_empty() {
            return vec![DaemonAction::Log("empty packet".to_string())];
        }
        let mode = NtpMode::from_bits(dgram.bytes[0]);

        // ─── Mode 6 control protocol (ntpq) — dispatch before NTP decode ──
        if mode == NtpMode::NtpControl {
            // Check restrictions first
            let (restrict_action, _) = self.restrictions.check(&dgram.source, mode);
            match restrict_action {
                RestrictAction::Accept => {}
                RestrictAction::Ignore | RestrictAction::Discard => return vec![],
                RestrictAction::SendKod => {
                    return vec![DaemonAction::Log("kod for control".to_string())];
                }
            }
            return self.handle_control(&dgram.bytes, dgram.source);
        }

        // 1. Decode 48-byte NTP header for time protocol packets
        let pkt = match NtpPacket::decode_header(&dgram.bytes) {
            Ok(p) => p,
            Err(e) => return vec![DaemonAction::Log(format!("bad packet header: {e}"))],
        };

        // 2. Check restrictions — exhaustively match all actions.
        // NOQUERY is handled contextually inside check() based on packet mode.
        let (restrict_action, _restrict_flags) = self.restrictions.check(&dgram.source, mode);

        match restrict_action {
            RestrictAction::Accept => {} // Continue processing
            RestrictAction::Ignore | RestrictAction::Discard => return vec![],
            RestrictAction::SendKod => {
                let kod_pkt =
                    build_kod_packet(&pkt, &self.system, dgram.rx_timestamp, self.precision);
                return vec![DaemonAction::Send {
                    destination: dgram.source,
                    bytes: kod_pkt.encode_header().to_vec(),
                }];
            }
        }

        // 3. Check rate limiting for client requests
        if mode == NtpMode::Client || mode == NtpMode::SymActive {
            let (rate_limited, _) = self.monitor.is_rate_limited(&dgram.source);
            if rate_limited {
                return vec![];
            }
        }

        // 4. Basic size validation
        if dgram.bytes.len() < NTP_HEADER_SIZE {
            return vec![DaemonAction::Log("packet too short".to_string())];
        }

        // 5. Branch on mode with contextual expectations
        match mode {
            // ─── Client request → respond as server ────────────────────────
            NtpMode::Client | NtpMode::SymActive => {
                if self.system.stratum >= NTP_MAXSTRAT {
                    return vec![]; // Not synchronized yet
                }
                let resp =
                    build_response(&pkt, None, &self.system, dgram.rx_timestamp, self.precision);
                return vec![DaemonAction::Send {
                    destination: dgram.source,
                    bytes: resp.encode_header().to_vec(),
                }];
            }

            // ─── Server or SymPassive response → update matching peer ──
            NtpMode::Server | NtpMode::SymPassive => {
                return self.handle_server_response(pkt, dgram);
            }

            // ─── Unsupported modes ─────────────────────────────────────────
            _ => {
                return vec![];
            }
        }
    }

    /// Handle a server (or symmetric passive) response packet.
    fn handle_server_response(
        &mut self,
        pkt: NtpPacket,
        dgram: ReceivedDatagram,
    ) -> Vec<DaemonAction> {
        // Match against pending requests by (originate_ts, source, expected_mode)
        let req_idx = self.find_pending_request(&pkt.originate_ts, &dgram.source, pkt.mode());

        if let Some(req_idx) = req_idx {
            let req = self.pending_requests[req_idx].clone();
            let pidx = req.peer_id;

            if let Some(peer) = self.peers.get_mut(pidx) {
                // T1 = full-resolution stored originate timestamp
                let t1 = req.full_t1;
                // T2 = server's receive timestamp from packet
                let t2 = ntp_fp::ntp_ts_to_ntpts(pkt.receive_ts);
                // T3 = server's transmit timestamp from packet
                let t3 = ntp_fp::ntp_ts_to_ntpts(pkt.transmit_ts);
                // T4 = our receive timestamp
                let t4 = dgram.rx_timestamp;

                // Check for duplicate (TEST1) — same originate already processed
                if peer.originate_time == t1 {
                    return vec![DaemonAction::Log(
                        "duplicate packet (same originate)".to_string(),
                    )];
                }

                // Check if server is unsynchronized (TEST3)
                if pkt.stratum >= NTP_MAXSTRAT {
                    peer.reach.record_failure();
                    // Remove this pending request so we don't match against it again
                    self.pending_requests.remove(req_idx);
                    return vec![];
                }

                // Compute offset and delay
                let (offset, delay) = compute_offsets(t1, t2, t3, t4);

                // Validate offset is sane
                if !offset.is_finite() || offset.abs() > 1_000_000.0 {
                    self.pending_requests.remove(req_idx);
                    return vec![DaemonAction::Log("crazy offset rejected".to_string())];
                }

                let delay = delay.max(0.0);

                // Compute dispersion from peer's root dispersion + epsilon
                let dispersion = ntp_fp::ntp_short_to_double(NtpShort {
                    seconds: (pkt.root_dispersion >> 16) as u16,
                    fraction: pkt.root_dispersion as u16,
                }) + (1u64 << peer.hpoll) as f64 * 1e-6;

                // Update peer variables from the response packet
                peer.stratum = pkt.stratum;
                peer.leap = pkt.leap_indicator();
                peer.precision = pkt.precision;
                peer.root_delay = ntp_fp::ntp_short_to_double(NtpShort {
                    seconds: (pkt.root_delay >> 16) as u16,
                    fraction: pkt.root_delay as u16,
                });
                peer.root_dispersion = ntp_fp::ntp_short_to_double(NtpShort {
                    seconds: (pkt.root_dispersion >> 16) as u16,
                    fraction: pkt.root_dispersion as u16,
                });
                peer.reference_id = pkt.reference_id;
                peer.reference_time = ntp_fp::ntp_ts_to_ntpts(pkt.reference_ts);

                // Accept the sample into the clock filter
                accept_sample(peer, offset, delay, dispersion, dgram.rx_timestamp);

                // Record originate to detect duplicates
                peer.originate_time = t1;

                // Update poll interval
                poll_update(peer, dgram.rx_timestamp);

                // Remove the pending request — response consumed
                self.pending_requests.remove(req_idx);
            }
        } else {
            // Unsolicited response or broadcast — silently drop
            return vec![];
        }

        vec![]
    }

    /// Handle a Mode 6 control protocol request (ntpq).
    fn handle_control(&mut self, bytes: &[u8], source: NetAddr) -> Vec<DaemonAction> {
        use crate::ntp_control::*;

        let exchange = match ControlExchange::parse(bytes) {
            Ok((ex, _)) => ex,
            Err(e) => {
                return vec![DaemonAction::Log(format!("bad control message: {e}"))];
            }
        };

        let req = &exchange.request;
        let oc = req.decode_opcode();

        // Determine which opcodes require authentication.
        // NTPsec: READSTAT, READVAR, READCLOCK, READ_MRU do not require auth;
        // WRITEVAR, CONFIGURE, READ_ORDLIST_A do.
        let requires_auth = matches!(
            oc.op,
            opcodes::OP_WRITEVAR | opcodes::OP_CONFIGURE | opcodes::OP_READ_ORDLIST_A
        );

        // Check authentication if a control key is configured.
        // The key ID used MUST match the configured control key.
        let configured_ckey = self.auth.get_control_key();
        let auth_valid = configured_ckey.map_or(false, |ckey| {
            // Verify key ID matches the configured control key
            exchange.auth_keyid == Some(ckey)
                // Verify the configured key exists in the store
                && self.auth.get_key(ckey).is_some()
                // Verify the MAC
                && exchange.verify_mac(&self.auth)
        });

        // If auth is required and not valid, return error.
        if requires_auth && !auth_valid {
            // Build a proper control error response (error bit set, error code 1 = Auth)
            let err_header = ControlMessage {
                li_vn_mode: req.li_vn_mode,
                opcode: ControlOpcode::new(true, true, false, oc.op).to_u8(),
                sequence: req.sequence,
                status: 0x0100, // Error code 1 in high byte = authentication failure
                associd: req.associd,
                offset: 0,
                count: 0,
            };
            return vec![DaemonAction::Send {
                destination: source,
                bytes: err_header.encode().to_vec(),
            }];
        }

        // For non-required ops, auth is optional but still verified if present.
        // NTPsec does not authenticate responses for ordinary READVAR/READSTAT.
        // We always pass None for auth_key to build_response (no MAC on responses).
        let _auth_valid = auth_valid;

        // Build the response data based on opcode
        let resp_data = match oc.op {
            // READSTAT: return binary associd/status pairs (ntpq associations)
            opcodes::OP_READSTAT => {
                let mut data = Vec::with_capacity(self.peers.len() * 4);
                for i in 0..self.peers.len() {
                    if let Some(peer) = self.peers.get(i) {
                        let associd = if peer.associd > 0 {
                            peer.associd
                        } else {
                            (i + 1) as u16
                        };
                        data.extend_from_slice(&associd.to_be_bytes());
                        let sel = if self.system_peer_associd == Some(peer.associd) {
                            crate::ntp_control::SelectionStatus::SystemPeer
                        } else if peer.reach.is_reachable() && peer.stratum < 16 {
                            crate::ntp_control::SelectionStatus::Candidate
                        } else {
                            crate::ntp_control::SelectionStatus::Rejected
                        };
                        data.extend_from_slice(
                            &crate::ntp_control::peer_status(peer, sel).to_be_bytes(),
                        );
                    }
                }
                data
            }

            // READVAR, READ_ORDLIST_A: associd==0 → system vars, else → peer vars
            opcodes::OP_READVAR | opcodes::OP_READ_ORDLIST_A => {
                if req.associd == 0 {
                    // System variables
                    let mut vars: Vec<(String, String)> = Vec::new();
                    let sys_names = [
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
                    for name in &sys_names {
                        if let Some(val) = get_system_variable(&self.system, name) {
                            vars.push((name.to_string(), val));
                        }
                    }
                    encode_var_list(
                        &vars
                            .iter()
                            .map(|(k, v)| (k.as_str(), v.as_str()))
                            .collect::<Vec<_>>(),
                    )
                    .into_bytes()
                } else {
                    // Peer variables for a specific association (look up by associd)
                    let peer_opt = self.peers.iter().find(|p| p.associd == req.associd);
                    if let Some(peer) = peer_opt {
                        let mut vars: Vec<(String, String)> = Vec::new();
                        let peer_names = [
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
                        for name in &peer_names {
                            if let Some(val) = get_peer_variable(peer, name) {
                                vars.push((name.to_string(), val));
                            }
                        }
                        encode_var_list(
                            &vars
                                .iter()
                                .map(|(k, v)| (k.as_str(), v.as_str()))
                                .collect::<Vec<_>>(),
                        )
                        .into_bytes()
                    } else {
                        // Peer not found — return error
                        let err_header = ControlMessage {
                            li_vn_mode: req.li_vn_mode,
                            opcode: ControlOpcode::new(true, true, false, oc.op).to_u8(),
                            sequence: req.sequence,
                            status: 0x0400, // Error code 4 = NotFound
                            associd: req.associd,
                            offset: 0,
                            count: 0,
                        };
                        return vec![DaemonAction::Send {
                            destination: source,
                            bytes: err_header.encode().to_vec(),
                        }];
                    }
                }
            }

            _ => {
                // Unsupported opcode — emit proper BADOP error
                let err_header = ControlMessage {
                    li_vn_mode: req.li_vn_mode,
                    opcode: ControlOpcode::new(true, true, false, oc.op).to_u8(),
                    sequence: req.sequence,
                    status: 0x0300, // Error code 3 = Format error / BADOP
                    associd: req.associd,
                    offset: 0,
                    count: 0,
                };
                return vec![DaemonAction::Send {
                    destination: source,
                    bytes: err_header.encode().to_vec(),
                }];
            }
        };

        // Build the response status word.
        // For associd != 0 READVAR, use peer status; otherwise system status.
        let status = if oc.op == opcodes::OP_READVAR && req.associd != 0 {
            // Look up the peer for its status
            if let Some(peer) = self.peers.iter().find(|p| p.associd == req.associd) {
                let sel = if self.system_peer_associd == Some(peer.associd) {
                    crate::ntp_control::SelectionStatus::SystemPeer
                } else if peer.reach.is_reachable() && peer.stratum < 16 {
                    crate::ntp_control::SelectionStatus::Candidate
                } else {
                    crate::ntp_control::SelectionStatus::Rejected
                };
                peer_status(peer, sel)
            } else {
                // Peer not found — this shouldn't happen since we validated above
                sys_status::make(3, 0, 0, 4)
            }
        } else {
            let li = match self.system.leap {
                LeapIndicator::NoWarning => 0,
                LeapIndicator::AddLeapSecond => 1,
                LeapIndicator::RemoveLeapSecond => 2,
                LeapIndicator::Alarm => 3,
            };
            let clock_source = if self.system.stratum < NTP_MAXSTRAT {
                6
            } else {
                0
            };
            sys_status::make(li, clock_source, 0, 0)
        };

        // No MAC on responses (per NTPsec behavior for ordinary control requests)
        let response = ControlExchange::build_response(req, &resp_data, req.sequence, status, None);

        vec![DaemonAction::Send {
            destination: source,
            bytes: response,
        }]
    }

    /// Find a pending request matching the response's originate timestamp,
    /// source address, and mode.
    fn find_pending_request(
        &self,
        originate_ts: &NtpTs,
        source: &NetAddr,
        mode: NtpMode,
    ) -> Option<usize> {
        for (i, req) in self.pending_requests.iter().enumerate() {
            let ts_match = req.wire_t1.seconds == originate_ts.seconds
                && req.wire_t1.fraction == originate_ts.fraction;
            let addr_match = req.destination.family == source.family
                && req.destination.addr == source.addr
                && req.destination.port == source.port;
            let mode_match = mode == req.expected_mode;

            if ts_match && addr_match && mode_match {
                return Some(i);
            }
        }
        None
    }

    /// Handle a timer event.
    fn handle_timer(&mut self, timer_id: TimerId) -> Vec<DaemonAction> {
        match timer_id {
            TimerId::Housekeeping => {
                let now = NtpTs64 {
                    seconds: 0,
                    fraction: 0,
                };
                self.run_selection(now)
            }
            _ => vec![],
        }
    }
}

/// Build a Kiss-o'-Death packet in response to a client request.
pub fn build_kod_packet(
    request: &NtpPacket,
    _system: &SystemState,
    now: NtpTs64,
    precision: i8,
) -> NtpPacket {
    let mut resp = NtpPacket::zeroed();
    resp.li_vn_mode =
        NtpPacket::set_li_vn_mode(LeapIndicator::Alarm, NtpVersion::V4, NtpMode::Server);
    resp.stratum = 0;
    resp.poll = request.poll;
    resp.precision = precision;
    resp.root_delay = 0;
    resp.root_dispersion = 0;
    resp.reference_id = crate::ntp_types::kiss_codes::RATE;
    resp.originate_ts = request.transmit_ts;
    resp.receive_ts = ntp_fp::ntp_ts64_to_ntpts(now);
    resp.transmit_ts = ntp_fp::ntp_ts64_to_ntpts(now);
    resp
}

/// Parse association options into structured form.
fn parse_assoc_options(options: &[String]) -> (u8, u8, bool) {
    let mut minpoll = NTP_MINPOLL;
    let mut maxpoll = NTP_MAXPOLL;
    let mut iburst = false;
    let mut i = 0;
    while i < options.len() {
        match options[i].as_str() {
            "iburst" => iburst = true,
            "burst" => {}
            "prefer" => {}
            s if s == "minpoll" && i + 1 < options.len() => {
                if let Ok(p) = options[i + 1].parse::<u8>() {
                    minpoll = p;
                }
                i += 1;
            }
            s if s == "maxpoll" && i + 1 < options.len() => {
                if let Ok(p) = options[i + 1].parse::<u8>() {
                    maxpoll = p;
                }
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    (minpoll, maxpoll, iburst)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntp_fp;

    /// Helper to create a minimal simulated engine for tests.
    fn create_lab_engine() -> (DaemonEngine, SimulatedClock) {
        let config = ConfigTree::new();
        let engine = DaemonEngine::new(config);
        let clock = SimulatedClock::unix_epoch();
        (engine, clock)
    }

    /// Helper to build a NetAddr for a peer, matching the engine's internal
    /// sockaddr_to_netaddr conversion (using to_ne_bytes).
    fn peer_netaddr(ip: [u8; 4], port: u16) -> NetAddr {
        let mut addr = [0u8; 16];
        addr[..4].copy_from_slice(&ip);
        NetAddr {
            family: 4,
            addr,
            port,
        }
    }

    /// Add a peer to an engine and return its ID.
    /// Add a peer and schedule its initial one-shot poll timer.
    /// Mirrors what apply_config() does for real associations.
    fn add_peer(engine: &mut DaemonEngine, ip: [u8; 4]) -> usize {
        let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let sin = unsafe { &mut *(&mut sa as *mut _ as *mut libc::sockaddr_in) };
        sin.sin_family = libc::AF_INET as libc::sa_family_t;
        sin.sin_port = 123u16.to_be();
        sin.sin_addr = libc::in_addr {
            s_addr: u32::from_ne_bytes(ip),
        };
        let id = engine.peers.len();
        engine
            .peers
            .add(Peer::new(sa, NtpMode::Client, NtpVersion::V4, 4, 10));
        // Schedule initial one-shot poll (matching apply_config)
        engine.timers.schedule_poll_once(id, 0);
        id
    }

    #[test]
    fn test_engine_creation() {
        let (engine, _) = create_lab_engine();
        assert_eq!(engine.system.stratum, NTP_MAXSTRAT);
        assert_eq!(engine.peers.len(), 0);
    }

    #[test]
    fn test_engine_tick_empty() {
        let mut engine = DaemonEngine::new(ConfigTree::new());
        let now = ntp_fp::ts_to_ntp(0, 0);
        let actions = engine.tick(now);
        assert!(actions.is_empty(), "no timers due at time 0");
    }

    #[test]
    fn test_engine_shutdown() {
        let mut engine = DaemonEngine::new(ConfigTree::new());
        let actions = engine.handle(DaemonEvent::Shutdown);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], DaemonAction::Log(_)));
    }

    #[test]
    fn test_engine_bad_packet() {
        let mut engine = DaemonEngine::new(ConfigTree::new());
        let dgram = ReceivedDatagram::test(
            vec![0u8; 10],
            peer_netaddr([127, 0, 0, 1], 123),
            peer_netaddr([127, 0, 0, 1], 123),
            ntp_fp::ts_to_ntp(1000, 0),
        );
        let actions = engine.handle(DaemonEvent::PacketReceived(dgram));
        assert!(actions
            .iter()
            .any(|a| matches!(a, DaemonAction::Log(s) if s.contains("bad packet"))));
    }

    #[test]
    fn test_engine_server_response_processing() {
        let mut engine = DaemonEngine::new(ConfigTree::new());
        let peer_id = add_peer(&mut engine, [127, 0, 0, 1]);

        let t1 = ntp_fp::ts_to_ntp(1000, 0);
        let t1_wire = ntp_fp::ntp_ts64_to_ntpts(t1);

        // Register a pending request manually (as tick() would)
        engine.pending_requests.push(PendingRequest {
            peer_id,
            wire_t1: t1_wire,
            full_t1: t1,
            destination: peer_netaddr([127, 0, 0, 1], 123),
            expected_mode: NtpMode::Server,
        });

        // Build server response
        let mut resp = NtpPacket::zeroed();
        resp.li_vn_mode =
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Server);
        resp.stratum = 2;
        resp.originate_ts = t1_wire;
        resp.receive_ts = ntp_fp::ntp_ts64_to_ntpts(ntp_fp::ts_to_ntp(1001, 0));
        resp.transmit_ts = ntp_fp::ntp_ts64_to_ntpts(ntp_fp::ts_to_ntp(1001, 500_000_000));

        let dgram = ReceivedDatagram::test(
            resp.encode_header().to_vec(),
            peer_netaddr([127, 0, 0, 1], 123),
            peer_netaddr([127, 0, 0, 1], 123),
            ntp_fp::ts_to_ntp(1002, 0),
        );

        let _actions = engine.handle(DaemonEvent::PacketReceived(dgram));

        // No pending requests should remain
        assert!(engine.pending_requests.is_empty());
        // Peer should be reachable with correct offset
        if let Some(peer) = engine.peers.get(peer_id) {
            assert!(peer.reach.is_reachable());
            assert!(
                (peer.offset - 0.25).abs() < 0.1,
                "expected offset ~0.25s, got {}",
                peer.offset
            );
        }
    }

    /// Test that two peers polled at the same instant don't cross-talk:
    /// each response must match the correct peer, even if responses arrive
    /// in reverse order.
    #[test]
    fn test_engine_multi_peer_no_crosstalk() {
        let mut engine = DaemonEngine::new(ConfigTree::new());
        let peer_a = add_peer(&mut engine, [127, 0, 0, 1]); // 127.0.0.1
        let peer_b = add_peer(&mut engine, [192, 0, 2, 44]); // 192.0.2.44

        // Tick at time 0 — both peers get one-shot polls re-armed
        let actions = engine.tick(ntp_fp::ts_to_ntp(0, 0));

        // Should have 2 Send actions
        assert_eq!(actions.len(), 2);
        assert!(actions
            .iter()
            .all(|a| matches!(a, DaemonAction::Send { .. })));

        // Should have 2 pending requests
        assert_eq!(engine.pending_requests.len(), 2);

        // Build responses that arrive in REVERSE order:
        // Response B arrives first, then Response A.
        let t1_a = engine.pending_requests[0].wire_t1;
        let t1_b = engine.pending_requests[1].wire_t1;

        // Response for B (192.0.2.44)
        let mut resp_b = NtpPacket::zeroed();
        resp_b.li_vn_mode =
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Server);
        resp_b.stratum = 3;
        resp_b.originate_ts = t1_b;
        resp_b.receive_ts = ntp_fp::ntp_ts64_to_ntpts(ntp_fp::ts_to_ntp(1, 0));
        resp_b.transmit_ts = ntp_fp::ntp_ts64_to_ntpts(ntp_fp::ts_to_ntp(1, 250_000_000));

        let dgram_b = ReceivedDatagram::test(
            resp_b.encode_header().to_vec(),
            peer_netaddr([192, 0, 2, 44], 123),
            peer_netaddr([127, 0, 0, 1], 123),
            ntp_fp::ts_to_ntp(2, 0),
        );

        // Process B's response first
        let _actions_b = engine.handle(DaemonEvent::PacketReceived(dgram_b));

        // Only the B pending request should be consumed
        assert_eq!(engine.pending_requests.len(), 1);
        assert_eq!(engine.pending_requests[0].peer_id, peer_a);

        // Peer B should be reachable, Peer A should not yet be
        assert!(
            engine.peers.get(peer_b).unwrap().reach.is_reachable(),
            "peer B should be reachable"
        );
        assert!(
            !engine.peers.get(peer_a).unwrap().reach.is_reachable(),
            "peer A should NOT be reachable yet"
        );

        // Now process A's response
        let mut resp_a = NtpPacket::zeroed();
        resp_a.li_vn_mode =
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Server);
        resp_a.stratum = 2;
        resp_a.originate_ts = t1_a;
        resp_a.receive_ts = ntp_fp::ntp_ts64_to_ntpts(ntp_fp::ts_to_ntp(1, 0));
        resp_a.transmit_ts = ntp_fp::ntp_ts64_to_ntpts(ntp_fp::ts_to_ntp(1, 500_000_000));

        let dgram_a = ReceivedDatagram::test(
            resp_a.encode_header().to_vec(),
            peer_netaddr([127, 0, 0, 1], 123),
            peer_netaddr([127, 0, 0, 1], 123),
            ntp_fp::ts_to_ntp(2, 0),
        );

        let _actions_a = engine.handle(DaemonEvent::PacketReceived(dgram_a));

        // All pending requests consumed
        assert!(engine.pending_requests.is_empty());

        // Both peers should be reachable
        assert!(engine.peers.get(peer_a).unwrap().reach.is_reachable());
        assert!(engine.peers.get(peer_b).unwrap().reach.is_reachable());
    }

    /// Test that poll timers don't multiply: after 100 responses, only 1
    /// poll timer exists per peer.
    #[test]
    fn test_engine_no_timer_multiplication() {
        let mut engine = DaemonEngine::new(ConfigTree::new());
        let peer_id = add_peer(&mut engine, [127, 0, 0, 1]);

        // Simulate 100 poll/response cycles.
        // The first iteration consumes the initial one-shot poll at due=0.
        for _ in 0..100 {
            // Find the next due time of the poll timer for this peer
            let next_due = engine
                .timers
                .iter()
                .find_map(|entry| match entry.event {
                    TimerEvent::Poll(id) if id == peer_id => Some(entry.due),
                    _ => None,
                })
                .expect("peer should have exactly one poll timer");

            // Tick at the due time — fires the poll, creates pending request, re-arms one-shot
            let actions = engine.tick(ntp_fp::ts_to_ntp(next_due, 0));
            assert!(
                actions
                    .iter()
                    .any(|a| matches!(a, DaemonAction::Send { .. })),
                "poll should produce exactly one Send action"
            );
            assert_eq!(
                engine.pending_requests.len(),
                1,
                "poll should create exactly one pending request"
            );

            // Clone the request before mutating engine
            let req = engine.pending_requests[0].clone();

            // Build a valid server response
            let mut resp = NtpPacket::zeroed();
            resp.li_vn_mode = NtpPacket::set_li_vn_mode(
                LeapIndicator::NoWarning,
                NtpVersion::V4,
                NtpMode::Server,
            );
            resp.stratum = 4;
            resp.originate_ts = req.wire_t1;
            resp.receive_ts = ntp_fp::ntp_ts64_to_ntpts(ntp_fp::ts_to_ntp(next_due + 1, 0));
            resp.transmit_ts =
                ntp_fp::ntp_ts64_to_ntpts(ntp_fp::ts_to_ntp(next_due + 1, 500_000_000));

            let dgram = ReceivedDatagram {
                bytes: resp.encode_header().to_vec(),
                source: peer_netaddr([127, 0, 0, 1], 123),
                destination: peer_netaddr([127, 0, 0, 1], 123),
                rx_timestamp: ntp_fp::ts_to_ntp(next_due + 2, 0),
                interface_index: None,
                timestamp_source: TimestampSource::UserspaceFallback,
            };

            // Consume the response — this should NOT create any new timers
            engine.handle(DaemonEvent::PacketReceived(dgram));
            assert!(
                engine.pending_requests.is_empty(),
                "response should consume the pending request"
            );

            // Exactly 1 poll timer should exist after each cycle
            let poll_timers = engine
                .timers
                .iter()
                .filter(|t| matches!(t.event, TimerEvent::Poll(id) if id == peer_id))
                .count();
            assert_eq!(
                poll_timers, 1,
                "exactly 1 poll timer should exist after cycle, got {}",
                poll_timers
            );
        }

        // After 100 cycles: exactly 1 poll timer for the peer
        let poll_timers = engine
            .timers
            .iter()
            .filter(|t| matches!(t.event, TimerEvent::Poll(id) if id == peer_id))
            .count();
        assert_eq!(
            poll_timers, 1,
            "should have exactly 1 poll timer after 100 cycles, got {}",
            poll_timers
        );
    }

    /// Test that losing all peers stops clock adjustment.
    ///
    /// This test simulates the synchronized state directly on the loop_filter
    /// and system, then removes all reachable peers and verifies the engine
    /// does not emit a stale AdjustClock.
    #[test]
    fn test_engine_stale_state_reset() {
        let mut engine = DaemonEngine::new(ConfigTree::new());
        let _peer_id = add_peer(&mut engine, [127, 0, 0, 1]);

        // Simulate a synchronized state directly on the loop filter
        engine.loop_filter.clock_set = true;
        engine.loop_filter.offset = 0.05;
        engine.loop_filter.last_update = ntp_fp::ts_to_ntp(1000, 0);

        // Set system state to synchronized
        engine.system.stratum = 4;
        engine.system.peer_count = 1;
        engine.system.sys_offset = 0.05;

        // Run housekeeping with the peer unreachable.
        // Since the peer has reach=0, update_from_peers will find no survivors
        // and reset peer_count to 0. run_selection() then skips clock adjustment.
        let actions = engine.tick(ntp_fp::ts_to_ntp(2000, 0));
        let clock_adjusts: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, DaemonAction::AdjustClock(_)))
            .collect();

        // With no survivors, system should NOT emit AdjustClock
        assert!(
            clock_adjusts.is_empty(),
            "no AdjustClock should be emitted when no peers survive selection"
        );
        assert_eq!(
            engine.system.peer_count, 0,
            "peer_count should be 0 after losing all peers"
        );
        assert_eq!(
            engine.system.leap,
            LeapIndicator::Alarm,
            "leap should be Alarm when unsynchronized"
        );
    }

    #[test]
    fn test_engine_client_request_response() {
        let mut engine = DaemonEngine::new(ConfigTree::new());
        engine.system.stratum = 3;
        engine.system.leap = LeapIndicator::NoWarning;
        engine.system.root_delay = 0.001;
        engine.system.root_dispersion = 0.001;

        let mut req = NtpPacket::zeroed();
        req.li_vn_mode =
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Client);
        req.transmit_ts = ntp_fp::ntp_ts64_to_ntpts(ntp_fp::ts_to_ntp(2000, 0));

        let dgram = ReceivedDatagram {
            bytes: req.encode_header().to_vec(),
            source: peer_netaddr([192, 168, 0, 1], 45678),
            destination: peer_netaddr([127, 0, 0, 1], 123),
            rx_timestamp: ntp_fp::ts_to_ntp(2001, 0),
            interface_index: None,
            timestamp_source: TimestampSource::UserspaceFallback,
        };

        let actions = engine.handle(DaemonEvent::PacketReceived(dgram));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, DaemonAction::Send { .. })),
            "should respond to client request"
        );

        if let Some(DaemonAction::Send { bytes, .. }) = actions.first() {
            let resp = NtpPacket::decode_header(bytes).unwrap();
            assert_eq!(resp.mode(), NtpMode::Server);
            assert_eq!(resp.stratum, 3);
            assert_eq!(resp.originate_ts, req.transmit_ts);
        }
    }

    #[test]
    fn test_simulated_clock_advance() {
        let mut clock = SimulatedClock::unix_epoch();
        let t0 = clock.now();
        assert_eq!(t0.seconds, ntp_fp::ts_to_ntp(0, 0).seconds);

        clock.advance(64.0);
        let t1 = clock.now();
        assert_eq!(t1.seconds, ntp_fp::ts_to_ntp(64, 0).seconds);
    }

    #[test]
    fn test_memory_state_store() {
        let mut store = MemoryStateStore::new();
        assert!(store.load_drift().is_err());

        store.drift = Some(42.5);
        assert_eq!(store.load_drift().unwrap(), 42.5);

        assert!(store.append_stats("loopstats", "test line").is_ok());
        assert_eq!(store.stats.len(), 1);
    }

    #[test]
    fn test_replay_network() {
        let dgram = ReceivedDatagram {
            bytes: vec![0u8; 48],
            source: peer_netaddr([127, 0, 0, 1], 123),
            destination: peer_netaddr([127, 0, 0, 1], 123),
            rx_timestamp: ntp_fp::ts_to_ntp(1000, 0),
            interface_index: None,
            timestamp_source: TimestampSource::UserspaceFallback,
        };
        let mut net = ReplayNetwork::new(vec![dgram.clone()]);
        assert!(net.bind("0.0.0.0:123").is_ok());
        let recv = net.recv().unwrap();
        assert_eq!(recv.bytes, vec![0u8; 48]);
        assert!(net.recv().is_err());

        // Verify sent packet recording
        let dest = peer_netaddr([192, 168, 1, 1], 123);
        assert!(net.send(&[1u8; 48], &dest).is_ok());
        assert_eq!(net.sent_packets.len(), 1);
        assert_eq!(net.sent_packets[0].1, vec![1u8; 48]);
    }

    #[test]
    fn test_kod_packet() {
        let mut req = NtpPacket::zeroed();
        req.li_vn_mode =
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Client);
        req.transmit_ts = ntp_fp::ntp_ts64_to_ntpts(ntp_fp::ts_to_ntp(500, 0));

        let system = SystemState::new();
        let now = ntp_fp::ts_to_ntp(501, 0);
        let kod = build_kod_packet(&req, &system, now, -20);

        assert_eq!(kod.stratum, 0);
        assert_eq!(kod.mode(), NtpMode::Server);
        assert_eq!(kod.originate_ts, req.transmit_ts);
    }

    #[test]
    fn test_build_request_ntp_proto() {
        let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let sin = unsafe { &mut *(&mut sa as *mut _ as *mut libc::sockaddr_in) };
        sin.sin_family = libc::AF_INET as libc::sa_family_t;
        sin.sin_port = 123u16.to_be();
        sin.sin_addr = libc::in_addr {
            s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        };
        let peer = Peer::new(sa, NtpMode::Client, NtpVersion::V4, 4, 10);
        let system = SystemState::new();
        let now = ntp_fp::ts_to_ntp(1000, 0);

        let pkt = build_request(&peer, &system, now, -20);
        assert_eq!(pkt.mode(), NtpMode::Client);
        assert_eq!(pkt.version(), NtpVersion::V4);
        assert_eq!(pkt.transmit_ts, ntp_fp::ntp_ts64_to_ntpts(now));
    }

    /// Decisive court: full pipeline with two peers, poll, response,
    /// selection, and stale-state reset.
    #[test]
    fn test_full_deterministic_pipeline() {
        let mut engine = DaemonEngine::new(ConfigTree::new());
        let peer_a = add_peer(&mut engine, [127, 0, 0, 1]);
        let peer_b = add_peer(&mut engine, [10, 0, 0, 1]);

        let now = ntp_fp::ts_to_ntp(0, 0);

        // 1. Initial tick emits two correctly addressed requests
        let actions = engine.tick(now);
        assert_eq!(actions.len(), 2, "two peers → two Send actions");
        assert_eq!(engine.pending_requests.len(), 2, "two pending requests");
        assert!(actions
            .iter()
            .all(|a| matches!(a, DaemonAction::Send { .. })));

        // Verify request addresses
        let addrs: Vec<_> = actions
            .iter()
            .filter_map(|a| {
                if let DaemonAction::Send { destination, .. } = a {
                    Some((
                        destination.addr[0],
                        destination.addr[1],
                        destination.addr[2],
                        destination.addr[3],
                    ))
                } else {
                    None
                }
            })
            .collect();
        assert!(addrs.contains(&(127, 0, 0, 1)), "peer A address");
        assert!(addrs.contains(&(10, 0, 0, 1)), "peer B address");

        // 2. Responses arrive in reverse order
        // Clone before mutating to avoid borrow conflicts
        let req_b = engine.pending_requests[1].clone();
        let req_a = engine.pending_requests[0].clone();

        let mut resp_b = NtpPacket::zeroed();
        resp_b.li_vn_mode =
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Server);
        resp_b.stratum = 3;
        resp_b.originate_ts = req_b.wire_t1;
        resp_b.receive_ts = ntp_fp::ntp_ts64_to_ntpts(ntp_fp::ts_to_ntp(1, 0));
        resp_b.transmit_ts = ntp_fp::ntp_ts64_to_ntpts(ntp_fp::ts_to_ntp(1, 500_000_000));

        let dgram_b = ReceivedDatagram {
            bytes: resp_b.encode_header().to_vec(),
            source: peer_netaddr([10, 0, 0, 1], 123),
            destination: peer_netaddr([127, 0, 0, 1], 123),
            rx_timestamp: ntp_fp::ts_to_ntp(2, 0),
            interface_index: None,
            timestamp_source: TimestampSource::UserspaceFallback,
        };
        engine.handle(DaemonEvent::PacketReceived(dgram_b));
        assert_eq!(
            engine.pending_requests.len(),
            1,
            "one pending after B's response"
        );

        let mut resp_a = NtpPacket::zeroed();
        resp_a.li_vn_mode =
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Server);
        resp_a.stratum = 2; // peer A is lower stratum → becomes system peer
        resp_a.originate_ts = req_a.wire_t1;
        resp_a.receive_ts = ntp_fp::ntp_ts64_to_ntpts(ntp_fp::ts_to_ntp(1, 0));
        resp_a.transmit_ts = ntp_fp::ntp_ts64_to_ntpts(ntp_fp::ts_to_ntp(1, 250_000_000));

        let dgram_a = ReceivedDatagram {
            bytes: resp_a.encode_header().to_vec(),
            source: peer_netaddr([127, 0, 0, 1], 123),
            destination: peer_netaddr([127, 0, 0, 1], 123),
            rx_timestamp: ntp_fp::ts_to_ntp(2, 0),
            interface_index: None,
            timestamp_source: TimestampSource::UserspaceFallback,
        };
        engine.handle(DaemonEvent::PacketReceived(dgram_a));
        assert!(engine.pending_requests.is_empty(), "all requests consumed");

        // 3. Both peers reachable
        assert!(engine.peers.get(peer_a).unwrap().reach.is_reachable());
        assert!(engine.peers.get(peer_b).unwrap().reach.is_reachable());

        // 4. Housekeeping: run selection → system state synchronized
        let house_actions = engine.tick(ntp_fp::ts_to_ntp(64, 0));
        assert_eq!(
            engine.system.peer_count, 2,
            "both peers should survive selection"
        );
        assert!(engine.system.stratum <= 4, "stratum set from best peer");
        assert!(
            house_actions
                .iter()
                .any(|a| matches!(a, DaemonAction::AdjustClock(_))),
            "AdjustClock should fire when synchronized"
        );

        // 5. Make all peers unreachable
        for i in 0..engine.peers.len() {
            if let Some(peer) = engine.peers.get_mut(i) {
                for _ in 0..8 {
                    peer.reach.record_failure();
                }
            }
        }

        // 6. Housekeeping again → system unsynchronized, no stale AdjustClock
        let stale_actions = engine.tick(ntp_fp::ts_to_ntp(128, 0));
        let has_clock_adj = stale_actions
            .iter()
            .any(|a| matches!(a, DaemonAction::AdjustClock(_)));
        assert!(!has_clock_adj, "no AdjustClock when all peers unreachable");
        assert_eq!(engine.system.peer_count, 0, "no survivors");
        assert_eq!(engine.system.leap, LeapIndicator::Alarm);
    }

    /// Test wrong-source rejection: a response from an unexpected source
    /// address should not match the pending request.
    #[test]
    fn test_engine_wrong_source_rejected() {
        let mut engine = DaemonEngine::new(ConfigTree::new());
        let peer_id = add_peer(&mut engine, [192, 168, 1, 1]);

        // Tick to generate a pending request
        engine.tick(ntp_fp::ts_to_ntp(0, 0));
        assert_eq!(engine.pending_requests.len(), 1);
        let req = engine.pending_requests[0].clone();

        // Response from WRONG source
        let mut resp = NtpPacket::zeroed();
        resp.li_vn_mode =
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Server);
        resp.stratum = 3;
        resp.originate_ts = req.wire_t1;
        resp.receive_ts = ntp_fp::ntp_ts64_to_ntpts(ntp_fp::ts_to_ntp(1, 0));
        resp.transmit_ts = ntp_fp::ntp_ts64_to_ntpts(ntp_fp::ts_to_ntp(1, 500_000_000));

        // Source is 10.0.0.1, but we polled 192.168.1.1
        let dgram = ReceivedDatagram {
            bytes: resp.encode_header().to_vec(),
            source: peer_netaddr([10, 0, 0, 1], 123),
            destination: peer_netaddr([127, 0, 0, 1], 123),
            rx_timestamp: ntp_fp::ts_to_ntp(2, 0),
            interface_index: None,
            timestamp_source: TimestampSource::UserspaceFallback,
        };
        let _actions = engine.handle(DaemonEvent::PacketReceived(dgram));

        // Response should be rejected — pending request still present
        assert_eq!(engine.pending_requests.len(), 1, "pending should remain");
        assert!(
            !engine.peers.get(peer_id).unwrap().reach.is_reachable(),
            "peer should NOT be reachable from wrong source"
        );
    }

    /// Test wrong-mode rejection: a response with wrong mode should not match.
    #[test]
    fn test_engine_wrong_mode_rejected() {
        let mut engine = DaemonEngine::new(ConfigTree::new());
        let peer_id = add_peer(&mut engine, [127, 0, 0, 1]);

        // Tick to generate a pending request
        engine.tick(ntp_fp::ts_to_ntp(0, 0));
        assert_eq!(engine.pending_requests.len(), 1);
        let req = engine.pending_requests[0].clone();

        // Response with WRONG mode (Broadcast instead of Server)
        let mut resp = NtpPacket::zeroed();
        resp.li_vn_mode =
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Broadcast);
        resp.stratum = 3;
        resp.originate_ts = req.wire_t1;
        resp.receive_ts = ntp_fp::ntp_ts64_to_ntpts(ntp_fp::ts_to_ntp(1, 0));
        resp.transmit_ts = ntp_fp::ntp_ts64_to_ntpts(ntp_fp::ts_to_ntp(1, 500_000_000));

        let dgram = ReceivedDatagram {
            bytes: resp.encode_header().to_vec(),
            source: peer_netaddr([127, 0, 0, 1], 123),
            destination: peer_netaddr([127, 0, 0, 1], 123),
            rx_timestamp: ntp_fp::ts_to_ntp(2, 0),
            interface_index: None,
            timestamp_source: TimestampSource::UserspaceFallback,
        };
        let _actions = engine.handle(DaemonEvent::PacketReceived(dgram));

        // Response should be rejected — pending request still present
        assert_eq!(engine.pending_requests.len(), 1, "pending should remain");
        assert!(
            !engine.peers.get(peer_id).unwrap().reach.is_reachable(),
            "peer should NOT be reachable from wrong mode"
        );
    }

    /// Test the full adapter stack: SimulatedClock, ReplayNetwork, MemoryStateStore,
    /// and DaemonEngine working together through action dispatch.
    ///
    /// This manually dispatches DaemonActions to adapters, proving the
    /// real/lab shared execution boundary works end-to-end.
    #[test]
    fn test_full_adapter_stack() {
        use crate::ntp_io::{MemoryStateStore, ReplayNetwork, SimulatedClock};

        let mut engine = DaemonEngine::new(ConfigTree::new());
        let peer_id = add_peer(&mut engine, [10, 0, 0, 1]);

        let mut clock = SimulatedClock::unix_epoch();
        let mut network = ReplayNetwork::new(Vec::new());
        let mut store = MemoryStateStore::new();

        // Helper: manually dispatch a Send action to ReplayNetwork.
        // We use discrete function calls rather than a closure to avoid
        // borrow conflicts with subsequent assertions.
        let t0 = clock.now();

        // 1. Tick → Send action dispatched to ReplayNetwork
        let now = ntp_fp::ts_to_ntp(0, 0);
        let timer_actions = engine.tick(now);
        assert!(
            timer_actions
                .iter()
                .any(|a| matches!(a, DaemonAction::Send { .. })),
            "tick should produce Send action"
        );
        // Dispatch Send to ReplayNetwork
        for action in timer_actions {
            if let DaemonAction::Send { destination, bytes } = action {
                network.send(&bytes, &destination).ok();
            }
        }

        // ReplayNetwork should have recorded the sent packet
        assert_eq!(
            network.sent_packets.len(),
            1,
            "ReplayNetwork should record sent packets"
        );
        assert_eq!(
            network.sent_packets[0].1.len(),
            48,
            "sent packet should be 48 bytes"
        );

        // 2. Inject a response via ReplayNetwork's recv buffer
        let req = engine.pending_requests[0].clone();
        let mut resp = NtpPacket::zeroed();
        resp.li_vn_mode =
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Server);
        resp.stratum = 3;
        resp.originate_ts = req.wire_t1;
        resp.receive_ts = ntp_fp::ntp_ts64_to_ntpts(ntp_fp::ts_to_ntp(1, 0));
        resp.transmit_ts = ntp_fp::ntp_ts64_to_ntpts(ntp_fp::ts_to_ntp(1, 500_000_000));

        // Manually provide the response datagram to the engine
        let dgram = ReceivedDatagram {
            bytes: resp.encode_header().to_vec(),
            source: peer_netaddr([10, 0, 0, 1], 123),
            destination: peer_netaddr([127, 0, 0, 1], 123),
            rx_timestamp: ntp_fp::ts_to_ntp(2, 0),
            interface_index: None,
            timestamp_source: TimestampSource::UserspaceFallback,
        };

        let resp_actions = engine.handle(DaemonEvent::PacketReceived(dgram));
        // Dispatch clock adjustments to SimulatedClock
        for action in resp_actions {
            if let DaemonAction::AdjustClock(adj) = action {
                match adj {
                    Adjustment::Step(offset) => {
                        clock.step(offset).ok();
                    }
                    Adjustment::Slew(offset, freq) => {
                        clock.slew(offset, freq).ok();
                    }
                    _ => {}
                }
            }
        }

        // Peer should be reachable
        assert!(
            engine.peers.get(peer_id).unwrap().reach.is_reachable(),
            "peer should be reachable after response"
        );

        // 3. Advance clock to housekeeping → selection → AdjustClock → SimulatedClock
        let house_time = ntp_fp::ts_to_ntp(64, 0);
        let house_actions = engine.tick(house_time);

        // Dispatch clock adjustments to SimulatedClock
        let mut has_adjust = false;
        for action in house_actions {
            if let DaemonAction::AdjustClock(adj) = action {
                has_adjust = true;
                match adj {
                    Adjustment::Step(offset) => {
                        clock.step(offset).ok();
                    }
                    Adjustment::Slew(offset, freq) => {
                        clock.slew(offset, freq).ok();
                    }
                    _ => {}
                }
            }
        }

        // If synchronized, the clock should have changed
        if has_adjust {
            let t1 = clock.now();
            assert!(
                t1.seconds != t0.seconds || t1.fraction != t0.fraction,
                "SimulatedClock should change after AdjustClock"
            );
        }

        // 4. PersistDrift action → MemoryStateStore
        assert!(store.save_drift(42.5).is_ok());
        assert_eq!(
            store.load_drift().unwrap(),
            42.5,
            "MemoryStateStore should persist drift through save_drift"
        );

        // 5. Verify ReplayNetwork recorded all sends
        // tick(0) produced 1 send; no other sends in this test
        assert_eq!(
            network.sent_packets.len(),
            1,
            "exactly one packet should have been sent"
        );
    }

    /// End-to-end Mode 6 control request: send a literal 16-byte ntpq READVAR
    /// request and verify the response matches ntpq expectations.
    #[test]
    fn test_engine_mode6_readvar() {
        use crate::ntp_control::*;

        let mut engine = DaemonEngine::new(ConfigTree::new());
        engine.system.stratum = 3;
        engine.system.leap = LeapIndicator::NoWarning;
        engine.system.sys_offset = 0.005;

        // Build a literal Mode 6 READVAR request (16 bytes typical):
        //   Bytes: LI=0 VN=4 Mode=6 = 0x26
        //          Opcode: R=0 E=0 M=0 Op=2 (READVAR) = 0x02
        //          Sequence: 0x0001
        //          Status: 0x0000 (request, system status is ignored)
        //          Assocation ID: 0x0000 (system, not peer)
        //          Offset: 0x0000
        //          Count: 0x0000 (no data)
        let mut msg = ControlMessage::zeroed();
        msg.li_vn_mode = NtpPacket::set_li_vn_mode(
            LeapIndicator::NoWarning,
            NtpVersion::V4,
            NtpMode::NtpControl,
        );
        msg.opcode = ControlOpcode::new(false, false, false, opcodes::OP_READVAR).to_u8();
        msg.sequence = 1;
        msg.associd = 0;
        msg.count = 0;

        let mut packet = msg.encode().to_vec();
        // Zero-pad to 16 bytes (multiple of 8, typical for real ntpq)
        packet.resize(16, 0);

        let dgram = ReceivedDatagram::test(
            packet,
            peer_netaddr([192, 168, 1, 100], 45678),
            peer_netaddr([127, 0, 0, 1], 123),
            ntp_fp::ts_to_ntp(0, 0),
        );

        let actions = engine.handle(DaemonEvent::PacketReceived(dgram));

        // Should produce a Send action with the response
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, DaemonAction::Send { .. })),
            "Mode 6 READVAR should produce a Send response"
        );

        // Decode the response
        if let Some(DaemonAction::Send { bytes, .. }) = actions.first() {
            // Response must contain at least the 12-byte header
            assert!(bytes.len() >= 12, "response must be >= 12 bytes");

            let (resp_header, resp_data) =
                ControlMessage::decode(bytes).expect("valid control response header");

            // Verify response flags
            let oc = resp_header.decode_opcode();
            assert!(oc.response, "response bit should be set");
            assert!(!oc.error, "error bit should not be set");
            assert_eq!(oc.op, opcodes::OP_READVAR, "opcode should match");
            assert_eq!(resp_header.sequence, 1, "sequence should match");
            assert_eq!(resp_header.associd, 0, "association ID should match");

            // Response data should contain system variables (text)
            let data_str = String::from_utf8_lossy(resp_data);
            assert!(
                data_str.contains("version"),
                "response should contain version"
            );
            assert!(
                data_str.contains("stratum"),
                "response should contain stratum"
            );
            assert!(
                data_str.contains("offset"),
                "response should contain offset"
            );
            assert!(
                data_str.contains("3"),
                "response should contain stratum value 3"
            );
        }
    }

    /// Test that a short Mode 6 packet (12 bytes, no padding) is accepted.
    #[test]
    fn test_engine_mode6_minimal() {
        use crate::ntp_control::*;

        let mut engine = DaemonEngine::new(ConfigTree::new());
        engine.system.stratum = 2;

        let mut msg = ControlMessage::zeroed();
        msg.li_vn_mode = NtpPacket::set_li_vn_mode(
            LeapIndicator::NoWarning,
            NtpVersion::V4,
            NtpMode::NtpControl,
        );
        msg.opcode = ControlOpcode::new(false, false, false, opcodes::OP_READVAR).to_u8();
        msg.sequence = 42;
        msg.associd = 0;
        msg.count = 0;

        let dgram = ReceivedDatagram::test(
            msg.encode().to_vec(),
            peer_netaddr([10, 0, 0, 55], 12345),
            peer_netaddr([127, 0, 0, 1], 123),
            ntp_fp::ts_to_ntp(0, 0),
        );

        let actions = engine.handle(DaemonEvent::PacketReceived(dgram));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, DaemonAction::Send { .. })),
            "12-byte Mode 6 request should be processed"
        );

        if let Some(DaemonAction::Send { bytes, .. }) = actions.first() {
            let (resp_header, _) = ControlMessage::decode(bytes).unwrap();
            let oc = resp_header.decode_opcode();
            assert!(oc.response);
            assert_eq!(resp_header.sequence, 42);
        }
    }

    /// Precision court: association allocator wraps around occupied IDs.
    #[test]
    fn test_associd_allocator_wrap() {
        let mut next: u16 = u16::MAX - 2;
        let mut peers = PeerTable::new();
        // Simulate 4 occupied peers at the wrap boundary
        for a in [u16::MAX - 2, u16::MAX - 1, u16::MAX, 1] {
            let mut p = Peer::new(
                unsafe { std::mem::zeroed() },
                NtpMode::Client,
                NtpVersion::V4,
                4,
                10,
            );
            p.associd = a;
            peers.add(p);
        }
        // Allocator should skip occupied IDs and return the first free ID (2)
        let aid = DaemonEngine::allocate_associd(&mut next, &peers);
        assert_eq!(aid, Some(2), "allocator should skip occupied IDs at wrap");
        // Next allocation should be 3
        let aid2 = DaemonEngine::allocate_associd(&mut next, &peers);
        assert_eq!(
            aid2,
            Some(3),
            "second alloc should be sequential after wrap"
        );
    }

    /// Precision court: allocator skips occupied prefix.
    #[test]
    fn test_associd_allocator_skips_occupied_prefix() {
        let mut next: u16 = 1;
        let mut peers = PeerTable::new();
        for a in 1..=100u16 {
            let mut p = Peer::new(
                unsafe { std::mem::zeroed() },
                NtpMode::Client,
                NtpVersion::V4,
                4,
                10,
            );
            p.associd = a;
            peers.add(p);
        }
        let aid = DaemonEngine::allocate_associd(&mut next, &peers);
        assert_eq!(aid, Some(101), "should skip occupied 1..100");
    }

    /// Precision court: all 65535 IDs exhausted returns None.
    /// Uses the predicate-based allocator to avoid constructing 65535 peers.
    #[test]
    fn test_associd_allocator_exhaustion() {
        let mut next: u16 = 1;
        let aid = DaemonEngine::allocate_associd_with(&mut next, |_| true);
        assert_eq!(aid, None, "every ID used → exhaustion");
    }

    /// Precision court: AES-CMAC short key zero-padding matches explicit 16-byte key.
    #[test]
    fn test_aes_short_key_zero_padding() {
        use crate::ntp_auth::*;
        // A 7-byte key should be zero-padded to 16 bytes
        let short_key = NtpAuthKey::new(1, DigestType::Aes128Cmac, b"1234567".to_vec());
        // Explicit 16-byte key with same bytes + zero padding
        let mut padded = [0u8; 16];
        padded[..7].copy_from_slice(b"1234567");
        let explicit_key = NtpAuthKey::new(2, DigestType::Aes128Cmac, padded.to_vec());

        let test_data = b"NTP test data for CMAC computation";
        let mac_short = short_key.mac(test_data);
        let mac_explicit = explicit_key.mac(test_data);

        assert!(mac_short.is_some(), "short key should produce MAC");
        assert!(mac_explicit.is_some(), "explicit key should produce MAC");
        assert_eq!(
            mac_short, mac_explicit,
            "zero-padded short key should match explicit 16-byte key"
        );
    }
}
