// ──── ntp_signd.rs ──────────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/ntp_signd.c
//
// Samba signing protocol support for MS-SNTP authentication.
// =============================================================================

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

/// The default path to the Samba NTP signing socket.
pub const DEFAULT_SIGN_SOCKET_PATH: &str = "/var/run/samba/ntp_signd";

/// The default timeout for signing socket I/O operations (milliseconds).
pub const DEFAULT_SIGN_TIMEOUT_MS: u64 = 2000;

/// Maximum NTP packet size as defined by RFC 5905.
const NTP_MAX_PACKET_SIZE: usize = 512;

/// Signing request message type marker (sent by client to signd).
const SIGNING_REQUEST_TYPE: u32 = 0;
/// Signing response message type marker (received from signd).
const SIGNING_RESPONSE_TYPE: u32 = 1;

// ──── Errors ────────────────────────────────────────────────────────────────

/// Errors that can occur during MS-SNTP signing operations.
#[derive(Debug)]
pub enum SigndError {
    /// The signing socket does not exist or is inaccessible.
    SocketNotFound(String),
    /// Could not connect to the signing daemon.
    ConnectionFailed(String),
    /// A write to the signing socket failed.
    WriteFailed(String),
    /// A read from the signing socket failed.
    ReadFailed(String),
    /// The signing daemon returned an invalid response (wrong length,
    /// wrong type, etc.).
    InvalidResponse(String),
    /// The I/O operation timed out.
    TimedOut(String),
}

impl std::fmt::Display for SigndError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SocketNotFound(s) => write!(f, "signing socket not found: {s}"),
            Self::ConnectionFailed(s) => write!(f, "connection to signing daemon failed: {s}"),
            Self::WriteFailed(s) => write!(f, "write to signing socket failed: {s}"),
            Self::ReadFailed(s) => write!(f, "read from signing socket failed: {s}"),
            Self::InvalidResponse(s) => write!(f, "invalid response from signing daemon: {s}"),
            Self::TimedOut(s) => write!(f, "signing operation timed out: {s}"),
        }
    }
}

impl std::error::Error for SigndError {}

// ──── Signing Client ────────────────────────────────────────────────────────

/// A client for the Samba NTP signing daemon (`samba-dcerpcd` or
/// `samba-ntp-sign`).
///
/// MS-SNTP uses a Unix domain socket to communicate with Samba's signing
/// daemon.  The daemon signs NTP packets with the domain controller's Kerberos
/// keys so that the NTP response can be authenticated by an Active Directory
/// domain member.
///
/// ## Protocol
///
/// The Samba signing protocol uses a simple framing format:
///
/// ```text
/// Client → Daemon:
///   [4 bytes: length (big-endian u32, includes these 4 bytes)]
///   [4 bytes: request type (big-endian u32, value 0)]
///   [NTP packet data]
///
/// Daemon → Client:
///   [4 bytes: length (big-endian u32, includes these 4 bytes)]
///   [4 bytes: response type (big-endian u32, value 1)]
///   [Signed NTP packet data]
/// ```
///
/// The response NTP packet includes the authentication MAC (Message
/// Authentication Code) appended to the standard NTP header.
#[derive(Debug)]
pub struct SigndClient {
    /// Path to the Samba signing Unix domain socket.
    socket_path: PathBuf,
    /// I/O timeout for socket operations.
    timeout: Duration,
}

impl SigndClient {
    /// Create a new `SigndClient` with the default socket path.
    pub fn new() -> Self {
        Self {
            socket_path: PathBuf::from(DEFAULT_SIGN_SOCKET_PATH),
            timeout: Duration::from_millis(DEFAULT_SIGN_TIMEOUT_MS),
        }
    }

    /// Create a new `SigndClient` with a custom socket path.
    pub fn with_path<P: AsRef<Path>>(path: P) -> Self {
        Self {
            socket_path: path.as_ref().to_path_buf(),
            timeout: Duration::from_millis(DEFAULT_SIGN_TIMEOUT_MS),
        }
    }

    /// Set the I/O timeout for socket operations.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Get a reference to the configured socket path.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Check whether the signing socket exists on the filesystem.
    ///
    /// This is a quick check — it does not attempt to connect.  The socket
    /// may still be unavailable at connect time (e.g. permissions, daemon not
    /// listening).
    pub fn is_available(&self) -> bool {
        self.socket_path.exists()
    }

    /// Send an NTP packet to the signing daemon and return the signed response.
    ///
    /// The `ntp_packet` should be the raw NTP response packet (header +
    /// extension fields, if any).  The signing daemon will append the
    /// appropriate Kerberos-based authentication MAC and return the signed
    /// packet.
    ///
    /// # Arguments
    ///
    /// * `ntp_packet` — The NTP response packet to be signed.  Must not exceed
    ///   `NTP_MAX_PACKET_SIZE` bytes.
    ///
    /// # Returns
    ///
    /// The signed NTP packet (with authentication data appended).
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be reached, the daemon returns
    /// an invalid response, or the operation times out.
    pub fn sign_request(&self, ntp_packet: &[u8]) -> Result<Vec<u8>, SigndError> {
        if ntp_packet.len() > NTP_MAX_PACKET_SIZE {
            return Err(SigndError::InvalidResponse(format!(
                "NTP packet too large: {} bytes (max {NTP_MAX_PACKET_SIZE})",
                ntp_packet.len()
            )));
        }

        // Connect to the signing daemon.
        let mut stream = UnixStream::connect(&self.socket_path).map_err(|e| {
            SigndError::ConnectionFailed(format!(
                "could not connect to {}: {e}",
                self.socket_path.display()
            ))
        })?;

        // Set read and write timeouts.
        stream.set_read_timeout(Some(self.timeout)).map_err(|e| {
            SigndError::ConnectionFailed(format!("failed to set read timeout: {e}"))
        })?;
        stream.set_write_timeout(Some(self.timeout)).map_err(|e| {
            SigndError::ConnectionFailed(format!("failed to set write timeout: {e}"))
        })?;

        // ----- Build the request frame -----
        // Frame format:
        //   [4 bytes: total length (big-endian)]
        //   [4 bytes: request type (big-endian, 0)]
        //   [NTP packet data]
        let total_len = 4 +                     // length field itself
            4 +                                  // request type field
            ntp_packet.len(); // NTP packet

        let mut request = Vec::with_capacity(total_len);
        request.extend_from_slice(&(total_len as u32).to_be_bytes());
        request.extend_from_slice(&SIGNING_REQUEST_TYPE.to_be_bytes());
        request.extend_from_slice(ntp_packet);

        // Send the request.
        stream.write_all(&request).map_err(|e| {
            SigndError::WriteFailed(format!(
                "failed to write to {}: {e}",
                self.socket_path.display()
            ))
        })?;

        // Flush to ensure all data is sent.
        stream
            .flush()
            .map_err(|e| SigndError::WriteFailed(format!("failed to flush: {e}")))?;

        // ----- Read the response frame -----
        // Frame format:
        //   [4 bytes: total length (big-endian)]
        //   [4 bytes: response type (big-endian, 1)]
        //   [Signed NTP packet data]
        let mut header_buf = [0u8; 8];

        // Read the 8-byte header (length + type).
        stream.read_exact(&mut header_buf).map_err(|e| {
            if e.kind() == std::io::ErrorKind::TimedOut
                || e.kind() == std::io::ErrorKind::WouldBlock
            {
                SigndError::TimedOut(format!(
                    "timeout reading response header from {}",
                    self.socket_path.display()
                ))
            } else {
                SigndError::ReadFailed(format!(
                    "failed to read response header from {}: {e}",
                    self.socket_path.display()
                ))
            }
        })?;

        let response_total_len =
            u32::from_be_bytes([header_buf[0], header_buf[1], header_buf[2], header_buf[3]])
                as usize;
        let response_type =
            u32::from_be_bytes([header_buf[4], header_buf[5], header_buf[6], header_buf[7]]);

        // Validate the response type.
        if response_type != SIGNING_RESPONSE_TYPE {
            return Err(SigndError::InvalidResponse(format!(
                "unexpected response type {response_type}, expected {SIGNING_RESPONSE_TYPE}"
            )));
        }

        // The total length includes the 4-byte length field and 4-byte type field.
        if response_total_len < 8 {
            return Err(SigndError::InvalidResponse(format!(
                "response total length too small: {response_total_len}"
            )));
        }

        // The signed packet data length.
        let signed_len = response_total_len - 8;

        // Cap the response to a reasonable size (NTP max + some margin for the MAC).
        // The MAC adds up to ~20 bytes (MD5) to ~88 bytes (full Kerberos ticket).
        const MAX_RESPONSE_SIZE: usize = NTP_MAX_PACKET_SIZE + 256;
        if signed_len > MAX_RESPONSE_SIZE {
            return Err(SigndError::InvalidResponse(format!(
                "signed packet too large: {signed_len} bytes (max {MAX_RESPONSE_SIZE})"
            )));
        }

        // Read the signed packet data.
        let mut signed_packet = vec![0u8; signed_len];
        if signed_len > 0 {
            stream.read_exact(&mut signed_packet).map_err(|e| {
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock
                {
                    SigndError::TimedOut(format!(
                        "timeout reading signed packet from {}",
                        self.socket_path.display()
                    ))
                } else {
                    SigndError::ReadFailed(format!(
                        "failed to read signed packet from {}: {e}",
                        self.socket_path.display()
                    ))
                }
            })?;
        }

        Ok(signed_packet)
    }

    /// Convenience method: sign an NTP response if the signing daemon is
    /// available, or return `None` if the socket does not exist.
    ///
    /// This is useful for callers that want to gracefully degrade to unsigned
    /// responses when signing is not configured.
    pub fn try_sign_request(&self, ntp_packet: &[u8]) -> Option<Vec<u8>> {
        if !self.is_available() {
            return None;
        }
        self.sign_request(ntp_packet).ok()
    }
}

impl Default for SigndClient {
    fn default() -> Self {
        Self::new()
    }
}

// ──── Global client for the legacy function API ─────────────────────────────

/// Global signing client, initialized once at daemon startup.
static GLOBAL_SIGND_CLIENT: OnceLock<SigndClient> = OnceLock::new();

/// Initialize the global signing client with a custom socket path.
///
/// Must be called before using `sign_ms_sntp_response` or
/// `is_signing_available` if a non-default socket path is needed.
/// Subsequent calls are silently ignored (first call wins).
pub fn init_signd_client<P: AsRef<Path>>(socket_path: P) {
    let client = SigndClient::with_path(socket_path);
    let _ = GLOBAL_SIGND_CLIENT.set(client);
}

/// Sign a response for MS-SNTP using the Samba signing daemon.
///
/// Returns `Some(())` if signing succeeded (the `response` buffer is updated
/// in place with the signed packet).  Returns `None` if signing is not
/// configured or fails.
///
/// This function preserves the signature expected by existing callers in the
/// codebase.  `request` is the original client request (used for context),
/// `response` is the server response to be signed, and `_key_id` is unused
/// in the Samba protocol (the signing daemon selects the key).
pub fn sign_ms_sntp_response(_request: &[u8], response: &mut [u8], _key_id: u32) -> Option<()> {
    let client = GLOBAL_SIGND_CLIENT.get()?;
    let signed = client.try_sign_request(response)?;

    // Copy the signed data back into the response buffer.
    let copy_len = signed.len().min(response.len());
    response[..copy_len].copy_from_slice(&signed[..copy_len]);
    Some(())
}

/// Check if MS-SNTP signing is configured (sign socket exists).
///
/// Checks the global client first (if initialized), then falls back to
/// checking the default socket path on the filesystem.
pub fn is_signing_available() -> bool {
    // Try the global client first.
    if let Some(client) = GLOBAL_SIGND_CLIENT.get() {
        if client.is_available() {
            return true;
        }
    }
    // Fall back: check the default socket path directly.
    Path::new(DEFAULT_SIGN_SOCKET_PATH).exists()
}

// ──── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;
    use std::thread;

    /// Helper: find a temp directory for test sockets.
    fn test_socket_dir() -> PathBuf {
        let dir = std::env::temp_dir().join("ntpsec-signd-test");
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    #[test]
    fn test_signd_client_default_path() {
        let client = SigndClient::new();
        assert_eq!(client.socket_path(), Path::new(DEFAULT_SIGN_SOCKET_PATH));
        assert_eq!(
            client.socket_path().to_string_lossy(),
            DEFAULT_SIGN_SOCKET_PATH
        );
    }

    #[test]
    fn test_signd_client_custom_path() {
        let client = SigndClient::with_path("/tmp/test_signd.sock");
        assert_eq!(client.socket_path(), Path::new("/tmp/test_signd.sock"));
    }

    #[test]
    fn test_signd_client_custom_timeout() {
        let client = SigndClient::new().with_timeout(Duration::from_secs(5));
        assert!(!client.is_available()); // Socket doesn't exist.
    }

    #[test]
    fn test_is_available_no_socket() {
        let client = SigndClient::new();
        assert!(!client.is_available());
    }

    #[test]
    fn test_is_available_with_socket() {
        let sock_path = test_socket_dir().join("test_available_ntp_signd.sock");
        // Create a fake socket file (just for path existence testing).
        let _ = std::fs::write(&sock_path, b"");

        let client = SigndClient::with_path(&sock_path);
        assert!(client.is_available());

        let _ = std::fs::remove_file(&sock_path);
    }

    #[test]
    fn test_sign_request_no_daemon() {
        let sock_path = test_socket_dir().join("nonexistent_signd.sock");
        let client = SigndClient::with_path(&sock_path);
        let packet = vec![0u8; 48];

        let result = client.sign_request(&packet);
        assert!(result.is_err());
        match result.unwrap_err() {
            SigndError::ConnectionFailed(_) => {} // Expected.
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn test_try_sign_request_no_daemon() {
        let sock_path = test_socket_dir().join("another_nonexistent.sock");
        let client = SigndClient::with_path(&sock_path);
        let packet = vec![0u8; 48];

        let result = client.try_sign_request(&packet);
        assert!(result.is_none());
    }

    #[test]
    fn test_sign_request_packet_too_large() {
        let client = SigndClient::new();
        let packet = vec![0u8; NTP_MAX_PACKET_SIZE + 1];

        let result = client.sign_request(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_ms_sntp_response_no_init() {
        let mut response = vec![0u8; 48];
        let result = sign_ms_sntp_response(&[], &mut response, 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_init_signd_client_and_available() {
        let sock_path = test_socket_dir().join("init_test.sock");
        init_signd_client(&sock_path);
        assert!(!is_signing_available());

        let _ = std::fs::write(&sock_path, b"");
        assert!(is_signing_available());

        let _ = std::fs::remove_file(&sock_path);
    }

    #[test]
    fn test_signd_error_display() {
        let err = SigndError::SocketNotFound("/var/run/samba/ntp_signd".to_string());
        let msg = format!("{err}");
        assert!(msg.contains("socket not found"));

        let err = SigndError::ConnectionFailed("connection refused".to_string());
        let msg = format!("{err}");
        assert!(msg.contains("connection refused"));

        let err = SigndError::InvalidResponse("bad type".to_string());
        let msg = format!("{err}");
        assert!(msg.contains("invalid response"));
    }

    #[test]
    fn test_signd_client_debug() {
        let client = SigndClient::new();
        let debug = format!("{client:?}");
        assert!(debug.contains("SigndClient"));
        assert!(debug.contains(DEFAULT_SIGN_SOCKET_PATH));
    }

    #[test]
    fn test_default_is_signing_available() {
        let _available = is_signing_available();
    }

    #[test]
    fn test_signd_client_roundtrip_with_mock_daemon() {
        let sock_path = test_socket_dir().join("mock_signd_roundtrip.sock");
        let _ = std::fs::remove_file(&sock_path);

        let listener = UnixListener::bind(&sock_path).unwrap();
        let (tx, rx) = mpsc::channel();

        let handle = thread::spawn(move || {
            let (mut stream, _addr) = listener.accept().unwrap();

            let mut header = [0u8; 8];
            stream.read_exact(&mut header).unwrap();
            let req_len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
            let req_type = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
            assert_eq!(req_type, SIGNING_REQUEST_TYPE);

            let packet_len = req_len - 8;
            let mut packet = vec![0u8; packet_len];
            if packet_len > 0 {
                stream.read_exact(&mut packet).unwrap();
            }

            // Build mock signed response: original + 16-byte MAC.
            let mut signed = packet.clone();
            signed.extend_from_slice(&[0xABu8; 16]);

            let total_len = 8 + signed.len();
            let mut response = Vec::new();
            response.extend_from_slice(&(total_len as u32).to_be_bytes());
            response.extend_from_slice(&SIGNING_RESPONSE_TYPE.to_be_bytes());
            response.extend_from_slice(&signed);

            stream.write_all(&response).unwrap();
            stream.flush().unwrap();
            tx.send(packet).unwrap();
        });

        thread::sleep(Duration::from_millis(200));

        let client = SigndClient::with_path(&sock_path).with_timeout(Duration::from_secs(5));
        let original_packet = vec![
            0x1c, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xe0, 0x83, 0x4f, 0x7b,
        ];
        let result = client.sign_request(&original_packet);

        let received = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(received, original_packet);

        let signed = result.unwrap();
        let mut expected = original_packet.clone();
        expected.extend_from_slice(&[0xABu8; 16]);
        assert_eq!(signed, expected);

        handle.join().unwrap();
        let _ = std::fs::remove_file(&sock_path);
    }
}
