// ──── nts_cookie.rs — NTS Cookie Operations ──────────────────────────
// RFC 8915 §4.2: NTS Cookie encryption and decryption.
//
// ## Cookie Plaintext Format
//
//   [ server_id: 32 bytes ][ c2s_key: 32 bytes ][ s2c_key: 32 bytes ]
//   [ seconds: 8 bytes     ][ fraction: 4 bytes ][ aead: 2 bytes     ]
//   Total: 110 bytes
//
// The plaintext is then encrypted with an AEAD algorithm (typically
// AES-SIV-CMAC-256 per RFC 5297).  This module provides the cookie
// structure and plaintext encode/decode; the actual AEAD encryption
// requires a vetted RFC 5297 implementation (not yet wired in).
// =============================================================================

use crate::ntp_types::*;

/// Size of the server identity field in the cookie plaintext.
pub const SERVER_ID_SIZE: usize = 32;

/// Client-to-server key size (256 bits).
pub const C2S_KEY_SIZE: usize = 32;

/// Server-to-client key size (256 bits).
pub const S2C_KEY_SIZE: usize = 32;

/// Minimum cookie plaintext size:
/// server_id(32) + c2s_key(32) + s2c_key(32) + timestamp_secs(8) +
/// timestamp_frac(4) + aead(2) = 110 bytes.
pub const COOKIE_PLAINTEXT_MIN: usize = 110;

/// NTS cookie structure (RFC 8915 §4.2).
///
/// The cookie is an opaque encrypted blob that encodes the server's
/// state: which keys to use, which AEAD algorithm was negotiated,
/// and when the cookie was issued.
#[derive(Debug, Clone)]
pub struct NtsCookie {
    /// Server identity (32 bytes, e.g. a SHA-256 hash of the server name).
    pub server_id: [u8; SERVER_ID_SIZE],
    /// Client-to-server key material (32 bytes).
    pub c2s_key: [u8; C2S_KEY_SIZE],
    /// Server-to-client key material (32 bytes).
    pub s2c_key: [u8; S2C_KEY_SIZE],
    /// Timestamp when the cookie was issued.
    pub timestamp: NtpTs64,
    /// Negotiated AEAD algorithm.
    pub aead: u16,
}

impl NtsCookie {
    /// Create a new NTS cookie.
    pub fn new(
        server_id: [u8; SERVER_ID_SIZE],
        c2s_key: [u8; C2S_KEY_SIZE],
        s2c_key: [u8; S2C_KEY_SIZE],
        timestamp: NtpTs64,
        aead: u16,
    ) -> Self {
        Self {
            server_id,
            c2s_key,
            s2c_key,
            timestamp,
            aead,
        }
    }

    /// Encode the cookie plaintext (without encryption).
    ///
    /// Wire format (all fields big-endian):
    ///   [ server_id: 32 ][ c2s_key: 32 ][ s2c_key: 32 ]
    ///   [ seconds: 8    ][ fraction: 4 ][ aead: 2     ]
    pub fn encode_plaintext(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(COOKIE_PLAINTEXT_MIN);
        buf.extend_from_slice(&self.server_id);
        buf.extend_from_slice(&self.c2s_key);
        buf.extend_from_slice(&self.s2c_key);
        buf.extend_from_slice(&self.timestamp.seconds.to_be_bytes());
        buf.extend_from_slice(&self.timestamp.fraction.to_be_bytes());
        buf.extend_from_slice(&self.aead.to_be_bytes());
        buf
    }

    /// Decode cookie plaintext from bytes.
    pub fn decode_plaintext(data: &[u8]) -> Option<Self> {
        if data.len() < COOKIE_PLAINTEXT_MIN {
            return None;
        }

        let mut offset = 0;

        let mut server_id = [0u8; SERVER_ID_SIZE];
        server_id.copy_from_slice(&data[offset..offset + SERVER_ID_SIZE]);
        offset += SERVER_ID_SIZE;

        let mut c2s_key = [0u8; C2S_KEY_SIZE];
        c2s_key.copy_from_slice(&data[offset..offset + C2S_KEY_SIZE]);
        offset += C2S_KEY_SIZE;

        let mut s2c_key = [0u8; S2C_KEY_SIZE];
        s2c_key.copy_from_slice(&data[offset..offset + S2C_KEY_SIZE]);
        offset += S2C_KEY_SIZE;

        let secs = i64::from_be_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        let frac = u32::from_be_bytes(data[offset..offset + 4].try_into().ok()?);
        offset += 4;

        let aead = u16::from_be_bytes(data[offset..offset + 2].try_into().ok()?);

        Some(Self {
            server_id,
            c2s_key,
            s2c_key,
            timestamp: NtpTs64 {
                seconds: secs,
                fraction: frac,
            },
            aead,
        })
    }

    /// Encrypt the cookie using the server's key.
    ///
    /// **Not yet implemented** — requires a vetted RFC 5297
    /// (AES-SIV) implementation.
    pub fn encrypt(&self, _server_key: &[u8]) -> Result<Vec<u8>, String> {
        Err("AES-SIV not yet implemented — requires vetted RFC 5297 implementation".to_string())
    }

    /// Decrypt and verify a cookie.
    ///
    /// **Not yet implemented** — requires a vetted RFC 5297
    /// (AES-SIV) implementation.
    pub fn decrypt(_data: &[u8], _server_key: &[u8]) -> Result<Self, String> {
        Err("AES-SIV not yet implemented — requires vetted RFC 5297 implementation".to_string())
    }

    /// Create a new cookie from a raw encrypted blob, decrypting with the
    /// given server key.  Convenience alias for `decrypt`.
    pub fn from_encrypted(data: &[u8], server_key: &[u8]) -> Result<Self, String> {
        Self::decrypt(data, server_key)
    }
}

// ──── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_cookie() -> NtsCookie {
        let server_id = [0x01u8; SERVER_ID_SIZE];
        let c2s_key = [0xABu8; C2S_KEY_SIZE];
        let s2c_key = [0xCDu8; S2C_KEY_SIZE];
        let timestamp = NtpTs64 {
            seconds: 1_000_000,
            fraction: 500,
        };
        NtsCookie::new(server_id, c2s_key, s2c_key, timestamp, 15)
    }

    #[test]
    fn test_cookie_plaintext_roundtrip() {
        let cookie = make_test_cookie();
        let encoded = cookie.encode_plaintext();
        assert_eq!(encoded.len(), COOKIE_PLAINTEXT_MIN);

        let decoded = NtsCookie::decode_plaintext(&encoded).unwrap();
        assert_eq!(decoded.server_id, [0x01u8; SERVER_ID_SIZE]);
        assert_eq!(decoded.c2s_key, [0xABu8; C2S_KEY_SIZE]);
        assert_eq!(decoded.s2c_key, [0xCDu8; S2C_KEY_SIZE]);
        assert_eq!(decoded.timestamp.seconds, 1_000_000);
        assert_eq!(decoded.timestamp.fraction, 500);
        assert_eq!(decoded.aead, 15);
    }

    #[test]
    fn test_cookie_encrypt_returns_error() {
        let cookie = make_test_cookie();
        let result = cookie.encrypt(&[0x42u8; 64]);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "AES-SIV not yet implemented — requires vetted RFC 5297 implementation"
        );
    }

    #[test]
    fn test_cookie_decrypt_returns_error() {
        let result = NtsCookie::decrypt(&[0u8; 128], &[0x42u8; 64]);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "AES-SIV not yet implemented — requires vetted RFC 5297 implementation"
        );
    }

    #[test]
    fn test_cookie_from_encrypted_returns_error() {
        let encrypted = vec![0u8; 128];
        let result = NtsCookie::from_encrypted(&encrypted, &[0x42u8; 64]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cookie_decode_plaintext_short() {
        let result = NtsCookie::decode_plaintext(&[0u8; COOKIE_PLAINTEXT_MIN - 1]);
        assert!(result.is_none());
    }

    #[test]
    fn test_debug_and_clone() {
        let cookie = make_test_cookie();
        // Verify Debug and Clone traits are implemented.
        let _ = format!("{:?}", cookie);
        let cloned = cookie.clone();
        assert_eq!(cloned.aead, cookie.aead);
    }
}
