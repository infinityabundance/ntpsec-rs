// ──── nts_cookie.rs ─────────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/nts_cookie.c (12K)
//
// NTS cookie encryption/decryption using AES-SIV-CMAC-256 (RFC 5297).
// The cookie is an encrypted blob containing the NTS key material that
// the server can recover to authenticate subsequent NTP requests.
//
// ## Cookie Format (matching ntpsec)
//
// The NTS cookie is an opaque encrypted blob with the following plaintext
// structure (before encryption):
//
//   [ server_id: 4 bytes ][ c2s_key: 32 bytes ][ s2c_key: 32 bytes ]
//   [ timestamp: 8 bytes ][ nonce: 8 bytes ][ padding: 0-7 bytes ]
//
// The plaintext is encrypted with AES-SIV-CMAC-256 using the master key
// as the SIV key.  SIV (RFC 5297) provides both confidentiality and
// authenticity in a single pass.
//
// ## Oracle
//   - ntpsec ntpd/nts_cookie.c
//   - RFC 5297 — AES-SIV
//   - RFC 8915 §5.2 — NTS AEAD
//   - ntpsec libaes_siv/ — reference AES-SIV implementation in C
//
// ## Court
//   - docs/courts/nts_cookie.md
// =============================================================================

use crate::ntp_types::*;
use crate::nts::*;

/// AES-SIV-CMAC-256 constants.
pub const SIV_KEY_SIZE: usize = 64; // Two 256-bit AES keys
pub const SIV_BLOCK_SIZE: usize = 16; // AES block size (128 bits)
pub const SIV_MAC_SIZE: usize = 16; // SIV MAC output size
pub const C2S_KEY_SIZE: usize = 32; // Client-to-server key size (256 bits)
pub const S2C_KEY_SIZE: usize = 32; // Server-to-client key size (256 bits)

/// Minimum cookie plaintext size: server_id(4) + c2s_key(32) + s2c_key(32) +
/// timestamp(8) + nonce(8) = 84 bytes.
pub const COOKIE_PLAINTEXT_MIN: usize = 84;

/// NTS cookie plaintext data.
#[derive(Debug, Clone)]
pub struct NtsCookie {
    pub server_id: u32,
    pub c2s_key: [u8; C2S_KEY_SIZE],
    pub s2c_key: [u8; S2C_KEY_SIZE],
    pub timestamp: NtpTs64,
    pub nonce: [u8; 8],
}

impl NtsCookie {
    /// Create a new NTS cookie from the raw key material.
    pub fn new(
        server_id: u32,
        c2s_key: [u8; C2S_KEY_SIZE],
        s2c_key: [u8; S2C_KEY_SIZE],
        timestamp: NtpTs64,
    ) -> Self {
        // Generate a random nonce
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut nonce = [0u8; 8];
        let mut rng = seed;
        for byte in nonce.iter_mut() {
            rng = rng
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *byte = ((rng >> 32) & 0xFF) as u8;
        }

        Self {
            server_id,
            c2s_key,
            s2c_key,
            timestamp,
            nonce,
        }
    }

    /// Encode the cookie plaintext (without encryption).
    pub fn encode_plaintext(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(COOKIE_PLAINTEXT_MIN);
        buf.extend_from_slice(&self.server_id.to_be_bytes());
        buf.extend_from_slice(&self.c2s_key);
        buf.extend_from_slice(&self.s2c_key);
        buf.extend_from_slice(&self.timestamp.seconds.to_be_bytes());
        buf.extend_from_slice(&self.timestamp.fraction.to_be_bytes());
        buf.extend_from_slice(&self.nonce);
        buf
    }

    /// Decode cookie plaintext from bytes.
    pub fn decode_plaintext(data: &[u8]) -> Option<Self> {
        if data.len() < COOKIE_PLAINTEXT_MIN {
            return None;
        }
        let mut offset = 0;

        let server_id = u32::from_be_bytes(data[offset..offset + 4].try_into().ok()?);
        offset += 4;

        let mut c2s_key = [0u8; C2S_KEY_SIZE];
        c2s_key.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut s2c_key = [0u8; S2C_KEY_SIZE];
        s2c_key.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let secs = i64::from_be_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;
        let frac = u32::from_be_bytes(data[offset..offset + 4].try_into().ok()?);
        offset += 4;

        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&data[offset..offset + 8]);

        Some(Self {
            server_id,
            c2s_key,
            s2c_key,
            timestamp: NtpTs64 {
                seconds: secs,
                fraction: frac,
            },
            nonce,
        })
    }

    /// Encrypt — NTS crypto not yet available. Always returns empty.
    /// Phase 2.5 will implement real AES-SIV-CMAC-256.
    pub fn encrypt(&self, _master_key: &[u8; SIV_KEY_SIZE]) -> Vec<u8> {
        Vec::new() // fail closed — no encryption until NTS is wired
    }

    /// Decrypt — NTS crypto not yet available. Always returns None.
    pub fn decrypt(_ciphertext: &[u8], _master_key: &[u8; SIV_KEY_SIZE]) -> Option<Self> {
        None // fail closed
    }

    /// Create a new cookie from a raw encrypted blob, decrypting with the
    /// given master key.
    pub fn from_encrypted(ciphertext: &[u8], master_key: &[u8; SIV_KEY_SIZE]) -> Option<Self> {
        Self::decrypt(ciphertext, master_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_plaintext() {
        let now = NtpTs64 {
            seconds: 1000,
            fraction: 500,
        };
        let cookie = NtsCookie::new(42, [0xABu8; 32], [0xCDu8; 32], now);
        let encoded = cookie.encode_plaintext();
        let decoded = NtsCookie::decode_plaintext(&encoded).unwrap();
        assert_eq!(decoded.server_id, 42);
        assert_eq!(decoded.timestamp.seconds, 1000);
        assert_eq!(decoded.timestamp.fraction, 500);
    }

    
}
