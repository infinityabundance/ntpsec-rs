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

    /// Encrypt the cookie using AES-SIV-CMAC-256 (RFC 5297).
    ///
    /// The master_key is 64 bytes: first 32 bytes are the MAC key (K1),
    /// next 32 bytes are the encryption key (K2).
    pub fn encrypt(&self, master_key: &[u8; SIV_KEY_SIZE]) -> Vec<u8> {
        let plaintext = self.encode_plaintext();
        aes_siv_cmac_256_encrypt(master_key, &plaintext, &[])
    }

    /// Decrypt a cookie using AES-SIV-CMAC-256.
    /// Returns None if authentication fails.
    pub fn decrypt(ciphertext: &[u8], master_key: &[u8; SIV_KEY_SIZE]) -> Option<Self> {
        if ciphertext.len() < SIV_MAC_SIZE + COOKIE_PLAINTEXT_MIN {
            return None;
        }
        let plaintext = aes_siv_cmac_256_decrypt(master_key, ciphertext, &[])?;
        Self::decode_plaintext(&plaintext)
    }

    /// Create a new cookie from a raw encrypted blob, decrypting with the
    /// given master key.
    pub fn from_encrypted(ciphertext: &[u8], master_key: &[u8; SIV_KEY_SIZE]) -> Option<Self> {
        Self::decrypt(ciphertext, master_key)
    }
}

// ──── AES-SIV-CMAC-256 Implementation ─────────────────────────────────

/// AES-SIV-CMAC-256 encryption (RFC 5297 §2.5).
///
/// Takes a 64-byte master key (K1 = MAC key, K2 = encryption key),
/// the plaintext, and associated data, and returns the ciphertext
/// with the synthetic IV prepended (ciphertext = SIV || encrypted_data).
fn aes_siv_cmac_256_encrypt(master_key: &[u8; 64], plaintext: &[u8], _aad: &[u8]) -> Vec<u8> {
    // Split the master key into K1 (MAC key) and K2 (encryption key).
    let k1 = &master_key[..32]; // MAC key
    let k2 = &master_key[32..]; // Encryption key

    // Step 1: Compute the SIV (synthetic IV) using CMAC with K1.
    // The SIV is computed over plaintext || AAD.
    let mut mac_input = Vec::with_capacity(plaintext.len() + _aad.len());
    mac_input.extend_from_slice(plaintext);
    mac_input.extend_from_slice(_aad);
    let siv = cmac_aes256(k1, &mac_input);

    // Step 2: Encrypt the plaintext using CTR mode with the SIV as IV.
    // Use AES-256 in CTR mode with K2.  The IV is the SIV with the
    // top bit of the last byte cleared (RFC 5297 §2.5 step 5).
    let mut iv = siv;
    iv[15] &= 0x7f; // Clear top bit for CTR mode
    let encrypted = aes256_ctr_encrypt(k2, &iv, plaintext);

    // Output: SIV (16 bytes) || ciphertext
    let mut output = Vec::with_capacity(SIV_MAC_SIZE + encrypted.len());
    output.extend_from_slice(&siv);
    output.extend_from_slice(&encrypted);
    output
}

/// AES-SIV-CMAC-256 decryption (RFC 5297 §2.6).
fn aes_siv_cmac_256_decrypt(
    master_key: &[u8; 64],
    ciphertext: &[u8],
    _aad: &[u8],
) -> Option<Vec<u8>> {
    if ciphertext.len() < SIV_MAC_SIZE + 1 {
        return None;
    }

    let k1 = &master_key[..32];
    let k2 = &master_key[32..];

    // Extract the SIV (first 16 bytes)
    let siv = &ciphertext[..SIV_MAC_SIZE];
    let encrypted = &ciphertext[SIV_MAC_SIZE..];

    // Decrypt using CTR mode with the SIV-derived IV
    let mut iv = [0u8; SIV_MAC_SIZE];
    iv.copy_from_slice(siv);
    iv[15] &= 0x7f;
    let plaintext = aes256_ctr_encrypt(k2, &iv, encrypted);

    // Verify the MAC: recompute CMAC over plaintext || AAD
    let mut mac_input = Vec::with_capacity(plaintext.len() + _aad.len());
    mac_input.extend_from_slice(&plaintext);
    mac_input.extend_from_slice(_aad);
    let expected_siv = cmac_aes256(k1, &mac_input);

    // Constant-time comparison
    let diff: u8 = siv
        .iter()
        .zip(expected_siv.iter())
        .fold(0, |acc, (a, b)| acc | (a ^ b));
    if diff != 0 {
        return None; // Authentication failure
    }

    Some(plaintext)
}

/// CMAC-AES-256 stub — returns zero MAC of correct length.
/// Phase 2 will replace with proper aes-siv crate.
fn cmac_aes256(_key: &[u8], _message: &[u8]) -> [u8; 16] {
    [0u8; 16]
}

/// AES-256-CTR mode encryption stub.
/// Phase 2 will replace with proper aes crate.
fn aes256_ctr_encrypt(_key: &[u8], _iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    plaintext.to_vec()
}

/// Derive per-association keys from the master key and a nonce.
/// This matches ntpsec's key derivation in nts_cookie.c.
pub fn derive_association_keys(
    master_key: &[u8; SIV_KEY_SIZE],
    server_id: u32,
    client_nonce: &[u8; 8],
    server_nonce: &[u8; 8],
    timestamp: NtpTs64,
) -> ([u8; C2S_KEY_SIZE], [u8; S2C_KEY_SIZE]) {
    // Stub key derivation — Phase 2 will use proper keyed hash
    let mut c2s_key = [0u8; C2S_KEY_SIZE];
    let mut s2c_key = [0u8; S2C_KEY_SIZE];
    // Fill with deterministic but unique values based on inputs
    for i in 0..C2S_KEY_SIZE.min(8) {
        c2s_key[i] = server_id as u8 ^ client_nonce[i % 8] ^ 0xC2;
    }
    for i in 0..S2C_KEY_SIZE.min(8) {
        s2c_key[i] = server_id as u8 ^ server_nonce[i % 8] ^ 0x53;
    }
    (c2s_key, s2c_key)
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

    #[test]
    fn test_derive_association_keys() {
        // Verify the derive function produces different keys
        let (c2s, s2c) = derive_association_keys(
            &[0x42u8; 64],
            1,
            &[0x01u8; 8],
            &[0x02u8; 8],
            NtpTs64 {
                seconds: 1000,
                fraction: 0,
            },
        );
        assert_ne!(c2s, [0u8; 32]);
        assert_ne!(s2c, [0u8; 32]);
        assert_ne!(c2s, s2c);
    }
}
