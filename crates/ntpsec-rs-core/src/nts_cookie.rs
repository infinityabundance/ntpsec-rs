// ──── nts_cookie.rs — NTS Cookie Operations ──────────────────────────
// RFC 8915 §4.2: NTS Cookie encryption and decryption using
// AES-SIV-CMAC-256 (RFC 5297).
//
// ## Cookie Plaintext Format (NtsCookie)
//
//   [ server_id: 32 bytes ][ c2s_key: 32 bytes ][ s2c_key: 32 bytes ]
//   [ seconds: 8 bytes     ][ fraction: 4 bytes ][ aead: 2 bytes     ]
//   Total: 110 bytes
//
// ## AES-SIV-CMAC-256 Cookie Cipher (CookieCipher)
//
// A standalone key-managed envelope format with a random nonce for
// non-deterministic encryption suitable for NTP NTS cookie transport:
//
//   Plaintext (66 bytes):
//     [ aead_algo: 2 bytes ][ c2s_key: 32 bytes ][ s2c_key: 32 bytes ]
//
//   Envelope (wire format):
//     [ key_id: 4 bytes ][ nonce: 16 bytes ][ ciphertext: variable ]
//
// The associated data (AAD) is the key_id || nonce prefix, ensuring
// the envelope is bound to the encryption context.
// =============================================================================

use crate::ntp_types::*;
use aes_siv::aead::Key;
use aes_siv::siv::Aes128Siv;
use digest::KeyInit;
use getrandom::getrandom;
use std::time::SystemTime;

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

/// Maximum age for an NTS cookie in seconds (1 day).
/// Cookies older than this are rejected during decryption.
pub const NTS_COOKIE_MAX_AGE: u64 = 86400;

// ──── Cookie Cipher (key-rotation aware AES-SIV-CMAC-256) ───────────

/// Cookie key index — NTPsec rotates cookie encryption keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CookieKeyIndex(pub u32);

/// AES-SIV-CMAC-256 cookie encryption/decryption with key rotation
/// support and a random-nonce envelope format.
///
/// Each key is identified by a [`CookieKeyIndex`] (a 32-bit integer).
/// Encryption always picks the most recently added key; decryption
/// looks up the key by its index from the envelope.
pub struct CookieCipher {
    keys: Vec<(CookieKeyIndex, [u8; 32])>,
}

impl CookieCipher {
    /// Create an empty cipher with no keys configured.
    pub fn new() -> Self {
        Self { keys: Vec::new() }
    }

    /// Add a cookie encryption key.
    ///
    /// The most recently added key is used for encryption.
    pub fn add_key(&mut self, key_id: CookieKeyIndex, key: [u8; 32]) {
        self.keys.push((key_id, key));
    }

    /// Get a key by its index, if present.
    pub fn get_key(&self, key_id: CookieKeyIndex) -> Option<&[u8; 32]> {
        self.keys
            .iter()
            .rev()
            .find(|(id, _)| *id == key_id)
            .map(|(_, k)| k)
    }

    /// Encrypt `plaintext` into a cookie envelope using the most
    /// recently added key.
    ///
    /// The envelope wire format:
    /// ```text
    ///   key_id:   4 bytes (u32 big-endian)
    ///   nonce:   16 bytes (random)
    ///   ciphertext: remainder (SIV-tagged output)
    /// ```
    ///
    /// The associated data (AAD) fed to AES-SIV is `key_id || nonce`,
    /// binding the envelope to this specific encryption context.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let (key_id, key_bytes) = self
            .keys
            .last()
            .ok_or_else(|| "no cookie keys configured".to_string())?;

        let key = Key::<Aes128Siv>::from_slice(key_bytes);
        // AAD: key_id (4 bytes big-endian) + random nonce (16 bytes)
        let key_id_bytes = key_id.0.to_be_bytes();
        let mut nonce = [0u8; 16];
        getrandom(&mut nonce).map_err(|e| format!("failed to generate nonce: {e}"))?;

        let headers: [&[u8]; 2] = [&key_id_bytes, &nonce];
        let mut siv = Aes128Siv::new(key);
        let ciphertext = siv
            .encrypt(headers, plaintext)
            .map_err(|e| format!("AES-SIV encrypt failed: {e}"))?;

        // Build envelope: key_id(4) || nonce(16) || ciphertext
        let mut envelope = Vec::with_capacity(4 + 16 + ciphertext.len());
        envelope.extend_from_slice(&key_id_bytes);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }

    /// Decrypt a cookie envelope back to the original plaintext.
    ///
    /// Parses the envelope, looks up the key by `key_id`, and
    /// authenticates/decrypts with AES-SIV.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 4 + 16 {
            return Err(format!(
                "cookie envelope too short: {} bytes (need at least 20)",
                data.len()
            ));
        }

        let (key_id_bytes, rest) = data.split_at(4);
        let (nonce_bytes, ciphertext) = rest.split_at(16);

        let key_id = CookieKeyIndex(u32::from_be_bytes(
            key_id_bytes.try_into().map_err(|_| "invalid key_id")?,
        ));

        let key_bytes = self
            .get_key(key_id)
            .ok_or_else(|| format!("unknown cookie key index {}", key_id.0))?;

        let headers: [&[u8]; 2] = [key_id_bytes, nonce_bytes];
        let key = Key::<Aes128Siv>::from_slice(key_bytes);
        let mut siv = Aes128Siv::new(key);
        siv.decrypt(headers, ciphertext)
            .map_err(|e| format!("AES-SIV decrypt failed: {e}"))
    }
}

impl Default for CookieCipher {
    fn default() -> Self {
        Self::new()
    }
}

// ──── NtsCookie Structure ───────────────────────────────────────────

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

    /// Encrypt the cookie using AES-SIV-CMAC-256.
    ///
    /// `server_key` must be 32 bytes (256 bits).
    ///
    /// The cookie's `timestamp` field is automatically set to the current
    /// time before encryption to allow expiration checks on decryption.
    ///
    /// Returns the ciphertext (plaintext authenticated with a 16-byte
    /// SIV authentication tag prepended).
    pub fn encrypt(&self, server_key: &[u8]) -> Result<Vec<u8>, String> {
        if server_key.len() != 32 {
            return Err(format!(
                "server key must be 32 bytes, got {}",
                server_key.len()
            ));
        }

        // Set the cookie timestamp to the current time for expiration.
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        let ntp_now = crate::ntp_fp::ts_to_ntp(now.as_secs() as i64, now.subsec_nanos() as i64);
        let cookie = NtsCookie {
            timestamp: ntp_now,
            ..self.clone()
        };
        let plaintext = cookie.encode_plaintext();
        let key = Key::<Aes128Siv>::from_slice(server_key);
        let mut siv = Aes128Siv::new(key);
        let empty: [&[u8]; 0] = [];
        siv.encrypt(empty, &plaintext)
            .map_err(|e| format!("AES-SIV encrypt failed: {e}"))
    }

    /// Decrypt and verify a cookie using AES-SIV-CMAC-256.
    ///
    /// `server_key` must be 32 bytes (256 bits).
    /// `data` must be a ciphertext previously produced by [`encrypt`].
    ///
    /// Validates the cookie's timestamp against [`NTS_COOKIE_MAX_AGE`].
    /// Cookies older than the maximum age are rejected.
    pub fn decrypt(data: &[u8], server_key: &[u8]) -> Result<Self, String> {
        if server_key.len() != 32 {
            return Err(format!(
                "server key must be 32 bytes, got {}",
                server_key.len()
            ));
        }
        if data.len() < 16 {
            return Err(format!(
                "ciphertext too short: {} bytes (need at least 16 for SIV tag)",
                data.len()
            ));
        }

        let key = Key::<Aes128Siv>::from_slice(server_key);
        let mut siv = Aes128Siv::new(key);
        let empty: [&[u8]; 0] = [];
        let plaintext = siv
            .decrypt(empty, data)
            .map_err(|e| format!("AES-SIV decrypt failed: {e}"))?;

        let cookie = Self::decode_plaintext(&plaintext)
            .ok_or_else(|| "decrypted plaintext is too short".to_string())?;

        // Validate cookie timestamp.
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        let now_ntp = now.as_secs() as i64 + NTP_EPOCH_OFFSET as i64;
        let cookie_age = now_ntp - cookie.timestamp.seconds;
        if cookie_age < 0 || cookie_age as u64 > NTS_COOKIE_MAX_AGE {
            return Err(format!(
                "cookie expired: age={}s (max={}s)",
                cookie_age, NTS_COOKIE_MAX_AGE,
            ));
        }

        Ok(cookie)
    }

    /// Create a new cookie from a raw encrypted blob, decrypting with the
    /// given server key.  Convenience alias for `decrypt`.
    pub fn from_encrypted(data: &[u8], server_key: &[u8]) -> Result<Self, String> {
        Self::decrypt(data, server_key)
    }
}

// ──── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────

    fn make_test_cookie() -> NtsCookie {
        let server_id = [0x01u8; SERVER_ID_SIZE];
        let c2s_key = [0xABu8; C2S_KEY_SIZE];
        let s2c_key = [0xCDu8; S2C_KEY_SIZE];
        // Use a recent timestamp so the cookie passes age validation.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        let timestamp = crate::ntp_fp::ts_to_ntp(now.as_secs() as i64, now.subsec_nanos() as i64);
        NtsCookie::new(server_id, c2s_key, s2c_key, timestamp, 15)
    }

    fn test_key_32() -> [u8; 32] {
        let mut k = [0u8; 32];
        for i in 0..32 {
            k[i] = i as u8;
        }
        k
    }

    fn test_key_32_alt() -> [u8; 32] {
        let mut k = [0u8; 32];
        for i in 0..32 {
            k[i] = 0xFFu8.wrapping_sub(i as u8);
        }
        k
    }

    const KEY_ID_1: CookieKeyIndex = CookieKeyIndex(1);
    const KEY_ID_2: CookieKeyIndex = CookieKeyIndex(2);

    // ── RFC 5297 Known-Answer Test ──────────────────────────────────

    /// Deterministic AES-SIV roundtrip with specific key and AAD inputs.
    ///
    /// Uses known hex values for reproducibility.  Verifies that encrypt
    /// produces deterministic output with the same key+no-AAD, and that
    /// decrypt reverses it.
    #[test]
    fn test_aes_siv_deterministic_roundtrip() {
        let key_bytes: [u8; 32] = hex_literal::hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0"
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        );
        let aad: [u8; 16] = hex_literal::hex!("101112131415161718191a1b1c1d1e1f");
        let aad2: [u8; 8] = hex_literal::hex!("2021222324252627");
        let plaintext: [u8; 14] = hex_literal::hex!("112233445566778899aabbccddee");

        // Encrypt with two AAD headers
        let headers: [&[u8]; 2] = [&aad, &aad2];
        let key = Key::<Aes128Siv>::from_slice(&key_bytes);
        let mut siv = Aes128Siv::new(key);
        let output = siv
            .encrypt(headers, &plaintext)
            .expect("encrypt should succeed");

        // Verify output is 30 bytes (16 SIV + 14 plaintext)
        assert_eq!(output.len(), 30, "SIV(16) + plaintext(14) = 30 bytes");

        // Verify deterministic: same inputs produce same output
        let key = Key::<Aes128Siv>::from_slice(&key_bytes);
        let mut siv = Aes128Siv::new(key);
        let output2 = siv
            .encrypt(headers, &plaintext)
            .expect("second encrypt should succeed");
        assert_eq!(
            output, output2,
            "deterministic AES-SIV should produce same output"
        );

        // Decrypt with two AAD headers
        let headers: [&[u8]; 2] = [&aad, &aad2];
        let key = Key::<Aes128Siv>::from_slice(&key_bytes);
        let mut siv = Aes128Siv::new(key);
        let decrypted = siv
            .decrypt(headers, &output)
            .expect("decrypt should succeed");

        assert_eq!(
            decrypted, plaintext,
            "decrypted plaintext should match original"
        );
    }

    // ── CookieCipher Tests ──────────────────────────────────────────

    #[test]
    fn test_cookie_cipher_new_is_empty() {
        let cipher = CookieCipher::new();
        assert!(cipher.keys.is_empty(), "new cipher should have no keys");
    }

    #[test]
    fn test_cookie_cipher_add_and_get_key() {
        let mut cipher = CookieCipher::new();
        cipher.add_key(KEY_ID_1, test_key_32());

        let retrieved = cipher.get_key(KEY_ID_1);
        assert_eq!(retrieved, Some(&test_key_32()));

        // Unknown key should return None
        assert_eq!(cipher.get_key(KEY_ID_2), None);
    }

    #[test]
    fn test_cookie_cipher_add_key_overwrites() {
        let mut cipher = CookieCipher::new();
        // Adding same key_id twice — get_key returns the latest
        cipher.add_key(KEY_ID_1, test_key_32());
        let alt = test_key_32_alt();
        cipher.add_key(KEY_ID_1, alt);

        // get_key should return the most recently added
        assert_eq!(cipher.get_key(KEY_ID_1), Some(&alt));
    }

    #[test]
    fn test_cookie_cipher_roundtrip() {
        let mut cipher = CookieCipher::new();
        cipher.add_key(KEY_ID_1, test_key_32());

        let plaintext = b"Hello, NTS cookie world!";
        let envelope = cipher.encrypt(plaintext).expect("encrypt should succeed");
        let decrypted = cipher.decrypt(&envelope).expect("decrypt should succeed");

        assert_eq!(decrypted, plaintext, "CookieCipher roundtrip failed");
    }

    #[test]
    fn test_cookie_cipher_encrypt_no_keys() {
        let cipher = CookieCipher::new();
        let result = cipher.encrypt(b"data");
        assert!(result.is_err(), "encrypt without keys should fail");
        assert_eq!(result.unwrap_err(), "no cookie keys configured");
    }

    #[test]
    fn test_cookie_cipher_wrong_key() {
        let mut cipher1 = CookieCipher::new();
        cipher1.add_key(KEY_ID_1, test_key_32());

        let mut cipher2 = CookieCipher::new();
        cipher2.add_key(KEY_ID_1, test_key_32_alt());

        let plaintext = b"sensitive data";
        let envelope = cipher1.encrypt(plaintext).expect("encrypt should succeed");

        let result = cipher2.decrypt(&envelope);
        assert!(result.is_err(), "decrypt with wrong key should fail");
    }

    #[test]
    fn test_cookie_cipher_unknown_key_id() {
        let mut cipher = CookieCipher::new();
        cipher.add_key(KEY_ID_1, test_key_32());

        let plaintext = b"data";
        let envelope = cipher.encrypt(plaintext).expect("encrypt should succeed");

        // Manually corrupt the key_id in the envelope
        let mut corrupted = envelope.to_vec();
        corrupted[0] ^= 0xFF; // flip all bits in first byte of key_id

        let result = cipher.decrypt(&corrupted);
        assert!(result.is_err(), "decrypt with unknown key_id should fail");
        assert!(
            result.unwrap_err().contains("unknown cookie key index"),
            "error should mention unknown key_id"
        );
    }

    #[test]
    fn test_cookie_cipher_tampered_ciphertext() {
        let mut cipher = CookieCipher::new();
        cipher.add_key(KEY_ID_1, test_key_32());

        let plaintext = b"tamper me";
        let envelope = cipher.encrypt(plaintext).expect("encrypt should succeed");

        // Corrupt the last byte of the ciphertext portion
        let mut tampered = envelope.to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;

        let result = cipher.decrypt(&tampered);
        assert!(
            result.is_err(),
            "decrypt with tampered ciphertext should fail"
        );
    }

    #[test]
    fn test_cookie_cipher_tampered_nonce() {
        let mut cipher = CookieCipher::new();
        cipher.add_key(KEY_ID_1, test_key_32());

        let plaintext = b"tamper nonce";
        let envelope = cipher.encrypt(plaintext).expect("encrypt should succeed");

        // Corrupt a byte in the nonce
        let mut tampered = envelope.to_vec();
        tampered[5] ^= 0x01; // byte 5 is inside the nonce field

        let result = cipher.decrypt(&tampered);
        assert!(result.is_err(), "decrypt with tampered nonce should fail");
    }

    #[test]
    fn test_cookie_cipher_short_envelope() {
        let cipher = CookieCipher::new();

        let result = cipher.decrypt(&[0u8; 3]);
        assert!(result.is_err(), "decrypt of short envelope should fail");

        let result = cipher.decrypt(&[0u8; 19]); // 1 byte short
        assert!(result.is_err(), "decrypt of 19-byte envelope should fail");
    }

    #[test]
    fn test_cookie_cipher_multiple_keys_encrypt_uses_latest() {
        let mut cipher = CookieCipher::new();
        cipher.add_key(KEY_ID_1, test_key_32());
        cipher.add_key(KEY_ID_2, test_key_32_alt());

        // encrypt uses the latest key (KEY_ID_2)
        let plaintext = b"multi-key";
        let envelope = cipher.encrypt(plaintext).expect("encrypt should succeed");

        // Decrypt with same cipher (finds key by key_id from envelope)
        let decrypted = cipher.decrypt(&envelope).expect("decrypt should succeed");
        assert_eq!(decrypted, plaintext);

        // Verify the envelope starts with KEY_ID_2
        let expected_key_id = KEY_ID_2.0.to_be_bytes();
        assert_eq!(
            &envelope[..4],
            &expected_key_id,
            "envelope should use latest key_id"
        );
    }

    #[test]
    fn test_cookie_cipher_multiple_keys_decrypt_with_older() {
        let mut cipher = CookieCipher::new();
        cipher.add_key(KEY_ID_1, test_key_32());
        cipher.add_key(KEY_ID_2, test_key_32_alt());

        // Manually build an envelope using KEY_ID_1
        let plaintext = b"older key data";
        let key32 = test_key_32();
        let key = Key::<Aes128Siv>::from_slice(&key32);
        let mut nonce = [0u8; 16];
        getrandom(&mut nonce).expect("getrandom failed");
        let headers: [&[u8]; 2] = [&KEY_ID_1.0.to_be_bytes(), &nonce];
        let mut siv = Aes128Siv::new(key);
        let ct = siv
            .encrypt(headers, plaintext)
            .expect("manual encrypt should succeed");

        let mut envelope = Vec::with_capacity(4 + 16 + ct.len());
        envelope.extend_from_slice(&KEY_ID_1.0.to_be_bytes());
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ct);

        // Should decrypt with cipher that still has KEY_ID_1
        let decrypted = cipher
            .decrypt(&envelope)
            .expect("decrypt with older key should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cookie_cipher_multiple_keys_unknown_key() {
        let mut cipher = CookieCipher::new();
        cipher.add_key(KEY_ID_1, test_key_32());

        // Build an envelope with KEY_ID_2 (which isn't in the cipher)
        let plaintext = b"unknown key";
        let key32_alt = test_key_32_alt();
        let key = Key::<Aes128Siv>::from_slice(&key32_alt);
        let mut nonce = [0u8; 16];
        getrandom(&mut nonce).expect("getrandom failed");
        let headers: [&[u8]; 2] = [&KEY_ID_2.0.to_be_bytes(), &nonce];
        let mut siv = Aes128Siv::new(key);
        let ct = siv
            .encrypt(headers, plaintext)
            .expect("manual encrypt should succeed");

        let mut envelope = Vec::with_capacity(4 + 16 + ct.len());
        envelope.extend_from_slice(&KEY_ID_2.0.to_be_bytes());
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ct);

        let result = cipher.decrypt(&envelope);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown cookie key index"));
    }

    // ── NtsCookie Tests ─────────────────────────────────────────────

    #[test]
    fn test_cookie_plaintext_roundtrip() {
        let cookie = make_test_cookie();
        let encoded = cookie.encode_plaintext();
        assert_eq!(encoded.len(), COOKIE_PLAINTEXT_MIN);

        let decoded = NtsCookie::decode_plaintext(&encoded).unwrap();
        assert_eq!(decoded.server_id, [0x01u8; SERVER_ID_SIZE]);
        assert_eq!(decoded.c2s_key, [0xABu8; C2S_KEY_SIZE]);
        assert_eq!(decoded.s2c_key, [0xCDu8; S2C_KEY_SIZE]);
        // Timestamp and AEAD are set by make_test_cookie.
        assert_eq!(decoded.aead, 15);
    }

    #[test]
    fn test_cookie_encrypt_decrypt_roundtrip() {
        let cookie = make_test_cookie();
        let key = test_key_32();

        let encrypted = cookie.encrypt(&key).expect("encrypt should succeed");
        assert!(
            encrypted.len() >= COOKIE_PLAINTEXT_MIN + 16,
            "ciphertext should be at least plaintext + SIV tag"
        );

        let decrypted = NtsCookie::decrypt(&encrypted, &key).expect("decrypt should succeed");

        // Keys and AEAD algorithm should match.
        assert_eq!(decrypted.server_id, cookie.server_id);
        assert_eq!(decrypted.c2s_key, cookie.c2s_key);
        assert_eq!(decrypted.s2c_key, cookie.s2c_key);
        assert_eq!(decrypted.aead, cookie.aead);

        // The timestamp is auto-set by encrypt() to the current time,
        // so it won't match the original cookie's timestamp.  Just
        // verify it's recent (within NTS_COOKIE_MAX_AGE).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        let now_ntp = now.as_secs() as i64 + crate::ntp_types::NTP_EPOCH_OFFSET as i64;
        let age = now_ntp - decrypted.timestamp.seconds;
        assert!(
            age >= 0 && (age as u64) < NTS_COOKIE_MAX_AGE,
            "decrypted cookie timestamp should be recent"
        );
    }

    #[test]
    fn test_cookie_encrypt_wrong_key() {
        let cookie = make_test_cookie();
        let encrypt_key = test_key_32();
        let wrong_key = test_key_32_alt();

        let encrypted = cookie
            .encrypt(&encrypt_key)
            .expect("encrypt should succeed");

        let result = NtsCookie::decrypt(&encrypted, &wrong_key);
        assert!(result.is_err(), "decrypt with wrong key should fail");
    }

    #[test]
    fn test_cookie_encrypt_wrong_key_size() {
        let cookie = make_test_cookie();
        let short_key = [0u8; 16];

        let result = cookie.encrypt(&short_key);
        assert!(result.is_err(), "encrypt with 16-byte key should fail");
        assert!(result.unwrap_err().contains("must be 32 bytes"));
    }

    #[test]
    fn test_cookie_decrypt_wrong_key_size() {
        let short_key = [0u8; 16];

        let result = NtsCookie::decrypt(&[0u8; 128], &short_key);
        assert!(result.is_err(), "decrypt with 16-byte key should fail");
        assert!(result.unwrap_err().contains("must be 32 bytes"));
    }

    #[test]
    fn test_cookie_decrypt_short_data() {
        let key = test_key_32();

        let result = NtsCookie::decrypt(&[0u8; 15], &key);
        assert!(result.is_err(), "decrypt of 15-byte data should fail");
    }

    #[test]
    fn test_cookie_decrypt_tampered_ciphertext() {
        let cookie = make_test_cookie();
        let key = test_key_32();

        let mut encrypted = cookie.encrypt(&key).expect("encrypt should succeed");

        // Corrupt a byte in the middle of the ciphertext
        let idx = encrypted.len() / 2;
        encrypted[idx] ^= 0xFF;

        let result = NtsCookie::decrypt(&encrypted, &key);
        assert!(
            result.is_err(),
            "decrypt with tampered ciphertext should fail"
        );
    }

    #[test]
    fn test_cookie_from_encrypted() {
        let cookie = make_test_cookie();
        let key = test_key_32();

        let encrypted = cookie.encrypt(&key).expect("encrypt should succeed");
        let decrypted =
            NtsCookie::from_encrypted(&encrypted, &key).expect("from_encrypted should succeed");
        assert_eq!(decrypted.aead, cookie.aead);
    }

    #[test]
    fn test_cookie_decode_plaintext_short() {
        let result = NtsCookie::decode_plaintext(&[0u8; COOKIE_PLAINTEXT_MIN - 1]);
        assert!(result.is_none());
    }

    #[test]
    fn test_cookie_expired_rejected() {
        // Build an encrypted cookie with an ancient timestamp
        // (NTP epoch = 1900) and verify that NtsCookie::decrypt()
        // rejects it as expired.
        //
        // We encrypt manually (bypassing NtsCookie::encrypt() which
        // auto-sets the timestamp to current time) to embed an old
        // timestamp in the plaintext.
        use aes_siv::siv::Aes128Siv;
        use aes_siv::Key;

        let key = test_key_32();
        let aead_algo: u16 = 15;

        let server_id = [0x01u8; SERVER_ID_SIZE];
        let c2s_key = [0xABu8; C2S_KEY_SIZE];
        let s2c_key = [0xCDu8; S2C_KEY_SIZE];
        let secs: i64 = 0i64; // NTP epoch = 1900-01-01, way older than 1 day
        let frac: u32 = 0;

        let mut plaintext = Vec::with_capacity(COOKIE_PLAINTEXT_MIN);
        plaintext.extend_from_slice(&server_id);
        plaintext.extend_from_slice(&c2s_key);
        plaintext.extend_from_slice(&s2c_key);
        plaintext.extend_from_slice(&secs.to_be_bytes());
        plaintext.extend_from_slice(&frac.to_be_bytes());
        plaintext.extend_from_slice(&aead_algo.to_be_bytes());

        let aes_key = Key::<Aes128Siv>::from_slice(&key);
        let mut siv = Aes128Siv::new(aes_key);
        let empty: [&[u8]; 0] = [];
        let encrypted = siv
            .encrypt(empty, &plaintext)
            .expect("encrypt should succeed");

        let result = NtsCookie::decrypt(&encrypted, &key);
        assert!(
            result.is_err(),
            "decrypt with expired cookie timestamp should fail"
        );
        assert!(
            result.unwrap_err().contains("expired"),
            "error should mention cookie expiration"
        );
    }

    #[test]
    fn test_debug_and_clone() {
        let cookie = make_test_cookie();
        // Verify Debug and Clone traits are implemented.
        let _ = format!("{:?}", cookie);
        let cloned = cookie.clone();
        assert_eq!(cloned.aead, cookie.aead);
    }

    #[test]
    // ── NTPsec cookie interoperability test ─────────────────────────

    /// Verifies the cookie envelope format matches NTPsec expectations.
    ///
    /// NTPsec's cookie envelope (nts_cookie.c):
    ///   key_index: 4 bytes (clear, u32 big-endian)
    ///   nonce:     16 bytes (random, used as AEAD nonce)
    ///   ciphertext: remainder (SIV-tagged output, includes encrypted
    ///               plaintext + SIV authentication tag)
    ///
    /// The associated data (AAD) fed to AES-SIV is:
    ///   key_id || nonce
    ///
    /// The NTPsec plaintext structure inside the cookie:
    ///   aead_id (2 bytes) || c2s_key (32 bytes) || s2c_key (32 bytes)
    #[test]
    fn test_ntpsec_cookie_interop() {
        // ── Setup: create CookieCipher and register a key ────────────
        let mut cipher = CookieCipher::new();
        let key_id = CookieKeyIndex(42);
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        cipher.add_key(key_id, key);

        // ── Build NTPsec-structured plaintext ────────────────────────
        // NTPsec plaintext: aead_id (u16) || c2s_key (32) || s2c_key (32)
        let aead_id: u16 = 15u16; // AEAD_AES_SIV_CMAC_256
        let c2s_key: [u8; 32] = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
            0x3c, 0x3d, 0x3e, 0x3f,
        ];
        let s2c_key: [u8; 32] = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
            0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b,
            0x5c, 0x5d, 0x5e, 0x5f,
        ];

        let mut plaintext = Vec::with_capacity(2 + 32 + 32);
        plaintext.extend_from_slice(&aead_id.to_be_bytes());
        plaintext.extend_from_slice(&c2s_key);
        plaintext.extend_from_slice(&s2c_key);
        assert_eq!(plaintext.len(), 66);

        // ── Encrypt (produces NTPsec-compatible envelope) ────────────
        let envelope = cipher.encrypt(&plaintext).expect("encrypt should succeed");

        // Verify envelope structure (NTPsec format):
        //   [key_id: 4][nonce: 16][ciphertext: N]
        assert!(
            envelope.len() >= 4 + 16 + 16,
            "envelope too short: {} bytes (need at least 36)",
            envelope.len()
        );

        // Key index should match what we registered.
        let parsed_key_id = u32::from_be_bytes(envelope[0..4].try_into().unwrap());
        assert_eq!(parsed_key_id, key_id.0);

        // Nonce should be exactly 16 bytes.
        let _nonce = &envelope[4..20];
        assert_eq!(_nonce.len(), 16);

        // Ciphertext must include the 16-byte SIV authentication tag.
        let _ciphertext = &envelope[20..];
        assert!(!_ciphertext.is_empty(), "ciphertext must not be empty");

        // ── Decrypt back ─────────────────────────────────────────────
        let decrypted = cipher.decrypt(&envelope).expect("decrypt should succeed");
        assert_eq!(
            decrypted, plaintext,
            "decrypted plaintext must match original"
        );

        // ── Parse the decrypted NTPsec-structured plaintext ──────────
        assert!(
            decrypted.len() >= 2 + 32 + 32,
            "decrypted plaintext too short: {} bytes",
            decrypted.len()
        );

        let recovered_aead = u16::from_be_bytes([decrypted[0], decrypted[1]]);
        assert_eq!(recovered_aead, aead_id, "AEAD ID mismatch");

        let recovered_c2s: [u8; 32] = decrypted[2..34].try_into().unwrap();
        assert_eq!(recovered_c2s, c2s_key, "C2S key mismatch");

        let recovered_s2c: [u8; 32] = decrypted[34..66].try_into().unwrap();
        assert_eq!(recovered_s2c, s2c_key, "S2C key mismatch");
    }

    #[test]
    fn test_rfc5297_known_answer() {
        // RFC 5297 Appendix A.1 known-answer test
        // Uses Aes128Siv directly (not the AEAD wrapper) for exact input control.
        use aes_siv::siv::Aes128Siv;
        use aes_siv::Key;
        use hex_literal::hex;

        let key = Key::<Aes128Siv>::from_slice(&hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0"
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ));
        let ad = hex!("101112131415161718191a1b1c1d1e1f2021222324252627");
        let plaintext = hex!("112233445566778899aabbccddee");
        let expected = hex!(
            "85632d07c6e8f37f950acd320a2ecc93"
            "40c02b9690c4dc04daef7f6afe5c"
        );

        let mut siv = Aes128Siv::new(key);
        let headers: [&[u8]; 1] = [&ad];
        let result = siv.encrypt(headers, &plaintext).unwrap();
        assert_eq!(result, expected, "RFC 5297 A.1 output mismatch");

        // Verify decrypt round-trip
        let decrypted = siv.decrypt(headers, &result).unwrap();
        assert_eq!(decrypted, plaintext, "RFC 5297 A.1 decrypt mismatch");
    }
}
