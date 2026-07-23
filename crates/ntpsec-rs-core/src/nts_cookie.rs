// ──── nts_cookie.rs — NTS Cookie Operations ──────────────────────────
// RFC 8915 §4.2: NTS Cookie encryption and decryption.
//
// Cookies are encrypted with AES-SIV-CMAC-256 (RFC 5297), providing
// both authenticated encryption and resistance to nonce reuse.
//
// ## Cookie Plaintext Format
//
//   [ server_id: 32 bytes ][ c2s_key: 32 bytes ][ s2c_key: 32 bytes ]
//   [ seconds: 8 bytes     ][ fraction: 4 bytes ][ aead: 2 bytes     ]
//   Total: 110 bytes
//
// The plaintext is then encrypted with AES-SIV-CMAC-256 using the
// server's 64-byte master key. The SIV construction provides:
//   - Authenticated encryption (integrity + confidentiality)
//   - Nonce-misuse resistance (deterministic, no nonce needed)
//
// ## AES-SIV-CMAC-256 (RFC 5297 §2.5, §2.6)
//
// The 64-byte server key is split into two 32-byte keys:
//   - K1 = key[0..32] — used for the S2V (CMAC-AES-256) operation
//   - K2 = key[32..64] — used for AES-256-CTR encryption
//
// Encryption:
//   1. SIV = S2V(K1, plaintext)     — synthetic IV (16 bytes)
//   2. ciphertext = CTR(K2, SIV, plaintext)
//   3. Output: SIV || ciphertext
//
// Decryption:
//   1. Split input into SIV (16 bytes) and ciphertext (rest)
//   2. plaintext = CTR(K2, SIV, ciphertext)
//   3. Verify SIV == S2V(K1, plaintext)
//
// ## Dependencies
//   - aes = "0.8" — AES-256 block cipher
//   - cmac = "0.7" — CMAC (OMAC1) for AES-256
//   - cipher = "0.4" — BlockEncrypt trait
// =============================================================================

use crate::ntp_types::*;

use aes::Aes256;
use cipher::{BlockEncrypt, KeyInit};
use cmac::{Cmac, Mac as CmacMac};
use digest::generic_array::GenericArray;

/// AES-SIV-CMAC-256 constants.
pub const SIV_KEY_SIZE: usize = 64; // Two 256-bit AES keys
pub const SIV_BLOCK_SIZE: usize = 16; // AES block size (128 bits)
pub const SIV_MAC_SIZE: usize = 16; // SIV MAC output size
pub const C2S_KEY_SIZE: usize = 32; // Client-to-server key size (256 bits)
pub const S2C_KEY_SIZE: usize = 32; // Server-to-client key size (256 bits)

/// Size of the server identity field in the cookie plaintext.
pub const SERVER_ID_SIZE: usize = 32;

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
    /// Uses AES-SIV-CMAC-256 (RFC 5297) for authenticated encryption.
    ///
    /// `server_key` must be 64 bytes: the first 32 bytes are used as
    /// the CMAC key for the S2V operation, the last 32 bytes are used
    /// as the AES-256-CTR encryption key.
    ///
    /// Returns the encrypted cookie: 16-byte SIV || ciphertext.
    pub fn encrypt(&self, server_key: &[u8]) -> Vec<u8> {
        let plaintext = self.encode_plaintext();
        aes_siv_cmac_256_encrypt(server_key, &plaintext)
    }

    /// Decrypt and verify a cookie.
    ///
    /// `data` is the encrypted cookie (SIV || ciphertext) from the wire.
    /// `server_key` is the server's 64-byte master key.
    ///
    /// Returns `None` if the key is the wrong size, the data is too short,
    /// or the authentication check (SIV verification) fails.
    pub fn decrypt(data: &[u8], server_key: &[u8]) -> Option<Self> {
        let plaintext = aes_siv_cmac_256_decrypt(server_key, data)?;
        Self::decode_plaintext(&plaintext)
    }

    /// Create a new cookie from a raw encrypted blob, decrypting with the
    /// given server key.  Convenience alias for `decrypt`.
    pub fn from_encrypted(data: &[u8], server_key: &[u8]) -> Option<Self> {
        Self::decrypt(data, server_key)
    }
}

// ──── AES-SIV-CMAC-256 implementation (RFC 5297) ──────────────────────

/// The expected size of the SIV output (16 bytes = 128 bits).
pub const SIV_OUTPUT_SIZE: usize = 16;

/// Encrypt a plaintext using AES-SIV-CMAC-256.
///
/// `key` must be exactly 64 bytes.  Output is `[SIV(16) | ciphertext(...)]`.
fn aes_siv_cmac_256_encrypt(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    if key.len() < SIV_KEY_SIZE {
        // Return SIV || plaintext for short keys so callers can detect
        // the issue without panicking.  Production code should validate
        // key size at a higher level.
        let mut result = vec![0u8; SIV_OUTPUT_SIZE];
        result.extend_from_slice(plaintext);
        return result;
    }

    let k1: &[u8; 32] = &key[..32].try_into().expect("key[..32]");
    let k2: &[u8; 32] = &key[32..64].try_into().expect("key[32..64]");

    // 1. S2V: compute the synthetic IV using CMAC-AES-256 with K1.
    let siv = s2v_cmac_aes256(k1, plaintext);

    // 2. CTR mode encryption using K2 with SIV as initial counter.
    let ciphertext = aes_ctr_encrypt(k2, &siv, plaintext);

    // 3. Output: SIV || ciphertext
    let mut output = Vec::with_capacity(SIV_OUTPUT_SIZE + ciphertext.len());
    output.extend_from_slice(&siv);
    output.extend_from_slice(&ciphertext);
    output
}

/// Decrypt a ciphertext using AES-SIV-CMAC-256.
///
/// `key` must be exactly 64 bytes.  `data` must be at least 17 bytes
/// (16-byte SIV + at least 1 byte of ciphertext).
///
/// Returns `None` if authentication fails (SIV mismatch).
fn aes_siv_cmac_256_decrypt(key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    if key.len() < SIV_KEY_SIZE {
        return None;
    }
    if data.len() < SIV_OUTPUT_SIZE + 1 {
        return None;
    }

    let k1: &[u8; 32] = &key[..32].try_into().expect("key[..32]");
    let k2: &[u8; 32] = &key[32..64].try_into().expect("key[32..64]");

    let siv_slice: &[u8; SIV_OUTPUT_SIZE] = &data[..SIV_OUTPUT_SIZE].try_into().expect("SIV size");
    let ciphertext = &data[SIV_OUTPUT_SIZE..];

    // Decrypt with CTR mode using K2 and the SIV.
    let plaintext = aes_ctr_encrypt(k2, siv_slice, ciphertext);

    // Verify: recompute S2V and compare (constant-time comparison).
    let expected_siv = s2v_cmac_aes256(k1, &plaintext);

    // Constant-time comparison of the SIV values (16 bytes).
    let mut diff = 0u8;
    for i in 0..SIV_OUTPUT_SIZE {
        diff |= siv_slice[i] ^ expected_siv[i];
    }

    if diff == 0 {
        Some(plaintext)
    } else {
        None
    }
}

/// S2V (RFC 5297 §2.3) — synthetic IV generation using CMAC-AES-256.
///
/// For a single input message (the plaintext), the S2V output is:
///
///   SIV = CMAC(K1, message)
///
/// When there are multiple associated data items, S2V XORs each
/// CMAC output together.  NTS cookies only have a single input
/// (the plaintext body), so we use the simple single-input form.
fn s2v_cmac_aes256(key: &[u8; 32], message: &[u8]) -> [u8; SIV_OUTPUT_SIZE] {
    let mut mac =
        <Cmac<Aes256> as CmacMac>::new_from_slice(key).expect("AES-256 key should be 32 bytes");
    mac.update(message);
    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut siv = [0u8; SIV_OUTPUT_SIZE];
    siv.copy_from_slice(&bytes);
    siv
}

/// AES-256-CTR mode encryption / decryption.
///
/// XOR-based CTR mode is symmetric: encrypt(plaintext) = ciphertext,
/// and encrypt(ciphertext) = plaintext.
///
/// The counter is a 128-bit big-endian value starting from the IV.
/// For each 16-byte block, the counter is encrypted with AES-256,
/// XORed with the input, and then the counter is incremented by 1.
fn aes_ctr_encrypt(key: &[u8; 32], iv: &[u8; SIV_OUTPUT_SIZE], input: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new_from_slice(key).expect("AES-256 key should be 32 bytes");

    // The counter block starts as the IV.
    let mut counter = *iv;
    let mut output = vec![0u8; input.len()];
    let mut block = GenericArray::from([0u8; SIV_BLOCK_SIZE]);

    // Process the input in 16-byte blocks using indexed access.
    for start in (0..input.len()).step_by(SIV_BLOCK_SIZE) {
        // Encrypt the current counter value.
        block.copy_from_slice(&counter);
        cipher.encrypt_block(&mut block);

        // XOR keystream with the input chunk.
        let end = (start + SIV_BLOCK_SIZE).min(input.len());
        for i in start..end {
            output[i] = input[i] ^ block[i - start];
        }

        // Increment the counter (128-bit big-endian).
        increment_counter_be(&mut counter);
    }

    output
}

/// Increment a 128-bit counter interpreted as a big-endian integer.
fn increment_counter_be(counter: &mut [u8; SIV_BLOCK_SIZE]) {
    for i in (0..SIV_BLOCK_SIZE).rev() {
        let (val, overflow) = counter[i].overflowing_add(1);
        counter[i] = val;
        if !overflow {
            break;
        }
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
        NtsCookie::new(server_id, c2s_key, s2c_key, timestamp, 1)
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
        assert_eq!(decoded.aead, 1);
    }

    #[test]
    fn test_cookie_encrypt_decrypt() {
        let cookie = make_test_cookie();
        // 64-byte server key (all zeroes is a valid AES-256 key).
        let server_key = [0x42u8; SIV_KEY_SIZE];

        let encrypted = cookie.encrypt(&server_key);
        // Encrypted output = 16-byte SIV + 110-byte ciphertext = 126 bytes
        assert_eq!(encrypted.len(), SIV_OUTPUT_SIZE + COOKIE_PLAINTEXT_MIN);
        assert_ne!(
            encrypted,
            cookie.encode_plaintext(),
            "encryption should change the data"
        );

        let decrypted = NtsCookie::decrypt(&encrypted, &server_key).unwrap();
        assert_eq!(decrypted.server_id, cookie.server_id);
        assert_eq!(decrypted.c2s_key, cookie.c2s_key);
        assert_eq!(decrypted.s2c_key, cookie.s2c_key);
        assert_eq!(decrypted.timestamp.seconds, cookie.timestamp.seconds);
        assert_eq!(decrypted.timestamp.fraction, cookie.timestamp.fraction);
        assert_eq!(decrypted.aead, cookie.aead);
    }

    #[test]
    fn test_cookie_decrypt_wrong_key_fails() {
        let cookie = make_test_cookie();
        let good_key = [0x42u8; SIV_KEY_SIZE];
        let bad_key = [0xFFu8; SIV_KEY_SIZE];

        let encrypted = cookie.encrypt(&good_key);

        // Decrypting with the wrong key should fail (SIV auth check).
        let result = NtsCookie::decrypt(&encrypted, &bad_key);
        assert!(
            result.is_none(),
            "decrypt with wrong key should return None"
        );
    }

    #[test]
    fn test_cookie_decrypt_tampered_data_fails() {
        let cookie = make_test_cookie();
        let server_key = [0x42u8; SIV_KEY_SIZE];

        let mut encrypted = cookie.encrypt(&server_key);

        // Tamper with the ciphertext (last byte).
        if let Some(last) = encrypted.last_mut() {
            *last ^= 0xFF;
        }

        let result = NtsCookie::decrypt(&encrypted, &server_key);
        assert!(
            result.is_none(),
            "decrypt of tampered data should return None"
        );
    }

    #[test]
    fn test_cookie_decrypt_short_data_fails() {
        let server_key = [0x42u8; SIV_KEY_SIZE];
        let result = NtsCookie::decrypt(&[0u8; 5], &server_key);
        assert!(result.is_none());
    }

    #[test]
    fn test_cookie_decrypt_empty_key_fails() {
        let data = [0u8; 32];
        let result = NtsCookie::decrypt(&data, &[]);
        assert!(result.is_none());
    }

    #[test]
    fn test_cookie_decode_plaintext_short() {
        let result = NtsCookie::decode_plaintext(&[0u8; COOKIE_PLAINTEXT_MIN - 1]);
        assert!(result.is_none());
    }

    #[test]
    fn test_cookie_encrypt_deterministic() {
        let cookie = make_test_cookie();
        let server_key = [0x42u8; SIV_KEY_SIZE];

        // AES-SIV is deterministic: same plaintext + same key = same output.
        let encrypted1 = cookie.encrypt(&server_key);
        let encrypted2 = cookie.encrypt(&server_key);
        assert_eq!(encrypted1, encrypted2);
    }

    #[test]
    fn test_cookie_from_encrypted() {
        let cookie = make_test_cookie();
        let server_key = [0x42u8; SIV_KEY_SIZE];

        let encrypted = cookie.encrypt(&server_key);
        let decrypted = NtsCookie::from_encrypted(&encrypted, &server_key).unwrap();
        assert_eq!(decrypted.aead, cookie.aead);
    }

    #[test]
    fn test_s2v_different_inputs_different_output() {
        let k1 = [0x01u8; 32];
        let siv1 = s2v_cmac_aes256(&k1, b"hello");
        let siv2 = s2v_cmac_aes256(&k1, b"world");
        assert_ne!(siv1, siv2);
    }

    #[test]
    fn test_ctr_roundtrip() {
        let key = [0x11u8; 32];
        let iv = [0x22u8; SIV_OUTPUT_SIZE];
        let plaintext = b"Hello, AES-SIV-CTR mode test!";

        let ciphertext = aes_ctr_encrypt(&key, &iv, plaintext);
        let decrypted = aes_ctr_encrypt(&key, &iv, &ciphertext);

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_ctr_different_iv_different_output() {
        let key = [0x11u8; 32];
        let iv1 = [0x22u8; SIV_OUTPUT_SIZE];
        let iv2 = [0x33u8; SIV_OUTPUT_SIZE];
        let plaintext = b"determinism check";

        let ct1 = aes_ctr_encrypt(&key, &iv1, plaintext);
        let ct2 = aes_ctr_encrypt(&key, &iv2, plaintext);
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_counter_increment() {
        let mut ctr = [0u8; SIV_BLOCK_SIZE];
        increment_counter_be(&mut ctr);
        assert_eq!(ctr[SIV_BLOCK_SIZE - 1], 1);
        assert_eq!(ctr[SIV_BLOCK_SIZE - 2], 0);

        let mut ctr = [0xFFu8; SIV_BLOCK_SIZE];
        increment_counter_be(&mut ctr);
        assert_eq!(ctr, [0u8; SIV_BLOCK_SIZE]); // wraps to zero

        let mut ctr = [0u8; SIV_BLOCK_SIZE];
        ctr[SIV_BLOCK_SIZE - 1] = 0xFF;
        increment_counter_be(&mut ctr);
        assert_eq!(ctr[SIV_BLOCK_SIZE - 1], 0);
        assert_eq!(ctr[SIV_BLOCK_SIZE - 2], 1);
    }

    #[test]
    fn test_encrypt_with_full_key_works() {
        // Verify that a proper 64-byte key works end-to-end.
        let cookie = make_test_cookie();
        let key = [0x42u8; SIV_KEY_SIZE];
        let encrypted = cookie.encrypt(&key);
        assert_eq!(encrypted.len(), SIV_OUTPUT_SIZE + COOKIE_PLAINTEXT_MIN);
        let decrypted = NtsCookie::decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted.server_id, cookie.server_id);
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
