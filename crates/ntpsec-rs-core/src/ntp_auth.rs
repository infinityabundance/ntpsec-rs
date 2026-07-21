// ──── ntp_auth.rs ───────────────────────────────────────────────────────────
// Forensic reconstruction of include/ntp_auth.h, libntp/authkeys.c,
// libntp/authreadkeys.c, libntp/macencrypt.c
//
// Full NTP authentication subsystem: key storage, key file parsing with the
// same format and error messages as ntpsec, MAC computation (MD5, SHA1,
// AES-128-CMAC), and cryptographic helper functions.
//
// ## Oracle
//   - ntpsec include/ntp_auth.h
//   - ntpsec libntp/authkeys.c (15K)
//   - ntpsec libntp/authreadkeys.c (11K)
//   - ntpsec libntp/macencrypt.c (10K)
//
// ## Court
//   - docs/courts/ntp_auth.md
// =============================================================================

use crate::ntp_types::*;

/// Key identifier type (32-bit unsigned, matching ntpsec's `keyid_t`).
pub type KeyId = u32;

/// Maximum key ID value (ntpsec uses u32 max).
pub const KEYID_MAX: KeyId = u32::MAX;

/// Maximum key length in bytes (ntpsec: 64 bytes for SHA1, 16 for MD5).
pub const KEY_MAX_LEN: usize = 64;

/// Supported digest types for NTP authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestType {
    None,
    Md5,
    Sha1,
    Aes128Cmac,
}

impl DigestType {
    /// MAC digest length in bytes.
    pub fn digest_length(&self) -> usize {
        match self {
            DigestType::None => 0,
            DigestType::Md5 => 16,
            DigestType::Sha1 => 20,
            DigestType::Aes128Cmac => 16,
        }
    }

    /// NTPsec name string for this digest type.
    pub fn as_str(&self) -> &'static str {
        match self {
            DigestType::None => "none",
            DigestType::Md5 => "MD5",
            DigestType::Sha1 => "SHA1",
            DigestType::Aes128Cmac => "AES-128-CMAC",
        }
    }

    /// Parse from ntp.keys format string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "md5" => Some(DigestType::Md5),
            "sha" | "sha1" => Some(DigestType::Sha1),
            "aes-128-cmac" | "cmac" => Some(DigestType::Aes128Cmac),
            _ => None,
        }
    }
}

/// An NTP authentication key (matching ntpsec's `symkey` struct).
#[derive(Debug, Clone)]
pub struct NtpAuthKey {
    pub id: KeyId,
    pub digest: DigestType,
    pub key_data: Vec<u8>,
}

impl NtpAuthKey {
    /// Create a new auth key, truncating key data to MAX_KEY_LEN.
    pub fn new(id: KeyId, digest: DigestType, key_data: Vec<u8>) -> Self {
        let key_data = key_data.into_iter().take(KEY_MAX_LEN).collect();
        Self {
            id,
            digest,
            key_data,
        }
    }

    /// Compute the MAC for a given packet buffer.
    /// Real implementation using md-5, sha-1, aes crates.
    pub fn mac(&self, pkt: &[u8]) -> Option<Vec<u8>> {
        use digest::{Digest, FixedOutput};
        let digest_len = self.digest.digest_length();
        if digest_len == 0 {
            return None;
        }

        match self.digest {
            DigestType::Md5 => {
                // Keyed MD5 as ntpsec's digest_encrypt: MD5(key || packet)
                let mut ctx = md5::Md5::default();
                Digest::update(&mut ctx, &self.key_data);
                Digest::update(&mut ctx, pkt);
                let hash = ctx.finalize_fixed();
                Some(hash[..digest_len].to_vec())
            }
            DigestType::Sha1 => {
                // Keyed SHA1 as ntpsec's digest_encrypt: SHA1(key || packet)
                let mut ctx = sha1::Sha1::default();
                Digest::update(&mut ctx, &self.key_data);
                Digest::update(&mut ctx, pkt);
                let hash = ctx.finalize_fixed();
                Some(hash[..digest_len].to_vec())
            }
            DigestType::Aes128Cmac => {
                // AES-128-CMAC (RFC 4493) via cmac + aes crates
                if self.key_data.len() < 16 {
                    return None;
                }
                use aes::Aes128;
                use cmac::{Cmac, Mac};
                let mut mac = Cmac::<Aes128>::new_from_slice(&self.key_data[..16]).ok()?;
                mac.update(pkt);
                let result = mac.finalize();
                let bytes = result.into_bytes();
                Some(bytes.to_vec())
            }
            DigestType::None => None,
        }
    }

    /// Verify a MAC against a packet (constant-time comparison).
    pub fn verify_mac(&self, pkt: &[u8], expected_mac: &[u8]) -> bool {
        self.mac(pkt).map_or(false, |computed| {
            computed.len() == expected_mac.len()
                && computed
                    .iter()
                    .zip(expected_mac.iter())
                    .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                    == 0
        })
    }
}

/// Authentication key store — matches ntpsec's key database.
#[derive(Debug, Default)]
pub struct AuthKeyStore {
    keys: Vec<NtpAuthKey>,
    trusted_keys: Vec<KeyId>,
    control_key: Option<KeyId>,
}

impl AuthKeyStore {
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
            trusted_keys: Vec::new(),
            control_key: None,
        }
    }

    pub fn add_key(&mut self, key: NtpAuthKey) {
        self.keys.push(key);
    }

    pub fn get_key(&self, id: KeyId) -> Option<&NtpAuthKey> {
        self.keys.iter().find(|k| k.id == id)
    }

    pub fn has_key(&self, id: KeyId) -> bool {
        self.keys.iter().any(|k| k.id == id)
    }

    pub fn remove_key(&mut self, id: KeyId) {
        self.keys.retain(|k| k.id != id);
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    pub fn add_trusted_key(&mut self, id: KeyId) {
        if !self.trusted_keys.contains(&id) {
            self.trusted_keys.push(id);
        }
    }

    pub fn remove_trusted_key(&mut self, id: KeyId) {
        self.trusted_keys.retain(|&k| k != id);
    }

    pub fn is_trusted_key(&self, id: KeyId) -> bool {
        self.trusted_keys.contains(&id)
    }

    pub fn set_control_key(&mut self, id: KeyId) {
        self.control_key = Some(id);
    }
    pub fn get_control_key(&self) -> Option<KeyId> {
        self.control_key
    }

    /// Parse an ntp.keys file.
    ///
    /// File format (matching ntpsec's authreadkeys.c):
    ///   `keyid digesttype keydata [trusted]`
    ///
    /// Comment lines start with `#`.  Empty lines are ignored.
    pub fn parse_keys_file(&mut self, content: &str) -> Result<usize, String> {
        let mut count = 0;
        for (lineno, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            match self.parse_key_line(trimmed, lineno + 1) {
                Ok(()) => count += 1,
                Err(e) => return Err(format!("line {}: {}", lineno + 1, e)),
            }
        }
        Ok(count)
    }

    /// Parse a single ntp.keys line.
    fn parse_key_line(&mut self, line: &str, lineno: usize) -> Result<(), String> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(format!(
                "too few fields (need at least 3, got {})",
                parts.len()
            ));
        }

        let id: KeyId = parts[0]
            .parse()
            .map_err(|_| format!("invalid key ID '{}'", parts[0]))?;
        let digest = DigestType::from_str(parts[1])
            .ok_or_else(|| format!("unknown digest type '{}'", parts[1]))?;
        // NTPsec rule (authreadkeys.c):
        //   ≤ 20 characters → printable ASCII key (used as-is)
        //   > 20 characters → hex-encoded binary key (decoded)
        let key_data = if parts[2].len() > 20
            && parts[2].chars().all(|c| c.is_ascii_hexdigit())
            && parts[2].len() % 2 == 0
        {
            hex_decode(parts[2]).unwrap_or_else(|_| parts[2].as_bytes().to_vec())
        } else {
            parts[2].as_bytes().to_vec()
        };

        let mut key = NtpAuthKey::new(id, digest, key_data);

        self.add_key(key);

        // Optional 4th field: "trusted"
        if parts.len() >= 4 && parts[3].to_lowercase() == "trusted" {
            self.add_trusted_key(id);
        }

        Ok(())
    }

    /// Iterate over all keys.
    pub fn iter(&self) -> impl Iterator<Item = &NtpAuthKey> {
        self.keys.iter()
    }

    /// Dump the key store in ntp.keys format (for debugging).
    pub fn format(&self) -> String {
        let mut out = String::new();
        for key in &self.keys {
            let hex = hex_encode(&key.key_data);
            let trusted = if self.trusted_keys.contains(&key.id) {
                " trusted"
            } else {
                ""
            };
            out.push_str(&format!(
                "{} {} {}{}\n",
                key.id,
                key.digest.as_str(),
                hex,
                trusted
            ));
        }
        out
    }
}

// ──── Crypto stubs (Phase 2: replace with proper md-5, sha-1, aes-siv crates)

/// Real

// ──── Hex Encoding/Decoding ───────────────────────────────────────────

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| format!("invalid hex: {}", s)))
        .collect()
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

// ──── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_key_line_md5() {
        let mut store = AuthKeyStore::new();
        assert!(store.parse_key_line("10 MD5 mysecretkey", 1).is_ok());
        let key = store.get_key(10).unwrap();
        assert_eq!(key.digest, DigestType::Md5);
    }

    #[test]
    fn test_parse_key_line_sha1() {
        let mut store = AuthKeyStore::new();
        assert!(store.parse_key_line("20 SHA1 mysecretkey", 1).is_ok());
        let key = store.get_key(20).unwrap();
        assert_eq!(key.digest, DigestType::Sha1);
    }

    #[test]
    fn test_parse_key_line_cmac() {
        let mut store = AuthKeyStore::new();
        assert!(store.parse_key_line("30 CMAC 0123456789abcdef", 1).is_ok());
        let key = store.get_key(30).unwrap();
        assert_eq!(key.digest, DigestType::Aes128Cmac);
    }

    #[test]
    fn test_parse_key_line_trusted() {
        let mut store = AuthKeyStore::new();
        assert!(store.parse_key_line("10 MD5 secret trusted", 1).is_ok());
        assert!(store.is_trusted_key(10));
    }

    #[test]
    fn test_parse_key_line_too_few() {
        let mut store = AuthKeyStore::new();
        assert!(store.parse_key_line("10 MD5", 1).is_err());
    }

    #[test]
    fn test_parse_key_line_bad_id() {
        let mut store = AuthKeyStore::new();
        assert!(store.parse_key_line("abc MD5 key", 1).is_err());
    }

    #[test]
    fn test_parse_keys_file() {
        let mut store = AuthKeyStore::new();
        let content =
            "# NTP keys file\n10 MD5 secret1\n20 SHA1 secret2 trusted\n\n30 CMAC abcdef\n";
        let count = store.parse_keys_file(content).unwrap();
        assert_eq!(count, 3);
        assert!(store.is_trusted_key(20));
    }

    #[test]
    fn test_mac_md5_roundtrip() {
        let key = NtpAuthKey::new(1, DigestType::Md5, b"password".to_vec());
        let mac = key.mac(b"test packet").unwrap();
        assert_eq!(mac.len(), 16);
        assert!(key.verify_mac(b"test packet", &mac));
        assert!(!key.verify_mac(b"wrong packet", &mac));
    }

    #[test]
    fn test_mac_sha1_roundtrip() {
        let key = NtpAuthKey::new(1, DigestType::Sha1, b"password".to_vec());
        let mac = key.mac(b"test packet").unwrap();
        assert_eq!(mac.len(), 20);
        assert!(key.verify_mac(b"test packet", &mac));
    }

    #[test]
    fn test_mac_aes128cmac_roundtrip() {
        let key = NtpAuthKey::new(1, DigestType::Aes128Cmac, b"0123456789abcdef".to_vec());
        let mac = key.mac(b"test packet").unwrap();
        assert_eq!(mac.len(), 16);
        assert!(key.verify_mac(b"test packet", &mac));
        assert!(!key.verify_mac(b"wrong packet", &mac));
    }

    #[test]
    fn test_md5_known_vector() {
        use digest::{Digest, FixedOutput};
        use hex_literal::hex;
        let result = md5::Md5::default().finalize_fixed();
        let expected = hex!("d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(result[..], expected);
    }

    #[test]
    fn test_sha1_known_vector() {
        use digest::{Digest, FixedOutput};
        use hex_literal::hex;
        let mut ctx = sha1::Sha1::default();
        Digest::update(&mut ctx, b"abc");
        let result = ctx.finalize_fixed();
        let expected = hex!("a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(result[..], expected);
    }

    #[test]
    fn test_hex_encoding() {
        let data = b"hello";
        let hex = hex_encode(data);
        let decoded = hex_decode(&hex).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_digest_lengths() {
        assert!(DigestType::Md5.digest_length() == 16);
        assert!(DigestType::Sha1.digest_length() == 20);
        assert!(DigestType::Aes128Cmac.digest_length() == 16);
    }

    #[test]
    fn test_key_format_dump() {
        let mut store = AuthKeyStore::new();
        store.parse_key_line("10 MD5 secret trusted", 1).unwrap();
        let dump = store.format();
        assert!(dump.contains("10"));
        assert!(dump.contains("MD5"));
    }

    #[test]
    fn test_remove_key() {
        let mut store = AuthKeyStore::new();
        store.add_key(NtpAuthKey::new(1, DigestType::Md5, b"key".to_vec()));
        assert!(store.has_key(1));
        store.remove_key(1);
        assert!(!store.has_key(1));
    }
}
