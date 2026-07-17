// ──── nts_extens.rs ─────────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/nts_extens.c
//
// NTS extension field handling: encoding and decoding NTP extension fields
// for cookie transport and authentication.
//
// ## Oracle
//   - ntpsec ntpd/nts_extens.c (12K)
//   - RFC 8915 §5 (NTP extension fields)
//   - RFC 7821 (NTP extension field format)
// =============================================================================

use crate::ntp_types::*;

/// NTP extension field header (4 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C, packed)]
pub struct ExtensionFieldHeader {
    pub field_type: u16,
    pub length: u16,
}

impl ExtensionFieldHeader {
    pub fn new(field_type: u16, payload_len: u16) -> Self {
        Self { field_type, length: payload_len + 4 } // total length including header
    }

    pub fn payload_length(&self) -> u16 {
        self.length.saturating_sub(4)
    }

    pub fn total_length(&self) -> u16 {
        self.length
    }
}

/// An NTP extension field.
#[derive(Debug, Clone)]
pub struct ExtensionField {
    pub field_type: u16,
    pub payload: Vec<u8>,
}

impl ExtensionField {
    pub fn new(field_type: u16, payload: Vec<u8>) -> Self {
        Self { field_type, payload }
    }

    /// Encode to wire format (padded to 4-byte boundary).
    pub fn encode(&self) -> Vec<u8> {
        let header = ExtensionFieldHeader::new(self.field_type, self.payload.len() as u16);
        let mut buf = Vec::with_capacity(header.total_length() as usize);
        buf.extend_from_slice(&header.field_type.to_be_bytes());
        buf.extend_from_slice(&header.length.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        // Pad to 4-byte boundary
        while buf.len() % 4 != 0 {
            buf.push(0);
        }
        buf
    }

    /// Decode from wire format.
    pub fn decode(data: &[u8]) -> Option<(Self, &[u8])> {
        if data.len() < 4 {
            return None;
        }
        let field_type = u16::from_be_bytes([data[0], data[1]]);
        let length = u16::from_be_bytes([data[2], data[3]]);
        if length as usize > data.len() || length < 4 {
            return None;
        }
        let payload = data[4..length as usize].to_vec();
        let remaining = &data[length as usize..];
        Some((Self { field_type, payload }, remaining))
    }
}

/// NTS Authenticator Encryption (AEAD) field header.
#[derive(Debug, Clone)]
pub struct NtsAuthHeader {
    pub nonce_len: u16,
}

impl NtsAuthHeader {
    pub const SIZE: usize = 2;

    pub fn encode(&self) -> Vec<u8> {
        self.nonce_len.to_be_bytes().to_vec()
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }
        Some(Self { nonce_len: u16::from_be_bytes([data[0], data[1]]) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extension_field_roundtrip() {
        let ef = ExtensionField::new(0x0104, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let encoded = ef.encode();
        let (decoded, remaining) = ExtensionField::decode(&encoded).unwrap();
        assert_eq!(decoded.field_type, 0x0104);
        assert_eq!(decoded.payload, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(remaining.is_empty());
    }

    #[test]
    fn test_extension_field_padding() {
        let ef = ExtensionField::new(0x0104, vec![1, 2, 3]);
        let encoded = ef.encode();
        assert_eq!(encoded.len() % 4, 0);
    }
}
