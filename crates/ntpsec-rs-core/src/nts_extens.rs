// ──── nts_extens.rs — NTS Extension Fields ─────────────────────────
// Forensic reconstruction of ntpd/nts_extens.c
//
// NTS extension field handling: encoding and decoding NTP extension fields
// for cookie transport and authentication (RFC 8915 §5).
//
// ## NTP Extension Field Format
//
// All NTP extension fields share a common 4-byte header (RFC 7821):
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  ┌─────────────────────────────────────────────────────────────────┐
//  │         Field Type (16)        │        Length (16)             │
//  ├─────────────────────────────────────────────────────────────────┤
//  │                          Payload (variable)                     │
//  ├─────────────────────────────────────────────────────────────────┤
//  │                      Padding (to 4-byte boundary)               │
//  └─────────────────────────────────────────────────────────────────┘
//
// The Length field includes the 4-byte header.  The total field size
// (including padding) must be a multiple of 4 bytes.
//
// ## NTS Extension Field Types (RFC 8915 §5)
//
// The following field types are used by NTS:
//   - 0x0104  NTS Unique Identifier
//   - 0x0204  NTS Cookie
//   - 0x0304  NTS Cookie Placeholder
//   - 0x0404  NTS Authenticator (AEAD encryption result)
//
// ## Oracle
//   - ntpsec ntpd/nts_extens.c (12K)
//   - RFC 8915 §5 (NTP extension fields)
//   - RFC 7821 (NTP extension field format)
// =============================================================================

use crate::ntp_types::*;

// ──── NTS Extension Field Type Constants ──────────────────────────────
//
// These constants match RFC 8915 §5 and the IANA NTP Extension Field
// Types registry.  They are distinct from, but related to, the NTS-KE
// record types defined in `nts.rs`'s `nts_record` and `nts_ef` modules.

/// NTS Unique Identifier extension field (RFC 8915 §5.1).
pub const EXTENSION_FIELD_UNIQUE_IDENTIFIER: u16 = 0x0104;
/// NTS Cookie extension field (RFC 8915 §5.2).
pub const EXTENSION_FIELD_NTS_COOKIE: u16 = 0x0204;
/// NTS Cookie Placeholder extension field (RFC 8915 §5.2).
pub const EXTENSION_FIELD_NTS_COOKIE_PLACEHOLDER: u16 = 0x0304;
/// NTS Authenticator — AEAD encryption result (RFC 8915 §5.3).
pub const EXTENSION_FIELD_NTS_AUTHENTICATOR: u16 = 0x0404;
/// NTS Authentication Result extension field (RFC 8915 §5.4).
pub const EXTENSION_FIELD_NTS_AUTH_RESULT: u16 = 0x0106;

// ──── NTP Extension Field Header ──────────────────────────────────────

/// NTP extension field header (4 bytes).
///
/// The header consists of a 16-bit field type and a 16-bit length.
/// The length includes the 4-byte header itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C, packed)]
pub struct ExtensionFieldHeader {
    pub field_type: u16,
    pub length: u16,
}

impl ExtensionFieldHeader {
    pub fn new(field_type: u16, payload_len: u16) -> Self {
        Self {
            field_type,
            length: payload_len + 4,
        } // total length including header
    }

    /// Return the payload length (total length minus the 4-byte header).
    pub fn payload_length(&self) -> u16 {
        self.length.saturating_sub(4)
    }

    /// Return the total length (header + payload).
    pub fn total_length(&self) -> u16 {
        self.length
    }

    /// Return the padded total length (rounded up to the next 4-byte boundary).
    pub fn padded_length(&self) -> u16 {
        let len = self.length as usize;
        let padded = (len + 3) & !3;
        padded as u16
    }
}

// ──── Extension Field ─────────────────────────────────────────────────

/// A single NTP extension field (RFC 7821).
#[derive(Debug, Clone)]
pub struct ExtensionField {
    pub field_type: u16,
    pub payload: Vec<u8>,
}

impl ExtensionField {
    pub fn new(field_type: u16, payload: Vec<u8>) -> Self {
        Self {
            field_type,
            payload,
        }
    }

    /// Encode to wire format (padded to 4-byte boundary).
    ///
    /// The encoded output consists of:
    ///   - 2 bytes: field type (big-endian)
    ///   - 2 bytes: length = payload.len() + 4 (big-endian)
    ///   - N bytes: payload
    ///   - 0-3 bytes: zero padding to 4-byte boundary
    pub fn encode(&self) -> Vec<u8> {
        let header = ExtensionFieldHeader::new(self.field_type, self.payload.len() as u16);
        let padded_len = header.padded_length() as usize;
        let mut buf = Vec::with_capacity(padded_len);
        buf.extend_from_slice(&header.field_type.to_be_bytes());
        buf.extend_from_slice(&header.length.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        // Pad to 4-byte boundary
        while buf.len() % 4 != 0 {
            buf.push(0);
        }
        debug_assert_eq!(buf.len() % 4, 0);
        buf
    }

    /// Decode a single extension field from wire format.
    ///
    /// Returns `(field, remaining_bytes)` on success, or `None` if the
    /// data is truncated or malformed.
    pub fn decode(data: &[u8]) -> Option<(Self, &[u8])> {
        if data.len() < 4 {
            return None;
        }
        let field_type = u16::from_be_bytes([data[0], data[1]]);
        let length = u16::from_be_bytes([data[2], data[3]]);

        // Length must include at least the 4-byte header.
        if length < 4 {
            return None;
        }

        // RFC 7821: maximum extension field size is 4096 bytes
        let max_ext_len = 4096usize;
        if length as usize > max_ext_len {
            return None;
        }

        let padded_len = (length as usize + 3) & !3;
        if data.len() < padded_len {
            return None;
        }

        // Payload is the data between the 4-byte header and the end of
        // the unpadded field.
        let payload = data[4..length as usize].to_vec();
        let remaining = &data[padded_len..];
        Some((
            Self {
                field_type,
                payload,
            },
            remaining,
        ))
    }

    /// Decode all extension fields from a buffer.
    ///
    /// Parses as many complete extension fields as possible.  Returns
    /// all successfully decoded fields; stops when remaining data is
    /// too short for a valid header.
    pub fn decode_all(data: &[u8]) -> Vec<Self> {
        let mut fields = Vec::new();
        let mut remain = data;
        while !remain.is_empty() {
            match Self::decode(remain) {
                Some((field, rest)) => {
                    fields.push(field);
                    remain = rest;
                }
                None => break,
            }
        }
        fields
    }

    /// Return the total wire size of this field including padding.
    pub fn wire_size(&self) -> usize {
        let header = ExtensionFieldHeader::new(self.field_type, self.payload.len() as u16);
        header.padded_length() as usize
    }

    /// Return the payload size.
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }
}

// ──── NTS Authentication Result ───────────────────────────────────────

/// NTS authentication result, written by the server into the NTP response
/// after verifying the NTS cookie (RFC 8915 §5.3).
///
/// The authentication result extension field (type 0x0106, NTS Authenticator)
/// carries the AEAD output (encrypted S2C keys and a MAC) that proves the
/// server successfully decrypted and verified the client's cookie.
#[derive(Debug, Clone)]
pub struct NtsAuthResult {
    /// Server identity bytes — used by the client to verify it's talking
    /// to the correct NTS-KE server (RFC 8915 §5.3).
    pub server_id: Vec<u8>,
}

impl NtsAuthResult {
    pub fn new(server_id: Vec<u8>) -> Self {
        Self { server_id }
    }

    /// Encode as an NTS Authenticator extension field payload.
    ///
    /// The payload format is simply the server identifier bytes.
    pub fn encode(&self) -> Vec<u8> {
        self.server_id.clone()
    }

    /// Decode from an NTS Authenticator extension field payload.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        Some(Self {
            server_id: data.to_vec(),
        })
    }
}

// ──── NTS Authenticator ──────────────────────────────────────────────

/// NTS Authenticator payload (RFC 8915 §5.3, extension type 0x0404).
///
/// Wire format:
///   [ nonce_len: 2 bytes ][ ciphertext_len: 2 bytes ]
///   [ nonce: variable (padded to 4-byte boundary) ]
///   [ ciphertext: variable (padded to 4-byte boundary) ]
#[derive(Debug, Clone)]
pub struct NtsAuthenticator {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl NtsAuthenticator {
    /// Create a new NTS authenticator.
    pub fn new(nonce: Vec<u8>, ciphertext: Vec<u8>) -> Self {
        Self { nonce, ciphertext }
    }

    /// Encode the authenticator payload with proper padding.
    pub fn encode(&self) -> Vec<u8> {
        let nonce_len = self.nonce.len() as u16;
        let ciphertext_len = self.ciphertext.len() as u16;
        let mut buf = Vec::new();
        buf.extend_from_slice(&nonce_len.to_be_bytes());
        buf.extend_from_slice(&ciphertext_len.to_be_bytes());
        buf.extend_from_slice(&self.nonce);
        // Pad nonce to 4-byte boundary
        let nonce_pad = (4 - (self.nonce.len() % 4)) % 4;
        buf.extend(std::iter::repeat(0u8).take(nonce_pad));
        buf.extend_from_slice(&self.ciphertext);
        // Pad ciphertext to 4-byte boundary
        let ciphertext_pad = (4 - (self.ciphertext.len() % 4)) % 4;
        buf.extend(std::iter::repeat(0u8).take(ciphertext_pad));
        buf
    }

    /// Decode an authenticator payload from wire format.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let nonce_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let ciphertext_len = u16::from_be_bytes([data[2], data[3]]) as usize;

        let nonce_start = 4;
        let nonce_end = nonce_start + nonce_len;
        let nonce_padded_end = (nonce_end + 3) & !3;

        let ciphertext_start = nonce_padded_end;
        let ciphertext_end = ciphertext_start + ciphertext_len;

        if data.len() < ciphertext_end {
            return None;
        }

        let nonce = data[nonce_start..nonce_end].to_vec();
        let ciphertext = data[ciphertext_start..ciphertext_end].to_vec();

        Some(Self { nonce, ciphertext })
    }
}

/// Validate that the total size of a sequence of extension fields does not
/// exceed the maximum allowed by the NTP packet format.
///
/// RFC 8915 §5: The total size of all extension fields must fit within an
/// NTP packet, which has a maximum payload size of 65535 bytes (including
/// the NTP header).
pub fn validate_extension_fields_total_size(fields: &[ExtensionField]) -> Result<(), String> {
    const MAX_TOTAL_SIZE: usize = 65535;
    let mut total: usize = 0;
    for field in fields {
        total += field.wire_size();
        if total > MAX_TOTAL_SIZE {
            return Err(format!(
                "extension fields total size {} exceeds maximum {}",
                total, MAX_TOTAL_SIZE
            ));
        }
    }
    Ok(())
}

// ──── Tests ───────────────────────────────────────────────────────────

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
        // Payload not aligned to 4 bytes.
        let ef = ExtensionField::new(0x0104, vec![1, 2, 3]);
        let encoded = ef.encode();
        assert_eq!(encoded.len() % 4, 0);
        // 4 header + 3 payload + 1 padding = 8 bytes
        assert_eq!(encoded.len(), 8);

        // Payload aligned to 4 bytes exactly.
        let ef = ExtensionField::new(0x0104, vec![1, 2, 3, 4]);
        let encoded = ef.encode();
        assert_eq!(encoded.len() % 4, 0);
        // 4 header + 4 payload = 8 bytes
        assert_eq!(encoded.len(), 8);

        // Empty payload.
        let ef = ExtensionField::new(0x0104, vec![]);
        let encoded = ef.encode();
        assert_eq!(encoded.len() % 4, 0);
        assert_eq!(encoded.len(), 4);
    }

    #[test]
    fn test_extension_field_decode_all() {
        let ef1 = ExtensionField::new(EXTENSION_FIELD_UNIQUE_IDENTIFIER, vec![1, 2, 3, 4]);
        let ef2 = ExtensionField::new(EXTENSION_FIELD_NTS_COOKIE_PLACEHOLDER, vec![5, 6, 7, 8]);
        let ef3 = ExtensionField::new(EXTENSION_FIELD_NTS_AUTHENTICATOR, vec![9, 10]);

        let mut data = ef1.encode();
        data.extend_from_slice(&ef2.encode());
        data.extend_from_slice(&ef3.encode());

        let fields = ExtensionField::decode_all(&data);
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].field_type, EXTENSION_FIELD_UNIQUE_IDENTIFIER);
        assert_eq!(fields[1].field_type, EXTENSION_FIELD_NTS_COOKIE_PLACEHOLDER);
        assert_eq!(fields[2].field_type, EXTENSION_FIELD_NTS_AUTHENTICATOR);
    }

    #[test]
    fn test_extension_field_decode_truncated() {
        // Only 2 bytes of data (need at least 4 for header).
        let result = ExtensionField::decode(&[0x01, 0x04]);
        assert!(result.is_none());
    }

    #[test]
    fn test_extension_field_decode_malformed_length() {
        // Length < 4 is invalid.
        let data = [0x01, 0x04, 0x00, 0x02, 0xFF, 0xFF];
        let result = ExtensionField::decode(&data);
        assert!(result.is_none());
    }

    #[test]
    fn test_extension_field_padded_length() {
        let hdr = ExtensionFieldHeader::new(0x0104, 3);
        assert_eq!(hdr.payload_length(), 3);
        assert_eq!(hdr.total_length(), 7);
        assert_eq!(hdr.padded_length(), 8);

        let hdr = ExtensionFieldHeader::new(0x0104, 4);
        assert_eq!(hdr.payload_length(), 4);
        assert_eq!(hdr.total_length(), 8);
        assert_eq!(hdr.padded_length(), 8);

        let hdr = ExtensionFieldHeader::new(0x0104, 0);
        assert_eq!(hdr.payload_length(), 0);
        assert_eq!(hdr.total_length(), 4);
        assert_eq!(hdr.padded_length(), 4);
    }

    #[test]
    fn test_authenticator_roundtrip() {
        let auth = NtsAuthenticator::new(vec![0x01, 0x02, 0x03, 0x04], vec![0xAA; 16]);
        let encoded = auth.encode();
        // 4 bytes header + 4 nonce + 0 pad + 16 ciphertext + 0 pad = 24
        assert_eq!(encoded.len(), 24);

        let decoded = NtsAuthenticator::decode(&encoded).unwrap();
        assert_eq!(decoded.nonce, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(decoded.ciphertext, vec![0xAA; 16]);
    }

    #[test]
    fn test_authenticator_padding() {
        // Nonce not aligned to 4 bytes => should have padding.
        let auth = NtsAuthenticator::new(vec![0x01, 0x02, 0x03], vec![0xBB; 5]);
        let encoded = auth.encode();
        // 4 + 3 nonce + 1 pad + 5 ciphertext + 3 pad = 16
        assert_eq!(encoded.len(), 16);

        let decoded = NtsAuthenticator::decode(&encoded).unwrap();
        assert_eq!(decoded.nonce, vec![0x01, 0x02, 0x03]);
        assert_eq!(decoded.ciphertext, vec![0xBB; 5]);
    }

    #[test]
    fn test_authenticator_decode_truncated() {
        let result = NtsAuthenticator::decode(&[0x00, 0x03, 0x00, 0x05]);
        // Says nonce_len=3, ciphertext_len=5, but no payload follows the header
        assert!(result.is_none());
    }

    #[test]
    fn test_authenticator_decode_too_short() {
        let result = NtsAuthenticator::decode(&[0x00, 0x01]);
        assert!(result.is_none());
    }

    #[test]
    fn test_nts_auth_result_roundtrip() {
        let server_id = b"ntp.example.com".to_vec();
        let auth = NtsAuthResult::new(server_id.clone());
        let encoded = auth.encode();
        assert_eq!(encoded, server_id);

        let decoded = NtsAuthResult::decode(&encoded).unwrap();
        assert_eq!(decoded.server_id, b"ntp.example.com");
    }

    #[test]
    fn test_nts_auth_result_empty() {
        let result = NtsAuthResult::decode(&[]);
        assert!(result.is_none(), "empty data should produce None");
    }

    #[test]
    fn test_extension_field_wire_size() {
        let ef = ExtensionField::new(0x0104, vec![1, 2, 3]);
        assert_eq!(ef.wire_size(), 8); // 4 header + 3 payload + 1 pad
        assert_eq!(ef.payload_len(), 3);

        let ef = ExtensionField::new(0x0104, vec![1, 2, 3, 4]);
        assert_eq!(ef.wire_size(), 8);
        assert_eq!(ef.payload_len(), 4);
    }

    #[test]
    fn test_extension_field_constants() {
        assert_eq!(EXTENSION_FIELD_UNIQUE_IDENTIFIER, 0x0104);
        assert_eq!(EXTENSION_FIELD_NTS_COOKIE, 0x0204);
        assert_eq!(EXTENSION_FIELD_NTS_COOKIE_PLACEHOLDER, 0x0304);
        assert_eq!(EXTENSION_FIELD_NTS_AUTHENTICATOR, 0x0404);
    }

    #[test]
    fn test_decode_all_empty() {
        let fields = ExtensionField::decode_all(&[]);
        assert!(fields.is_empty());
    }

    #[test]
    fn test_decode_all_partial() {
        // Valid field followed by truncated data.
        let ef = ExtensionField::new(0x0104, vec![1, 2, 3, 4]);
        let mut data = ef.encode();
        data.extend_from_slice(&[0xFF, 0xFF]); // truncated header

        let fields = ExtensionField::decode_all(&data);
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].field_type, 0x0104);
    }

    #[test]
    fn test_debug_and_clone() {
        let ef = ExtensionField::new(EXTENSION_FIELD_UNIQUE_IDENTIFIER, vec![1, 2, 3]);
        let _ = format!("{:?}", ef);
        let cloned = ef.clone();
        assert_eq!(cloned.field_type, ef.field_type);
        assert_eq!(cloned.payload, ef.payload);

        let ar = NtsAuthResult::new(vec![1, 2, 3]);
        let _ = format!("{:?}", ar);
        let _ = ar.clone();
    }
}
