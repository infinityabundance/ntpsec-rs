// ──── ntp_signd.rs ──────────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/ntp_signd.c
//
// Samba signing protocol support for MS-SNTP authentication.
// =============================================================================

/// MS-SNTP signing for Active Directory integration.
/// This is a niche feature used when ntpd operates as an AD domain member.

/// Sign a response for MS-SNTP using the given key.
/// Returns None if signing is not configured.
pub fn sign_ms_sntp_response(_request: &[u8], _response: &mut [u8], _key_id: u32) -> Option<()> {
    // MS-SNTP signing requires the Samba ntpd_sign socket.
    // Not yet implemented — returns None (unsigned response).
    None
}

/// Check if MS-SNTP signing is configured (sign socket exists).
pub fn is_signing_available() -> bool {
    false // Not yet wired
}
