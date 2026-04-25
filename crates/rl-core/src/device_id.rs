//! Device ID: Ed25519 certificate → SHA-256 fingerprint → Base32+Luhn encoding.

use sha2::{Digest, Sha256};

/// A Device ID derived from an Ed25519 self-signed certificate.
///
/// Format: Base32(SHA-256(cert_der)) with Luhn checksum,
/// similar to Syncthing's device ID scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceId {
    /// Raw 32-byte SHA-256 fingerprint of the certificate DER.
    fingerprint: [u8; 32],
    /// Human-readable Base32+Luhn string.
    display: String,
}

impl DeviceId {
    /// Generate a new Ed25519 keypair, create a self-signed cert, and derive the Device ID.
    pub fn generate() -> Result<(Self, rcgen::CertifiedKey<rcgen::KeyPair>), DeviceIdError> {
        let certified =
            rcgen::generate_simple_self_signed(Vec::new()).map_err(DeviceIdError::CertCreate)?;
        let cert_der = certified.cert.der();
        let id = Self::from_cert_der(cert_der.as_ref());
        Ok((id, certified))
    }

    /// Derive a Device ID from an existing certificate DER bytes.
    pub fn from_cert_der(cert_der: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(cert_der);
        let fingerprint: [u8; 32] = hasher.finalize().into();

        let display = encode_base32_luhn(&fingerprint);

        Self {
            fingerprint,
            display,
        }
    }

    /// The human-readable Base32+Luhn display string.
    pub fn display(&self) -> &str {
        &self.display
    }

    /// The raw 32-byte SHA-256 fingerprint.
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }
}

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display)
    }
}

impl std::str::FromStr for DeviceId {
    type Err = DeviceIdError;

    fn from_str(s: &str) -> Result<Self, DeviceIdError> {
        let fingerprint = decode_base32_luhn(s)?;
        let display = encode_base32_luhn(&fingerprint);
        Ok(Self {
            fingerprint,
            display,
        })
    }
}

/// Encode 32 bytes as Base32 with Luhn checksum, grouped for readability.
///
/// 32 bytes → 52 Base32 chars. Split into groups of 4 chars + 1 Luhn check char.
/// 13 groups × 5 chars = 65 chars, separated by dashes = 77 chars total.
fn encode_base32_luhn(bytes: &[u8; 32]) -> String {
    let b32 = data_encoding::BASE32_NOPAD.encode(bytes);
    assert_eq!(b32.len(), 52);

    let mut groups: Vec<String> = Vec::new();
    for chunk in b32.as_bytes().chunks(4) {
        let group_str = std::str::from_utf8(chunk).unwrap();
        let check = luhn_check_char(group_str);
        groups.push(format!("{}{}", group_str, check));
    }

    groups.join("-")
}

/// Decode a Base32+Luhn string back to 32 bytes, validating checksums.
fn decode_base32_luhn(s: &str) -> Result<[u8; 32], DeviceIdError> {
    let cleaned: String = s.chars().filter(|c| *c != '-').collect();
    // 13 groups × 5 chars (4 data + 1 check) = 65
    if cleaned.len() != 65 {
        return Err(DeviceIdError::InvalidLength {
            expected: 65,
            got: cleaned.len(),
        });
    }

    // Verify Luhn checksum in each 5-char group and strip check digits
    let mut b32_chars = String::new();
    for chunk in cleaned.as_bytes().chunks(5) {
        let group = std::str::from_utf8(chunk).map_err(|_| DeviceIdError::InvalidEncoding)?;
        if group.len() != 5 {
            return Err(DeviceIdError::InvalidEncoding);
        }
        let data = &group[..4];
        let expected_check = luhn_check_char(data);
        let actual_check = group.as_bytes()[4] as char;
        if expected_check != actual_check {
            return Err(DeviceIdError::ChecksumMismatch);
        }
        b32_chars.push_str(data);
    }

    let decoded = data_encoding::BASE32_NOPAD
        .decode(b32_chars.as_bytes())
        .map_err(|_| DeviceIdError::InvalidEncoding)?;

    if decoded.len() != 32 {
        return Err(DeviceIdError::InvalidLength {
            expected: 32,
            got: decoded.len(),
        });
    }

    let fingerprint: [u8; 32] = decoded.try_into().unwrap();
    Ok(fingerprint)
}

/// Luhn mod-32 check character for a Base32 data string.
fn luhn_check_char(data: &str) -> char {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let mut sum: u32 = 0;
    for (i, ch) in data.chars().enumerate() {
        let val = ALPHABET.iter().position(|&c| c == ch as u8).unwrap_or(0) as u32;
        let factor = if i % 2 == 0 { 2 } else { 1 };
        sum += val * factor;
    }
    let check_val = (32 - (sum % 32)) % 32;
    ALPHABET[check_val as usize] as char
}

#[derive(Debug, thiserror::Error)]
pub enum DeviceIdError {
    #[error("certificate creation failed: {0}")]
    CertCreate(#[source] rcgen::Error),
    #[error("invalid length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },
    #[error("invalid encoding")]
    InvalidEncoding,
    #[error("checksum mismatch")]
    ChecksumMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_roundtrip() {
        let (id, _cert) = DeviceId::generate().unwrap();
        let display = id.display().to_string();
        let parsed: DeviceId = display.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn device_id_display_format() {
        let (id, _cert) = DeviceId::generate().unwrap();
        let display = id.display();
        // 13 groups of 5 chars separated by dashes
        let groups: Vec<&str> = display.split('-').collect();
        assert_eq!(groups.len(), 13);
        for group in &groups {
            assert_eq!(group.len(), 5);
        }
    }

    #[test]
    fn device_id_from_cert_der_consistent() {
        let (id, certified) = DeviceId::generate().unwrap();
        let id2 = DeviceId::from_cert_der(certified.cert.der().as_ref());
        assert_eq!(id, id2);
    }

    #[test]
    fn invalid_device_id_rejected() {
        assert!("invalid".parse::<DeviceId>().is_err());
    }

    #[test]
    fn device_id_deterministic_from_der() {
        let (id1, certified) = DeviceId::generate().unwrap();
        let der = certified.cert.der().to_vec();
        let id2 = DeviceId::from_cert_der(&der);
        let id3 = DeviceId::from_cert_der(&der);
        assert_eq!(id1, id2);
        assert_eq!(id2, id3);
    }
}
