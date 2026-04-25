//! Segment-wise AES-256-GCM stream encryption.
//!
//! Each segment is up to 4 MB. Nonce is a 96-bit counter starting from 0,
//! incremented per segment.

use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::Aes256Gcm;
use rand::RngCore;

/// Maximum size of a plaintext segment before encryption (4 MB).
pub const SEGMENT_SIZE: usize = 4 * 1024 * 1024;

/// Nonce size for AES-256-GCM (96 bits = 12 bytes).
const NONCE_SIZE: usize = 12;

/// Encrypt a single segment with AES-256-GCM.
///
/// `segment_index` determines the nonce: big-endian 96-bit counter.
/// Returns `[ciphertext || tag]` (16-byte GCM tag appended).
pub fn encrypt_segment(
    key: &Aes256Gcm,
    segment_index: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce_bytes = make_nonce_bytes(segment_index);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    key.encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)
}

/// Decrypt a single segment with AES-256-GCM.
///
/// `segment_index` must match the index used during encryption.
pub fn decrypt_segment(
    key: &Aes256Gcm,
    segment_index: u32,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce_bytes = make_nonce_bytes(segment_index);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    key.decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Encrypt a complete data stream in segments.
///
/// Returns the concatenated encrypted segments, each prefixed with a 4-byte BE length.
/// Also returns the number of segments written.
pub fn encrypt_stream(key: &Aes256Gcm, data: &[u8]) -> Result<(Vec<u8>, u32), CryptoError> {
    let mut output = Vec::with_capacity(data.len() + data.len() / SEGMENT_SIZE * 20 + 20);
    let mut segment_index: u32 = 0;

    for chunk in data.chunks(SEGMENT_SIZE) {
        let encrypted = encrypt_segment(key, segment_index, chunk)?;
        output.extend_from_slice(&(encrypted.len() as u32).to_be_bytes());
        output.extend_from_slice(&encrypted);
        segment_index += 1;
    }

    // Handle empty data: still encrypt one empty segment so decryption can roundtrip
    if data.is_empty() {
        let encrypted = encrypt_segment(key, 0, &[])?;
        output.extend_from_slice(&(encrypted.len() as u32).to_be_bytes());
        output.extend_from_slice(&encrypted);
        segment_index = 1;
    }

    Ok((output, segment_index))
}

/// Decrypt a complete stream of length-prefixed encrypted segments.
///
/// `total_segments` must be the number of segments returned by `encrypt_stream`.
pub fn decrypt_stream(
    key: &Aes256Gcm,
    encrypted: &[u8],
    total_segments: u32,
) -> Result<Vec<u8>, CryptoError> {
    let mut output = Vec::new();

    if total_segments == 0 {
        return Ok(output);
    }

    let mut pos = 0;
    for i in 0..total_segments {
        if encrypted.len() < pos + 4 {
            return Err(CryptoError::InvalidSegmentLayout);
        }
        let seg_len = u32::from_be_bytes([
            encrypted[pos],
            encrypted[pos + 1],
            encrypted[pos + 2],
            encrypted[pos + 3],
        ]) as usize;
        pos += 4;

        if encrypted.len() < pos + seg_len {
            return Err(CryptoError::InvalidSegmentLayout);
        }
        let segment = &encrypted[pos..pos + seg_len];
        pos += seg_len;

        let decrypted = decrypt_segment(key, i, segment)?;
        output.extend_from_slice(&decrypted);
    }

    Ok(output)
}

/// Generate a random 256-bit DEK (Data Encryption Key) as raw bytes.
pub fn generate_dek() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Wrap (encrypt) a DEK with a KEK using AES-256-GCM with a random nonce.
///
/// Returns `[12-byte nonce || ciphertext || 16-byte tag]` = 60 bytes.
pub fn wrap_dek(kek: &Aes256Gcm, dek: &[u8; 32]) -> Result<[u8; 60], CryptoError> {
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let ciphertext = kek
        .encrypt(nonce, dek.as_slice())
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut output = [0u8; 60];
    output[..12].copy_from_slice(&nonce_bytes);
    output[12..].copy_from_slice(&ciphertext);
    Ok(output)
}

/// Unwrap (decrypt) a DEK with a KEK.
pub fn unwrap_dek(kek: &Aes256Gcm, wrapped: &[u8; 60]) -> Result<[u8; 32], CryptoError> {
    let nonce = aes_gcm::Nonce::from_slice(&wrapped[..12]);
    let plaintext = kek
        .decrypt(nonce, &wrapped[12..])
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let mut dek = [0u8; 32];
    dek.copy_from_slice(&plaintext);
    Ok(dek)
}

fn make_nonce_bytes(segment_index: u32) -> [u8; NONCE_SIZE] {
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    nonce_bytes[8..].copy_from_slice(&segment_index.to_be_bytes());
    nonce_bytes
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed (wrong key or tampered data)")]
    DecryptionFailed,
    #[error("invalid segment layout")]
    InvalidSegmentLayout,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::KeyInit;

    fn test_key() -> Aes256Gcm {
        Aes256Gcm::new_from_slice(&[0u8; 32]).unwrap()
    }

    #[test]
    fn segment_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = b"hello world";
        let encrypted = encrypt_segment(&key, 0, plaintext).unwrap();
        let decrypted = decrypt_segment(&key, 0, &encrypted).unwrap();
        assert_eq!(plaintext.as_slice(), &decrypted);
    }

    #[test]
    fn stream_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let data = vec![0xABu8; 5_000_000]; // > 1 segment
        let (encrypted, segments) = encrypt_stream(&key, &data).unwrap();
        let decrypted = decrypt_stream(&key, &encrypted, segments).unwrap();
        assert_eq!(data, decrypted);
    }

    #[test]
    fn empty_stream_roundtrip() {
        let key = test_key();
        let (encrypted, segments) = encrypt_stream(&key, &[]).unwrap();
        let decrypted = decrypt_stream(&key, &encrypted, segments).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = test_key();
        let key2 = Aes256Gcm::new_from_slice(&[1u8; 32]).unwrap();
        let encrypted = encrypt_segment(&key1, 0, b"secret").unwrap();
        assert!(decrypt_segment(&key2, 0, &encrypted).is_err());
    }

    #[test]
    fn wrong_segment_index_fails() {
        let key = test_key();
        let encrypted = encrypt_segment(&key, 0, b"secret").unwrap();
        assert!(decrypt_segment(&key, 1, &encrypted).is_err());
    }

    #[test]
    fn wrap_unwrap_dek_roundtrip() {
        let kek = test_key();
        let dek = generate_dek();
        let wrapped = wrap_dek(&kek, &dek).unwrap();
        let unwrapped = unwrap_dek(&kek, &wrapped).unwrap();
        assert_eq!(dek, unwrapped);
    }

    #[test]
    fn wrap_dek_wrong_kek_fails() {
        let kek1 = test_key();
        let kek2 = Aes256Gcm::new_from_slice(&[1u8; 32]).unwrap();
        let dek = generate_dek();
        let wrapped = wrap_dek(&kek1, &dek).unwrap();
        assert!(unwrap_dek(&kek2, &wrapped).is_err());
    }
}
