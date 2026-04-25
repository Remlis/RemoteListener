//! High-level decryption pipeline for .rlrec recording files.

use crate::encrypt::{self, CryptoError};
use crate::format::RecordingFile;
use aes_gcm::{Aes256Gcm, KeyInit};

/// Decrypt a recording file using the receiver's keypair.
///
/// Looks up the key entry matching `my_fingerprint`, unwraps the DEK,
/// then decrypts all audio segments.
pub fn decrypt_recording(
    file: &RecordingFile,
    my_fingerprint: &[u8; 32],
    kek: &Aes256Gcm,
) -> Result<Vec<u8>, CryptoError> {
    let key_entry = file
        .header
        .find_key_entry(my_fingerprint)
        .ok_or(CryptoError::DecryptionFailed)?;

    // Unwrap DEK
    let dek = encrypt::unwrap_dek(kek, key_entry.wrapped_dek())?;
    let cipher = Aes256Gcm::new_from_slice(&dek).map_err(|_| CryptoError::DecryptionFailed)?;

    // Decrypt all segments
    encrypt::decrypt_stream(&cipher, &file.encrypted_data, file.header.segment_count)
}
