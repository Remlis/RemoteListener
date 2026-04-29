//! Key export/import: encrypt a secret key with a passphrase using scrypt + AES-256-GCM.
//!
//! Export format:
//! ```text
//! [magic 4B "RLKE"][version 1B][scrypt_salt 16B][scrypt_n 4B][scrypt_r 4B][scrypt_p 4B]
//! [nonce 12B][encrypted_key 48B (32 data + 16 tag)]
//! ```

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::{rngs::OsRng, RngCore};

/// Magic for key export blobs.
const MAGIC: [u8; 4] = [b'R', b'L', b'K', b'E'];
const VERSION: u8 = 1;
const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;

/// Default scrypt parameters (moderate security, reasonable performance).
const SCRYPT_N: u32 = 1 << 15; // 32768
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

/// Export a 32-byte secret key, encrypting it with a passphrase.
///
/// Returns 93 bytes: magic(4) + version(1) + salt(16) + N(4) + r(4) + p(4) + nonce(12) + ciphertext+tag(48)
pub fn export_key(secret_key: &[u8; 32], passphrase: &[u8]) -> Result<[u8; 93], KeyError> {
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);

    let kek = derive_kek(passphrase, &salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = kek
        .encrypt(nonce, secret_key.as_slice())
        .map_err(|_| KeyError::EncryptionFailed)?;

    let mut output = [0u8; 93];
    let mut pos = 0;

    output[pos..pos + 4].copy_from_slice(&MAGIC);
    pos += 4;
    output[pos] = VERSION;
    pos += 1;
    output[pos..pos + SALT_SIZE].copy_from_slice(&salt);
    pos += SALT_SIZE;
    output[pos..pos + 4].copy_from_slice(&SCRYPT_N.to_be_bytes());
    pos += 4;
    output[pos..pos + 4].copy_from_slice(&SCRYPT_R.to_be_bytes());
    pos += 4;
    output[pos..pos + 4].copy_from_slice(&SCRYPT_P.to_be_bytes());
    pos += 4;
    output[pos..pos + NONCE_SIZE].copy_from_slice(nonce);
    pos += NONCE_SIZE;
    output[pos..].copy_from_slice(&ciphertext);

    Ok(output)
}

/// Import a secret key from an encrypted blob, decrypting with a passphrase.
pub fn import_key(blob: &[u8; 93], passphrase: &[u8]) -> Result<[u8; 32], KeyError> {
    let mut pos = 0;

    if blob[pos..pos + 4] != MAGIC {
        return Err(KeyError::InvalidMagic);
    }
    pos += 4;

    let version = blob[pos];
    if version != VERSION {
        return Err(KeyError::UnsupportedVersion(version));
    }
    pos += 1;

    let mut salt = [0u8; SALT_SIZE];
    salt.copy_from_slice(&blob[pos..pos + SALT_SIZE]);
    pos += SALT_SIZE;

    let n = u32::from_be_bytes([blob[pos], blob[pos + 1], blob[pos + 2], blob[pos + 3]]);
    pos += 4;
    let r = u32::from_be_bytes([blob[pos], blob[pos + 1], blob[pos + 2], blob[pos + 3]]);
    pos += 4;
    let p = u32::from_be_bytes([blob[pos], blob[pos + 1], blob[pos + 2], blob[pos + 3]]);
    pos += 4;

    let nonce = Nonce::from_slice(&blob[pos..pos + NONCE_SIZE]);
    pos += NONCE_SIZE;

    let ciphertext = &blob[pos..];

    let kek = derive_kek(passphrase, &salt, n, r, p)?;
    let plaintext = kek
        .decrypt(nonce, ciphertext)
        .map_err(|_| KeyError::DecryptionFailed)?;

    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    Ok(key)
}

fn derive_kek(
    passphrase: &[u8],
    salt: &[u8],
    n: u32,
    r: u32,
    p: u32,
) -> Result<Aes256Gcm, KeyError> {
    let mut kek_bytes = [0u8; 32];
    scrypt::scrypt(
        passphrase,
        salt,
        &scrypt::Params::new(n.ilog2() as u8, r, p, 32)
            .map_err(|_| KeyError::InvalidScryptParams)?,
        &mut kek_bytes,
    )
    .map_err(|_| KeyError::ScryptFailed)?;
    Ok(Aes256Gcm::new_from_slice(&kek_bytes).expect("32 bytes is valid AES-256 key"))
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("invalid magic bytes")]
    InvalidMagic,
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed (wrong passphrase?)")]
    DecryptionFailed,
    #[error("invalid scrypt parameters")]
    InvalidScryptParams,
    #[error("scrypt key derivation failed")]
    ScryptFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic cross-platform test vector for scrypt key derivation.
    /// This must match the Swift RLKitTests test vector.
    #[test]
    fn scrypt_derive_kek_deterministic() {
        // Fixed inputs
        let passphrase = b"test-password";
        let salt = [0x01u8; 16]; // 16 bytes of 0x01
        let n: u32 = 1024; // 2^10 — small for test speed
        let r: u32 = 8;
        let p: u32 = 1;

        // Compute scrypt output directly
        let mut kek_bytes = [0u8; 32];
        scrypt::scrypt(
            passphrase,
            &salt,
            &scrypt::Params::new(n.ilog2() as u8, r, p, 32).unwrap(),
            &mut kek_bytes,
        )
        .unwrap();

        // Expected scrypt output (pre-computed via `scrypt` crate)
        // scrypt("test-password", 0x01*16, N=1024, r=8, p=1, len=32)
        let expected: [u8; 32] = [
            0x36, 0x28, 0xa6, 0x06, 0xdb, 0x99, 0x72, 0x6a, 0x23, 0xbd, 0x6e, 0xa8, 0xda, 0x74,
            0xc8, 0x96, 0x15, 0x83, 0xb7, 0x2e, 0x7f, 0xba, 0xaf, 0xf3, 0x2c, 0xd2, 0x43, 0xd9,
            0xcc, 0xc9, 0x75, 0x30,
        ];
        assert_eq!(
            kek_bytes, expected,
            "scrypt KEK derivation mismatch — cross-platform compatibility broken"
        );
    }

    #[test]
    fn export_import_roundtrip() {
        let secret_key = [0x42u8; 32];
        let passphrase = b"roundtrip-pass";

        let blob = export_key(&secret_key, passphrase).unwrap();
        let imported = import_key(&blob, passphrase).unwrap();
        assert_eq!(imported, secret_key);
    }

    #[test]
    fn import_wrong_passphrase_fails() {
        let secret_key = [0x42u8; 32];
        let blob = export_key(&secret_key, b"correct-pass").unwrap();
        assert!(import_key(&blob, b"wrong-pass").is_err());
    }
}
