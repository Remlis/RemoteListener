//! Recording file format (.rlrec):
//!
//! ```text
//! [magic 4B][version 1B][channel_id_len 2B][channel_id][num_key_entries 2B]
//! [key_entry_1][key_entry_2]...[sender_key_present 1B][sender_public_key 32B]
//! [nonce 12B][segment_count 4B][encrypted_data...]
//! ```
//!
//! Version 1 files don't have sender_public_key. Version 2+ includes it.
//!
//! Key entry:
//! ```text
//! [fingerprint 32B][wrapped_dek 60B]
//! ```

use crate::encrypt::{self, CryptoError};
use aes_gcm::{Aes256Gcm, KeyInit};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

/// Magic bytes for .rlrec files: "RLRF" (Remote Listener Recording Format).
pub const MAGIC: [u8; 4] = [b'R', b'L', b'R', b'F'];

/// Current format version.
pub const FORMAT_VERSION: u8 = 2;

/// Version 1 (no sender public key).
const FORMAT_VERSION_V1: u8 = 1;

/// Size of a wrapped DEK entry: 12 (nonce) + 32 (ciphertext) + 16 (tag) = 60 bytes.
pub const WRAPPED_DEK_SIZE: usize = 60;

/// A single key entry in the file header: public key fingerprint + wrapped DEK.
#[derive(Debug, Clone)]
pub struct KeyEntry {
    /// SHA-256 fingerprint of the receiver's X25519 public key.
    fingerprint: [u8; 32],
    /// AES-256-GCM wrapped DEK: [nonce 12B || ciphertext+tag 48B] = 60 bytes.
    wrapped_dek: [u8; WRAPPED_DEK_SIZE],
}

impl KeyEntry {
    /// Create a new key entry by wrapping the DEK for a specific receiver.
    pub fn new(
        kek: &Aes256Gcm,
        public_key_fingerprint: [u8; 32],
        dek: &[u8; 32],
    ) -> Result<Self, CryptoError> {
        let wrapped_dek = encrypt::wrap_dek(kek, dek)?;
        Ok(Self {
            fingerprint: public_key_fingerprint,
            wrapped_dek,
        })
    }

    /// The public key fingerprint this entry is for.
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    /// The wrapped DEK bytes.
    pub fn wrapped_dek(&self) -> &[u8; WRAPPED_DEK_SIZE] {
        &self.wrapped_dek
    }

    /// Serialize to bytes: [fingerprint 32B][wrapped_dek 60B] = 92 bytes.
    pub fn to_bytes(&self) -> [u8; 92] {
        let mut buf = [0u8; 92];
        buf[..32].copy_from_slice(&self.fingerprint);
        buf[32..].copy_from_slice(&self.wrapped_dek);
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(buf: &[u8; 92]) -> Self {
        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(&buf[..32]);
        let mut wrapped_dek = [0u8; WRAPPED_DEK_SIZE];
        wrapped_dek.copy_from_slice(&buf[32..]);
        Self {
            fingerprint,
            wrapped_dek,
        }
    }
}

/// Recording file header (unencrypted).
#[derive(Debug, Clone)]
pub struct RecordingHeader {
    /// Channel ID this recording belongs to.
    pub channel_id: String,
    /// Key entries — one per authorized receiver.
    pub key_entries: Vec<KeyEntry>,
    /// Sender's X25519 public key (for ECDH by receivers).
    pub sender_public_key: Option<[u8; 32]>,
    /// Nonce used for the first segment (12 bytes).
    pub nonce: [u8; 12],
    /// Number of encrypted segments.
    pub segment_count: u32,
}

impl RecordingHeader {
    /// Find the key entry matching a given public key fingerprint.
    pub fn find_key_entry(&self, fingerprint: &[u8; 32]) -> Option<&KeyEntry> {
        self.key_entries
            .iter()
            .find(|e| e.fingerprint == *fingerprint)
    }
}

/// A complete recording file (header + encrypted data).
#[derive(Debug, Clone)]
pub struct RecordingFile {
    pub header: RecordingHeader,
    pub encrypted_data: Vec<u8>,
}

/// Builder for creating recording files.
pub struct RecordingFileBuilder {
    channel_id: String,
    key_entries: Vec<KeyEntry>,
    sender_public_key: Option<[u8; 32]>,
    dek: [u8; 32],
    nonce: [u8; 12],
}

impl RecordingFileBuilder {
    /// Create a new builder. Generates a random DEK and nonce.
    pub fn new(channel_id: String) -> Self {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        Self {
            channel_id,
            key_entries: Vec::new(),
            sender_public_key: None,
            dek: encrypt::generate_dek(),
            nonce,
        }
    }

    /// Create a builder with a specific DEK (for testing).
    pub fn with_dek(channel_id: String, dek: [u8; 32]) -> Self {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        Self {
            channel_id,
            key_entries: Vec::new(),
            sender_public_key: None,
            dek,
            nonce,
        }
    }

    /// Set the sender's X25519 public key (for ECDH by receivers).
    pub fn with_sender_public_key(mut self, public_key: [u8; 32]) -> Self {
        self.sender_public_key = Some(public_key);
        self
    }

    /// Add a key entry for a receiver (wraps the DEK with the receiver's KEK).
    pub fn add_receiver(
        mut self,
        kek: &Aes256Gcm,
        public_key_fingerprint: [u8; 32],
    ) -> Result<Self, CryptoError> {
        let entry = KeyEntry::new(kek, public_key_fingerprint, &self.dek)?;
        self.key_entries.push(entry);
        Ok(self)
    }

    /// Get the DEK (for direct encryption without going through file serialization).
    pub fn dek(&self) -> &[u8; 32] {
        &self.dek
    }

    /// Get the nonce.
    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }

    /// Encrypt the audio data and build the recording file.
    pub fn build(self, audio_data: &[u8]) -> Result<RecordingFile, CryptoError> {
        let cipher =
            Aes256Gcm::new_from_slice(&self.dek).map_err(|_| CryptoError::DecryptionFailed)?;
        let (encrypted_data, segment_count) = encrypt::encrypt_stream(&cipher, audio_data)?;

        Ok(RecordingFile {
            header: RecordingHeader {
                channel_id: self.channel_id,
                key_entries: self.key_entries,
                sender_public_key: self.sender_public_key,
                nonce: self.nonce,
                segment_count,
            },
            encrypted_data,
        })
    }
}

impl RecordingFile {
    /// Serialize the complete recording file to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Magic
        buf.extend_from_slice(&MAGIC);

        // Version
        buf.push(FORMAT_VERSION);

        // Channel ID (length-prefixed)
        let channel_bytes = self.header.channel_id.as_bytes();
        buf.extend_from_slice(&(channel_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(channel_bytes);

        // Number of key entries
        buf.extend_from_slice(&(self.header.key_entries.len() as u16).to_be_bytes());

        // Key entries
        for entry in &self.header.key_entries {
            buf.extend_from_slice(&entry.to_bytes());
        }

        // Sender public key (1 byte present flag + 32 bytes if present)
        if let Some(ref pk) = self.header.sender_public_key {
            buf.push(1);
            buf.extend_from_slice(pk);
        } else {
            buf.push(0);
        }

        // Nonce
        buf.extend_from_slice(&self.header.nonce);

        // Segment count
        buf.extend_from_slice(&self.header.segment_count.to_be_bytes());

        // Encrypted data
        buf.extend_from_slice(&self.encrypted_data);

        buf
    }

    /// Deserialize a recording file from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, FormatError> {
        let mut pos = 0;

        // Magic
        if data.len() < 4 || data[..4] != MAGIC {
            return Err(FormatError::InvalidMagic);
        }
        pos += 4;

        // Version
        if data.len() <= pos {
            return Err(FormatError::Truncated);
        }
        let version = data[pos];
        if version > FORMAT_VERSION {
            return Err(FormatError::UnsupportedVersion(version));
        }
        pos += 1;

        // Channel ID
        if data.len() < pos + 2 {
            return Err(FormatError::Truncated);
        }
        let channel_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if data.len() < pos + channel_len {
            return Err(FormatError::Truncated);
        }
        let channel_id = String::from_utf8(data[pos..pos + channel_len].to_vec())
            .map_err(|_| FormatError::InvalidChannelId)?;
        pos += channel_len;

        // Number of key entries
        if data.len() < pos + 2 {
            return Err(FormatError::Truncated);
        }
        let num_entries = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        // Key entries
        let mut key_entries = Vec::with_capacity(num_entries);
        for _ in 0..num_entries {
            if data.len() < pos + 92 {
                return Err(FormatError::Truncated);
            }
            let entry_bytes: &[u8; 92] = data[pos..pos + 92].try_into().unwrap();
            key_entries.push(KeyEntry::from_bytes(entry_bytes));
            pos += 92;
        }

        // Sender public key (v2+ only: present flag + 32 bytes)
        let sender_public_key = if version > FORMAT_VERSION_V1 {
            if data.len() <= pos {
                return Err(FormatError::Truncated);
            }
            let present = data[pos];
            pos += 1;
            if present != 0 {
                if data.len() < pos + 32 {
                    return Err(FormatError::Truncated);
                }
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&data[pos..pos + 32]);
                pos += 32;
                Some(pk)
            } else {
                None
            }
        } else {
            None
        };

        // Nonce
        if data.len() < pos + 12 {
            return Err(FormatError::Truncated);
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[pos..pos + 12]);
        pos += 12;

        // Segment count
        if data.len() < pos + 4 {
            return Err(FormatError::Truncated);
        }
        let segment_count =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;

        // Encrypted data (remainder)
        let encrypted_data = data[pos..].to_vec();

        Ok(RecordingFile {
            header: RecordingHeader {
                channel_id,
                key_entries,
                sender_public_key,
                nonce,
                segment_count,
            },
            encrypted_data,
        })
    }
}

/// Compute the SHA-256 fingerprint of an X25519 public key.
pub fn public_key_fingerprint(public_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    hasher.finalize().into()
}

#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("invalid magic bytes")]
    InvalidMagic,
    #[error("unsupported format version: {0}")]
    UnsupportedVersion(u8),
    #[error("data truncated")]
    Truncated,
    #[error("invalid channel ID encoding")]
    InvalidChannelId,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KeyPair;
    use aes_gcm::KeyInit;

    #[test]
    fn file_format_roundtrip() {
        let tx = KeyPair::generate();
        let rx = KeyPair::generate();
        let shared = tx.diffie_hellman(rx.public_key());
        let kek = shared.derive_kek(b"rl-keks/v1");

        let audio = b"test audio data for roundtrip";
        let file = RecordingFileBuilder::new("ch-001".into())
            .add_receiver(&kek, rx.fingerprint())
            .unwrap()
            .build(audio.as_slice())
            .unwrap();

        let bytes = file.to_bytes();
        let parsed = RecordingFile::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.header.channel_id, "ch-001");
        assert_eq!(parsed.header.key_entries.len(), 1);
    }

    #[test]
    fn encrypt_decrypt_end_to_end() {
        let tx = KeyPair::generate();
        let rx = KeyPair::generate();
        let shared = tx.diffie_hellman(rx.public_key());
        let kek = shared.derive_kek(b"rl-keks/v1");

        let audio = b"hello from the transmitter!";
        let file = RecordingFileBuilder::new("ch-001".into())
            .add_receiver(&kek, rx.fingerprint())
            .unwrap()
            .build(audio.as_slice())
            .unwrap();

        // Receiver derives the same KEK and decrypts
        let shared_rx = rx.diffie_hellman(tx.public_key());
        let kek_rx = shared_rx.derive_kek(b"rl-keks/v1");

        let decrypted =
            crate::decrypt::decrypt_recording(&file, &rx.fingerprint(), &kek_rx).unwrap();
        assert_eq!(audio.as_slice(), &decrypted);
    }

    #[test]
    fn multi_key_entry_select() {
        let tx = KeyPair::generate();
        let rx1 = KeyPair::generate();
        let rx2 = KeyPair::generate();

        let kek1 = tx
            .diffie_hellman(rx1.public_key())
            .derive_kek(b"rl-keks/v1");
        let kek2 = tx
            .diffie_hellman(rx2.public_key())
            .derive_kek(b"rl-keks/v1");

        let audio = b"multi-receiver audio";
        let file = RecordingFileBuilder::new("ch-001".into())
            .add_receiver(&kek1, rx1.fingerprint())
            .unwrap()
            .add_receiver(&kek2, rx2.fingerprint())
            .unwrap()
            .build(audio.as_slice())
            .unwrap();

        // Rx2 can decrypt
        let kek2_rx = rx2
            .diffie_hellman(tx.public_key())
            .derive_kek(b"rl-keks/v1");
        let decrypted =
            crate::decrypt::decrypt_recording(&file, &rx2.fingerprint(), &kek2_rx).unwrap();
        assert_eq!(audio.as_slice(), &decrypted);

        // Rx1 can also decrypt
        let kek1_rx = rx1
            .diffie_hellman(tx.public_key())
            .derive_kek(b"rl-keks/v1");
        let decrypted1 =
            crate::decrypt::decrypt_recording(&file, &rx1.fingerprint(), &kek1_rx).unwrap();
        assert_eq!(audio.as_slice(), &decrypted1);
    }

    #[test]
    fn invalid_magic_rejected() {
        assert!(RecordingFile::from_bytes(b"XXXX").is_err());
    }

    #[test]
    fn key_export_import_roundtrip() {
        let keypair = KeyPair::generate();
        let passphrase = b"correct-horse-battery-staple";

        let exported = crate::key_export::export_key(&keypair.secret_bytes(), passphrase).unwrap();
        let imported = crate::key_export::import_key(&exported, passphrase).unwrap();

        assert_eq!(keypair.secret_bytes(), imported);
    }

    #[test]
    fn key_export_wrong_passphrase_fails() {
        let keypair = KeyPair::generate();
        let exported =
            crate::key_export::export_key(&keypair.secret_bytes(), b"good-passphrase").unwrap();
        assert!(crate::key_export::import_key(&exported, b"wrong-passphrase").is_err());
    }
}
