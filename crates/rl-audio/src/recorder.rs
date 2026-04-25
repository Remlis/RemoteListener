//! Recording file writer and reader.

use std::path::Path;

use rl_crypto::format::{RecordingFile, RecordingFileBuilder};

/// Writes encrypted recording data to a .rlrec file.
pub struct RecordingWriter {
    path: std::path::PathBuf,
    #[allow(dead_code)]
    channel_id: String,
    audio_data: Vec<u8>,
}

impl RecordingWriter {
    pub fn new(path: std::path::PathBuf, channel_id: String) -> Self {
        Self {
            path,
            channel_id,
            audio_data: Vec::new(),
        }
    }

    /// Append raw Opus-encoded audio data.
    pub fn write_chunk(&mut self, data: &[u8]) {
        self.audio_data.extend_from_slice(data);
    }

    /// Finalize and write the encrypted .rlrec file.
    pub fn finalize(
        self,
        builder: RecordingFileBuilder,
    ) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
        let file = builder.build(&self.audio_data)?;
        let bytes = file.to_bytes();

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.path, &bytes)?;

        Ok(self.path)
    }
}

/// Read and decrypt a .rlrec recording file.
pub struct RecordingReader;

impl RecordingReader {
    /// Read a .rlrec file from disk.
    pub fn read_file(path: &Path) -> Result<RecordingFile, rl_crypto::format::FormatError> {
        let data = std::fs::read(path).map_err(|_| rl_crypto::format::FormatError::Truncated)?;
        RecordingFile::from_bytes(&data)
    }

    /// Read and decrypt a .rlrec file.
    pub fn read_and_decrypt(
        path: &Path,
        my_fingerprint: &[u8; 32],
        kek: &aes_gcm::Aes256Gcm,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let file = Self::read_file(path)?;
        let decrypted = rl_crypto::decrypt::decrypt_recording(&file, my_fingerprint, kek)?;
        Ok(decrypted)
    }
}
