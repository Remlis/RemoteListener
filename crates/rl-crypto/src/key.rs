//! X25519 key generation, ECDH shared secret, HKDF-SHA256 key derivation.

use aes_gcm::{Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

/// A persistent X25519 keypair owned by the transmitter or receiver.
pub struct KeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl KeyPair {
    /// Generate a new random X25519 keypair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Restore a keypair from raw secret key bytes.
    pub fn from_bytes(secret_bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// The public key bytes.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// The raw secret key bytes (use carefully).
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Perform X25519 ECDH with another public key, returning the shared secret.
    pub fn diffie_hellman(&self, their_public: &PublicKey) -> SharedSecret {
        let shared = self.secret.diffie_hellman(their_public);
        SharedSecret(shared.to_bytes())
    }

    /// SHA-256 fingerprint of the public key, for identification.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.public.as_bytes());
        hasher.finalize().into()
    }
}

/// A Diffie-Hellman shared secret.
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    /// Derive a 256-bit key encryption key (KEK) using HKDF-SHA256.
    pub fn derive_kek(&self, info: &[u8]) -> Aes256Gcm {
        let hkdf = Hkdf::<Sha256>::new(None, &self.0);
        let mut okm = [0u8; 32];
        hkdf.expand(info, &mut okm)
            .expect("32 bytes is a valid HKDF output length");
        Aes256Gcm::new_from_slice(&okm).expect("32 bytes is a valid AES-256 key")
    }

    /// Derive a data encryption key (DEK) — a raw 32-byte key for AES-256-GCM.
    pub fn derive_dek(&self, info: &[u8]) -> [u8; 32] {
        let hkdf = Hkdf::<Sha256>::new(None, &self.0);
        let mut okm = [0u8; 32];
        hkdf.expand(info, &mut okm)
            .expect("32 bytes is a valid HKDF output length");
        okm
    }
}

/// Perform an ephemeral ECDH (one-shot, no persistent keypair needed).
pub fn ephemeral_dh(their_public: &PublicKey) -> (SharedSecret, PublicKey) {
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(their_public);
    (SharedSecret(shared.to_bytes()), ephemeral_public)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_generate_roundtrip() {
        let kp = KeyPair::generate();
        let bytes = kp.secret_bytes();
        let kp2 = KeyPair::from_bytes(bytes);
        assert_eq!(kp.public_key().as_bytes(), kp2.public_key().as_bytes());
    }

    #[test]
    fn ecdh_shared_secret_symmetric() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let shared_ab = alice.diffie_hellman(bob.public_key());
        let shared_ba = bob.diffie_hellman(alice.public_key());
        // Both should derive the same DEK
        let dek_ab = shared_ab.derive_dek(b"rl-test");
        let dek_ba = shared_ba.derive_dek(b"rl-test");
        assert_eq!(dek_ab, dek_ba);
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let kp = KeyPair::generate();
        let fp1 = kp.fingerprint();
        let kp2 = KeyPair::from_bytes(kp.secret_bytes());
        let fp2 = kp2.fingerprint();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn different_keypairs_different_fingerprints() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        assert_ne!(kp1.fingerprint(), kp2.fingerprint());
    }
}
