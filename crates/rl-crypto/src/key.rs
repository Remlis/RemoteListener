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

/// Compute SHA-256 fingerprint of raw public key bytes.
pub fn fingerprint(public_key_bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(public_key_bytes);
    hasher.finalize().to_vec()
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

    /// Cross-platform test vector for ECDH + HKDF-SHA256.
    /// This uses fixed keys so the output is deterministic and can be
    /// verified in Swift/CryptoKit.
    #[test]
    fn ecdh_hkdf_cross_platform_vector() {
        // Fixed private keys (little-endian X25519 scalar)
        let alice_secret: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let bob_secret: [u8; 32] = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80,
            0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27,
            0xff, 0x88, 0xe9, 0xeb,
        ];

        let alice = KeyPair::from_bytes(alice_secret);
        let bob = KeyPair::from_bytes(bob_secret);

        // Alice's public key (for Swift verification)
        let alice_pub = alice.public_key().as_bytes();
        // Bob's public key
        let bob_pub = bob.public_key().as_bytes();

        // ECDH both ways
        let shared_ab = alice.diffie_hellman(bob.public_key());
        let shared_ba = bob.diffie_hellman(alice.public_key());

        // Derive KEK with HKDF-SHA256(salt=empty, info=b"rl-recording-v1")
        let info = b"rl-recording-v1";
        let dek_ab = shared_ab.derive_dek(info);
        let dek_ba = shared_ba.derive_dek(info);

        assert_eq!(dek_ab, dek_ba, "ECDH+HKDF must be symmetric");

        // Print values for Swift test vector (visible with --nocapture)
        eprintln!("alice_public:  {:02x?}", alice_pub);
        eprintln!("bob_public:    {:02x?}", bob_pub);
        eprintln!("derived_dek:   {:02x?}", dek_ab);
    }
}
