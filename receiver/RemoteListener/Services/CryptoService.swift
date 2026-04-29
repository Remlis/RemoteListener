// SPDX-License-Identifier: MIT
// CryptoService.swift — Curve25519 ECDH + AES-256-GCM decryption

import Foundation
import CryptoKit

/// Service for cryptographic operations compatible with the Rust transmitter.
class CryptoService {

    /// Perform X25519 ECDH and derive a shared KEK using HKDF-SHA256.
    static func deriveKEK(myPrivateKey: Curve25519.KeyAgreement.PrivateKey,
                          theirPublicKey: Curve25519.KeyAgreement.PublicKey,
                          info: Data) throws -> SymmetricKey {
        let sharedSecret = try myPrivateKey.sharedSecretFromKeyAgreement(with: theirPublicKey)
        return sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self,
                                                     salt: Data(),
                                                     sharedInfo: info,
                                                     outputByteCount: 32)
    }

    /// Decrypt AES-256-GCM data.
    static func decryptAES256GCM(key: SymmetricKey,
                                  sealedBox: AES.GCM.SealedBox) throws -> Data {
        return try AES.GCM.open(sealedBox, using: key)
    }

    /// Compute SHA-256 fingerprint of a public key for identification.
    static func publicKeyFingerprint(_ publicKeyData: Data) -> Data {
        return Data(SHA256.hash(data: publicKeyData))
    }
}
