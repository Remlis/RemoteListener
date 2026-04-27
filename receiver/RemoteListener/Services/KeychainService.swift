// SPDX-License-Identifier: MIT
// KeychainService.swift — Secure key storage using iOS Keychain

import Foundation
import Security

/// Service for storing and retrieving cryptographic keys in the iOS Keychain.
class KeychainService {
    static let shared = KeychainService()

    private let service = "com.rl.receiver.keys"

    private init() {}

    // MARK: - Private Key

    /// Store the receiver's X25519 private key for a given transmitter fingerprint.
    func storePrivateKey(_ key: Data, forTransmitterFingerprint fingerprint: Data) -> Bool {
        let key = keyForItem(type: "private", fingerprint: fingerprint)
        return storeData(key, data: key)
    }

    /// Retrieve the receiver's X25519 private key for a given transmitter fingerprint.
    func retrievePrivateKey(forTransmitterFingerprint fingerprint: Data) -> Data? {
        let key = keyForItem(type: "private", fingerprint: fingerprint)
        return retrieveData(key)
    }

    /// Delete the receiver's private key for a given transmitter fingerprint.
    func deletePrivateKey(forTransmitterFingerprint fingerprint: Data) -> Bool {
        let key = keyForItem(type: "private", fingerprint: fingerprint)
        return deleteData(key)
    }

    // MARK: - Transmitter Public Key

    /// Store a transmitter's X25519 public key.
    func storeTransmitterPublicKey(_ publicKey: Data, forTransmitterFingerprint fingerprint: Data) -> Bool {
        let key = keyForItem(type: "tx_pub", fingerprint: fingerprint)
        return storeData(key, data: publicKey)
    }

    /// Retrieve a transmitter's X25519 public key.
    func retrieveTransmitterPublicKey(forTransmitterFingerprint fingerprint: Data) -> Data? {
        let key = keyForItem(type: "tx_pub", fingerprint: fingerprint)
        return retrieveData(key)
    }

    // MARK: - All Paired Transmitters

    /// List all transmitter fingerprints that have stored keys.
    func listPairedFingerprints() -> [Data] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess, let items = result as? [[String: Any]] else {
            return []
        }

        var fingerprints: [Data] = []
        for item in items {
            guard let account = item[kSecAttrAccount as String] as? String,
                  account.hasPrefix("private:") else { continue }
            // Extract fingerprint from account name "private:<hex>"
            let hex = account.dropFirst("private:".count)
            if let data = Data(hexString: String(hex)) {
                fingerprints.append(data)
            }
        }
        return fingerprints
    }

    /// Delete all keys for a given transmitter fingerprint.
    func deleteAllKeys(forTransmitterFingerprint fingerprint: Data) {
        let privKey = keyForItem(type: "private", fingerprint: fingerprint)
        deleteData(privKey)
        let pubKey = keyForItem(type: "tx_pub", fingerprint: fingerprint)
        deleteData(pubKey)
    }

    // MARK: - Private Helpers

    private func keyForItem(type: String, fingerprint: Data) -> String {
        return "\(type):\(fingerprint.hexString)"
    }

    private func storeData(_ account: String, data: Data) -> Bool {
        // Delete existing first
        deleteData(account)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    private func retrieveData(_ account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess else { return nil }
        return result as? Data
    }

    private func deleteData(_ account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]

        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}

// MARK: - Data hex helpers

extension Data {
    /// Initialize from a hex string.
    init?(hexString: String) {
        let clean = hexString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard clean.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        var index = clean.startIndex
        while index < clean.endIndex {
            let next = clean.index(after: index)
            guard let byte = UInt8(clean[index...next], radix: 16) else { return nil }
            bytes.append(byte)
            index = clean.index(after: next)
        }
        self = Data(bytes)
    }

    /// Convert to hex string.
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
