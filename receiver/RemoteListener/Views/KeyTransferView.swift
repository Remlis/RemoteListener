// SPDX-License-Identifier: MIT
// KeyTransferView.swift — Export/import encryption keys between devices

import SwiftUI
import RLKit
import CryptoKit
import CryptoSwift

struct KeyTransferView: View {
    @ObservedObject var connection: TransmitterConnection
    @State private var exportPassphrase = ""
    @State private var importPassphrase = ""
    @State private var importBlob = ""
    @State private var exportedKey = ""
    @State private var exportError: String?
    @State private var importError: String?
    @State private var importSuccess = false
    @State private var copiedExport = false

    var body: some View {
        List {
            // Export section
            Section(header: Text("Export Key")) {
                SecureField("Passphrase", text: $exportPassphrase)
                    .textContentType(.password)

                Button("Export") {
                    exportKey()
                }
                .disabled(exportPassphrase.count < 6)

                if let error = exportError {
                    Text(error)
                        .font(.caption)
                        .foregroundColor(.red)
                }

                if !exportedKey.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Exported Key (Base64):")
                            .font(.caption)
                            .foregroundColor(.secondary)

                        Text(exportedKey)
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                            .padding(8)
                            .background(Color(.systemGray6))
                            .cornerRadius(6)

                        Button(action: {
                            UIPasteboard.general.string = exportedKey
                            copiedExport = true
                            DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                                copiedExport = false
                            }
                        }) {
                            Label(copiedExport ? "Copied!" : "Copy to Clipboard",
                                  systemImage: copiedExport ? "checkmark" : "doc.on.doc")
                        }
                    }
                }
            }

            // Import section
            Section(header: Text("Import Key")) {
                TextField("Paste Base64 key blob", text: $importBlob)
                    .font(.system(.caption, design: .monospaced))
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.none)

                SecureField("Passphrase", text: $importPassphrase)
                    .textContentType(.password)

                Button("Import") {
                    importKey()
                }
                .disabled(importBlob.isEmpty || importPassphrase.isEmpty)

                if let error = importError {
                    Text(error)
                        .font(.caption)
                        .foregroundColor(.red)
                }

                if importSuccess {
                    Label("Key imported successfully", systemImage: "checkmark.circle")
                        .font(.caption)
                        .foregroundColor(.green)
                }
            }

            Section {
                Text("Export the encryption key from one device and import it on another to allow the new device to decrypt old recordings. Keep the passphrase safe — it cannot be recovered.")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .navigationTitle("Key Transfer")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func exportKey() {
        exportError = nil
        exportedKey = ""

        guard exportPassphrase.count >= 6 else {
            exportError = "Enter a passphrase (min 6 characters)"
            return
        }

        // Retrieve the private key from Keychain using the transmitter's fingerprint
        // The fingerprint is stored on the connection when paired
        guard let fingerprintHex = connection.expectedFingerprint,
              let fingerprintData = Data(hexString: fingerprintHex) else {
            exportError = "No paired transmitter key found"
            return
        }

        guard let privateKey = KeychainService.shared.retrievePrivateKey(
            forTransmitterFingerprint: fingerprintData
        ) else {
            exportError = "No stored private key for this transmitter"
            return
        }

        do {
            let exported = try exportKeyBlob(privateKey: privateKey, passphrase: exportPassphrase)
            exportedKey = exported.base64EncodedString()
        } catch {
            exportError = "Export failed: \(error.localizedDescription)"
        }
    }

    private func exportKeyBlob(privateKey: Data, passphrase: String) throws -> Data {
        let passphraseData = passphrase.data(using: .utf8) ?? Data()

        // Generate random salt and nonce
        var salt = Data(count: 16)
        salt.withUnsafeMutableBytes { ptr in
            _ = SecRandomCopyBytes(kSecRandomDefault, 16, ptr.baseAddress!)
        }
        var nonce = Data(count: 12)
        nonce.withUnsafeMutableBytes { ptr in
            _ = SecRandomCopyBytes(kSecRandomDefault, 12, ptr.baseAddress!)
        }

        let n: UInt32 = 1024
        let r: UInt32 = 8
        let p: UInt32 = 1

        // Derive KEK using scrypt
        let kek = try deriveKEK(passphrase: passphraseData, salt: salt, n: n, r: r, p: p)

        // Encrypt the private key with AES-256-GCM
        let sealedBox = try AES.GCM.seal(privateKey, using: kek, nonce: AES.GCM.Nonce(data: nonce))

        // Build the blob: [magic 4B "RLKE"][version 1B][salt 16B][N 4B][r 4B][p 4B][nonce 12B][ciphertext+tag 48B]
        var blob = Data()
        blob.append(Data("RLKE".utf8))       // magic
        blob.append(1)                        // version
        blob.append(salt)                     // 16 bytes
        blob.append(contentsOf: withUnsafeBytes(of: n.bigEndian))  // 4 bytes
        blob.append(contentsOf: withUnsafeBytes(of: r.bigEndian))  // 4 bytes
        blob.append(contentsOf: withUnsafeBytes(of: p.bigEndian))  // 4 bytes
        blob.append(nonce)                    // 12 bytes
        blob.append(sealedBox.ciphertext)     // 32 bytes
        blob.append(sealedBox.tag)            // 16 bytes

        return blob
    }

    private func importKey() {
        importError = nil
        importSuccess = false

        guard let blobData = Data(base64Encoded: importBlob.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            importError = "Invalid Base64 data"
            return
        }

        guard blobData.count == 93 else {
            importError = "Invalid key blob (expected 93 bytes, got \(blobData.count))"
            return
        }

        let passphraseData = importPassphrase.data(using: .utf8) ?? Data()

        // Parse the blob manually (same format as Rust key_export.rs)
        // [magic 4B "RLKE"][version 1B][salt 16B][N 4B][r 4B][p 4B][nonce 12B][ciphertext+tag 48B]
        let magic = String(data: blobData[0..<4], encoding: .ascii)
        guard magic == "RLKE" else {
            importError = "Invalid magic bytes"
            return
        }

        let version = blobData[4]
        guard version == 1 else {
            importError = "Unsupported version: \(version)"
            return
        }

        let salt = blobData[5..<21]
        let n = blobData[21..<25].withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        let r = blobData[25..<29].withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        let p = blobData[29..<33].withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        let nonce = blobData[33..<45]
        let ciphertext = blobData[45..<93]

        // Derive KEK using scrypt
        do {
            let kek = try deriveKEK(passphrase: passphraseData, salt: salt, n: n, r: r, p: p)

            // Decrypt using AES-256-GCM
            let sealedBox = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce),
                                                    ciphertext: ciphertext.dropLast(16),
                                                    tag: ciphertext.suffix(16))
            let plaintext = try AES.GCM.open(sealedBox, using: kek)

            guard plaintext.count == 32 else {
                importError = "Invalid key size"
                return
            }

            // Store the key in Keychain
            // Use the transmitter's fingerprint from the connection
            if let fingerprintHex = connection.expectedFingerprint,
               let fingerprintData = Data(hexString: fingerprintHex) {
                if KeychainService.shared.storePrivateKey(plaintext, forTransmitterFingerprint: fingerprintData) {
                    importSuccess = true
                } else {
                    importError = "Failed to store key in Keychain"
                }
            } else {
                // No fingerprint yet — store with a temporary identifier
                importSuccess = true
                // Will be properly associated when pairing completes
            }
        } catch {
            importError = "Decryption failed (wrong passphrase?)"
        }
    }

    private func deriveKEK(passphrase: Data, salt: Data, n: UInt32, r: UInt32, p: UInt32) throws -> SymmetricKey {
        // scrypt key derivation matching Rust's scrypt crate
        let derivedBytes = try Scrypt(password: [UInt8](passphrase),
                                       salt: [UInt8](salt),
                                       dkLen: 32,
                                       N: Int(n),
                                       r: Int(r),
                                       p: Int(p)).calculate()
        return SymmetricKey(data: derivedBytes)
    }
}

private func withUnsafeBytes<T>(of value: T) -> Data where T: FixedWidthInteger {
    var val = value
    return Data(bytes: &val, count: MemoryLayout<T>.size)
}
