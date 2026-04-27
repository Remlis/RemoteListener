// SPDX-License-Identifier: MIT
// KeyTransferView.swift — Export/import encryption keys between devices

import SwiftUI
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

        // The key is stored in the Keychain. For now, we need the paired key.
        // This requires access to the stored key from Keychain.
        // Since we don't have a full Keychain service yet, we'll implement
        // a placeholder that works with the connection's paired state.
        guard !exportPassphrase.isEmpty else {
            exportError = "Enter a passphrase (min 6 characters)"
            return
        }

        // TODO: Retrieve the actual secret key from Keychain and export it
        // For now, show a placeholder message
        exportError = "Key export requires stored keypair from Keychain (not yet implemented)"
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

            // Store the key in Keychain (TODO: implement Keychain service)
            // For now, just verify decryption worked
            if plaintext.count == 32 {
                importSuccess = true
            } else {
                importError = "Invalid key size"
            }
        } catch {
            importError = "Decryption failed (wrong passphrase?)"
        }
    }

    private func deriveKEK(passphrase: Data, salt: Data, n: UInt32, r: UInt32, p: UInt32) throws -> SymmetricKey {
        // scrypt key derivation matching Rust's scrypt crate
        // Rust uses: scrypt::Params::new(n.ilog2() as u8, r, p, 32)
        let logN = UInt8(n == 0 ? 0 : n.bitWidth - n.leadingZeroBitCount - 1)
        let params = try ScryptParams(N: logN, r: Int(r), p: Int(p))
        let derivedBytes = try Scrypt(password: passphrase.bytes,
                                       salt: salt.bytes,
                                       blocksize: Int(r),
                                       costParameter: Int(n),
                                       parallelism: Int(p),
                                       keyLength: 32).calculate()
        return SymmetricKey(data: derivedBytes)
    }
}
