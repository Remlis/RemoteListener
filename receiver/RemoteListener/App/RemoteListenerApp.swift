// SPDX-License-Identifier: MIT
// RemoteListenerApp.swift — iOS App entry point

import SwiftUI
import RLKit

@main
struct RemoteListenerApp: App {
    @StateObject private var store = TransmitterStore()

    var body: some Scene {
        WindowGroup {
            TransmittersView()
                .environmentObject(store)
                .onAppear {
                    // Set up callbacks for all restored connections
                    for conn in store.connections {
                        setupConnectionCallbacks(conn)
                    }
                }
        }
    }

    private func setupConnectionCallbacks(_ conn: TransmitterConnection) {
        // Store transmitter's public key in Keychain when pairing completes
        conn.onPairResponse = { publicKey, tlsCertFingerprint in
            _ = KeychainService.shared.storeTransmitterPublicKey(publicKey, forTransmitterFingerprint: tlsCertFingerprint)
        }

        // Load receiver's private key from Keychain
        conn.loadPrivateKey = { tlsCertFingerprint in
            guard let fpData = Data(hexString: tlsCertFingerprint) else { return nil }
            return KeychainService.shared.retrievePrivateKey(forTransmitterFingerprint: fpData)
        }

        // Store receiver's private key in Keychain
        conn.storePrivateKey = { key, tlsCertFingerprint in
            guard let fpData = Data(hexString: tlsCertFingerprint) else { return }
            _ = KeychainService.shared.storePrivateKey(key, forTransmitterFingerprint: fpData)
        }
    }
}
