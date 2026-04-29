// SPDX-License-Identifier: MIT
// PairingView.swift — Pair with a new transmitter via mDNS discovery or Device ID

import SwiftUI
import RLKit
import Combine

struct PairingView: View {
    @EnvironmentObject var store: TransmitterStore
    @StateObject private var browser = BonjourBrowser()
    @State private var deviceID = ""
    @State private var hostOverride = ""
    @State private var portOverride = "22000"
    @State private var isPairing = false
    @State private var errorMessage: String?
    @State private var connectionObserver: AnyCancellable?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Form {
            // Auto-discovered transmitters via Bonjour/mDNS
            Section(header: Text("Nearby Transmitters")) {
                if browser.discovered.isEmpty && browser.isSearching {
                    HStack {
                        ProgressView()
                        Text("Searching for transmitters...")
                            .foregroundColor(.secondary)
                    }
                } else if browser.discovered.isEmpty {
                    Text("No transmitters found on the local network")
                        .foregroundColor(.secondary)
                } else {
                    ForEach(browser.discovered) { transmitter in
                        Button(action: { pairWithDiscovered(transmitter) }) {
                            HStack {
                                Image(systemName: "antenna.radiowaves.left.and.right")
                                    .foregroundColor(.blue)
                                VStack(alignment: .leading) {
                                    Text(transmitter.name)
                                        .font(.headline)
                                    if let deviceID = transmitter.deviceID {
                                        Text(deviceID)
                                            .font(.caption)
                                            .foregroundColor(.secondary)
                                            .lineLimit(1)
                                    }
                                }
                                Spacer()
                                if transmitter.isResolved {
                                    Image(systemName: "plus.circle")
                                        .foregroundColor(.green)
                                } else {
                                    ProgressView()
                                }
                            }
                        }
                        .disabled(!transmitter.isResolved || isPairing)
                    }
                }
            }

            // Manual entry via Device ID
            Section(header: Text("Pair via Device ID"), footer: Text("Enter the transmitter's Device ID (shown in its tray menu). The app will discover its address on the local network or via the discovery server.")) {
                TextField("Device ID (e.g. ABCDE-...)", text: $deviceID)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)
            }

            // Advanced: manual address override
            Section(header: Text("Advanced (Optional)"), footer: Text("Only needed if discovery can't find the transmitter.")) {
                TextField("Host (optional)", text: $hostOverride)
                    .autocapitalization(.none)
                TextField("Port", text: $portOverride)
                    .keyboardType(.numberPad)
            }

            if let error = errorMessage {
                Section {
                    Text(error)
                        .foregroundColor(.red)
                }
            }

            Button(action: pairManual) {
                if isPairing {
                    ProgressView()
                } else {
                    Text("Pair")
                }
            }
            .disabled(deviceID.trimmingCharacters(in: .whitespaces).isEmpty || isPairing)
        }
        .navigationTitle("Pair Transmitter")
        .onAppear {
            browser.startSearching()
        }
        .onDisappear {
            browser.stopSearching()
        }
    }

    private func pairWithDiscovered(_ transmitter: DiscoveredTransmitter) {
        guard let ip = transmitter.ipAddress, let port = transmitter.port else { return }
        pair(host: ip, port: port)
    }

    private func pairManual() {
        let trimmedID = deviceID.trimmingCharacters(in: .whitespaces)
        guard !trimmedID.isEmpty else { return }

        // Try to find the transmitter in discovered list by Device ID
        if let discovered = browser.discovered.first(where: { $0.deviceID == trimmedID }),
           let ip = discovered.ipAddress, let port = discovered.port {
            pair(host: ip, port: port)
            return
        }

        // Fallback: use manual host override if provided
        let overrideHost = hostOverride.trimmingCharacters(in: .whitespaces)
        if !overrideHost.isEmpty {
            guard let portNum = UInt16(portOverride) else {
                errorMessage = "Invalid port number"
                return
            }
            pair(host: overrideHost, port: portNum)
            return
        }

        // If no override, keep searching (the transmitter might appear via mDNS)
        errorMessage = "Transmitter \(trimmedID) not found on local network. Enter host override."
    }

    private func pair(host: String, port: UInt16) {
        isPairing = true
        errorMessage = nil

        let conn = store.addTransmitter(host: host, port: port)

        setupCallbacks(conn)

        connectionObserver = conn.$state.sink { state in
            DispatchQueue.main.async {
                switch state {
                case .ready:
                    isPairing = false
                    connectionObserver = nil
                    dismiss()
                case .closed:
                    isPairing = false
                    errorMessage = "Connection failed — check Device ID and network"
                    connectionObserver = nil
                default:
                    break
                }
            }
        }
    }

    private func setupCallbacks(_ conn: TransmitterConnection) {
        // Store transmitter public key in Keychain when pairing completes
        conn.onPairResponse = { publicKey, tlsCertFingerprint in
            _ = KeychainService.shared.storeTransmitterPublicKey(publicKey, forTransmitterFingerprint: tlsCertFingerprint)
        }

        // Load/store receiver private key via Keychain
        conn.loadPrivateKey = { tlsCertFingerprint in
            guard let fpData = Data(hexString: tlsCertFingerprint) else { return nil }
            return KeychainService.shared.retrievePrivateKey(forTransmitterFingerprint: fpData)
        }
        conn.storePrivateKey = { key, tlsCertFingerprint in
            guard let fpData = Data(hexString: tlsCertFingerprint) else { return }
            _ = KeychainService.shared.storePrivateKey(key, forTransmitterFingerprint: fpData)
        }
    }
}

#Preview {
    NavigationView {
        PairingView().environmentObject(TransmitterStore())
    }
}
