// SPDX-License-Identifier: MIT
// PairingView.swift — Pair with a new transmitter (auto-discovered or manual)

import SwiftUI
import Combine

struct PairingView: View {
    @EnvironmentObject var store: TransmitterStore
    @StateObject private var browser = BonjourBrowser()
    @State private var host = ""
    @State private var port = "22000"
    @State private var isPairing = false
    @State private var errorMessage: String?
    @State private var connectionObserver: AnyCancellable?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Form {
            // Auto-discovered transmitters
            if !browser.discovered.isEmpty {
                Section(header: Text("Nearby Transmitters")) {
                    ForEach(browser.discovered) { transmitter in
                        Button(action: { pairWithDiscovered(transmitter) }) {
                            HStack {
                                Image(systemName: "antenna.radiowaves.left.and.right")
                                    .foregroundColor(.blue)
                                VStack(alignment: .leading) {
                                    Text(transmitter.name)
                                        .font(.headline)
                                    if let ip = transmitter.ipAddress, let port = transmitter.port {
                                        Text("\(ip):\(port)")
                                            .font(.caption)
                                            .foregroundColor(.secondary)
                                    } else {
                                        Text("Resolving...")
                                            .font(.caption)
                                            .foregroundColor(.secondary)
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

            // Manual entry
            Section(header: Text("Manual Entry")) {
                TextField("Host (e.g. 192.168.1.100)", text: $host)
                    .textContentType(.URL)
                    .autocapitalization(.none)
                TextField("Port", text: $port)
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
            .disabled(host.isEmpty || isPairing)
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
        guard let portNum = UInt16(port) else {
            errorMessage = "Invalid port number"
            return
        }
        pair(host: host, port: portNum)
    }

    private func pair(host: String, port: UInt16) {
        isPairing = true
        errorMessage = nil

        let conn = store.addTransmitter(host: host, port: port)

        connectionObserver = conn.$state.sink { state in
            DispatchQueue.main.async {
                switch state {
                case .ready:
                    isPairing = false
                    connectionObserver = nil
                    dismiss()
                case .closed:
                    isPairing = false
                    errorMessage = "Connection failed — check host and port"
                    connectionObserver = nil
                default:
                    break
                }
            }
        }
    }
}

#Preview {
    NavigationView {
        PairingView().environmentObject(TransmitterStore())
    }
}
