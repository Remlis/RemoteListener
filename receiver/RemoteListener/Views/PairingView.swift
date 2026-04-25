// SPDX-License-Identifier: MIT
// PairingView.swift — Pair with a new transmitter

import SwiftUI

struct PairingView: View {
    let store: TransmitterStore

    @State private var deviceId = ""
    @State private var host = ""
    @State private var port = "22000"
    @State private var isPairing = false
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Form {
            Section(header: Text("Transmitter Address")) {
                TextField("Host (e.g. 192.168.1.100)", text: $host)
                    .textContentType(.URL)
                    .autocapitalization(.none)
                TextField("Port", text: $port)
                    .keyboardType(.numberPad)
            }

            Section(header: Text("Device ID (optional verification)")) {
                TextField("Device ID", text: $deviceId)
                    .autocapitalization(.none)
                    .font(.system(.body, design: .monospaced))
            }

            Button(action: pair) {
                if isPairing {
                    ProgressView()
                } else {
                    Text("Pair")
                }
            }
            .disabled(host.isEmpty || isPairing)
        }
        .navigationTitle("Pair Transmitter")
    }

    private func pair() {
        guard let portNum = UInt16(port) else { return }
        isPairing = true

        let conn = store.addTransmitter(host: host, port: portNum)

        // Wait briefly for connection, then dismiss
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
            isPairing = false
            if conn.state == .ready {
                dismiss()
            }
        }
    }
}

#Preview {
    NavigationView {
        PairingView(store: TransmitterStore())
    }
}
