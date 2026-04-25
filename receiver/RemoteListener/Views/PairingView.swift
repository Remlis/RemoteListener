// SPDX-License-Identifier: MIT
// PairingView.swift — Pair with a new transmitter

import SwiftUI
import Combine

struct PairingView: View {
    @EnvironmentObject var store: TransmitterStore
    @State private var host = ""
    @State private var port = "22000"
    @State private var isPairing = false
    @State private var errorMessage: String?
    @State private var connectionObserver: AnyCancellable?
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

            if let error = errorMessage {
                Section {
                    Text(error)
                        .foregroundColor(.red)
                }
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
        guard let portNum = UInt16(port) else {
            errorMessage = "Invalid port number"
            return
        }
        isPairing = true
        errorMessage = nil

        let conn = store.addTransmitter(host: host, port: portNum)

        // Observe connection state and dismiss when ready or failed
        connectionObserver = conn.$state.sink { state in
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

#Preview {
    NavigationView {
        PairingView().environmentObject(TransmitterStore())
    }
}
