// SPDX-License-Identifier: MIT
// TransmittersView.swift — Main view showing paired transmitters

import SwiftUI
import RLKit

struct TransmittersView: View {
    @EnvironmentObject var store: TransmitterStore
    @State private var showPairing = false

    var body: some View {
        NavigationView {
            List {
                ForEach(store.connections) { conn in
                    NavigationLink(destination: TransmitterDetailView(connection: conn)) {
                        TransmitterRow(connection: conn)
                    }
                }
                .onDelete { indexSet in
                    for index in indexSet {
                        store.removeTransmitter(store.connections[index])
                    }
                }

                if store.connections.isEmpty {
                    Text("No paired transmitters")
                        .foregroundColor(.secondary)
                }
            }
            .navigationTitle("RemoteListener")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: { showPairing = true }) {
                        Image(systemName: "plus")
                    }
                }
            }
            .sheet(isPresented: $showPairing) {
                NavigationView {
                    PairingView()
                        .environmentObject(store)
                }
            }

            Text("Select a transmitter")
                .foregroundColor(.secondary)
        }
    }
}

/// Row view for a single transmitter in the list.
struct TransmitterRow: View {
    @ObservedObject var connection: TransmitterConnection

    var body: some View {
        HStack {
            Image(systemName: connectionIcon)
                .foregroundColor(connectionColor)
            VStack(alignment: .leading) {
                Text(connection.remoteDeviceName ?? connection.identifier)
                    .font(.headline)
                Text("\(connection.channels.count) channels")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }
        }
    }

    private var connectionIcon: String {
        switch connection.state {
        case .connecting: return "antenna.radiowaves.left.and.right"
        case .hello: return "hand.wave"
        case .ready: return "checkmark.circle"
        case .closed: return "xmark.circle"
        }
    }

    private var connectionColor: Color {
        switch connection.state {
        case .connecting, .hello: return .orange
        case .ready: return .green
        case .closed: return .red
        }
    }
}

#Preview {
    TransmittersView()
}
