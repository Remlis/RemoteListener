// SPDX-License-Identifier: MIT
// TransmittersView.swift — Main view showing paired transmitters

import SwiftUI

struct TransmittersView: View {
    var body: some View {
        NavigationView {
            List {
                // TODO: List of paired transmitters
                Text("No paired transmitters")
                    .foregroundColor(.secondary)
            }
            .navigationTitle("RemoteListener")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: { /* TODO: Add transmitter */ }) {
                        Image(systemName: "plus")
                    }
                }
            }

            Text("Select a transmitter")
                .foregroundColor(.secondary)
        }
    }
}

#Preview {
    TransmittersView()
}
