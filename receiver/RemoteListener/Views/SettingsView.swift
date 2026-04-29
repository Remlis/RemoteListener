// SPDX-License-Identifier: MIT
// SettingsView.swift — Remote configuration for a transmitter

import SwiftUI
import RLKit

struct SettingsView: View {
    @ObservedObject var connection: TransmitterConnection
    @State private var autoDeleteDays: UInt32 = 0
    @State private var showAutoDeletePicker = false

    var body: some View {
        List {
            // Storage info
            if let storage = connection.storageInfo {
                Section(header: Text("Storage")) {
                    HStack {
                        Text("Recordings")
                        Spacer()
                        Text("\(storage.recordingCount) files")
                            .foregroundColor(.secondary)
                    }
                    HStack {
                        Text("Used Space")
                        Spacer()
                        Text(ByteCountFormatter.string(fromByteCount: Int64(storage.usedBytes), countStyle: .file))
                            .foregroundColor(.secondary)
                    }
                }
            }

            // Auto-delete settings
            Section(header: Text("Auto-Delete")) {
                HStack {
                    Text("Keep recordings for")
                    Spacer()
                    Button(action: {
                        showAutoDeletePicker = true
                    }) {
                        Text(autoDeleteDaysText)
                            .foregroundColor(.blue)
                    }
                }
            }

            // Last response
            if let response = connection.lastControlResponse {
                Section(header: Text("Last Response")) {
                    HStack {
                        Image(systemName: response.success ? "checkmark.circle" : "xmark.circle")
                            .foregroundColor(response.success ? .green : .red)
                        Text(response.message)
                            .font(.caption)
                    }
                }
            }

            Section {
                Button("Refresh Storage Info") {
                    connection.getStorageInfo()
                }
            }
        }
        .navigationTitle("Settings")
        .navigationBarTitleDisplayMode(.inline)
        .confirmationDialog("Auto-Delete After", isPresented: $showAutoDeletePicker) {
            ForEach([0, 7, 14, 30, 60, 90], id: \.self) { days in
                Button(autoDeleteLabel(days)) {
                    autoDeleteDays = UInt32(days)
                    connection.setAutoDeleteDays(UInt32(days))
                }
            }
            Button("Cancel", role: .cancel) {}
        }
    }

    private var autoDeleteDaysText: String {
        autoDeleteLabel(Int(autoDeleteDays))
    }

    private func autoDeleteLabel(_ days: Int) -> String {
        switch days {
        case 0: return "Never"
        case 7: return "7 days"
        case 14: return "14 days"
        case 30: return "30 days"
        case 60: return "60 days"
        case 90: return "90 days"
        default: return "\(days) days"
        }
    }
}
