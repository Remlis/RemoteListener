// SPDX-License-Identifier: MIT
// TransmitterDetailView.swift — Channels, controls, and live audio for a transmitter

import SwiftUI
import RLKit

struct TransmitterDetailView: View {
    @ObservedObject var connection: TransmitterConnection
    @State private var showBitratePicker = false
    @State private var selectedChannelID: String?
    @State private var selectedBitrate: UInt32 = 16

    var body: some View {
        List {
            Section(header: Text("Status")) {
                HStack {
                    Text("State")
                    Spacer()
                    Text(stateText)
                        .foregroundColor(stateColor)
                }
                if let name = connection.remoteDeviceName {
                    HStack {
                        Text("Device")
                        Spacer()
                        Text(name)
                            .foregroundColor(.secondary)
                    }
                }
            }

            Section(header: Text("Channels")) {
                if connection.channels.isEmpty {
                    Text("No channels available")
                        .foregroundColor(.secondary)
                } else {
                    ForEach(connection.channels) { channel in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                VStack(alignment: .leading) {
                                    Text(channel.deviceName)
                                        .font(.headline)
                                    HStack(spacing: 8) {
                                        Text("\(channel.bitrate) kbps")
                                            .font(.caption)
                                            .foregroundColor(.secondary)
                                        if channel.recordingEnabled {
                                            Text("REC")
                                                .font(.caption2)
                                                .fontWeight(.bold)
                                                .foregroundColor(.red)
                                        }
                                        if channel.isActive {
                                            Circle()
                                                .fill(Color.green)
                                                .frame(width: 6, height: 6)
                                        }
                                    }
                                }
                                Spacer()
                                // Live audio: navigate to dedicated listen view
                                NavigationLink(destination: LiveListenView(
                                    connection: connection,
                                    channelID: channel.id,
                                    channelName: channel.deviceName,
                                    channelBitrate: channel.bitrate
                                )) {
                                    Image(systemName: "play.circle")
                                        .foregroundColor(.green)
                                }
                                .disabled(connection.state != .ready)
                            }

                            // Control buttons
                            HStack(spacing: 12) {
                                // Recording toggle
                                Button(action: {
                                    connection.setChannelRecording(
                                        channelID: channel.id,
                                        enabled: !channel.recordingEnabled
                                    )
                                }) {
                                    Label(
                                        channel.recordingEnabled ? "Stop Rec" : "Record",
                                        systemImage: channel.recordingEnabled ? "stop.circle" : "record.circle"
                                    )
                                    .font(.caption)
                                    .foregroundColor(channel.recordingEnabled ? .red : .blue)
                                }

                                // Bitrate change
                                Button(action: {
                                    selectedChannelID = channel.id
                                    selectedBitrate = channel.bitrate
                                    showBitratePicker = true
                                }) {
                                    Label("Bitrate", systemImage: "speedometer")
                                        .font(.caption)
                                        .foregroundColor(.blue)
                                }

                                // Recordings list
                                NavigationLink(destination: RecordingsView(connection: connection, channelID: channel.id)) {
                                    Label("Files", systemImage: "list.bullet")
                                        .font(.caption)
                                        .foregroundColor(.blue)
                                }
                            }
                        }
                    }
                }
            }

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
                Button("Refresh Channels") {
                    connection.requestChannelList()
                }
                NavigationLink(destination: SettingsView(connection: connection)) {
                    Text("Transmitter Settings")
                }
                NavigationLink(destination: KeyTransferView(connection: connection)) {
                    Text("Key Transfer")
                }
            }
        }
        .navigationTitle(connection.remoteDeviceName ?? "Transmitter")
        .navigationBarTitleDisplayMode(.inline)
        .confirmationDialog("Select Bitrate", isPresented: $showBitratePicker) {
            ForEach([16, 32, 64, 128], id: \.self) { bitrate in
                Button("\(bitrate) kbps") {
                    if let channelID = selectedChannelID {
                        connection.setChannelBitrate(channelID: channelID, bitrate: UInt32(bitrate))
                    }
                }
            }
            Button("Cancel", role: .cancel) {}
        }
    }

    private var stateText: String {
        switch connection.state {
        case .connecting: return "Connecting"
        case .hello: return "Handshake"
        case .ready: return "Ready"
        case .closed: return "Disconnected"
        }
    }

    private var stateColor: Color {
        switch connection.state {
        case .connecting, .hello: return .orange
        case .ready: return .green
        case .closed: return .red
        }
    }
}
