// SPDX-License-Identifier: MIT
// TransmitterDetailView.swift — Channels and live audio for a transmitter

import SwiftUI

struct TransmitterDetailView: View {
    @ObservedObject var connection: TransmitterConnection
    @State private var liveChannels: Set<String> = []

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
                        HStack {
                            VStack(alignment: .leading) {
                                Text(channel.deviceName)
                                    .font(.headline)
                                Text("\(channel.bitrate) kbps")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                            Spacer()
                            Button(action: {
                                toggleLive(channelID: channel.id)
                            }) {
                                if liveChannels.contains(channel.id) {
                                    Image(systemName: "stop.circle")
                                        .foregroundColor(.red)
                                } else {
                                    Image(systemName: "play.circle")
                                        .foregroundColor(.green)
                                }
                            }
                            .buttonStyle(.borderless)
                        }
                    }
                }
            }

            Section {
                Button("Refresh Channels") {
                    connection.requestChannelList()
                }
            }
        }
        .navigationTitle(connection.remoteDeviceName ?? "Transmitter")
        .navigationBarTitleDisplayMode(.inline)
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

    private func toggleLive(channelID: String) {
        if liveChannels.contains(channelID) {
            connection.stopLiveAudio(channelID: channelID)
            liveChannels.remove(channelID)
        } else {
            connection.startLiveAudio(channelID: channelID)
            liveChannels.insert(channelID)
        }
    }
}
