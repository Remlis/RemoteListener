// SPDX-License-Identifier: MIT
// RecordingsView.swift — Browse and manage recordings for a channel

import SwiftUI

struct RecordingsView: View {
    @ObservedObject var connection: TransmitterConnection
    let channelID: String
    @State private var isFetching = false

    var body: some View {
        List {
            if connection.recordings.isEmpty {
                Text("No recordings available")
                    .foregroundColor(.secondary)
            } else {
                ForEach(connection.recordings) { recording in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(recording.id)
                                .font(.caption)
                                .lineLimit(1)
                            HStack(spacing: 8) {
                                Text(ByteCountFormatter.string(fromByteCount: Int64(recording.fileSize), countStyle: .file))
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                                if recording.durationSeconds > 0 {
                                    Text(formatDuration(recording.durationSeconds))
                                        .font(.caption2)
                                        .foregroundColor(.secondary)
                                }
                            }
                        }
                        Spacer()
                        // Fetch button
                        Button(action: {
                            connection.fetchRecording(recordingID: recording.id)
                        }) {
                            Image(systemName: "arrow.down.circle")
                                .foregroundColor(.blue)
                        }
                        .buttonStyle(.borderless)
                        // Delete button
                        Button(action: {
                            connection.deleteRecording(recordingID: recording.id)
                        }) {
                            Image(systemName: "trash")
                                .foregroundColor(.red)
                        }
                        .buttonStyle(.borderless)
                    }
                }
            }

            // Storage info section
            if let storage = connection.storageInfo {
                Section(header: Text("Storage")) {
                    HStack {
                        Text("Recordings")
                        Spacer()
                        Text("\(storage.recordingCount) files")
                            .foregroundColor(.secondary)
                    }
                    HStack {
                        Text("Used")
                        Spacer()
                        Text(ByteCountFormatter.string(fromByteCount: Int64(storage.usedBytes), countStyle: .file))
                            .foregroundColor(.secondary)
                    }
                }
            }

            Section {
                Button("Refresh") {
                    connection.requestRecordingList(channelID: channelID)
                }
            }
        }
        .navigationTitle("Recordings")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            connection.requestRecordingList(channelID: channelID)
        }
    }

    private func formatDuration(_ seconds: UInt32) -> String {
        let mins = seconds / 60
        let secs = seconds % 60
        if mins > 60 {
            let hours = mins / 60
            let remainingMins = mins % 60
            return "\(hours)h \(remainingMins)m"
        } else if mins > 0 {
            return "\(mins)m \(secs)s"
        } else {
            return "\(secs)s"
        }
    }
}
