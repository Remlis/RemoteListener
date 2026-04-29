// SPDX-License-Identifier: MIT
// RecordingsView.swift — Browse and manage recordings for a channel

import SwiftUI
import RLKit
import Combine

struct RecordingsView: View {
    @ObservedObject var connection: TransmitterConnection
    let channelID: String
    @StateObject private var playbackService = RecordingPlaybackService()
    @State private var fetchedRecordingID: String?
    @State private var fetchedRecordingData: Data?
    @State private var isFetching = false
    @State private var playingRecordingID: String?
    @State private var fetchError: String?
    @State private var fetchCancellables = Set<AnyCancellable>()

    private var decoder: OpusDecoding? = LibOpusDecoder()

    init(connection: TransmitterConnection, channelID: String) {
        self.connection = connection
        self.channelID = channelID
    }

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

                        // Play/Stop button
                        if playingRecordingID == recording.id && playbackService.isPlaying {
                            Button(action: {
                                playbackService.stop()
                                playingRecordingID = nil
                            }) {
                                Image(systemName: "stop.circle.fill")
                                    .foregroundColor(.red)
                            }
                            .buttonStyle(.borderless)
                        } else {
                            Button(action: {
                                playRecording(recording)
                            }) {
                                Image(systemName: "play.circle")
                                    .foregroundColor(.green)
                            }
                            .buttonStyle(.borderless)
                            .disabled(isFetching)
                        }

                        // Fetch button
                        Button(action: {
                            fetchRecording(recording.id)
                        }) {
                            if isFetching && fetchedRecordingID == recording.id {
                                ProgressView()
                            } else {
                                Image(systemName: "arrow.down.circle")
                                    .foregroundColor(.blue)
                            }
                        }
                        .buttonStyle(.borderless)
                        .disabled(isFetching)

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

            // Playback error
            if let error = playbackService.playbackError {
                Section {
                    Text(error)
                        .font(.caption)
                        .foregroundColor(.red)
                }
            }

            // Fetch error
            if let error = fetchError {
                Section {
                    Text(error)
                        .font(.caption)
                        .foregroundColor(.red)
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

    private func fetchRecording(_ recordingID: String) {
        isFetching = true
        fetchedRecordingID = recordingID
        fetchedRecordingData = nil
        fetchError = nil

        // Collect chunks via recordingDataSubject
        var collectedData = Data()
        let dataSub = connection.recordingDataSubject
            .sink { chunk in
                collectedData.append(chunk)
            }

        // Wait for completion via recordingFetchCompleteSubject
        connection.recordingFetchCompleteSubject
            .filter { $0 == recordingID }
            .first()
            .sink { [self] _ in
                dataSub.cancel()
                isFetching = false
                if !collectedData.isEmpty {
                    fetchedRecordingData = collectedData
                    fetchedRecordingID = recordingID
                } else {
                    fetchError = "No data received"
                }
            }
            .store(in: &fetchCancellables)

        connection.fetchRecording(recordingID: recordingID)
    }

    private func playRecording(_ recording: RecordingInfo) {
        // If we already have the data, play it
        if let data = fetchedRecordingData, fetchedRecordingID == recording.id {
            doPlay(data: data, recordingID: recording.id)
            return
        }

        // Otherwise, fetch first then play
        isFetching = true
        fetchedRecordingID = recording.id
        fetchError = nil

        var collectedData = Data()
        let dataSub = connection.recordingDataSubject
            .sink { chunk in
                collectedData.append(chunk)
            }

        connection.recordingFetchCompleteSubject
            .filter { $0 == recording.id }
            .first()
            .sink { [self] _ in
                dataSub.cancel()
                isFetching = false
                if !collectedData.isEmpty {
                    fetchedRecordingData = collectedData
                    fetchedRecordingID = recording.id
                    doPlay(data: collectedData, recordingID: recording.id)
                } else {
                    fetchError = "No data received"
                }
            }
            .store(in: &fetchCancellables)

        connection.fetchRecording(recordingID: recording.id)
    }

    private func doPlay(data: Data, recordingID: String) {
        guard let dec = decoder else {
            fetchError = "Opus decoder not available"
            return
        }
        playingRecordingID = recordingID
        playbackService.play(recordingData: data, connection: connection, decoder: dec)
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
