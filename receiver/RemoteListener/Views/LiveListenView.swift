// SPDX-License-Identifier: MIT
// LiveListenView.swift — Live audio monitoring with latency display

import SwiftUI
import RLKit

struct LiveListenView: View {
    @ObservedObject var connection: TransmitterConnection
    let channelID: String
    let channelName: String
    let channelBitrate: UInt32

    @StateObject private var audioPlayer = AudioPlayerService()
    @Environment(\.dismiss) private var dismiss
    @State private var started = false

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            // Listening indicator
            if audioPlayer.isPlaying {
                VStack(spacing: 8) {
                    Image(systemName: "waveform")
                        .font(.system(size: 60))
                        .foregroundColor(.green)
                    Text("Listening")
                        .font(.title2)
                        .fontWeight(.semibold)
                }
            } else if started {
                VStack(spacing: 8) {
                    ProgressView()
                        .scaleEffect(1.5)
                    Text("Buffering...")
                        .font(.title2)
                        .foregroundColor(.secondary)
                }
            }

            // Channel & connection info
            VStack(spacing: 4) {
                Text(channelName)
                    .font(.headline)
                Text("\(channelBitrate) kbps · Opus 48kHz")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Text(connection.remoteDeviceName ?? "Unknown")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }

            // Latency indicator
            HStack(spacing: 4) {
                Image(systemName: "clock")
                    .font(.caption)
                Text("\(audioPlayer.currentLatencyMs) ms")
                    .font(.title3)
                    .monospacedDigit()
            }
            .foregroundColor(latencyColor)
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            .background(latencyColor.opacity(0.1))
            .cornerRadius(8)

            Spacer()

            // Stop button
            Button(action: stop) {
                Label("Stop Listening", systemImage: "stop.circle.fill")
                    .font(.title3)
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color.red)
                    .cornerRadius(12)
            }
            .padding(.horizontal, 32)
            .padding(.bottom, 48)
        }
        .navigationTitle("Live Listen")
        .navigationBarTitleDisplayMode(.inline)
        .navigationBarBackButtonHidden(audioPlayer.isPlaying)
        .onAppear { start() }
        .onDisappear { stop() }
    }

    private var latencyColor: Color {
        if audioPlayer.currentLatencyMs < 200 {
            return .green
        } else if audioPlayer.currentLatencyMs < 400 {
            return .orange
        } else {
            return .red
        }
    }

    private func start() {
        guard !started else { return }
        started = true
        guard let decoder = LibOpusDecoder() else {
            print("LiveListenView: failed to create Opus decoder")
            dismiss()
            return
        }
        connection.startLiveAudio(channelID: channelID)
        audioPlayer.start(connection: connection, decoder: decoder)
    }

    private func stop() {
        guard started else { return }
        started = false
        audioPlayer.stop()
        connection.stopLiveAudio(channelID: channelID)
    }
}
