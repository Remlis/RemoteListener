// SPDX-License-Identifier: MIT
// AudioPlayerService.swift — Live audio playback with jitter buffer

import Foundation
import AVFoundation
import Combine
import RLKit

/// Plays live audio from a transmitter's `audioChunkSubject`.
///
/// Pipeline: Opus data → decode → jitter buffer → AVAudioEngine PCM playback.
class AudioPlayerService: ObservableObject {
    @Published private(set) var isPlaying = false
    @Published private(set) var currentLatencyMs: Int = 0

    private var engine: AVAudioEngine?
    private var playerNode: AVAudioPlayerNode?
    private var cancellable: AnyCancellable?
    private var decoder: OpusDecoding?

    /// Jitter buffer: queues decoded PCM buffers before playback.
    /// Target latency is adaptive between 160ms–500ms.
    private var jitterBuffer: [AVAudioPCMBuffer] = []
    private let maxJitterBuffers = 25 // 25 × 20ms = 500ms
    private let minJitterBuffers = 8  // 8 × 20ms = 160ms

    private let sampleRate: Double = 48000
    private let channels: UInt32 = 1
    private let frameSize: AVAudioFrameCount = 960 // 20ms at 48kHz

    init() {}

    deinit {
        stop()
    }

    // MARK: - Public API

    /// Start live audio playback for the given connection's audio chunk stream.
    /// - Parameters:
    ///   - connection: The transmitter connection to receive audio from.
    ///   - decoder: An Opus decoder conforming to `OpusDecoding`.
    func start(connection: TransmitterConnection, decoder: OpusDecoding) {
        guard !isPlaying else { return }
        self.decoder = decoder
        setupAudioSession()
        setupEngine()
        subscribeToChunks(connection: connection)
        isPlaying = true
    }

    /// Stop live audio playback.
    func stop() {
        guard isPlaying else { return }
        cancellable?.cancel()
        cancellable = nil
        playerNode?.stop()
        engine?.stop()
        engine = nil
        playerNode = nil
        jitterBuffer.removeAll()
        decoder = nil
        isPlaying = false
        currentLatencyMs = 0
    }

    // MARK: - Setup

    private func setupAudioSession() {
        do {
            let session = AVAudioSession.sharedInstance()
            try session.setCategory(.playback, mode: .default, options: [.mixWithOthers])
            try session.setActive(true)
        } catch {
            print("AudioPlayer: failed to set up audio session: \(error)")
        }

        // Handle audio interruptions (phone calls, alarms, etc.)
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleInterruption),
            name: AVAudioSession.interruptionNotification,
            object: nil
        )

        // Handle route changes (headphones unplugged, etc.)
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleRouteChange),
            name: AVAudioSession.routeChangeNotification,
            object: nil
        )
    }

    @objc private func handleInterruption(_ notification: Notification) {
        guard let type = notification.userInfo?[AVAudioSessionInterruptionTypeKey] as? UInt,
              let interruptionType = AVAudioSession.InterruptionType(rawValue: type) else {
            return
        }

        switch interruptionType {
        case .began:
            // Audio interrupted (e.g., phone call) — pause playback
            pauseForInterruption()
        case .ended:
            guard let options = notification.userInfo?[AVAudioSessionInterruptionOptionKey] as? UInt else { return }
            let shouldResume = AVAudioSession.InterruptionOptions(rawValue: options).contains(.shouldResume)
            if shouldResume {
                resumeAfterInterruption()
            }
        @unknown default:
            break
        }
    }

    @objc private func handleRouteChange(_ notification: Notification) {
        guard let reasonValue = notification.userInfo?[AVAudioSessionRouteChangeReasonKey] as? UInt,
              let reason = AVAudioSession.RouteChangeReason(rawValue: reasonValue) else {
            return
        }
        if reason == .oldDeviceUnavailable {
            // Headphones unplugged — pause to avoid speaker blast
            pauseForInterruption()
        }
    }

    private func pauseForInterruption() {
        playerNode?.pause()
        engine?.pause()
        do {
            try AVAudioSession.sharedInstance().setActive(false)
        } catch {
            print("AudioPlayer: failed to deactivate session: \(error)")
        }
    }

    private func resumeAfterInterruption() {
        do {
            try AVAudioSession.sharedInstance().setActive(true)
            try engine?.start()
            playerNode?.play()
        } catch {
            print("AudioPlayer: failed to resume after interruption: \(error)")
        }
    }

    private func setupEngine() {
        let engine = AVAudioEngine()
        let playerNode = AVAudioPlayerNode()

        engine.attach(playerNode)

        let format = AVAudioFormat(commonFormat: .pcmFormatInt16,
                                     sampleRate: sampleRate,
                                     channels: channels,
                                     interleaved: true)!
        engine.connect(playerNode, to: engine.mainMixerNode, format: format)

        self.engine = engine
        self.playerNode = playerNode

        do {
            try engine.start()
        } catch {
            print("AudioPlayer: failed to start engine: \(error)")
        }
    }

    // MARK: - Chunk subscription

    private func subscribeToChunks(connection: TransmitterConnection) {
        cancellable = connection.audioChunkSubject.sink { [weak self] chunk in
            self?.handleChunk(chunk)
        }
    }

    private func handleChunk(_ chunk: LiveAudioChunkData) {
        guard let decoder = decoder,
              let playerNode = playerNode,
              let format = AVAudioFormat(commonFormat: .pcmFormatInt16,
                                           sampleRate: sampleRate,
                                           channels: channels,
                                           interleaved: true) else { return }

        // Decode Opus frame to PCM
        guard let pcmSamples = decoder.decode(opusData: chunk.data) else { return }
        guard !pcmSamples.isEmpty else { return }

        let frameCount = AVAudioFrameCount(pcmSamples.count)
        guard let buffer = AVAudioPCMBuffer(pcmFormat: format, frameCapacity: frameCount) else { return }

        // Copy PCM data into buffer
        pcmSamples.enumerated().forEach { i, sample in
            buffer.int16ChannelData![0][i] = sample
        }
        buffer.frameLength = frameCount

        // Add to jitter buffer
        jitterBuffer.append(buffer)

        // Adaptive jitter: if buffer is growing too large, drop oldest
        while jitterBuffer.count > maxJitterBuffers {
            jitterBuffer.removeFirst()
        }

        // If buffer has reached minimum, start scheduling
        if jitterBuffer.count >= minJitterBuffers {
            scheduleBuffers()
        }

        currentLatencyMs = jitterBuffer.count * 20 // 20ms per frame
    }

    private func scheduleBuffers() {
        guard let playerNode = playerNode else { return }

        while !jitterBuffer.isEmpty {
            let buffer = jitterBuffer.removeFirst()
            playerNode.scheduleBuffer(buffer) { [weak self] in
                if let self = self {
                    self.currentLatencyMs = max(0, self.currentLatencyMs - 20)
                }
            }
        }

        if !playerNode.isPlaying {
            playerNode.play()
        }
    }
}
