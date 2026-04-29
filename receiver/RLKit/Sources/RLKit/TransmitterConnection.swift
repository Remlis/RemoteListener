// SPDX-License-Identifier: MIT
// TransmitterConnection.swift — Single transmitter connection with frame I/O

import Foundation
import Network
import Combine
import CryptoKit
#if canImport(UIKit)
import UIKit
#endif

/// Connection state matching the Rust ConnectionState enum.
public enum ConnectionState: Equatable {
    case connecting
    case hello
    case ready
    case closed
}

/// Information about a channel on a transmitter.
public struct ChannelInfo: Identifiable, Equatable {
    public let id: String
    public let deviceName: String
    public let deviceUID: String
    public let recordingEnabled: Bool
    public let isActive: Bool
    public let bitrate: UInt32
    public let recordedBytes: UInt64

    public init(id: String, deviceName: String, deviceUID: String,
                recordingEnabled: Bool, isActive: Bool, bitrate: UInt32, recordedBytes: UInt64) {
        self.id = id
        self.deviceName = deviceName
        self.deviceUID = deviceUID
        self.recordingEnabled = recordingEnabled
        self.isActive = isActive
        self.bitrate = bitrate
        self.recordedBytes = recordedBytes
    }
}

/// A single audio chunk received from the transmitter.
public struct LiveAudioChunkData {
    public let channelID: String
    public let data: Data
    public let sequence: UInt32
    public let timestamp: Int64

    public init(channelID: String, data: Data, sequence: UInt32, timestamp: Int64) {
        self.channelID = channelID
        self.data = data
        self.sequence = sequence
        self.timestamp = timestamp
    }
}

/// Result of a control command.
public struct ControlResponseResult: Identifiable {
    public let id = UUID()
    public let success: Bool
    public let message: String

    public init(success: Bool, message: String) {
        self.success = success
        self.message = message
    }
}

/// Information about a recording on a transmitter.
public struct RecordingInfo: Identifiable, Equatable {
    public let id: String
    public let channelID: String
    public let startTimestamp: UInt64
    public let endTimestamp: UInt64
    public let fileSize: UInt64
    public let durationSeconds: UInt32

    public init(id: String, channelID: String, startTimestamp: UInt64, endTimestamp: UInt64, fileSize: UInt64, durationSeconds: UInt32) {
        self.id = id
        self.channelID = channelID
        self.startTimestamp = startTimestamp
        self.endTimestamp = endTimestamp
        self.fileSize = fileSize
        self.durationSeconds = durationSeconds
    }
}

/// Storage info from the transmitter.
public struct StorageInfo: Equatable {
    public let totalBytes: UInt64
    public let usedBytes: UInt64
    public let recordingCount: UInt64

    public init(totalBytes: UInt64, usedBytes: UInt64, recordingCount: UInt64) {
        self.totalBytes = totalBytes
        self.usedBytes = usedBytes
        self.recordingCount = recordingCount
    }
}

/// Manages a single connection to a transmitter.
public class TransmitterConnection: ObservableObject, Identifiable {
    /// Unique identifier for this connection (host:port).
    public let identifier: String
    public let id: String
    public let host: String
    public let port: UInt16

    /// Expected SHA-256 fingerprint of the peer's TLS certificate (hex string).
    /// If nil, certificate verification is skipped (only for first-time pairing).
    public var expectedFingerprint: String?

    @Published public private(set) var state: ConnectionState = .connecting
    @Published public private(set) var remoteDeviceName: String?
    @Published public private(set) var channels: [ChannelInfo] = []
    @Published public private(set) var isPaired: Bool = false

    /// Last control response received from the transmitter.
    @Published public private(set) var lastControlResponse: ControlResponseResult?

    /// Recordings list for the current channel.
    @Published public private(set) var recordings: [RecordingInfo] = []

    /// Storage info from the transmitter.
    @Published public private(set) var storageInfo: StorageInfo?

    /// Currently fetching recording data (accumulated chunks).
    @Published public private(set) var fetchingRecordingID: String?
    public let recordingDataSubject = PassthroughSubject<Data, Never>()
    /// Emits recording ID when a fetch completes.
    public let recordingFetchCompleteSubject = PassthroughSubject<String, Never>()

    /// Live audio chunks received from the transmitter.
    public let audioChunkSubject = PassthroughSubject<LiveAudioChunkData, Never>()

    /// Called when a PairResponse is received with the transmitter's public key and TLS cert fingerprint.
    public var onPairResponse: ((_ transmitterPublicKey: Data, _ tlsCertFingerprint: Data) -> Void)?

    /// Load the receiver's private key for a given TLS cert fingerprint (hex string).
    /// Set by the app layer to provide Keychain-backed storage.
    public var loadPrivateKey: ((_ tlsCertFingerprint: String) -> Data?)?

    /// Store the receiver's private key for a given TLS cert fingerprint (hex string).
    /// Set by the app layer to provide Keychain-backed storage.
    public var storePrivateKey: ((_ key: Data, _ tlsCertFingerprint: String) -> Void)?

    private var connection: NWConnection?
    private var readBuffer = Data()
    private let readQueue = DispatchQueue(label: "com.rl.receiver.read", qos: .userInitiated)
    private let writeQueue = DispatchQueue(label: "com.rl.receiver.write", qos: .userInitiated)

    /// Whether the last disconnect was initiated by the user (prevents auto-reconnect).
    private var userInitiatedDisconnect = false
    /// Current reconnect backoff delay in seconds.
    private var reconnectDelay: TimeInterval = 1.0
    /// Maximum reconnect backoff delay.
    private let maxReconnectDelay: TimeInterval = 60.0
    /// Heartbeat timer for sending periodic PINGs.
    private var heartbeatTimer: Timer?
    /// Time of last received data from the transmitter.
    private var lastReceivedTime: Date = Date()
    /// Receiver's X25519 private key for this connection (generated or loaded from Keychain).
    private var receiverPrivateKey: Data?

    public init(host: String, port: UInt16, expectedFingerprint: String? = nil) {
        self.host = host
        self.port = port
        self.identifier = "\(host):\(port)"
        self.id = self.identifier
        self.expectedFingerprint = expectedFingerprint
    }

    /// Connect to the transmitter.
    public func connect() {
        let endpointHost = NWEndpoint.Host(host)
        guard let endpointPort = NWEndpoint.Port(rawValue: port) else { return }

        let tlsOptions = NWProtocolTLS.Options()
        let alpnString = "rl/1.0"
        alpnString.withCString { alpnPtr in
            sec_protocol_options_add_tls_application_protocol(
                tlsOptions.securityProtocolOptions, alpnPtr)
        }

        // Verify certificate fingerprint against expected value
        let expectedFingerprint = self.expectedFingerprint
        // Capture the TLS cert fingerprint on first-time connections for later storage
        let capturedFingerprint = Box<String?>(nil)
        sec_protocol_options_set_verify_block(tlsOptions.securityProtocolOptions,
            { (_, sec_trust, verifyCallback) in
                let trust = sec_trust_copy_ref(sec_trust).takeRetainedValue()

                // Get the leaf certificate and compute its SHA-256 fingerprint
                guard let certChain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
                      let leafCert = certChain.first,
                      let certData = SecCertificateCopyData(leafCert) as Data? else {
                    print("TLS: could not extract peer certificate")
                    verifyCallback(false)
                    return
                }
                let fingerprint = SHA256.hash(data: certData).compactMap { String(format: "%02x", $0) }.joined()

                if let expected = expectedFingerprint {
                    // Known transmitter — verify fingerprint matches
                    if fingerprint == expected {
                        verifyCallback(true)
                    } else {
                        print("TLS: fingerprint mismatch (expected \(expected), got \(fingerprint))")
                        verifyCallback(false)
                    }
                } else {
                    // First-time pairing — accept and capture fingerprint for future connections
                    capturedFingerprint.value = fingerprint
                    verifyCallback(true)
                }
            }, DispatchQueue.main)

        let parameters = NWParameters(tls: tlsOptions, tcp: NWProtocolTCP.Options())
        connection = NWConnection(host: endpointHost, port: endpointPort, using: parameters)

        connection?.stateUpdateHandler = { [weak self] newState in
            DispatchQueue.main.async {
                guard let self = self else { return }
                switch newState {
                case .ready:
                    // Capture the TLS cert fingerprint from first-time handshake
                    if self.expectedFingerprint == nil, let fp = capturedFingerprint.value {
                        self.expectedFingerprint = fp
                        print("Captured TLS cert fingerprint: \(fp)")
                    }
                    self.state = .hello
                    self.sendHello()
                    self.startReadLoop()
                case .failed, .cancelled:
                    self.stopHeartbeat()
                    self.state = .closed
                    if !self.userInitiatedDisconnect {
                        self.scheduleReconnect()
                    }
                default:
                    break
                }
            }
        }

        state = .connecting
        userInitiatedDisconnect = false
        connection?.start(queue: readQueue)
    }

    /// Disconnect from the transmitter.
    public func disconnect() {
        userInitiatedDisconnect = true
        stopHeartbeat()
        if state == .ready || state == .hello {
            sendClose(reason: "User disconnect")
        }
        connection?.cancel()
        connection = nil
        DispatchQueue.main.async { self.state = .closed }
    }

    // MARK: - Sending Messages

    private func sendHello() {
        // Minimal protobuf: Hello { device_name = "iOS Receiver", client_version = "0.1.0", timestamp = now }
        var body = Data()
        #if canImport(UIKit)
        body.appendProtoString(field: 1, value: UIDevice.current.name)
        #else
        body.appendProtoString(field: 1, value: "RL Receiver")
        #endif
        body.appendProtoString(field: 2, value: "0.1.0")
        body.appendProtoInt64(field: 3, value: Int64(Date().timeIntervalSince1970))

        sendFrame(messageType: .hello, body: body)
    }

    /// Request the channel list from the transmitter.
    public func requestChannelList() {
        // ChannelListRequest is an empty message
        sendFrame(messageType: .channelListRequest, body: Data())
    }

    /// Start live audio for a channel.
    public func startLiveAudio(channelID: String) {
        var body = Data()
        body.appendProtoString(field: 1, value: channelID)
        sendFrame(messageType: .liveAudioStart, body: body)
    }

    /// Stop live audio for a channel.
    public func stopLiveAudio(channelID: String) {
        var body = Data()
        body.appendProtoString(field: 1, value: channelID)
        sendFrame(messageType: .liveAudioStop, body: body)
    }

    /// Send a ping.
    public func sendPing() {
        var body = Data()
        body.appendProtoInt64(field: 1, value: Int64(Date().timeIntervalSince1970))
        sendFrame(messageType: .ping, body: body)
    }

    /// Set recording enabled/disabled for a channel.
    public func setChannelRecording(channelID: String, enabled: Bool) {
        var body = Data()
        // ControlCommand { control_type = 1, channel_id = 2, recording_enabled = 10 }
        body.appendProtoUInt32(field: 1, value: 1) // SET_CHANNEL_RECORDING
        body.appendProtoString(field: 2, value: channelID)
        body.appendProtoBool(field: 10, value: enabled) // oneof payload field 10
        sendFrame(messageType: .controlCommand, body: body)
    }

    /// Set bitrate for a channel.
    public func setChannelBitrate(channelID: String, bitrate: UInt32) {
        var body = Data()
        // ControlCommand { control_type = 2, channel_id = 2, bitrate = 11 }
        body.appendProtoUInt32(field: 1, value: 2) // SET_CHANNEL_BITRATE
        body.appendProtoString(field: 2, value: channelID)
        body.appendProtoUInt32(field: 11, value: bitrate) // oneof payload field 11
        sendFrame(messageType: .controlCommand, body: body)
    }

    /// Request the recording list for a channel.
    public func requestRecordingList(channelID: String) {
        var body = Data()
        body.appendProtoString(field: 1, value: channelID)
        sendFrame(messageType: .recordingListRequest, body: body)
    }

    /// Request to fetch a recording.
    public func fetchRecording(recordingID: String) {
        var body = Data()
        body.appendProtoString(field: 1, value: recordingID)
        sendFrame(messageType: .recordingFetchRequest, body: body)
    }

    /// Delete a recording.
    public func deleteRecording(recordingID: String) {
        var body = Data()
        // ControlCommand { control_type = 3, recording_id = 12 }
        body.appendProtoUInt32(field: 1, value: 3) // DELETE_RECORDING
        body.appendProtoString(field: 12, value: recordingID) // oneof payload field 12
        sendFrame(messageType: .controlCommand, body: body)
    }

    /// Request storage info from the transmitter.
    public func getStorageInfo() {
        var body = Data()
        // ControlCommand { control_type = 4 (GET_STORAGE_INFO) }
        body.appendProtoUInt32(field: 1, value: 4) // GET_STORAGE_INFO
        sendFrame(messageType: .controlCommand, body: body)
    }

    /// Send a PairRequest with the receiver's X25519 public key.
    private func sendPairRequest() {
        // Try to load existing private key for this transmitter
        if let fp = expectedFingerprint,
           let existingKey = loadPrivateKey?(fp) {
            receiverPrivateKey = existingKey
        }

        // Generate a new X25519 keypair if we don't have one
        if receiverPrivateKey == nil {
            let privateKey: Curve25519.KeyAgreement.PrivateKey
            do {
                privateKey = try Curve25519.KeyAgreement.PrivateKey()
            } catch {
                print("Failed to generate X25519 keypair: \(error)")
                return
            }
            receiverPrivateKey = privateKey.rawRepresentation

            // Store the private key via the app-provided callback
            if let fp = expectedFingerprint {
                storePrivateKey?(receiverPrivateKey!, fp)
            }
        }

        // Derive the public key from the private key
        guard let privKeyData = receiverPrivateKey,
              let privateKey = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privKeyData) else {
            print("Failed to reconstruct X25519 private key")
            return
        }
        let publicKeyData = privateKey.publicKey.rawRepresentation

        // Send PairRequest { device_name = 1, public_key = 2 }
        var body = Data()
        #if canImport(UIKit)
        body.appendProtoString(field: 1, value: UIDevice.current.name)
        #else
        body.appendProtoString(field: 1, value: "RL Receiver")
        #endif
        body.appendProtoBytes(field: 2, value: publicKeyData)
        sendFrame(messageType: .pairRequest, body: body)
    }

    /// Set auto-delete days on the transmitter.
    public func setAutoDeleteDays(_ days: UInt32) {
        var body = Data()
        // ControlCommand { control_type = 5, auto_delete_days = 13 }
        body.appendProtoUInt32(field: 1, value: 5) // SET_AUTO_DELETE_DAYS
        body.appendProtoUInt32(field: 13, value: days) // oneof payload field 13
        sendFrame(messageType: .controlCommand, body: body)
    }

    private func sendClose(reason: String) {
        var body = Data()
        body.appendProtoString(field: 1, value: reason)
        sendFrame(messageType: .close, body: body)
    }

    private func sendFrame(messageType: MessageType, body: Data) {
        let frameData = RLPFrame.create(messageType: messageType, body: body)
        NSLog("sendFrame: type=%@, bytes=%lu, queue=%@", String(describing: messageType), UInt(frameData.count), String(cString: __dispatch_queue_get_label(nil)))
        connection?.send(content: frameData, completion: .contentProcessed { error in
            if let error = error {
                NSLog("Send error (\(messageType)): \(error)")
            } else {
                NSLog("Send OK: %@", String(describing: messageType))
            }
        })
    }

    // MARK: - Reading

    private func startReadLoop() {
        readQueue.async { [weak self] in
            self?.readBuffer = Data()
            self?.readNextChunk()
        }
    }

    private func readNextChunk() {
        connection?.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] content, _, isComplete, error in
            guard let self = self else { return }

            if let content = content, !content.isEmpty {
                NSLog("readNextChunk: received %lu bytes", UInt(content.count))
                self.readBuffer.append(content)
                self.processReadBuffer()
                DispatchQueue.main.async { self.lastReceivedTime = Date() }
            }

            if let error = error {
                print("Read error: \(error)")
                DispatchQueue.main.async {
                    self.stopHeartbeat()
                    self.state = .closed
                    if !self.userInitiatedDisconnect {
                        self.scheduleReconnect()
                    }
                }
                return
            }

            if isComplete {
                DispatchQueue.main.async {
                    self.stopHeartbeat()
                    self.state = .closed
                    if !self.userInitiatedDisconnect {
                        self.scheduleReconnect()
                    }
                }
                return
            }

            self.readNextChunk()
        }
    }

    private func processReadBuffer() {
        while !readBuffer.isEmpty {
            if let (frame, consumed) = RLPFrame.decode(from: readBuffer) {
                readBuffer = readBuffer.dropFirst(consumed)
                handleFrame(frame)
            } else {
                break // Need more data
            }
        }
    }

    private func handleFrame(_ frame: RLPFrame) {
        guard let header = RLPHeader.decode(from: frame.header) else {
            NSLog("handleFrame: failed to decode header, headerLen=%lu", UInt(frame.header.count))
            return
        }
        NSLog("handleFrame: type=%@ bodyLen=%lu", String(describing: header.messageType), UInt(frame.body.count))

        switch header.messageType {
        case .hello:
            handleHello(frame.body)
        case .ping:
            // Respond with ping
            var body = Data()
            body.appendProtoInt64(field: 1, value: Int64(Date().timeIntervalSince1970))
            sendFrame(messageType: .ping, body: body)
        case .close:
            DispatchQueue.main.async { self.state = .closed }
        case .channelList:
            handleChannelList(frame.body)
        case .liveAudioStartResponse:
            handleLiveAudioStartResponse(frame.body)
        case .liveAudioChunk:
            handleLiveAudioChunk(frame.body)
        case .pairResponse:
            handlePairResponse(frame.body)
        case .pairConfirm:
            handlePairConfirm(frame.body)
        case .deviceStatus:
            handleDeviceStatus(frame.body)
        case .controlResponse:
            handleControlResponse(frame.body)
        case .recordingListResponse:
            handleRecordingListResponse(frame.body)
        case .recordingChunk:
            handleRecordingChunk(frame.body)
        case .recordingFetchComplete:
            handleRecordingFetchComplete(frame.body)
        case .recordingFetchError:
            handleRecordingFetchError(frame.body)
        case .unknown:
            print("Received unknown message type: \(header.messageType.rawValue)")
        default:
            break
        }
    }

    private func handleHello(_ data: Data) {
        let deviceName = data.parseProtoString(field: 1)

        // Send responses immediately on the current queue (readQueue) to avoid
        // dispatch delays that cause the transmitter to think we're unresponsive
        self.requestChannelList()
        self.sendPairRequest()
        self.sendPing()

        // Update @Published properties on main queue (required by SwiftUI)
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.remoteDeviceName = deviceName
            self.state = .ready
            self.reconnectDelay = 1.0
            self.startHeartbeat()
        }
    }

    private func handleChannelList(_ data: Data) {
        // Parse repeated ChannelInfo messages from the body
        // The body is a ChannelList protobuf with field 1 = repeated ChannelInfo
        var channels: [ChannelInfo] = []
        var offset = 0

        while offset < data.count {
            // Read field tag
            guard let tag = data[offset...].readVarInt(offset: &offset) else { break }
            let fieldNumber = UInt32(tag >> 3)
            let wireType = tag & 0x07

            guard fieldNumber == 1 && wireType == 2 else {
                // Skip non-ChannelInfo fields
                if wireType == 2, let len = data[offset...].readVarInt(offset: &offset) {
                    offset += Int(len)
                } else if wireType == 0 {
                    _ = data[offset...].readVarInt(offset: &offset)
                } else {
                    break
                }
                continue
            }

            // Read length-delimited ChannelInfo
            guard let len = data[offset...].readVarInt(offset: &offset) else { break }
            let endOffset = offset + Int(len)
            guard endOffset <= data.count else { break }

            let channelData = data[offset..<endOffset]
            offset = endOffset

            if let ch = parseChannelInfo(channelData) {
                channels.append(ch)
            }
        }

        DispatchQueue.main.async {
            self.channels = channels
        }
    }

    private func parseChannelInfo(_ data: Data) -> ChannelInfo? {
        var offset = 0
        var channelID = ""
        var deviceName = ""
        var deviceUID = ""
        var recordingEnabled = false
        var isActive = false
        var bitrate: UInt32 = 0
        var recordedBytes: UInt64 = 0

        while offset < data.count {
            guard let tag = data[offset...].readVarInt(offset: &offset) else { return nil }
            let fieldNumber = UInt32(tag >> 3)
            let wireType = tag & 0x07

            switch (fieldNumber, wireType) {
            case (1, 2): channelID = data.parseStringAt(offset: &offset) ?? ""
            case (2, 2): deviceName = data.parseStringAt(offset: &offset) ?? ""
            case (3, 2): deviceUID = data.parseStringAt(offset: &offset) ?? ""
            case (4, 0): recordingEnabled = data.parseBoolAt(offset: &offset)
            case (5, 0): isActive = data.parseBoolAt(offset: &offset)
            case (6, 0): bitrate = UInt32(data.parseVarIntAt(offset: &offset) ?? 0)
            case (7, 0): recordedBytes = data.parseVarIntAt(offset: &offset) ?? 0
            default:
                switch wireType {
                case 0: _ = data[offset...].readVarInt(offset: &offset)
                case 2:
                    if let len = data[offset...].readVarInt(offset: &offset) {
                        offset += Int(len)
                    }
                default: break
                }
            }
        }

        return ChannelInfo(
            id: channelID.isEmpty ? deviceUID : channelID, deviceName: deviceName, deviceUID: deviceUID,
            recordingEnabled: recordingEnabled, isActive: isActive,
            bitrate: bitrate, recordedBytes: recordedBytes
        )
    }

    private func handleLiveAudioStartResponse(_ data: Data) {
        let channelID = data.parseProtoString(field: 1) ?? ""
        let success = data.parseProtoBool(field: 2)
        if !success {
            let error = data.parseProtoString(field: 3) ?? "Unknown error"
            print("Live audio start failed for \(channelID): \(error)")
        }
    }

    private func handleLiveAudioChunk(_ data: Data) {
        let channelID = data.parseProtoString(field: 1) ?? ""
        let audioData = data.parseProtoBytes(field: 2) ?? Data()
        let sequence = UInt32(data.parseProtoVarInt(field: 3) ?? 0)
        let timestamp = Int64(data.parseProtoVarInt(field: 4) ?? 0)

        let chunk = LiveAudioChunkData(
            channelID: channelID, data: audioData,
            sequence: sequence, timestamp: timestamp
        )
        DispatchQueue.main.async {
            self.audioChunkSubject.send(chunk)
        }
    }

    private func handlePairResponse(_ data: Data) {
        // PairResponse { public_key = 1, existing_key_fingerprints = 3 }
        let publicKeyData = data.parseProtoBytes(field: 1)
        // Store the transmitter's X25519 public key for ECDH key derivation
        if let pubKey = publicKeyData {
            // Use the TLS cert fingerprint (already set from TLS handshake) as the storage key
            if let fp = expectedFingerprint, let fingerprintData = Data(hexString: fp) {
                print("Paired with transmitter, TLS fingerprint: \(fp)")
                onPairResponse?(pubKey, fingerprintData)
            }
        }
        DispatchQueue.main.async {
            self.isPaired = true
        }
    }

    private func handlePairConfirm(_ data: Data) {
        let accepted = data.parseProtoBool(field: 1)
        DispatchQueue.main.async {
            self.isPaired = accepted
        }
    }

    private func handleDeviceStatus(_ data: Data) {
        // DeviceStatus { device_name = 1, channels = 2, storage = 3, uptime_seconds = 4 }
        var deviceName: String?
        var channels: [ChannelInfo] = []

        var offset = 0
        while offset < data.count {
            guard let tag = data[offset...].readVarInt(offset: &offset) else { break }
            let fieldNumber = UInt32(tag >> 3)
            let wireType = tag & 0x07

            switch (fieldNumber, wireType) {
            case (1, 2): deviceName = data.parseStringAt(offset: &offset)
            case (2, 2):
                // Parse channel list (same format as ChannelList.channels)
                guard let len = data[offset...].readVarInt(offset: &offset) else { break }
                let endOffset = offset + Int(len)
                guard endOffset <= data.count else { break }
                let channelListData = data[offset..<endOffset]
                offset = endOffset
                // Parse inner ChannelInfo messages from ChannelList
                var innerOffset = 0
                while innerOffset < channelListData.count {
                    guard let innerTag = channelListData[innerOffset...].readVarInt(offset: &innerOffset) else { break }
                    let innerField = UInt32(innerTag >> 3)
                    let innerWire = innerTag & 0x07
                    if innerField == 1 && innerWire == 2 {
                        if let ch = parseSubChannelInfo(channelListData, offset: &innerOffset) {
                            channels.append(ch)
                        }
                    } else {
                        guard channelListData.skipField(wireType: innerWire, offset: &innerOffset) else { break }
                    }
                }
            default:
                guard data.skipField(wireType: wireType, offset: &offset) else { break }
            }
        }

        DispatchQueue.main.async {
            if let name = deviceName { self.remoteDeviceName = name }
            if !channels.isEmpty { self.channels = channels }
        }
    }

    private func handleControlResponse(_ data: Data) {
        // ControlResponse { success = 1, message/error = 2, payload.storage_info = 10 }
        let success = data.parseProtoBool(field: 1)
        let message = data.parseProtoString(field: 2) ?? ""

        // Check for StorageInfo payload (field 10, wire type 2)
        var storage: StorageInfo?
        if let storageData = data.parseProtoBytes(field: 10) {
            storage = parseStorageInfo(storageData)
        }

        DispatchQueue.main.async {
            self.lastControlResponse = ControlResponseResult(success: success, message: message)
            if let storage = storage {
                self.storageInfo = storage
            }
        }
    }

    private func handleRecordingListResponse(_ data: Data) {
        // RecordingListResponse { repeated RecordingInfo recordings = 1 }
        var recordings: [RecordingInfo] = []
        var offset = 0

        while offset < data.count {
            guard let tag = data[offset...].readVarInt(offset: &offset) else { break }
            let fieldNumber = UInt32(tag >> 3)
            let wireType = tag & 0x07

            if fieldNumber == 1 && wireType == 2 {
                guard let len = data[offset...].readVarInt(offset: &offset) else { break }
                let endOffset = offset + Int(len)
                guard endOffset <= data.count else { break }
                let recData = data[offset..<endOffset]
                offset = endOffset
                if let rec = parseRecordingInfo(recData) {
                    recordings.append(rec)
                }
            } else {
                guard data.skipField(wireType: wireType, offset: &offset) else { break }
            }
        }

        DispatchQueue.main.async {
            self.recordings = recordings
        }
    }

    private var recordingChunkBuffer: Data = Data()

    private func handleRecordingChunk(_ data: Data) {
        // RecordingChunk { recording_id = 1, data = 2, chunk_index = 3, is_last = 4 }
        let recordingID = data.parseProtoString(field: 1) ?? ""
        let chunkData = data.parseProtoBytes(field: 2) ?? Data()

        recordingChunkBuffer.append(chunkData)

        // Send incremental data via subject
        DispatchQueue.main.async {
            self.fetchingRecordingID = recordingID
            self.recordingDataSubject.send(chunkData)
        }
    }

    private func handleRecordingFetchComplete(_ data: Data) {
        // RecordingFetchComplete { recording_id = 1 }
        let recordingID = data.parseProtoString(field: 1) ?? ""
        recordingChunkBuffer = Data()

        DispatchQueue.main.async {
            self.fetchingRecordingID = nil
            self.recordingFetchCompleteSubject.send(recordingID)
        }
    }

    private func handleRecordingFetchError(_ data: Data) {
        // RecordingFetchError { recording_id = 1, error = 2 }
        let recordingID = data.parseProtoString(field: 1) ?? ""
        let error = data.parseProtoString(field: 2) ?? "Unknown error"

        recordingChunkBuffer = Data()

        DispatchQueue.main.async {
            self.fetchingRecordingID = nil
            self.lastControlResponse = ControlResponseResult(
                success: false,
                message: "Fetch error for \(recordingID): \(error)"
            )
        }
    }

    private func parseRecordingInfo(_ data: Data) -> RecordingInfo? {
        var offset = 0
        var recordingID = ""
        var channelID = ""
        var startTimestamp: UInt64 = 0
        var endTimestamp: UInt64 = 0
        var fileSize: UInt64 = 0
        var durationSeconds: UInt32 = 0

        while offset < data.count {
            guard let tag = data[offset...].readVarInt(offset: &offset) else { return nil }
            let fieldNumber = UInt32(tag >> 3)
            let wireType = tag & 0x07

            switch (fieldNumber, wireType) {
            case (1, 2): recordingID = data.parseStringAt(offset: &offset) ?? ""
            case (2, 2): channelID = data.parseStringAt(offset: &offset) ?? ""
            case (3, 0): startTimestamp = data.parseVarIntAt(offset: &offset) ?? 0
            case (4, 0): endTimestamp = data.parseVarIntAt(offset: &offset) ?? 0
            case (5, 0): fileSize = data.parseVarIntAt(offset: &offset) ?? 0
            case (6, 0): durationSeconds = UInt32(data.parseVarIntAt(offset: &offset) ?? 0)
            default:
                guard data.skipField(wireType: wireType, offset: &offset) else { return nil }
            }
        }

        return RecordingInfo(
            id: recordingID, channelID: channelID,
            startTimestamp: startTimestamp, endTimestamp: endTimestamp,
            fileSize: fileSize, durationSeconds: durationSeconds
        )
    }

    private func parseStorageInfo(_ data: Data) -> StorageInfo? {
        var offset = 0
        var totalBytes: UInt64 = 0
        var usedBytes: UInt64 = 0
        var recordingCount: UInt64 = 0

        while offset < data.count {
            guard let tag = data[offset...].readVarInt(offset: &offset) else { return nil }
            let fieldNumber = UInt32(tag >> 3)
            let wireType = tag & 0x07

            switch (fieldNumber, wireType) {
            case (1, 0): totalBytes = data.parseVarIntAt(offset: &offset) ?? 0
            case (2, 0): usedBytes = data.parseVarIntAt(offset: &offset) ?? 0
            case (3, 0): recordingCount = data.parseVarIntAt(offset: &offset) ?? 0
            default:
                guard data.skipField(wireType: wireType, offset: &offset) else { return nil }
            }
        }

        return StorageInfo(totalBytes: totalBytes, usedBytes: usedBytes, recordingCount: recordingCount)
    }

    /// Parse a ChannelInfo sub-message at the current offset (length-delimited).
    private func parseSubChannelInfo(_ data: Data, offset: inout Int) -> ChannelInfo? {
        guard let len = data[offset...].readVarInt(offset: &offset) else { return nil }
        let endOffset = offset + Int(len)
        guard endOffset <= data.count else { return nil }
        let channelData = data[offset..<endOffset]
        offset = endOffset
        return parseChannelInfo(channelData)
    }

    // MARK: - Reconnection

    /// Schedule a reconnection attempt with exponential backoff.
    private func scheduleReconnect() {
        let delay = reconnectDelay
        reconnectDelay = min(reconnectDelay * 2, maxReconnectDelay)
        print("Reconnecting in \(delay)s...")
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
            guard let self = self, !self.userInitiatedDisconnect else { return }
            self.connect()
        }
    }

    // MARK: - Heartbeat

    /// Start the heartbeat timer (sends PING every 30s, closes if no response in 90s).
    private func startHeartbeat() {
        stopHeartbeat()
        lastReceivedTime = Date()
        heartbeatTimer = Timer.scheduledTimer(withTimeInterval: 30.0, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            self.sendPing()
            // Check if we've received any data in the last 90 seconds
            let elapsed = Date().timeIntervalSince(self.lastReceivedTime)
            if elapsed > 90.0 {
                print("Heartbeat timeout: no data received in \(Int(elapsed))s, closing connection")
                self.stopHeartbeat()
                self.connection?.cancel()
                self.connection = nil
                self.state = .closed
                if !self.userInitiatedDisconnect {
                    self.scheduleReconnect()
                }
            }
        }
    }

    /// Stop the heartbeat timer.
    private func stopHeartbeat() {
        heartbeatTimer?.invalidate()
        heartbeatTimer = nil
    }
}

/// Reference-type wrapper for communicating values from C closures.
private class Box<T> {
    var value: T
    init(_ value: T) { self.value = value }
}

// MARK: - Protobuf encoding helpers

extension Data {
    /// Append a protobuf field tag (VarInt-encoded: field_number << 3 | wire_type).
    private mutating func appendTag(field: UInt32, wireType: UInt8) {
        appendVarInt(UInt64((field << 3) | UInt32(wireType)))
    }

    mutating func appendProtoVarInt(field: UInt32, value: UInt64) {
        appendTag(field: field, wireType: 0)
        appendVarInt(value)
    }

    mutating func appendProtoInt64(field: UInt32, value: Int64) {
        appendProtoVarInt(field: field, value: UInt64(bitPattern: value))
    }

    mutating func appendProtoString(field: UInt32, value: String) {
        guard let strData = value.data(using: .utf8) else { return }
        appendTag(field: field, wireType: 2)
        appendVarInt(UInt64(strData.count))
        append(strData)
    }

    mutating func appendProtoBytes(field: UInt32, value: Data) {
        appendTag(field: field, wireType: 2)
        appendVarInt(UInt64(value.count))
        append(value)
    }

    mutating func appendProtoBool(field: UInt32, value: Bool) {
        appendProtoVarInt(field: field, value: value ? 1 : 0)
    }

    mutating func appendProtoUInt32(field: UInt32, value: UInt32) {
        appendProtoVarInt(field: field, value: UInt64(value))
    }
}

// MARK: - Protobuf parsing helpers

extension Data {
    /// Parse a string field from protobuf data.
    func parseProtoString(field: UInt32) -> String? {
        var offset = 0
        while offset < count {
            guard let tag = self[offset...].readVarInt(offset: &offset) else { return nil }
            let fieldNumber = UInt32(tag >> 3)
            let wireType = tag & 0x07

            if fieldNumber == field && wireType == 2 {
                return parseStringAt(offset: &offset)
            } else {
                guard skipField(wireType: wireType, offset: &offset) else { return nil }
            }
        }
        return nil
    }

    func parseProtoBool(field: UInt32) -> Bool {
        var offset = 0
        while offset < count {
            guard let tag = self[offset...].readVarInt(offset: &offset) else { return false }
            let fieldNumber = UInt32(tag >> 3)
            let wireType = tag & 0x07

            if fieldNumber == field && wireType == 0 {
                return parseBoolAt(offset: &offset)
            } else {
                guard skipField(wireType: wireType, offset: &offset) else { return false }
            }
        }
        return false
    }

    func parseProtoVarInt(field: UInt32) -> UInt64? {
        var offset = 0
        while offset < count {
            guard let tag = self[offset...].readVarInt(offset: &offset) else { return nil }
            let fieldNumber = UInt32(tag >> 3)
            let wireType = tag & 0x07

            if fieldNumber == field && wireType == 0 {
                return parseVarIntAt(offset: &offset)
            } else {
                guard skipField(wireType: wireType, offset: &offset) else { return nil }
            }
        }
        return nil
    }

    func parseProtoBytes(field: UInt32) -> Data? {
        var offset = 0
        while offset < count {
            guard let tag = self[offset...].readVarInt(offset: &offset) else { return nil }
            let fieldNumber = UInt32(tag >> 3)
            let wireType = tag & 0x07

            if fieldNumber == field && wireType == 2 {
                guard let len = self[offset...].readVarInt(offset: &offset) else { return nil }
                let endOffset = offset + Int(len)
                guard endOffset <= count else { return nil }
                let result = Data(self[offset..<endOffset])
                offset = endOffset
                return result
            } else {
                guard skipField(wireType: wireType, offset: &offset) else { return nil }
            }
        }
        return nil
    }

    func parseStringAt(offset: inout Int) -> String? {
        guard let len = self[offset...].readVarInt(offset: &offset) else { return nil }
        let endOffset = offset + Int(len)
        guard endOffset <= count else { return nil }
        let strData = self[offset..<endOffset]
        offset = endOffset
        return String(data: strData, encoding: .utf8)
    }

    func parseBoolAt(offset: inout Int) -> Bool {
        guard let value = self[offset...].readVarInt(offset: &offset) else { return false }
        return value != 0
    }

    func parseVarIntAt(offset: inout Int) -> UInt64? {
        self[offset...].readVarInt(offset: &offset)
    }

    func skipField(wireType: UInt64, offset: inout Int) -> Bool {
        switch wireType {
        case 0: _ = self[offset...].readVarInt(offset: &offset)
        case 1: offset += 8
        case 2:
            guard let len = self[offset...].readVarInt(offset: &offset) else { return false }
            offset += Int(len)
        case 5: offset += 4
        default: return false // Unknown wire type — cannot skip
        }
        return true
    }
}

// MARK: - Data hex helpers

extension Data {
    /// Initialize from a hex string.
    init?(hexString: String) {
        let clean = hexString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard clean.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        var index = clean.startIndex
        while index < clean.endIndex {
            let next = clean.index(after: index)
            guard let byte = UInt8(clean[index...next], radix: 16) else { return nil }
            bytes.append(byte)
            index = clean.index(after: next)
        }
        self = Data(bytes)
    }
}
