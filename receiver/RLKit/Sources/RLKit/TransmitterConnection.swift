// SPDX-License-Identifier: MIT
// TransmitterConnection.swift — Single transmitter connection with frame I/O

import Foundation
import Network
import Combine

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

/// Manages a single connection to a transmitter.
public class TransmitterConnection: ObservableObject, Identifiable {
    /// Unique identifier for this connection (host:port).
    public let identifier: String
    public let id: String
    public let host: String
    public let port: UInt16

    @Published public private(set) var state: ConnectionState = .connecting
    @Published public private(set) var remoteDeviceName: String?
    @Published public private(set) var channels: [ChannelInfo] = []
    @Published public private(set) var isPaired: Bool = false

    /// Live audio chunks received from the transmitter.
    public let audioChunkSubject = PassthroughSubject<LiveAudioChunkData, Never>()

    private var connection: NWConnection?
    private var readBuffer = Data()
    private let readQueue = DispatchQueue(label: "com.rl.receiver.read", qos: .userInitiated)
    private let writeQueue = DispatchQueue(label: "com.rl.receiver.write", qos: .userInitiated)

    public init(host: String, port: UInt16) {
        self.host = host
        self.port = port
        self.identifier = "\(host):\(port)"
        self.id = self.identifier
    }

    /// Connect to the transmitter.
    public func connect() {
        let endpointHost = NWEndpoint.Host(host)
        guard let endpointPort = NWEndpoint.Port(rawValue: port) else { return }

        let tlsOptions = NWProtocolTLS.Options()
        let alpnData = "rl/1.0".data(using: .utf8)!
        sec_protocol_options_add_tls_application_protocol(
            tlsOptions.securityProtocolOptions, alpnData)

        // TODO: Verify certificate fingerprint
        sec_protocol_options_set_verify_block(tlsOptions.securityProtocolOptions,
            { (_, _, verifyCallback) in
                verifyCallback(true)
            }, DispatchQueue.main)

        let parameters = NWParameters(tls: tlsOptions, tcp: NWProtocolTCP.Options())
        connection = NWConnection(host: endpointHost, port: endpointPort, using: parameters)

        connection?.stateUpdateHandler = { [weak self] newState in
            DispatchQueue.main.async {
                switch newState {
                case .ready:
                    self?.state = .hello
                    self?.sendHello()
                    self?.startReadLoop()
                case .failed, .cancelled:
                    self?.state = .closed
                default:
                    break
                }
            }
        }

        state = .connecting
        connection?.start(queue: readQueue)
    }

    /// Disconnect from the transmitter.
    public func disconnect() {
        if state == .ready || state == .hello {
            sendClose(reason: "User disconnect")
        }
        connection?.cancel()
        connection = nil
        state = .closed
    }

    // MARK: - Sending Messages

    private func sendHello() {
        // Minimal protobuf: Hello { device_name = "iOS Receiver", client_version = "0.1.0", timestamp = now }
        var body = Data()
        body.appendProtoString(field: 1, value: UIDevice.current.name)
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

    private func sendClose(reason: String) {
        var body = Data()
        body.appendProtoString(field: 1, value: reason)
        sendFrame(messageType: .close, body: body)
    }

    private func sendFrame(messageType: MessageType, body: Data) {
        let frameData = RLPFrame.create(messageType: messageType, body: body)
        connection?.send(content: frameData, completion: .contentProcessed { error in
            if let error = error {
                print("Send error: \(error)")
            }
        })
    }

    // MARK: - Reading

    private func startReadLoop() {
        readBuffer = Data()
        readNextChunk()
    }

    private func readNextChunk() {
        connection?.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] content, _, isComplete, error in
            guard let self = self else { return }

            if let content = content, !content.isEmpty {
                self.readBuffer.append(content)
                self.processReadBuffer()
            }

            if let error = error {
                print("Read error: \(error)")
                DispatchQueue.main.async { self.state = .closed }
                return
            }

            if isComplete {
                DispatchQueue.main.async { self.state = .closed }
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
        guard let header = RLPHeader.decode(from: frame.header) else { return }

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
            break // TODO
        case .recordingListResponse, .recordingChunk, .recordingFetchComplete, .recordingFetchError:
            break // TODO: recording handling
        default:
            break
        }
    }

    private func handleHello(_ data: Data) {
        let deviceName = data.parseProtoString(field: 1)
        DispatchQueue.main.async {
            self.remoteDeviceName = deviceName
            self.state = .ready
            // Request channel list after hello
            self.requestChannelList()
        }
    }

    private func handleChannelList(_ data: Data) {
        // Parse repeated ChannelInfo messages from the body
        // The body is a ChannelList protobuf with field 1 = repeated ChannelInfo
        var channels: [ChannelInfo] = []
        var offset = 0

        while offset < data.count {
            // Read field tag
            guard let tag = data[offset..].readVarInt(offset: &offset) else { break }
            let fieldNumber = UInt32(tag >> 3)
            let wireType = tag & 0x07

            guard fieldNumber == 1 && wireType == 2 else {
                // Skip non-ChannelInfo fields
                if wireType == 2, let len = data[offset..].readVarInt(offset: &offset) {
                    offset += Int(len)
                } else if wireType == 0 {
                    _ = data[offset..].readVarInt(offset: &offset)
                } else {
                    break
                }
                continue
            }

            // Read length-delimited ChannelInfo
            guard let len = data[offset..].readVarInt(offset: &offset) else { break }
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
            guard let tag = data[offset..].readVarInt(offset: &offset) else { return nil }
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
                case 0: _ = data[offset..].readVarInt(offset: &offset)
                case 2:
                    if let len = data[offset..].readVarInt(offset: &offset) {
                        offset += Int(len)
                    }
                default: break
                }
            }
        }

        return ChannelInfo(
            id: channelID, deviceName: deviceName, deviceUID: deviceUID,
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
        audioChunkSubject.send(chunk)
    }

    private func handlePairResponse(_ data: Data) {
        // TODO: Full pairing implementation
        // publicKey = field 1, privateKey = field 2, fingerprints = field 3
    }

    private func handlePairConfirm(_ data: Data) {
        let accepted = data.parseProtoBool(field: 1)
        DispatchQueue.main.async {
            self.isPaired = accepted
        }
    }

    private func handleDeviceStatus(_ data: Data) {
        // Re-parse channel list from device status
        // DeviceStatus { device_name = 1, channels = 2, storage = 3, uptime = 4 }
        var offset = 0
        while offset < data.count {
            guard let tag = data[offset..].readVarInt(offset: &offset) else { break }
            let fieldNumber = UInt32(tag >> 3)
            let wireType = tag & 0x07

            if fieldNumber == 2 && wireType == 2 {
                // Parse channel list (same format as ChannelList.channels)
                if let len = data[offset..].readVarInt(offset: &offset) {
                    let endOffset = offset + Int(len)
                    if endOffset <= data.count {
                        _ = data[offset..<endOffset]
                        offset = endOffset
                    }
                }
            } else {
                switch wireType {
                case 0: _ = data[offset..].readVarInt(offset: &offset)
                case 2:
                    if let len = data[offset..].readVarInt(offset: &offset) {
                        offset += Int(len)
                    }
                default: break
                }
            }
        }
    }
}

// MARK: - Protobuf encoding helpers

extension Data {
    mutating func appendProtoVarInt(field: UInt32, value: UInt64) {
        append(UInt8((field << 3) | 0)) // wire type 0 = varint
        appendVarInt(value)
    }

    mutating func appendProtoInt64(field: UInt32, value: Int64) {
        appendProtoVarInt(field: field, value: UInt64(bitPattern: value))
    }

    mutating func appendProtoString(field: UInt32, value: String) {
        guard let strData = value.data(using: .utf8) else { return }
        append(UInt8((field << 3) | 2)) // wire type 2 = length-delimited
        appendVarInt(UInt64(strData.count))
        append(strData)
    }

    mutating func appendProtoBytes(field: UInt32, value: Data) {
        append(UInt8((field << 3) | 2)) // wire type 2
        appendVarInt(UInt64(value.count))
        append(value)
    }

    mutating func appendProtoBool(field: UInt32, value: Bool) {
        appendProtoVarInt(field: field, value: value ? 1 : 0)
    }
}

// MARK: - Protobuf parsing helpers

extension Data {
    /// Parse a string field from protobuf data.
    func parseProtoString(field: UInt32) -> String? {
        var offset = 0
        while offset < count {
            guard let tag = self[offset..].readVarInt(offset: &offset) else { return nil }
            let fieldNumber = UInt32(tag >> 3)
            let wireType = tag & 0x07

            if fieldNumber == field && wireType == 2 {
                return parseStringAt(offset: &offset)
            } else {
                skipField(wireType: wireType, offset: &offset)
            }
        }
        return nil
    }

    func parseProtoBool(field: UInt32) -> Bool {
        var offset = 0
        while offset < count {
            guard let tag = self[offset..].readVarInt(offset: &offset) else { return false }
            let fieldNumber = UInt32(tag >> 3)
            let wireType = tag & 0x07

            if fieldNumber == field && wireType == 0 {
                return parseBoolAt(offset: &offset)
            } else {
                skipField(wireType: wireType, offset: &offset)
            }
        }
        return false
    }

    func parseProtoVarInt(field: UInt32) -> UInt64? {
        var offset = 0
        while offset < count {
            guard let tag = self[offset..].readVarInt(offset: &offset) else { return nil }
            let fieldNumber = UInt32(tag >> 3)
            let wireType = tag & 0x07

            if fieldNumber == field && wireType == 0 {
                return parseVarIntAt(offset: &offset)
            } else {
                skipField(wireType: wireType, offset: &offset)
            }
        }
        return nil
    }

    func parseProtoBytes(field: UInt32) -> Data? {
        var offset = 0
        while offset < count {
            guard let tag = self[offset..].readVarInt(offset: &offset) else { return nil }
            let fieldNumber = UInt32(tag >> 3)
            let wireType = tag & 0x07

            if fieldNumber == field && wireType == 2 {
                guard let len = self[offset..].readVarInt(offset: &offset) else { return nil }
                let endOffset = offset + Int(len)
                guard endOffset <= count else { return nil }
                let result = Data(self[offset..<endOffset])
                offset = endOffset
                return result
            } else {
                skipField(wireType: wireType, offset: &offset)
            }
        }
        return nil
    }

    func parseStringAt(offset: inout Int) -> String? {
        guard let len = self[offset..].readVarInt(offset: &offset) else { return nil }
        let endOffset = offset + Int(len)
        guard endOffset <= count else { return nil }
        let strData = self[offset..<endOffset]
        offset = endOffset
        return String(data: strData, encoding: .utf8)
    }

    func parseBoolAt(offset: inout Int) -> Bool {
        guard let value = self[offset..].readVarInt(offset: &offset) else { return false }
        return value != 0
    }

    func parseVarIntAt(offset: inout Int) -> UInt64? {
        self[offset..].readVarInt(offset: &offset)
    }

    func skipField(wireType: UInt64, offset: inout Int) {
        switch wireType {
        case 0: _ = self[offset..].readVarInt(offset: &offset)
        case 1: offset += 8
        case 2:
            if let len = self[offset..].readVarInt(offset: &offset) {
                offset += Int(len)
            }
        case 5: offset += 4
        default: break
        }
    }
}
