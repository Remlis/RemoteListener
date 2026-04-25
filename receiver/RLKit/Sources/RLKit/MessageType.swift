// SPDX-License-Identifier: MIT
// MessageType.swift — RLP message type constants matching rl_protocol.proto

import Foundation

/// Message types matching the proto MessageType enum.
public enum MessageType: UInt32, CaseIterable {
    // Handshake
    case hello = 1
    case pairRequest = 2
    case pairResponse = 3
    case pairConfirm = 4
    case ping = 5
    case close = 6
    case unpair = 7

    // Channel management
    case channelListRequest = 8
    case channelList = 9

    // Recording
    case recordingListRequest = 10
    case recordingListResponse = 11
    case recordingFetchRequest = 12
    case recordingChunk = 13
    case recordingFetchComplete = 14
    case recordingFetchError = 15

    // Live audio
    case liveAudioStart = 20
    case liveAudioStop = 21
    case liveAudioChunk = 22
    case liveAudioStartResponse = 23

    // Remote control
    case controlCommand = 30
    case controlResponse = 31

    // Device status
    case deviceStatus = 40

    /// Unknown message type not in this enum. Stored so the raw value is preserved.
    case unknown = 0

    public init(rawValue: UInt32) {
        self = Self.allCases.first { $0.rawValue == rawValue } ?? .unknown
    }
}

/// RLP frame header, matching the proto Header message.
public struct RLPHeader {
    public let messageType: MessageType
    public let compressed: Bool

    public init(messageType: MessageType, compressed: Bool = false) {
        self.messageType = messageType
        self.compressed = compressed
    }

    /// Encode as a minimal protobuf message:
    /// field 1 (type) = varint, field 2 (compressed) = bool
    public func encode() -> Data {
        var data = Data()
        // Field 1: message_type (varint)
        data.append(0x08) // field 1, wire type 0
        data.appendVarInt(messageType.rawValue)
        // Field 2: compressed (bool)
        if compressed {
            data.append(0x10) // field 2, wire type 0
            data.append(0x01) // true
        }
        return data
    }

    /// Decode from protobuf header data.
    public static func decode(from data: Data) -> RLPHeader? {
        var offset = 0
        var msgType: UInt32 = 0
        var compressed = false

        while offset < data.count {
            guard let tag = data[offset..].readVarInt(offset: &offset) else { return nil }
            let fieldNumber = UInt32(tag >> 3)
            let wireType = tag & 0x07

            switch fieldNumber {
            case 1: // message_type
                guard wireType == 0, let value = data[offset..].readVarInt(offset: &offset) else { return nil }
                msgType = UInt32(value)
            case 2: // compressed
                guard wireType == 0, let value = data[offset..].readVarInt(offset: &offset) else { return nil }
                compressed = value != 0
            default:
                // Skip unknown fields
                switch wireType {
                case 0: _ = data[offset..].readVarInt(offset: &offset)
                case 1: offset += 8
                case 2:
                    guard let len = data[offset..].readVarInt(offset: &offset) else { return nil }
                    offset += Int(len)
                case 5: offset += 4
                default: return nil
                }
            }
        }

        let mt = MessageType(rawValue: msgType)
        return RLPHeader(messageType: mt, compressed: compressed)
    }
}

// MARK: - VarInt encoding/decoding

extension Data {
    mutating func appendVarInt(_ value: UInt64) {
        var v = value
        while v > 0x7F {
            append(UInt8(v & 0x7F) | 0x80)
            v >>= 7
        }
        append(UInt8(v))
    }

    func readVarInt(offset: inout Int) -> UInt64? {
        var result: UInt64 = 0
        var shift = 0
        while offset < count {
            let byte = self[offset]
            offset += 1
            result |= UInt64(byte & 0x7F) << shift
            if byte & 0x80 == 0 { return result }
            shift += 7
            if shift >= 64 { return nil }
        }
        return nil
    }
}

// MARK: - Frame encoding helper

extension RLPFrame {
    /// Create an RLP frame from a message type and body data.
    public static func create(messageType: MessageType, body: Data = Data()) -> Data {
        let header = RLPHeader(messageType: messageType).encode()
        let frame = RLPFrame(header: header, body: body)
        return frame.encode()
    }
}
