// SPDX-License-Identifier: MIT
// MessageType.swift — RLP message type constants matching rl_protocol.proto

import Foundation

/// Message types matching the proto MessageType enum.
public enum MessageType: UInt32, CaseIterable {
    case hello = 1
    case pairRequest = 2
    case pairResponse = 3
    case pairConfirm = 4
    case unpair = 5
    case ping = 6
    case close = 7
    case channelListRequest = 20
    case channelList = 21
    case liveAudioStart = 30
    case liveAudioStartResponse = 31
    case liveAudioStop = 32
    case liveAudioChunk = 33
    case recordingListRequest = 40
    case recordingListResponse = 41
    case recordingFetchRequest = 42
    case recordingChunk = 43
    case recordingFetchComplete = 44
    case recordingFetchError = 45
    case controlCommand = 50
    case controlResponse = 51
    case deviceStatus = 60
    case storageInfo = 61

    public init?(rawValue: UInt32) {
        Self.allCases.first { $0.rawValue == rawValue }
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
                    if let len = data[offset..].readVarInt(offset: &offset) {
                        offset += Int(len)
                    }
                case 5: offset += 4
                default: return nil
                }
            }
        }

        guard let mt = MessageType(rawValue: msgType) else { return nil }
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
