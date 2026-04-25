// SPDX-License-Identifier: MIT
// RLKit — Shared Swift Package for protocol, crypto, and networking

import Foundation
import CryptoKit

/// RLP frame format: [2-byte header_len][Header protobuf][4-byte body_len][Body protobuf]
public struct RLPFrame {
    public let header: Data
    public let body: Data

    public init(header: Data, body: Data) {
        self.header = header
        self.body = body
    }

    /// Encode an RLP frame to bytes.
    public func encode() -> Data {
        var result = Data()
        result.append(UInt16(header.count).bigEndianBytes)
        result.append(header)
        result.append(UInt32(body.count).bigEndianBytes)
        result.append(body)
        return result
    }

    /// Decode an RLP frame from data.
    public static func decode(from data: Data) -> (frame: RLPFrame, bytesConsumed: Int)? {
        guard data.count >= 2 else { return nil }

        let headerLen = data.readUInt16(at: 0)
        guard data.count >= 2 + Int(headerLen) + 4 else { return nil }

        let headerData = data[2..<(2 + Int(headerLen))]
        let bodyLenOffset = 2 + Int(headerLen)
        let bodyLen = data.readUInt32(at: bodyLenOffset)

        let totalLen = bodyLenOffset + 4 + Int(bodyLen)
        guard data.count >= totalLen else { return nil }

        let bodyData = Data(data[(bodyLenOffset + 4)..<totalLen])
        return (RLPFrame(header: headerData, body: bodyData), totalLen)
    }
}

// MARK: - Data helpers

extension Data {
    func readUInt16(at offset: Int) -> UInt16 {
        let value = self[offset..<(offset + 2)].withUnsafeBytes { $0.load(as: UInt16.self) }
        return UInt16(bigEndian: value)
    }

    func readUInt32(at offset: Int) -> UInt32 {
        let value = self[offset..<(offset + 4)].withUnsafeBytes { $0.load(as: UInt32.self) }
        return UInt32(bigEndian: value)
    }
}

extension UInt16 {
    var bigEndianBytes: Data {
        var value = self.bigEndian
        return Data(bytes: &value, count: MemoryLayout<UInt16>.size)
    }
}

extension UInt32 {
    var bigEndianBytes: Data {
        var value = self.bigEndian
        return Data(bytes: &value, count: MemoryLayout<UInt32>.size)
    }
}
