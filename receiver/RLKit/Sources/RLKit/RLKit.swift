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
        let hi = UInt16(self[offset])
        let lo = UInt16(self[offset + 1])
        return (hi << 8) | lo
    }

    func readUInt32(at offset: Int) -> UInt32 {
        let b0 = UInt32(self[offset])
        let b1 = UInt32(self[offset + 1])
        let b2 = UInt32(self[offset + 2])
        let b3 = UInt32(self[offset + 3])
        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
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
