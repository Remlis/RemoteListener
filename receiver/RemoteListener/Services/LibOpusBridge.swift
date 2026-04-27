// SPDX-License-Identifier: MIT
// LibOpusBridge.swift — Concrete Opus decoder using libopus C interop
//
// This file requires libopus to be linked (via XCFramework or system library).
// Add this file to the RemoteListener target in Xcode, and add the
// Opus.xcframework to the project.
//
// To create the Opus.xcframework:
//   1. Build libopus for iOS device + simulator from source
//   2. Create xcframework with: xcodebuild -create-xcframework
//   3. Add to the Xcode project under "Frameworks, Libraries, and Embedded Content"

import Foundation

/// Concrete Opus decoder using libopus C library.
///
/// Usage:
///   if let decoder = LibOpusDecoder() {
///       audioPlayer.start(connection: conn, decoder: decoder)
///   }
public class LibOpusDecoder: OpusDecoding {
    // Opaque pointer to OpusDecoder C struct
    private typealias OpusDecoderPtr = UnsafeMutableRawPointer

    private var decoder: OpusDecoderPtr?

    public init?() {
        var error: Int32 = 0
        guard let dec = rl_opus_bridge_decoder_create(&error), error == 0 else {
            return nil
        }
        self.decoder = dec
    }

    deinit {
        if let dec = decoder {
            rl_opus_bridge_decoder_destroy(dec)
        }
    }

    public func decode(opusData: Data) -> [Int16]? {
        guard let dec = decoder else { return nil }

        let maxFrameSize = 5760 // 120ms at 48kHz
        var pcmBuffer = [Int16](repeating: 0, count: maxFrameSize)

        let sampleCount = opusData.withUnsafeBytes { ptr in
            rl_opus_bridge_decode(
                dec,
                ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                opusData.count,
                &pcmBuffer,
                Int32(maxFrameSize)
            )
        }

        guard sampleCount > 0 else { return nil }
        return Array(pcmBuffer.prefix(Int(sampleCount)))
    }
}

// MARK: - C function declarations
// These are provided by the rl_opus_bridge C source file in the project.

@_silgen_name("rl_opus_bridge_decoder_create")
private func rl_opus_bridge_decoder_create(_ error: UnsafeMutablePointer<Int32>) -> UnsafeMutableRawPointer?

@_silgen_name("rl_opus_bridge_decoder_destroy")
private func rl_opus_bridge_decoder_destroy(_ decoder: UnsafeMutableRawPointer)

@_silgen_name("rl_opus_bridge_decode")
private func rl_opus_bridge_decode(_ decoder: UnsafeMutableRawPointer,
                                    _ data: UnsafePointer<UInt8>?,
                                    _ len: Int,
                                    _ pcm: UnsafeMutablePointer<Int16>,
                                    _ maxFrameSize: Int32) -> Int32
