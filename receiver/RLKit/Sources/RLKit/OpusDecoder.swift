// SPDX-License-Identifier: MIT
// OpusDecoder.swift — Opus decoding protocol for live audio playback

import Foundation

/// Protocol for Opus decoding, allowing C interop or mock implementations.
///
/// The concrete `RLKitOpusDecoder` implementation requires linking libopus
/// (via XCFramework in the Xcode project). For SPM-only builds without
/// libopus, provide a custom conforming type.
public protocol OpusDecoding {
    /// Decode an Opus frame to PCM (Int16, mono, 48kHz).
    /// Returns the decoded samples, or nil on error.
    func decode(opusData: Data) -> [Int16]?
}
