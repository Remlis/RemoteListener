// SPDX-License-Identifier: MIT
// TransmitterStore.swift — Manages multiple transmitter connections with persistence

import Foundation
import Combine

/// Persistent info about a paired transmitter.
struct PairedTransmitter: Codable, Identifiable {
    let id: String
    let host: String
    let port: UInt16
    let fingerprint: String?
    let remoteDeviceName: String?
}

/// Manages connections to multiple transmitters with persistence.
public class TransmitterStore: ObservableObject {
    @Published public private(set) var connections: [TransmitterConnection] = []

    private let defaults = UserDefaults.standard
    private let pairedKey = "com.rl.receiver.pairedTransmitters"

    public init() {
        restoreConnections()
    }

    /// Add and connect to a new transmitter.
    public func addTransmitter(host: String, port: UInt16, fingerprint: String? = nil) -> TransmitterConnection {
        let conn = TransmitterConnection(host: host, port: port, expectedFingerprint: fingerprint)
        connections.append(conn)
        conn.connect()
        saveConnections()
        return conn
    }

    /// Remove and disconnect from a transmitter.
    public func removeTransmitter(_ connection: TransmitterConnection) {
        connection.disconnect()
        connections.removeAll { $0.identifier == connection.identifier }
        saveConnections()
    }

    /// Find a connection by identifier.
    public func connection(for identifier: String) -> TransmitterConnection? {
        connections.first { $0.identifier == identifier }
    }

    /// Number of connected (non-closed) transmitters.
    public var connectedCount: Int {
        connections.filter { $0.state != .closed }.count
    }

    // MARK: - Persistence

    private func saveConnections() {
        var paired: [PairedTransmitter] = []
        for conn in connections {
            paired.append(PairedTransmitter(
                id: conn.identifier,
                host: conn.host,
                port: conn.port,
                fingerprint: conn.expectedFingerprint,
                remoteDeviceName: conn.remoteDeviceName
            ))
        }
        if let data = try? JSONEncoder().encode(paired) {
            defaults.set(data, forKey: pairedKey)
        }
    }

    private func restoreConnections() {
        guard let data = defaults.data(forKey: pairedKey),
              let paired = try? JSONDecoder().decode([PairedTransmitter].self, from: data) else {
            return
        }
        for info in paired {
            let conn = TransmitterConnection(
                host: info.host,
                port: info.port,
                expectedFingerprint: info.fingerprint
            )
            connections.append(conn)
            conn.connect()
        }
    }
}
