// SPDX-License-Identifier: MIT
// TransmitterStore.swift — Manages multiple transmitter connections

import Foundation
import Combine

/// Manages connections to multiple transmitters.
public class TransmitterStore: ObservableObject {
    @Published public private(set) var connections: [TransmitterConnection] = []

    public init() {}

    /// Add and connect to a new transmitter.
    public func addTransmitter(host: String, port: UInt16) -> TransmitterConnection {
        let conn = TransmitterConnection(host: host, port: port)
        connections.append(conn)
        conn.connect()
        return conn
    }

    /// Remove and disconnect from a transmitter.
    public func removeTransmitter(_ connection: TransmitterConnection) {
        connection.disconnect()
        connections.removeAll { $0.identifier == connection.identifier }
    }

    /// Find a connection by identifier.
    public func connection(for identifier: String) -> TransmitterConnection? {
        connections.first { $0.identifier == identifier }
    }

    /// Number of connected (non-closed) transmitters.
    public var connectedCount: Int {
        connections.filter { $0.state != .closed }.count
    }
}
