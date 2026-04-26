// SPDX-License-Identifier: MIT
// DiscoveryService.swift — Global discovery server client for remote transmitter lookup

import Foundation

/// A transmitter found via the global discovery server.
public struct RemoteDiscoveredTransmitter: Identifiable, Equatable {
    public let id: String      // device_id
    public let deviceName: String
    public let address: String
    public let port: UInt16

    public init(deviceID: String, deviceName: String, address: String, port: UInt16) {
        self.id = deviceID
        self.deviceName = deviceName
        self.address = address
        self.port = port
    }

    public static func == (lhs: RemoteDiscoveredTransmitter, rhs: RemoteDiscoveredTransmitter) -> Bool {
        lhs.id == rhs.id
    }
}

/// Client for the RemoteListener global discovery server.
///
/// Looks up transmitters by device ID to find their WAN address when
/// mDNS discovery (LAN-only) is not sufficient.
public class DiscoveryService {
    private let baseURL: String

    /// Create a discovery client pointing at the given server URL.
    public init(serverURL: String) {
        self.baseURL = serverURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    }

    /// Look up a transmitter by device ID.
    public func lookup(deviceID: String) async throws -> RemoteDiscoveredTransmitter? {
        guard let encodedID = deviceID.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed),
              let url = URL(string: "\(baseURL)/lookup?device_id=\(encodedID)") else {
            return nil
        }

        let (data, response) = try await URLSession.shared.data(from: url)

        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else {
            return nil
        }

        struct LookupResponse: Decodable {
            struct Announcement: Decodable {
                let device_id: String
                let device_name: String
                let address: String
                let port: UInt16
            }
            let found: Announcement?
        }

        let result = try JSONDecoder().decode(LookupResponse.self, from: data)
        guard let ann = result.found else { return nil }

        return RemoteDiscoveredTransmitter(
            deviceID: ann.device_id,
            deviceName: ann.device_name,
            address: ann.address,
            port: ann.port
        )
    }
}
